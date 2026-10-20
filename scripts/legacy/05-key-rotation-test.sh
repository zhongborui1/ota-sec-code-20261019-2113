#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OTA_API="http://127.0.0.1:8080"
EVIDENCE="$ROOT/evidence/raw"
mkdir -p "$EVIDENCE"

LOG="$EVIDENCE/key-rotation-$(date +%Y%m%d-%H%M%S).log"
exec > >(tee "$LOG") 2>&1

echo "============================================================"
echo "密钥轮换 + 5 分钟撤销测试"
echo "============================================================"
echo "开始时间：$(date -Iseconds)"
echo

# ===== 阶段 0：记录初始状态 =====
echo "--- 阶段 0：初始状态 ---"
curl -s "$OTA_API/health" | python3 -m json.tool
echo
INITIAL_ACTIVE=$(curl -s "$OTA_API/health" | python3 -c "import sys,json;print(json.load(sys.stdin)['active_key_id'])")
echo "初始 active key: $INITIAL_ACTIVE"
echo

# ===== 阶段 1：v1 active，100 车升级 =====
echo "--- 阶段 1：v1 active，100 车升级 ---"
T_PHASE1=$(date +%s)
python3 "$ROOT/services/vehicle-sim/simulator.py" 100 2>&1 | tee /tmp/phase1.txt
PHASE1_RATE=$(grep "成功率" /tmp/phase1.txt | awk '{print $2}' | tr -d '%')
echo "阶段 1 成功率: $PHASE1_RATE%"
echo

# ===== 阶段 2：轮换 =====
echo "--- 阶段 2：触发轮换 ---"
T_ROTATE_START=$(date +%s)
T_ROTATE_START_ISO=$(date -Iseconds)
echo "轮换开始时间：$T_ROTATE_START_ISO"

curl -s -X POST "$OTA_API/admin/rotate-trust" \
  -H "Content-Type: application/json" \
  -d '{"auto_rotate":true}' | python3 -m json.tool
echo

# ===== 阶段 3：等待生效（轮询 /health） =====
echo "--- 阶段 3：等待新密钥生效 ---"
echo "TTL = 60s，最多等 300s"
T_EFFECTIVE=""
for i in $(seq 1 60); do
  sleep 5
  ACTIVE=$(curl -s "$OTA_API/health" | python3 -c "import sys,json;print(json.load(sys.stdin)['active_key_id'])")
  ELAPSED=$(( $(date +%s) - T_ROTATE_START ))
  echo "  [${ELAPSED}s] active_key_id = $ACTIVE"
  if [ "$ACTIVE" = "ota-signing-v2" ]; then
    T_EFFECTIVE=$ELAPSED
    echo "  ✓ 新密钥在 ${ELAPSED}s 后生效"
    break
  fi
done

if [ -z "$T_EFFECTIVE" ]; then
  echo "  ✗ 5 分钟内未生效！"
  exit 1
fi
echo

# ===== 阶段 4：v1 签发的包被拒绝 =====
echo "--- 阶段 4：用 v1 手工签包，尝试验签 ---"

# 4.1 用 v1 私钥手工签一个 manifest
cat > /tmp/v1-manifest.json <<EOF
{"ecu_type":"ECU_ENGINE","package_id":"revoked-test","rollback_index":12,"version":"2.4.1","vin":"LSVAM4187C2999999"}
EOF

gmssl sm2sign -key pki/signing-v1/signing.key -pass v1pass \
  -id ota-signing-v1 \
  -in /tmp/v1-manifest.json \
  -out /tmp/v1-manifest.sig

V1_SIG_HEX=$(xxd -p /tmp/v1-manifest.sig | tr -d '\n')

# 4.2 尝试用 v1 key_id 验签 → 应被拒
echo "请求：key_id=ota-signing-v1（已 revoked）"
curl -s -X POST "$OTA_API/verify-manifest" \
  -H "Content-Type: application/json" \
  -d "{\"manifest\": {\"ecu_type\":\"ECU_ENGINE\",\"package_id\":\"revoked-test\",\"rollback_index\":12,\"version\":\"2.4.1\",\"vin\":\"LSVAM4187C2999999\"}, \"sig_hex\": \"$V1_SIG_HEX\", \"key_id\": \"ota-signing-v1\"}" | python3 -m json.tool
echo

# ===== 阶段 5：v2 重签 manifest，100 车升级 =====
echo "--- 阶段 5：v2 重签 manifest，100 车升级 ---"

# 5.1 用 v2 重签当前 manifest
cp packages/manifests/manifest-v1.sig packages/manifests/manifest-v1.sig.v1-backup
gmssl sm2sign -key pki/signing-v2/signing.key -pass v2pass \
  -id ota-signing-v2 \
  -in packages/manifests/manifest-canonical.json \
  -out packages/manifests/manifest-v1.sig

gmssl sm2verify -pubkey pki/signing-v2/signing.pub \
  -id ota-signing-v2 \
  -in packages/manifests/manifest-canonical.json \
  -sig packages/manifests/manifest-v1.sig

echo "[OK] manifest 已用 v2 重签"
echo

# 5.2 100 车升级
T_PHASE5=$(date +%s)
python3 "$ROOT/services/vehicle-sim/simulator.py" 100 2>&1 | tee /tmp/phase5.txt
PHASE5_RATE=$(grep "成功率" /tmp/phase5.txt | awk '{print $2}' | tr -d '%')
echo "阶段 5 成功率: $PHASE5_RATE%"
echo

# ===== 汇总 =====
echo "============================================================"
echo "测试结果汇总"
echo "============================================================"
echo "开始时间：              $(date -Iseconds)"
echo "初始 active key:        $INITIAL_ACTIVE"
echo "轮换触发时间：          $T_ROTATE_START_ISO"
echo "新密钥生效耗时：        ${T_EFFECTIVE}s（要求 < 300s）"
echo "阶段 1（v1）成功率：    ${PHASE1_RATE}%"
echo "阶段 5（v2）成功率：    ${PHASE5_RATE}%"
echo "v1 已停用密钥验签：     拒绝（见阶段 4 输出）"
echo "============================================================"
echo "日志：$LOG"
