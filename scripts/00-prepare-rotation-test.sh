#!/usr/bin/env bash
#
# 密钥轮换测试的前置状态准备脚本。
# 目标状态：
#   - trust 元数据：v1 active，v2 prepared
#   - manifest 签名：用 v1 私钥签
#   - task 目录：清空
#   - Redis trust 缓存：清空（由 ota-api 下次请求重建）
#
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

OTA_API="http://127.0.0.1:8080"

echo "=== 准备轮换测试前置状态 ==="

# 1. 清 Redis trust 缓存（带密码）
echo "[1/5] 清 Redis trust 缓存"
REDIS_PASS=$(grep REDIS_PASSWORD "$ROOT/compose/.env" | cut -d= -f2)
docker exec ota-redis redis-cli -a "$REDIS_PASS" --no-auth-warning DEL ota:trust-metadata >/dev/null

# 2. 删磁盘 trust 元数据（ota-api 会用默认值重建）
echo "[2/5] 删磁盘 trust 元数据（ota-api 重启后重建默认 v1 active）"
rm -f data/trust/trust-metadata.json

# 3. 用 v1 重签 manifest
echo "[3/5] 用 v1 私钥重签 manifest"
python3 - <<'PY'
import json, subprocess
from pathlib import Path

ROOT = Path("/home/rjh/ota-sec")
m_json = ROOT / "packages/manifests/manifest-v1.json"
m_canon = ROOT / "packages/manifests/manifest-canonical.json"
m_sig = ROOT / "packages/manifests/manifest-v1.sig"

manifest = json.loads(m_json.read_text())
manifest["key_id"] = "ota-signing-v1"
m_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))

canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False)
m_canon.write_text(canonical)

subprocess.run([
    "gmssl", "sm2sign",
    "-key", str(ROOT / "pki/signing-v1/signing.key"), "-pass", (ROOT / "pki/.secrets/signing-v1.pass").read_text().strip(),
    "-id", "ota-signing-v1",
    "-in", str(m_canon), "-out", str(m_sig),
], check=True)
print("  manifest 已用 v1 重签")
PY

# 4. 清 task 目录
echo "[4/5] 清空 task 目录"
rm -f data/tasks/*.json

# 5. 重启 ota-api
echo "[5/5] 重启 ota-api 让它重新初始化"
cd compose
docker compose restart ota-api >/dev/null
sleep 5

echo
echo "[6/6] 用 v1 签发发布授权票据（轮换前发布）"
python3 "$ROOT/scripts/15-release-authorize.py" issue \
  --key-id ota-signing-v1 --max-tasks 2000 --validity-hours 6

# 7. 验证前置条件
echo
echo "=== 前置状态验证 ==="
HEALTH=$(curl -s "$OTA_API/health")
ACTIVE=$(echo "$HEALTH" | python3 -c "import sys,json;print(json.load(sys.stdin)['active_key_id'])")
REDIS_OK=$(echo "$HEALTH" | python3 -c "import sys,json;print(json.load(sys.stdin)['redis_ok'])")
echo "active_key_id: $ACTIVE"
echo "redis_ok:      $REDIS_OK"

if [ "$ACTIVE" != "ota-signing-v1" ]; then
  echo "[FAIL] active key 不是 v1"
  exit 1
fi
if [ "$REDIS_OK" != "True" ]; then
  echo "[FAIL] Redis 未连接"
  exit 1
fi

echo
echo "[OK] 前置状态就绪：v1 active，Redis 正常"
