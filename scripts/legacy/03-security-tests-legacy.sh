#!/usr/bin/env bash
#
# ⚠️  LEGACY: 早期手工安全测试脚本（5 次单点测试）
#
# 已被 08-negative-tests.py 完全覆盖：
#   - 08 脚本对 6 类攻击各跑 100 次，输出拒绝率统计
#   - 08 包含 2a（篡改 manifest）和 2b（密钥混淆）两个细分测试
#   - 08 包含 1b（真改 MinIO 对象）端到端测试
#
# 保留本脚本仅用于快速手测，不作为正式竞赛证据。
#
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT/packages/manifests"

mkdir -p "$ROOT/evidence/raw"
PUB="$ROOT/pki/signing-v1/signing.pub"

run_test() {
  local name="$1" file="$2" out="$ROOT/evidence/raw/$3"
  echo "=== $name ===" | tee "$out"
  echo "命令：gmssl sm2verify -pubkey signing-v1.pub -id ota-signing-v1 -in $file -sig manifest-v1.sig" | tee -a "$out"
  echo "--- 输出 ---" | tee -a "$out"
  gmssl sm2verify -pubkey "$PUB" -id ota-signing-v1 \
    -in "$file" -sig manifest-v1.sig 2>&1 | tee -a "$out"
  echo "--- 判定：非 success 即为拒绝 ---" | tee -a "$out"
  echo | tee -a "$out"
}

cp manifest-v1.json t1.json && sed -i 's/2.4.1/2.4.2/' t1.json
run_test "篡改版本号 2.4.1 -> 2.4.2" t1.json tamper-version.txt

cp manifest-v1.json t2.json && sed -i 's/ECU_ENGINE/ECU_BRAKE/' t2.json
run_test "篡改 ECU 类型 ECU_ENGINE -> ECU_BRAKE" t2.json tamper-ecu.txt

cp manifest-v1.json t3.json && sed -i 's/LSVAM4187C2123456/LSVAM4187C2999999/' t3.json
run_test "篡改 VIN LSVAM4187C2123456 -> LSVAM4187C2999999" t3.json tamper-vin.txt

cp manifest-v1.json t4.json && sed -i 's/"rollback_index": 12/"rollback_index": 11/' t4.json
run_test "降级 rollback_index 12 -> 11" t4.json tamper-rollback.txt

# 伪造：v2 私钥签，v1 公钥验
gmssl sm2sign -key "$ROOT/pki/signing-v2/signing.key" -pass v2pass \
  -id ota-signing-v2 -in manifest-v1.json -out forged.sig
OUT="$ROOT/evidence/raw/forged-key.txt"
echo "=== 伪造签名：v2 私钥签，v1 公钥验 ===" | tee "$OUT"
echo "命令：gmssl sm2sign -key signing-v2.key -id ota-signing-v2 -in manifest-v1.json -out forged.sig" | tee -a "$OUT"
echo "命令：gmssl sm2verify -pubkey signing-v1.pub -id ota-signing-v2 -in manifest-v1.json -sig forged.sig" | tee -a "$OUT"
echo "--- 输出 ---" | tee -a "$OUT"
gmssl sm2verify -pubkey "$PUB" -id ota-signing-v2 \
  -in manifest-v1.json -sig forged.sig 2>&1 | tee -a "$OUT"
echo "--- 判定：非 success 即为拒绝 ---" | tee -a "$OUT"

rm -f t1.json t2.json t3.json t4.json forged.sig
echo "[OK] all security tests done, results in $ROOT/evidence/raw/"
