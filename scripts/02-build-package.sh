#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p packages/{source,chunks,manifests}
mkdir -p evidence/raw

# 1. 生成 100 MB payload
if [ ! -f packages/source/payload.bin ]; then
  dd if=/dev/urandom of=packages/source/payload.bin bs=1M count=100 status=progress
fi

# 2. 计算明文 SM3
gmssl sm3 -in packages/source/payload.bin -out packages/source/payload.sm3
PAYLOAD_SM3=$(awk '{print $1}' packages/source/payload.sm3)
PLAIN_SIZE=$(stat -c%s packages/source/payload.bin)
echo "[OK] payload 明文 SM3 = $PAYLOAD_SM3 (size=$PLAIN_SIZE)"

# ========== SM4-CTR 加密 ==========
echo "[SM4] 生成会话密钥 + IV..."
SM4_KEY=$(openssl rand -hex 16)
SM4_IV=$(openssl rand -hex 16)
echo "$SM4_KEY" > packages/source/sm4_key.hex
echo "$SM4_IV" > packages/source/sm4_iv.hex
chmod 600 packages/source/sm4_key.hex
chmod 644 packages/source/sm4_iv.hex
echo "[SM4] key: ${SM4_KEY:0:8}... iv: ${SM4_IV:0:8}..."

echo "[SM4] 加密 payload (SM4-CTR)..."
gmssl sm4_ctr -key "$SM4_KEY" -iv "$SM4_IV" -encrypt \
  -in packages/source/payload.bin \
  -out packages/source/payload.enc

ENC_SIZE=$(stat -c%s packages/source/payload.enc)
echo "[SM4] payload.enc size = $ENC_SIZE"

gmssl sm3 -in packages/source/payload.enc -out packages/source/payload.enc.sm3
ENC_SM3=$(awk '{print $1}' packages/source/payload.enc.sm3)
echo "[SM4] 密文 SM3 = $ENC_SM3"

# 3. 分块（基于密文 payload.enc）
rm -rf packages/chunks/*
split -b 1M -d -a 6 packages/source/payload.enc packages/chunks/chunk-
for f in packages/chunks/chunk-*; do
  gmssl sm3 -in "$f" -out "$f.sm3"
done
echo "[OK] 密文分块为 $(ls packages/chunks/chunk-* | grep -v '\.sm3$' | wc -l) 块"

# 4. 生成 manifest（人类可读）
cat > packages/manifests/manifest-v1.json <<EOF
{
  "package_id": "ecu-a-2026-001",
  "vehicle_models": ["MODEL-A"],
  "ecu_type": "ECU_ENGINE",
  "component": "engine-control",
  "version": "2.4.1",
  "min_version": "2.3.0",
  "rollback_index": 12,
  "size": $PLAIN_SIZE,
  "sm3": "$PAYLOAD_SM3",
  "encrypted_size": $ENC_SIZE,
  "encrypted_sm3": "$ENC_SM3",
  "sm4_iv": "$SM4_IV",
  "chunk_size": 1048576,
  "expires_at": "2026-12-31T23:59:59Z",
  "key_id": "ota-signing-v1",
  "task_id": "task-2026-09-28-0001",
  "vin": "LSVAM4187C2123456"
}
EOF

# 5. 规范化：生成 manifest-canonical.json（签名/验签的实际对象）
python3 - <<'PY'
import json
from pathlib import Path
src = Path("packages/manifests/manifest-v1.json")
dst = Path("packages/manifests/manifest-canonical.json")
canonical = json.dumps(
    json.loads(src.read_text()),
    sort_keys=True, separators=(",", ":"), ensure_ascii=False,
)
dst.write_text(canonical)
print(f"[OK] canonical bytes = {len(canonical.encode('utf-8'))}")
print(f"[OK] canonical content = {canonical}")
PY

# 6. 对规范化字节签名
gmssl sm2sign -key pki/signing-v1/signing.key -pass "$(cat ~/ota-sec/pki/.secrets/signing-v1.pass)" \
  -id ota-signing-v1 \
  -in packages/manifests/manifest-canonical.json \
  -out packages/manifests/manifest-v1.sig

# 7. 本地验签
gmssl sm2verify -pubkey pki/signing-v1/signing.pub \
  -id ota-signing-v1 \
  -in packages/manifests/manifest-canonical.json \
  -sig packages/manifests/manifest-v1.sig

echo "[OK] package built and signed (SM4-CTR encrypted + SM2 signed)"
echo "     plain  SM3: $PAYLOAD_SM3"
echo "     enc    SM3: $ENC_SM3"
echo "     SM4 IV:     $SM4_IV"
