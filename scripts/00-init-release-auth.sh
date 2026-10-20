#!/usr/bin/env bash
#
# 初始化"发布授权 + 服务身份"材料（幂等）。
#
# 产出：
#   pki/release-v1/release.key           发布授权私钥（离线，仅签发 grant 时使用）
#   pki/release-v1/release.pub           发布授权公钥
#   pki/release-v1/release.cert.json     由 root 签发的密钥证书（role=release-authority）
#   pki/release-v1/release.cert.sig      root 对证书的 SM2 签名
#   pki/service-auth/<svc>.key           各服务 HMAC-SM3 身份密钥（0600）
#   pki/service-auth/identities.json     服务身份 → 权限范围登记表
#   pki/service-auth/admin.token         管理接口令牌
#   data/release-grants/                 授权票据目录（ota-api 只读挂载）
#   data/signing-auth/                   签名服务本地授权库（nonce/配额/审计）
#
# 私钥 release.key 不挂载进任何容器；签名容器只拿到 release.cert + root.pub。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p pki/{release-v1,service-auth,.secrets} data/{release-grants,signing-auth}
chmod 700 pki/release-v1 pki/service-auth pki/.secrets data/release-grants data/signing-auth

get_or_create_pass() {
    local name="$1"
    local pass_file="pki/.secrets/${name}.pass"
    if [ -f "$pass_file" ]; then
        cat "$pass_file"
    else
        local p
        p=$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 32)
        echo "$p" > "$pass_file"
        chmod 600 "$pass_file"
        echo "[NEW] $name 口令已生成" >&2
        echo "$p"
    fi
}

ROOT_PASS=$(cat pki/.secrets/root.pass)
REL_PASS=$(get_or_create_pass release-v1)

# 1. 发布授权密钥（与签名密钥分离的另一把私钥）
if [ ! -f pki/release-v1/release.key ]; then
    gmssl sm2keygen -pass "$REL_PASS" \
        -out pki/release-v1/release.key -pubout pki/release-v1/release.pub
    chmod 600 pki/release-v1/release.key
    chmod 644 pki/release-v1/release.pub
    echo "[OK] release-v1 密钥生成"
fi

# 2. root 签发的发布授权密钥证书
if [ ! -f pki/release-v1/release.cert.json ] || [ ! -f pki/release-v1/release.cert.sig ]; then
    REL_PASS="$REL_PASS" ROOT_PASS="$ROOT_PASS" python3 - <<'PY'
import json, os, subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

root = Path("pki")
cert = {
    "cert_version": 1,
    "key_id": "ota-release-v1",
    "role": "release-authority",
    "pubkey_pem": (root / "release-v1/release.pub").read_text(),
    "not_before": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "not_after": (datetime.now(timezone.utc) + timedelta(days=730)).strftime("%Y-%m-%dT%H:%M:%SZ"),
}
canonical = json.dumps(cert, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode()
(root / "release-v1/release.cert.json").write_text(json.dumps(cert, indent=2))
inp = root / "release-v1/.cert.canon"
inp.write_bytes(canonical)
subprocess.run([
    "gmssl", "sm2sign",
    "-key", str(root / "root/root.key"), "-pass", os.environ["ROOT_PASS"],
    "-id", "ota-root-v1", "-in", str(inp),
    "-out", str(root / "release-v1/release.cert.sig"),
], check=True, capture_output=True)
inp.unlink()
print("[OK] root 已签发 release-v1 证书")
PY
fi

# 3. 服务身份密钥与范围登记表
if [ ! -f pki/service-auth/ota-api.key ]; then
    openssl rand -hex 32 > pki/service-auth/ota-api.key
    chmod 600 pki/service-auth/ota-api.key
    echo "[OK] ota-api 服务身份密钥生成"
fi
if [ ! -f pki/service-auth/admin.token ]; then
    openssl rand -hex 32 > pki/service-auth/admin.token
    chmod 600 pki/service-auth/admin.token
    echo "[OK] admin token 生成"
fi

cat > pki/service-auth/identities.json <<'JSON'
{
  "services": {
    "ota-api": {
      "secret_file": "/keys/service-auth/ota-api.key",
      "scopes": [
        "manifest:sign",
        "manifest:verify",
        "ecu:provision",
        "ecu:wrap",
        "time:attest",
        "pubkey:read"
      ]
    }
  }
}
JSON
chmod 644 pki/service-auth/identities.json

echo "[OK] 发布授权与服务身份材料就绪"
echo "     grant 目录: $ROOT/data/release-grants"
echo "     授权库:     $ROOT/data/signing-auth"
