#!/usr/bin/env bash
# PKI 初始化：生成 root / signing-v1 / signing-v2 密钥
# 口令优先从 pki/.secrets 读；不存在则生成 32 字符强口令并保存
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p pki/{root,signing-v1,signing-v2,trust}
mkdir -p pki/.secrets
chmod 700 pki/.secrets

get_or_create_pass() {
    local name="$1"
    local pass_file="pki/.secrets/${name}.pass"
    if [ -f "$pass_file" ]; then
        cat "$pass_file"
    else
        local new_pass=$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 32)
        echo "$new_pass" > "$pass_file"
        chmod 600 "$pass_file"
        echo "[NEW] $name 强口令已生成" >&2
        echo "$new_pass"
    fi
}

# root 密钥（离线根密钥，口令单独生成）
if [ -f pki/root/root.key ] && [ ! -f pki/.secrets/root.pass ]; then
    echo "[FAIL] pki/root/root.key 已存在但 pki/.secrets/root.pass 缺失。" >&2
    echo "       不能为新口令重新加密已有私钥；请从备份恢复口令文件。" >&2
    exit 1
fi
if [ ! -f pki/.secrets/root.pass ]; then
    ROOT_PASS=$(openssl rand -base64 48 | tr -d '/+=\n' | head -c 32)
    echo "$ROOT_PASS" > pki/.secrets/root.pass
    chmod 600 pki/.secrets/root.pass
else
    ROOT_PASS=$(cat pki/.secrets/root.pass)
fi

V1_PASS=$(get_or_create_pass signing-v1)
V2_PASS=$(get_or_create_pass signing-v2)

if [ ! -f pki/root/root.key ]; then
    gmssl sm2keygen -pass "$ROOT_PASS" \
        -out pki/root/root.key -pubout pki/root/root.pub
    echo "[OK] root key 生成"
fi

if [ ! -f pki/signing-v1/signing.key ]; then
    gmssl sm2keygen -pass "$V1_PASS" \
        -out pki/signing-v1/signing.key -pubout pki/signing-v1/signing.pub
    echo "[OK] signing-v1 生成"
fi

if [ ! -f pki/signing-v2/signing.key ]; then
    gmssl sm2keygen -pass "$V2_PASS" \
        -out pki/signing-v2/signing.key -pubout pki/signing-v2/signing.pub
    echo "[OK] signing-v2 生成"
fi

chmod 600 pki/*/*.key
chmod 644 pki/*/*.pub

echo "[OK] PKI initialized at $ROOT/pki"
echo "     口令文件: $ROOT/pki/.secrets/"
