#!/usr/bin/env python3
"""
OTA 车端共享客户端。

被 simulator.py 与各测试脚本复用，保证车端逻辑走同一条真实路径：
  - enroll()                     设备注册 PoP，拿 Bearer token（本地缓存）
  - verify_manifest_vehicle_side  车端本地验签（VIN 绑定 + 防回滚 + 信任状态 + 本地 SM2 验签）
  - load_rollback / save_rollback 防回滚索引持久化（替代随机值）
  - request_task / download_chunk 带鉴权头的请求封装

车端信任锚：
  - 预置在 pki/vehicle-trust/<key_id>.pub（只读语义）
  - 轮换出新密钥时，车端从 /signing-pub/<key_id> 拉取并缓存，模拟"信任锚更新"。
    生产环境该更新应由 root 密钥签名后下发（本工程 root 离线，故简化为预置+拉取）。
"""
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(os.environ.get("OTA_ROOT", "/home/rjh/ota-sec"))
OTA_API = os.environ.get("OTA_API", "http://127.0.0.1:8080")

PKI = ROOT / "pki"
ECU_LOCAL = PKI / "ecu-local"
TRUST_ANCHORS = PKI / "vehicle-trust"
VEHICLE_STATE = ROOT / "data" / "vehicle-state"


def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sm3_hex(data: bytes) -> str:
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def _safe_vin(vin: str) -> str:
    return "".join(c for c in vin if c.isalnum())


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------- HTTP（可选鉴权） ----------
def http_get_json(url, headers=None, timeout=30):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def http_post_json(url, obj, headers=None, timeout=120):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode())


def http_get_bytes(url, headers=None, timeout=120):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


# ---------- 注册 PoP ----------
def enroll(vin):
    """设备注册 PoP，返回 Bearer token。token 本地缓存（pki/ecu-local/<vin>/token）。"""
    safe = _safe_vin(vin)
    local_dir = ECU_LOCAL / safe
    local_dir.mkdir(parents=True, exist_ok=True)
    key_path = local_dir / "ecu.key"
    pub_path = local_dir / "ecu.pub"
    token_path = local_dir / "token"

    if token_path.exists():
        return token_path.read_text().strip()

    if not key_path.exists():
        subprocess.run([
            "gmssl", "sm2keygen",
            "-pass", f"localpass-{safe}",
            "-out", str(key_path),
            "-pubout", str(pub_path),
        ], check=True, capture_output=True)
        os.chmod(key_path, 0o600)

    _, ch = http_post_json(f"{OTA_API}/api/enrollment/challenge", {"vin": vin})
    nonce = ch["nonce"]

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(nonce)
        nonce_file = f.name
    sig_file = nonce_file + ".sig"
    try:
        subprocess.run([
            "gmssl", "sm2sign",
            "-key", str(key_path),
            "-pass", f"localpass-{safe}",
            "-id", vin,
            "-in", nonce_file,
            "-out", sig_file,
        ], check=True, capture_output=True)
        sig_hex = Path(sig_file).read_bytes().hex()
    finally:
        Path(nonce_file).unlink(missing_ok=True)
        Path(sig_file).unlink(missing_ok=True)

    _, reg = http_post_json(f"{OTA_API}/api/enrollment/register", {
        "vin": vin, "nonce": nonce, "sig_hex": sig_hex,
        "pub_pem": pub_path.read_text(),
    })
    token = reg["token"]
    token_path.write_text(token)
    return token


# ---------- 鉴权业务请求 ----------
def request_task(vin):
    """鉴权申请升级任务。"""
    token = enroll(vin)
    return http_post_json(f"{OTA_API}/request-task", {"vin": vin},
                          auth_headers(token))


def download_chunk(vin, task_id, chunk_idx):
    """鉴权下载分块。"""
    token = enroll(vin)
    return http_get_bytes(f"{OTA_API}/download/{task_id}/{chunk_idx}",
                          auth_headers(token))


def report_status(vin, payload):
    """鉴权上报状态。"""
    token = enroll(vin)
    return http_post_json(f"{OTA_API}/report-status", payload, auth_headers(token))


# ---------- 车端本地验签 ----------
def fetch_signing_pub(key_id):
    """取签名公钥 PEM：优先本地信任锚，缺失则从云端拉取并缓存。"""
    TRUST_ANCHORS.mkdir(parents=True, exist_ok=True)
    local_pub = TRUST_ANCHORS / f"{key_id}.pub"
    if local_pub.exists():
        return local_pub.read_text()
    data = http_get_json(f"{OTA_API}/signing-pub/{key_id}")
    pub_pem = data["pub_pem"]
    local_pub.write_text(pub_pem)
    return pub_pem


def verify_manifest_vehicle_side(vin, manifest, sig_hex, key_id, local_rollback):
    """
    车端完整校验（不委托云端 /verify-manifest）：
      1. VIN 绑定（升级授权）
      2. 防回滚（本地持久化 rollback_index）
      3. 信任锚状态（/trust-metadata 里 key 状态必须 active/deprecated）
      4. 本地 SM2 验签（用本地信任锚里的公钥）
    """
    if manifest.get("vin") != vin:
        return False, f"vin_mismatch: manifest.vin={manifest.get('vin')} != {vin}"
    ri = manifest.get("rollback_index", 0)
    # 防降级：仅拒绝严格低于本地已安装版本（ri < local），允许同版本重刷
    if ri < local_rollback:
        return False, f"rollback_rejected: {local_rollback} -> {ri}"

    trust = http_get_json(f"{OTA_API}/trust-metadata")
    key_info = trust.get("keys", {}).get(key_id)
    if not key_info:
        return False, "unknown_key"
    if key_info.get("status") not in ("active", "deprecated"):
        return False, f"key_{key_info.get('status')}"

    pub_pem = fetch_signing_pub(key_id)
    manifest_bytes = canonical_json_bytes(manifest)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(manifest_bytes)
        in_path = f.name
    sig_path = in_path + ".sig"
    pub_path = in_path + ".pub"
    Path(sig_path).write_bytes(bytes.fromhex(sig_hex))
    Path(pub_path).write_text(pub_pem)
    try:
        r = subprocess.run([
            "gmssl", "sm2verify",
            "-pubkey", pub_path,
            "-id", key_id,
            "-in", in_path,
            "-sig", sig_path,
        ], capture_output=True)
        if r.returncode == 0 and b"success" in r.stdout.lower():
            return True, "ok"
        return False, f"sm2_verify_failed: {r.stderr.decode(errors='ignore')[:120]}"
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)
        Path(pub_path).unlink(missing_ok=True)


def validate_received_manifest(vin, manifest, sig_hex, key_id,
                               local_rollback, chunk_hashes=None):
    """向后兼容别名：车辆侧收到 manifest 后的完整校验。"""
    return verify_manifest_vehicle_side(vin, manifest, sig_hex, key_id, local_rollback)


# ---------- 防回滚持久化 ----------
def rollback_state_path(vin):
    return VEHICLE_STATE / _safe_vin(vin) / "rollback_index"


def load_rollback(vin, default=10):
    p = rollback_state_path(vin)
    if p.exists():
        try:
            return int(p.read_text().strip())
        except (ValueError, OSError):
            pass
    return default


def save_rollback(vin, value):
    p = rollback_state_path(vin)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(value))
