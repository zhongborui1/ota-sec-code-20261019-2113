#!/usr/bin/env python3
"""
OTA 车端共享客户端。

被 simulator.py 与各测试脚本复用，保证车端逻辑走同一条真实路径：
  - enroll()                     设备注册 PoP，拿 Bearer token（本地缓存）
  - verify_manifest_vehicle_side  车端本地验签（VIN 绑定 + 防回滚 + 信任状态 + 本地 SM2 验签）
  - load_rollback / save_rollback 防回滚索引持久化（替代随机值）
  - request_task / download_chunk 带鉴权头的请求封装

车端信任锚：
  - 仅通过可信初始化预置 root.pub；新发布公钥必须由根签名策略授权。
  - 每车 SQLite 保存接受过的最高策略版本，拒绝回退及同版本内容变更。
"""
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
import urllib.error
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ota_common.trust import (SecurityError, accept_policy, cached_policy, trusted_key,
                              enrollment_message, timestamp)
ROOT = Path(os.environ.get("OTA_ROOT", str(Path(__file__).resolve().parents[2])))
OTA_API = os.environ.get("OTA_API", "http://127.0.0.1:8080")

PKI = ROOT / "pki"
ECU_LOCAL = PKI / "ecu-local"
TRUST_ANCHORS = PKI / "vehicle-trust"
ROOT_PUB = TRUST_ANCHORS / "root.pub"
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
def enroll(vin, force=False):
    """设备注册 PoP，返回 Bearer token。token 本地缓存（pki/ecu-local/<vin>/token）。"""
    safe = _safe_vin(vin)
    local_dir = ECU_LOCAL / safe
    local_dir.mkdir(parents=True, exist_ok=True)
    key_path = local_dir / "ecu.key"
    pub_path = local_dir / "ecu.pub"
    token_path = local_dir / "token"

    if token_path.exists() and not force:
        return token_path.read_text().strip()

    if not key_path.exists() or not pub_path.exists():
        raise SecurityError("device_not_initialized: run scripts/17-security-admin.py provision")

    _, ch = http_post_json(f"{OTA_API}/api/enrollment/challenge", {"vin": vin})
    nonce = ch["nonce"]

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(enrollment_message(vin, nonce, pub_path.read_text()).decode())
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
    os.chmod(token_path, 0o600)
    return token


# ---------- 鉴权业务请求 ----------
def _authenticated(vin, operation):
    token = enroll(vin)
    try:
        return operation(auth_headers(token))
    except urllib.error.HTTPError as exc:
        if exc.code != 401:
            raise
    return operation(auth_headers(enroll(vin, force=True)))


def request_task(vin):
    return _authenticated(vin, lambda headers: http_post_json(
        f"{OTA_API}/request-task", {"vin": vin}, headers))


def download_chunk(vin, task_id, chunk_idx):
    return _authenticated(vin, lambda headers: http_get_bytes(
        f"{OTA_API}/download/{task_id}/{chunk_idx}", headers))


def report_status(vin, payload):
    return _authenticated(vin, lambda headers: http_post_json(
        f"{OTA_API}/report-status", payload, headers))


def trust_state_path(vin):
    return VEHICLE_STATE / _safe_vin(vin) / "trust.sqlite3"


def refresh_trust(vin):
    response = http_get_json(f"{OTA_API}/trust-metadata")
    return accept_policy(response.get("document"), ROOT_PUB, trust_state_path(vin))


def verify_manifest_vehicle_side(vin, manifest, sig_hex, key_id, local_rollback):
    from ota_common.trust import verify_sm2, canonical
    try:
        if manifest.get("vin") != vin:
            raise SecurityError("vin_mismatch")
        if manifest.get("key_id") != key_id:
            raise SecurityError("key_id_mismatch")
        if type(manifest.get("rollback_index")) is not int or manifest["rollback_index"] < local_rollback:
            raise SecurityError("rollback_rejected")
        if timestamp(manifest.get("expires_at")) <= __import__('time').time():
            raise SecurityError("manifest_expired")
        policy = refresh_trust(vin)
        pub = trusted_key(policy, key_id)
        if not verify_sm2(pub, canonical(manifest), sig_hex, key_id):
            raise SecurityError("sm2_verify_failed")
        return True, "ok"
    except (SecurityError, OSError, ValueError) as exc:
        return False, str(exc)


def validate_received_manifest(vin, manifest, sig_hex, key_id,
                               local_rollback, chunk_hashes=None):
    """向后兼容别名：车辆侧收到 manifest 后的完整校验。"""
    return verify_manifest_vehicle_side(vin, manifest, sig_hex, key_id, local_rollback)


# ---------- 防回滚持久化 ----------
def rollback_state_path(vin):
    return VEHICLE_STATE / _safe_vin(vin) / "rollback_index"


def load_rollback(vin, default=10):
    p = rollback_state_path(vin)
    floor = default
    if p.exists():
        try:
            floor = int(p.read_text().strip())
            if floor < 0:
                raise ValueError()
        except (ValueError, OSError) as exc:
            raise SecurityError('rollback_state_corrupt') from exc
    boot = p.parent / 'boot_state.json'
    if boot.exists():
        state = json.loads(boot.read_text())
        floor = max(floor, int(state.get('rollback_index', floor)))
    return floor


def save_rollback(vin, value):
    p = rollback_state_path(vin)
    p.parent.mkdir(parents=True, exist_ok=True)
    from ota_common.trust import atomic_json
    atomic_json(p, max(load_rollback(vin), int(value)))
