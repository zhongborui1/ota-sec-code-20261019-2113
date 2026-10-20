#!/usr/bin/env python3
"""
OTA 签名服务：私钥唯一持有者 + 发布授权检查点。

对外接口全部要求服务身份（HMAC-SM3 请求签名）与最小权限 scope。
签名接口 /sign-manifest 还要求出示由 release 私钥签发、root 证书背书的
授权票据，并逐字段核对 manifest 确实属于被批准的那次发布。

不再提供对任意字节签名的 /sign 接口。
"""
import os
import json
import re
import subprocess
import tempfile
import time
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, g

import security
from security import Deny
from ota_common.trust import (device_record, enrollment_message, verify_sm2,
                              SecurityError)
DEVICE_REGISTRY = Path(os.environ.get("DEVICE_REGISTRY", "/keys/device-registry"))

app = Flask(__name__)
@app.errorhandler(SecurityError)
def security_error(exc):
    return jsonify({"error": str(exc)}), 403

app.config["MAX_CONTENT_LENGTH"] = 4 * 1024 * 1024

KEY_DIR = Path(os.environ.get("KEY_DIR", "/keys"))
MAX_SIGN_BYTES = 64 * 1024

_KEYS_CACHE = {"data": {}, "at": 0.0}

VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")


def get_keys():
    """扫描 KEY_DIR 下所有 signing-* 目录，5 秒缓存。"""
    now = time.time()
    if now - _KEYS_CACHE["at"] < 5.0 and _KEYS_CACHE["data"]:
        return _KEYS_CACHE["data"]

    keys = {}
    for d in sorted(KEY_DIR.glob("signing-*")):
        if not d.is_dir():
            continue
        key_file = d / "signing.key"
        pub_file = d / "signing.pub"
        if not key_file.exists() or not pub_file.exists():
            continue
        suffix = d.name.replace("signing-", "", 1)
        key_id = f"ota-signing-{suffix}"
        pass_env = f"{suffix.upper().replace('-', '_')}_PASS"
        pass_file_env = f"{suffix.upper().replace('-', '_')}_PASS_FILE"
        pass_file_path = os.environ.get(pass_file_env, "")
        if pass_file_path and Path(pass_file_path).exists():
            pass_val = Path(pass_file_path).read_text().strip()
        else:
            pass_val = os.environ.get(pass_env, "")
            if not pass_val:
                # 没有口令就不加载该密钥；绝不回退到可猜的默认口令
                print(f"[WARN] {key_id} 缺少口令文件，跳过", flush=True)
                continue
        keys[key_id] = {"key": key_file, "pub": pub_file, "pass": pass_val}

    _KEYS_CACHE["data"] = keys
    _KEYS_CACHE["at"] = now
    return keys


def run_gmssl(args):
    proc = subprocess.run(["gmssl"] + args, capture_output=True)
    return proc.returncode, proc.stdout, proc.stderr


def require(scope):
    """服务身份 + scope 校验；失败统一返回机器可读原因。"""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                g.caller = security.verify_service_request(request, scope)
            except Deny as e:
                security.log_decision(caller=None, action=request.path,
                                      decision="deny", reason=e.reason,
                                      detail=e.detail)
                return jsonify({"error": e.reason, "detail": e.detail}), e.status
            return fn(*args, **kwargs)
        return wrapper
    return deco


def deny_response(e):
    security.log_decision(caller=getattr(g, "caller", None),
                          action=request.path, decision="deny",
                          reason=e.reason, detail=e.detail)
    return jsonify({"error": e.reason, "detail": e.detail}), e.status


@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "signing-service",
        "key_count": len(get_keys()),
        "raw_signing_enabled": False,
    })


# ---------- 核心：授权签名 ----------

@app.route("/sign-manifest", methods=["POST"])
@require("manifest:sign")
def sign_manifest():
    try:
        body = request.get_json(force=True)
        manifest = body.get("manifest")
        grant = body.get("grant")
        grant_sig_hex = body.get("grant_sig_hex")
        if not manifest or not grant or not grant_sig_hex:
            raise Deny(400, "missing_grant_or_manifest")

        security.verify_grant(grant, grant_sig_hex)
        security.check_manifest(manifest, grant)

        key_id = manifest["key_id"]
        key_status = security.signing_key_status(key_id)
        if key_status != "active":
            raise Deny(403, "key_not_active",
                       {"key_id": key_id, "status": key_status})

        keys = get_keys()
        if key_id not in keys:
            raise Deny(400, "unknown_key_id", {"available": sorted(keys)})
        k = keys[key_id]

        manifest_bytes = security.canonical_json_bytes(manifest)
        if len(manifest_bytes) > MAX_SIGN_BYTES:
            raise Deny(413, "manifest_too_large")
        digest = security.sm3_hex(manifest_bytes)
        task_id = manifest["task_id"]
        auth_id = grant["auth_id"]

        mode, existing_sig = security.reserve_task(grant, task_id, digest)
        if mode == "replay" and existing_sig:
            security.log_decision(caller=g.caller, action="sign-manifest",
                                  decision="replay", auth_id=auth_id,
                                  task_id=task_id, key_id=key_id,
                                  digest=digest)
            return jsonify({
                "key_id": key_id, "sig_hex": existing_sig,
                "sig_len": len(bytes.fromhex(existing_sig)),
                "auth_id": auth_id, "manifest_digest": digest,
                "idempotent_replay": True,
            })

        with tempfile.NamedTemporaryFile(delete=False) as fin:
            fin.write(manifest_bytes)
            in_path = fin.name
        out_path = in_path + ".sig"
        try:
            rc, _, err = run_gmssl([
                "sm2sign", "-key", str(k["key"]), "-pass", k["pass"],
                "-id", key_id, "-in", in_path, "-out", out_path,
            ])
            if rc != 0:
                security.release_reservation(auth_id, task_id)
                security.log_decision(caller=g.caller, action="sign-manifest",
                                      decision="deny", reason="sign_failed",
                                      auth_id=auth_id, task_id=task_id,
                                      key_id=key_id)
                return jsonify({"error": "sign failed",
                                "stderr": err.decode(errors="ignore")}), 500
            sig = Path(out_path).read_bytes()
        finally:
            Path(in_path).unlink(missing_ok=True)
            Path(out_path).unlink(missing_ok=True)

        sig_hex = sig.hex()
        security.store_signature(auth_id, task_id, sig_hex)
        security.log_decision(caller=g.caller, action="sign-manifest",
                              decision="allow", auth_id=auth_id,
                              task_id=task_id, key_id=key_id,
                              digest=digest, sig_len=len(sig))
        return jsonify({
            "key_id": key_id, "sig_hex": sig_hex, "sig_len": len(sig),
            "auth_id": auth_id, "manifest_digest": digest,
            "idempotent_replay": False,
        })
    except Deny as e:
        return deny_response(e)


# ---------- 验签 ----------

@app.route("/verify", methods=["POST"])
@require("manifest:verify")
def verify():
    body = request.get_json(force=True)
    key_id = body.get("key_id", "ota-signing-v1")
    keys = get_keys()
    if key_id not in keys:
        return jsonify({"valid": False,
                        "error": f"unknown key_id: {key_id}"}), 400
    k = keys[key_id]

    try:
        data = bytes.fromhex(body["data_hex"])
        sig = bytes.fromhex(body["sig_hex"])
    except (KeyError, ValueError) as e:
        return jsonify({"error": f"bad input: {e}"}), 400
    if len(data) > security.MAX_VERIFY_BYTES or len(sig) > 256:
        return jsonify({"valid": False, "error": "input too large"}), 413

    with tempfile.NamedTemporaryFile(delete=False) as fin:
        fin.write(data)
        in_path = fin.name
    sig_path = in_path + ".sig"
    Path(sig_path).write_bytes(sig)

    try:
        rc, out, err = run_gmssl([
            "sm2verify", "-pubkey", str(k["pub"]), "-id", key_id,
            "-in", in_path, "-sig", sig_path,
        ])
        valid = (rc == 0) and (b"success" in out.lower())
        return jsonify({
            "valid": valid, "key_id": key_id,
            "stdout": out.decode(errors="ignore").strip(),
            "stderr": err.decode(errors="ignore").strip(),
        })
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


@app.route("/pubkey/<key_id>", methods=["GET"])
@require("pubkey:read")
def pubkey(key_id):
    keys = get_keys()
    if key_id not in keys:
        return jsonify({"error": f"unknown key_id: {key_id}",
                        "available": sorted(keys.keys())}), 404
    return jsonify({"key_id": key_id, "pub_pem": keys[key_id]["pub"].read_text()})


# ---------- 设备密钥服务 ----------

@app.route("/ecu_keygen", methods=["POST"])
@require("ecu:provision")
def ecu_keygen():
    # Retained internal name; this endpoint never generates or exports a private key.
    record = device_record(DEVICE_REGISTRY, request.get_json(force=True).get("vin"))
    return jsonify({"pub_hex": record["public_key"], "created": False, "vin": record["vin"]})


@app.route("/verify_device_pop", methods=["POST"])
@require("ecu:provision")
def verify_device_pop():
    body = request.get_json(force=True)
    vin, nonce, pub = body.get("vin"), body.get("nonce"), body.get("pub_pem")
    record = device_record(DEVICE_REGISTRY, vin)
    if not isinstance(nonce, str) or not re.fullmatch(r"[a-f0-9]{64}", nonce):
        return jsonify({"error": "invalid_nonce"}), 400
    if not isinstance(pub, str) or pub.strip() != record["public_key"].strip():
        return jsonify({"error": "unapproved_public_key"}), 403
    valid = verify_sm2(record["public_key"], enrollment_message(vin, nonce, pub),
                       body.get("sig_hex"), vin)
    # Verification uses temporary files only; registered public keys are read-only.
    return jsonify({"valid": valid, "vin": vin}), 200 if valid else 403


@app.route("/sm2_encrypt", methods=["POST"])
@require("ecu:wrap")
def sm2_encrypt():
    body = request.get_json(force=True)
    data_hex = body.get("data_hex")
    vin = body.get("vin")
    if not data_hex or not vin:
        return jsonify({"error": "missing data_hex or vin"}), 400
    if not VIN_RE.fullmatch(vin):
        return jsonify({"error": "invalid vin"}), 400
    try:
        plain = bytes.fromhex(data_hex)
    except ValueError:
        return jsonify({"error": "invalid hex"}), 400
    if len(plain) != 16:
        return jsonify({"error": "only 16-byte content keys may be wrapped"}), 400

    safe_vin = "".join(c for c in vin if c.isalnum())
    record = device_record(DEVICE_REGISTRY, vin)
    pub_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
    pub_file.write(record["public_key"])
    pub_file.close()
    pub_path = Path(pub_file.name)

    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(plain)
        in_path = f.name
    out_path = in_path + ".der"
    try:
        rc, _, err = run_gmssl([
            "sm2encrypt", "-pubkey", str(pub_path),
            "-in", in_path, "-out", out_path,
        ])
        if rc != 0:
            return jsonify({"error": "encrypt failed",
                            "stderr": err.decode(errors="ignore")}), 500
        wrapped = Path(out_path).read_bytes()
        return jsonify({"wrapped_hex": wrapped.hex(), "wrapped_len": len(wrapped)})
    finally:
        pub_path.unlink(missing_ok=True)
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


@app.route("/sign_time", methods=["POST"])
@require("time:attest")
def sign_time():
    body = request.get_json(force=True)
    nonce = body.get("nonce")
    if not isinstance(nonce, str) or not 8 <= len(nonce) <= 128:
        return jsonify({"error": "invalid nonce"}), 400
    if not re.fullmatch(r"[A-Za-z0-9_-]+", nonce):
        return jsonify({"error": "invalid nonce charset"}), 400

    time_key = KEY_DIR / "time-v1" / "time.key"
    time_pub = KEY_DIR / "time-v1" / "time.pub"
    if not time_key.exists() or not time_pub.exists():
        return jsonify({"error": "time key not configured"}), 500

    server_ts = int(time.time())
    payload = {"nonce": nonce, "server_ts": server_ts}
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)

    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(canonical)
        in_path = f.name
    out_path = in_path + ".sig"
    try:
        rc, _, err = run_gmssl([
            "sm2sign", "-key", str(time_key),
            "-pass", (
                Path(os.environ["TIME_PASS_FILE"]).read_text().strip()
                if os.environ.get("TIME_PASS_FILE")
                and Path(os.environ["TIME_PASS_FILE"]).exists()
                else os.environ.get("TIME_PASS", "")
            ),
            "-id", "ota-time-v1", "-in", in_path, "-out", out_path,
        ])
        if rc != 0:
            return jsonify({"error": "sign time failed",
                            "stderr": err.decode(errors="ignore")}), 500
        sig = Path(out_path).read_bytes()
        return jsonify({
            "nonce": nonce, "server_ts": server_ts, "expires_in": 300,
            "sig_hex": sig.hex(), "key_id": "ota-time-v1",
        })
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


@app.errorhandler(404)
def not_found(_e):
    return jsonify({"error": "not_found"}), 404


security.init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
