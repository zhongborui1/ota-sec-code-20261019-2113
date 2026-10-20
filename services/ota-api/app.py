#!/usr/bin/env python3
"""
OTA API：业务逻辑层，不接触私钥。
- 信任元数据：只读根签名策略 + SQLite 单调版本记录
- 轮换：离线发布策略，在线服务不可修改信任授权
- 审计：所有签名/验签操作写 Postgres audit_log
- ECU 身份：离线预登记公钥，私钥仅保存在车辆侧
"""
import os
import sys
import json
import hmac
import hashlib
import time
import urllib.request
import urllib.error
from datetime import datetime
from pathlib import Path
from flask import Flask, request, jsonify, Response

import redis
import psycopg2
from psycopg2.extras import Json
from minio import Minio
from minio.error import S3Error
import io

from svc_client import SigningClient, admin_token
from ota_common.trust import (SecurityError, accept_policy, effective_policy, atomic_json,
                              device_record, enrollment_message, trusted_key)
from ota_common.reports import validate_report, persist_report
ROOT_PUB = Path(os.environ.get("ROOT_PUB", "/keys/root.pub"))
TRUST_STATE = Path(os.environ.get("TRUST_STATE", "/data/tasks/trust-state.sqlite3"))
DEVICE_REGISTRY = Path(os.environ.get("DEVICE_REGISTRY", "/keys/device-registry"))

app = Flask(__name__)


@app.after_request
def _add_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS,PUT,DELETE"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    return resp

SIGNING_URL = os.environ.get("SIGNING_URL", "http://ota-signing-service:8081")
SIGNING_SERVICE_ID = os.environ.get("SIGNING_SERVICE_ID", "ota-api")
SIGNING_SECRET_FILE = os.environ.get(
    "SIGNING_SECRET_FILE", "/keys/service-auth/ota-api.key")
RELEASE_GRANT_DIR = Path(os.environ.get("RELEASE_GRANT_DIR",
                                        "/data/release-grants"))
PACKAGES_DIR = Path(os.environ.get("PACKAGES_DIR", "/data/packages"))
TASKS_DIR = Path(os.environ.get("TASKS_DIR", "/data/tasks"))
TRUST_FILE = Path(os.environ.get("TRUST_FILE", "/data/trust/trust-metadata.json"))

signing = SigningClient(SIGNING_URL, SIGNING_SERVICE_ID, SIGNING_SECRET_FILE)

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# 存储后端：local | minio
STORAGE_BACKEND = os.environ.get("STORAGE_BACKEND", "minio")
MINIO_ENDPOINT = os.environ.get("MINIO_ENDPOINT", "ota-minio:9000")
MINIO_ACCESS_KEY = os.environ.get("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.environ.get("MINIO_SECRET_KEY", "minioadmin123")
MINIO_BUCKET = os.environ.get("MINIO_BUCKET", "ota-packages")

LOCAL_CACHE_TTL = 0  # 撤销截止时间由签名策略确定，不依赖清理线程。


TASKS_DIR.mkdir(parents=True, exist_ok=True)
TRUST_FILE.parent.mkdir(parents=True, exist_ok=True)

# ---------- Redis ----------
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD") or None
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                password=REDIS_PASSWORD, decode_responses=True)

# ---------- MinIO ----------
minio_client = None
if STORAGE_BACKEND == "minio":
    try:
        minio_client = Minio(MINIO_ENDPOINT,
                             access_key=MINIO_ACCESS_KEY,
                             secret_key=MINIO_SECRET_KEY,
                             secure=False)
    except Exception as e:
        print(f"[WARN] MinIO 初始化失败，回退到本地: {e}", flush=True)
        minio_client = None

# ---------- 本地缓存 ----------
_consistency_cache = {}


def _read_trust_disk():
    # No unsigned defaults and no Redis fallback that could resurrect a revoked key.
    try:
        doc = json.loads(TRUST_FILE.read_text())
    except (OSError, ValueError) as exc:
        raise SecurityError("trusted_policy_unavailable") from exc
    return effective_policy(accept_policy(doc, ROOT_PUB, TRUST_STATE))


def get_trust(force_refresh=False):
    return _read_trust_disk()


def get_active_key_id():
    trust = get_trust()
    for key_id, info in trust["keys"].items():
        if info.get("status") == "active":
            trusted_key(trust, key_id)
            return key_id
    return None


@app.errorhandler(SecurityError)
def security_error(exc):
    return jsonify({"error": str(exc)}), 403


# ---------- Postgres 审计 ----------
AUDIT_FALLBACK = Path(os.environ.get("AUDIT_FALLBACK", "/data/tasks/audit-fallback.jsonl"))


def audit_log(action, key_id, resource_id, result, detail=None):
    """
    写审计日志到 Postgres。
    失败时：
      1. 打印 stderr（不再静默）
      2. 追加写入本地 fallback 文件（JSONL 格式）
    绝不阻塞业务。
    """
    entry = {
        "ts": datetime.utcnow().isoformat() + "Z",
        "action": action, "key_id": key_id,
        "resource_id": resource_id, "result": result,
        "detail": detail or {},
    }

    if DATABASE_URL:
        try:
            conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO audit_log (action, key_id, resource_id, result, detail) "
                "VALUES (%s, %s, %s, %s, %s)",
                (action, key_id, resource_id, result, Json(detail or {})))
            conn.commit()
            cur.close()
            conn.close()
            return
        except Exception as e:
            print(f"[AUDIT-FAIL] Postgres 写入失败: {type(e).__name__}: {e}",
                  file=sys.stderr, flush=True)

    # fallback：写本地文件
    try:
        AUDIT_FALLBACK.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FALLBACK, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"[AUDIT-FATAL] fallback 也失败: {e}", file=sys.stderr, flush=True)


# ---------- 通用工具 ----------
def call_signing_service(path, obj, timeout=60):
    """
    调用签名服务：HMAC-SM3 服务身份 + JSON 体。
    返回 (status, dict)。签名服务不可达时返回 502，由调用方决定是否降级。
    """
    return signing.post_json(path, obj, timeout=timeout)


# ---------- 发布授权票据 ----------
_grant_cache = {"data": None, "mtime": None, "at": 0.0}


def load_active_grant():
    """
    读 data/release-grants/active.json（由 scripts/15-release-authorize.py 生成）。
    只读，不缓存超过 5 秒；缺失或过期时返回 (None, reason)。
    """
    p = RELEASE_GRANT_DIR / "active.json"
    if not p.exists():
        return None, "no_active_release_grant"
    mtime = p.stat().st_mtime
    if (_grant_cache["data"] is not None and _grant_cache["mtime"] == mtime
            and time.time() - _grant_cache["at"] < 5):
        return _grant_cache["data"], None
    try:
        doc = json.loads(p.read_text())
    except ValueError as e:
        return None, f"grant_file_invalid: {e}"
    if not doc.get("grant") or not doc.get("grant_sig_hex"):
        return None, "grant_file_incomplete"
    _grant_cache.update({"data": doc, "mtime": mtime, "at": time.time()})
    return doc, None


def fetch_chunk_from_minio(chunk_idx, chunk_size):
    """从 MinIO 用 Range 请求拉一个分块。"""
    if minio_client is None:
        raise Exception("MinIO 未初始化")
    offset = chunk_idx * chunk_size
    try:
        resp = minio_client.get_object(
            MINIO_BUCKET, "payload.enc",
            offset=offset, length=chunk_size)
        data = resp.read()
        resp.close()
        resp.release_conn()
        return data
    except S3Error as e:
        raise Exception(f"MinIO Range 请求失败: {e}")


def fetch_chunk_from_local(chunk_idx):
    """从本地文件系统读分块。"""
    chunk_file = PACKAGES_DIR / "chunks" / f"chunk-{chunk_idx:06d}"
    if not chunk_file.exists():
        raise Exception(f"本地分块不存在: {chunk_file}")
    return chunk_file.read_bytes()


def fetch_chunk(chunk_idx, chunk_size, prefer_minio=True):
    """
    统一的分块获取接口。
    优先 MinIO（如果启用），失败回退本地。
    """
    if prefer_minio and minio_client is not None:
        try:
            return fetch_chunk_from_minio(chunk_idx, chunk_size), "minio"
        except Exception as e:
            print(f"[WARN] MinIO 拉分块失败，回退本地: {e}", flush=True)
    return fetch_chunk_from_local(chunk_idx), "local"


def check_payload_consistency():
    """
    校验 MinIO payload.enc 的 SM3 是否与 manifest.encrypted_sm3 一致。
    """
    result = {"ok": False, "manifest_sm3": None, "minio_sm3": None,
              "checked_at": datetime.utcnow().isoformat() + "Z", "error": None}
    try:
        manifest_path = PACKAGES_DIR / "manifests" / "manifest-v1.json"
        if not manifest_path.exists():
            result["error"] = "manifest not found"
            return result
        manifest = json.loads(manifest_path.read_text())
        expected = manifest.get("encrypted_sm3") or manifest.get("sm3")
        result["manifest_sm3"] = expected

        if minio_client is None:
            result["error"] = "minio not initialized"
            return result

        h = hashlib.new("sm3")
        resp = minio_client.get_object(MINIO_BUCKET, "payload.enc")
        try:
            while True:
                chunk = resp.read(4 * 1024 * 1024)
                if not chunk:
                    break
                h.update(chunk)
        finally:
            resp.close()
            resp.release_conn()
        actual = h.hexdigest()
        result["minio_sm3"] = actual
        result["ok"] = (actual == expected)
        if not result["ok"]:
            result["error"] = "SM3 mismatch"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
    return result


def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def task_path(task_id):
    import re
    if not isinstance(task_id, str) or not re.fullmatch(r"[A-Za-z0-9._:-]{8,80}", task_id):
        raise SecurityError("invalid_task_id")
    return TASKS_DIR / f"{task_id}.json"


def load_task(task_id):
    p = task_path(task_id)
    return json.loads(p.read_text()) if p.exists() else None


def save_task(task_id, data):
    atomic_json(task_path(task_id), data)


# ---------- 接口 ----------
@app.route("/health", methods=["GET"])
def health():
    redis_ok = False
    try:
        r.ping()
        redis_ok = True
    except Exception as e:
        print(f"[HEALTH-REDIS-PING-ERROR] {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    minio_ok = False
    if minio_client is not None:
        try:
            minio_ok = minio_client.bucket_exists(MINIO_BUCKET)
        except Exception:
            minio_ok = False

    global _consistency_cache
    now = time.time()
    if not _consistency_cache or (now - _consistency_cache.get("at", 0)) > 5:
        pc = check_payload_consistency()
        _consistency_cache = {"at": now, "data": pc}
    else:
        pc = _consistency_cache["data"]

    return jsonify({
        "status": "ok", "service": "ota-api",
        "active_key_id": get_active_key_id(),
        "redis_ok": redis_ok,
        "storage_backend": STORAGE_BACKEND,
        "minio_ok": minio_ok,
        "payload_consistency": {
            "ok": pc["ok"],
            "manifest_sm3": (pc["manifest_sm3"][:16] + "...") if pc["manifest_sm3"] else None,
            "minio_sm3": (pc["minio_sm3"][:16] + "...") if pc["minio_sm3"] else None,
            "error": pc["error"],
            "checked_at": pc["checked_at"],
        },
        "local_cache_ttl_s": LOCAL_CACHE_TTL,
    })


@app.route("/rotation-state", methods=["GET"])
def rotation_state():
    trust = get_trust()
    active = None
    for key_id, info in trust["keys"].items():
        if info.get("status") == "active":
            active = key_id
    return jsonify({
        "worker_pid": os.getpid(),
        "active_key_id": active,
        "trust_updated_at": trust.get("updated_at"),
        "cache_age_s": 0,
        "local_cache_ttl_s": LOCAL_CACHE_TTL,
    })


@app.route("/trust-metadata", methods=["GET"])
def get_trust_metadata():
    try:
        doc = json.loads(TRUST_FILE.read_text())
    except (OSError, ValueError) as exc:
        raise SecurityError("trusted_policy_unavailable") from exc
    policy = effective_policy(accept_policy(doc, ROOT_PUB, TRUST_STATE))
    # signed document is authoritative; summary fields are display only.
    return jsonify({**policy, "document": doc})


@app.route("/admin/rotate-trust", methods=["POST"])
def rotate_trust():
    supplied = request.headers.get("X-Admin-Token", "")
    expected = admin_token()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        return jsonify({"error": "admin authentication required"}), 401
    # The API does not possess the root private key. Publish using the offline CLI.
    return jsonify({"error": "offline_signed_policy_required",
                    "command": "python3 scripts/17-security-admin.py policy --help"}), 409


@app.route("/sign-manifest", methods=["POST"])
def sign_manifest():
    """
    对一份完整 manifest 请求签名。
    必须存在有效的发布授权票据；签名服务会逐字段核对，ota-api 无法越权。
    """
    manifest = request.get_json(force=True)
    if not manifest:
        return jsonify({"error": "empty manifest"}), 400
    key_id = get_active_key_id()
    if not key_id:
        return jsonify({"error": "no active key"}), 500

    grant_doc, grant_err = load_active_grant()
    if grant_err:
        audit_log("sign-manifest", key_id, manifest.get("package_id"),
                  "deny", {"reason": grant_err})
        return jsonify({"error": grant_err}), 503

    status, sig_data = call_signing_service("/sign-manifest", {
        "manifest": manifest,
        "grant": grant_doc["grant"],
        "grant_sig_hex": grant_doc["grant_sig_hex"],
    })
    if status != 200:
        audit_log("sign-manifest", key_id, manifest.get("package_id"),
                  "deny", sig_data)
        return jsonify({"error": "signing denied", "detail": sig_data}), status
    audit_log("sign-manifest", key_id, manifest.get("package_id"), "ok",
              {"sig_len": sig_data["sig_len"],
               "auth_id": sig_data.get("auth_id")})
    return jsonify({
        "manifest": manifest, "key_id": key_id,
        "sig_hex": sig_data["sig_hex"], "sig_len": sig_data["sig_len"],
        "auth_id": sig_data.get("auth_id"),
    })


@app.route("/verify-manifest", methods=["POST"])
def verify_manifest():
    body = request.get_json(force=True)
    manifest = body.get("manifest")
    sig_hex = body.get("sig_hex")
    key_id = body.get("key_id")
    if not manifest or not sig_hex or not key_id:
        return jsonify({"error": "missing args"}), 400

    trust = get_trust()
    key_info = trust["keys"].get(key_id)
    if not key_info:
        audit_log("verify-manifest", key_id, manifest.get("package_id"),
                  "reject", {"reason": "unknown_key"})
        return jsonify({"valid": False, "reason": "unknown_key", "key_id": key_id}), 400
    status = key_info.get("status")
    if status not in ("active", "deprecated"):
        audit_log("verify-manifest", key_id, manifest.get("package_id"),
                  "reject", {"reason": f"key_{status}"})
        return jsonify({"valid": False, "reason": f"key_{status}", "key_id": key_id})

    try:
        trusted_key(trust, key_id)
    except SecurityError as exc:
        return jsonify({"valid": False, "reason": str(exc), "key_id": key_id})
    manifest_bytes = canonical_json_bytes(manifest)
    verify_payload = {
        "data_hex": manifest_bytes.hex(),
        "sig_hex": sig_hex, "key_id": key_id,
    }
    s, result = call_signing_service("/verify", verify_payload)

    audit_log("verify-manifest", key_id, manifest.get("package_id"),
              "ok" if result.get("valid") else "reject",
              {"valid": result.get("valid")})

    return jsonify(result), s


# ---------- 设备注册 PoP（使用 Redis 存 nonce，多 worker 共享） ----------
_ENROLL_TTL = 120


def _enroll_key(nonce):
    return f"ota:enroll:{nonce}"


def _token_key(token):
    return "ota:token:" + hashlib.sha256(token.encode()).hexdigest()


def _require_auth(vin=None):
    """
    校验 Bearer token：
      - 从 Authorization: Bearer <token> 取 token
      - Redis 查 ota:token:<token> → 绑定的 vin
      - 若指定 vin，则校验 token 绑定 VIN 与之一致（设备授权）
    返回 (bound_vin_or_None, error_or_None)
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, ("missing or invalid Authorization header", 401)
    token = auth[len("Bearer "):].strip()
    if not token:
        return None, ("empty token", 401)
    bound_vin = None
    try:
        bound_vin = r.get(_token_key(token))
    except Exception:
        bound_vin = None
    if not bound_vin:
        return None, ("invalid or expired token", 401)
    if vin is not None and bound_vin != vin:
        return None, ("token not authorized for this VIN", 403)
    try:
        device_record(DEVICE_REGISTRY, bound_vin)
    except SecurityError as exc:
        return None, (str(exc), 403)
    return bound_vin, None


@app.route("/api/enrollment/challenge", methods=["POST"])
def enroll_challenge():
    """车辆请求注册挑战。返回一次性 nonce（120s 有效，Redis 存储）。"""
    body = request.get_json(force=True)
    vin = body.get("vin")
    if not vin:
        return jsonify({"error": "missing vin"}), 400
    device = device_record(DEVICE_REGISTRY, vin)
    nonce = os.urandom(32).hex()
    # 存 Redis，TTL 120s
    r.setex(_enroll_key(nonce), _ENROLL_TTL, vin)
    audit_log("enroll-challenge", None, vin, "ok", {"nonce_prefix": nonce[:8]})
    return jsonify({
        "nonce": nonce,
        "statement": enrollment_message(vin, nonce, device["public_key"]).decode(),
        "expires_in": _ENROLL_TTL,
    })


@app.route("/api/enrollment/register", methods=["POST"])
def enroll_register():
    """公钥须匹配离线登记记录；在线注册只验 PoP，不修改公钥。"""
    body = request.get_json(force=True)
    vin = body.get("vin")
    nonce = body.get("nonce")
    sig_hex = body.get("sig_hex")
    pub_pem = body.get("pub_pem")
    if not all([vin, nonce, sig_hex, pub_pem]):
        return jsonify({"error": "missing fields"}), 400

    device = device_record(DEVICE_REGISTRY, vin)
    if not isinstance(pub_pem, str) or pub_pem.strip() != device["public_key"].strip():
        return jsonify({"error": "unapproved_public_key"}), 403

    # 从 Redis 取 nonce（跨 worker 共享）
    stored_vin = r.getdel(_enroll_key(nonce))
    if not stored_vin:
        return jsonify({"error": "unknown or expired nonce"}), 400
    if stored_vin != vin:
        return jsonify({"error": "vin mismatch"}), 400

    # 转发给 signing-service 验签
    st, resp = call_signing_service("/verify_device_pop", {
        "vin": vin, "nonce": nonce, "sig_hex": sig_hex, "pub_pem": pub_pem,
    })
    if st != 200 or not resp.get("valid"):
        audit_log("enroll-register", None, vin, "reject", resp)
        return jsonify({"error": "pop verify failed", "detail": resp}), 400

    # 签发 Bearer token（也存 Redis，TTL 24h）
    token = os.urandom(32).hex()
    r.setex(_token_key(token), 86400, vin)
    r.set("ota:registered:" + vin, "1")
    audit_log("enroll-register", None, vin, "ok", {"pub_received": True})
    return jsonify({"token": token, "vin": vin})




@app.route("/signing-pub/<key_id>", methods=["GET"])
def signing_pub(key_id):
    """仅查询公钥；ECU 不将未经根签名的响应作为信任依据。"""
    st, data = signing.get_json(f"/pubkey/{key_id}")
    return jsonify(data), st


@app.route("/time-attestation", methods=["POST"])
def time_attestation():
    """转发时间证明请求到 signing-service（时间签名密钥由 signing-service 保管）"""
    body = request.get_json(force=True)
    nonce = body.get("nonce")
    if not nonce:
        return jsonify({"error": "missing nonce"}), 400
    st, resp = call_signing_service("/sign_time", {"nonce": nonce})
    return jsonify(resp), st


@app.route("/request-task", methods=["POST"])
def request_task():
    """
    每辆车单独签名：
    - 读 manifest 模板
    - 覆盖 vin/task_id/issued_at/key_id
    - 确保该 VIN 已离线登记公钥
    - 用该 VIN 的 ECU 公钥做 SM2 信封加密 SM4 会话密钥
    - 现场签名
    - 返回这辆车专属的 manifest + 签名
    """
    body = request.get_json(force=True)
    vin = body.get("vin")
    if not vin:
        return jsonify({"error": "missing vin"}), 400

    # 升级授权：token 必须存在且绑定 VIN 一致
    bound_vin, auth_err = _require_auth(vin)
    if auth_err:
        audit_log("request-task", None, vin, "auth_reject", {"reason": auth_err[0]})
        return jsonify({"error": auth_err[0]}), auth_err[1]

    template_path = PACKAGES_DIR / "manifests" / "manifest-v1.json"
    if not template_path.exists():
        return jsonify({"error": "package template not built"}), 500

    # 1. 发布授权：没有有效 grant 就不签，签名密钥由 grant 指定
    grant_doc, grant_err = load_active_grant()
    if grant_err:
        audit_log("request-task", None, vin, "deny", {"reason": grant_err})
        return jsonify({"error": grant_err}), 503
    grant = grant_doc["grant"]
    key_id = grant["key_id"]
    active_key = get_active_key_id()
    if active_key != key_id:
        audit_log("request-task", key_id, vin, "deny",
                  {"reason": "grant_key_not_active", "active": active_key})
        return jsonify({"error": "release_grant_key_not_active",
                        "grant_key_id": key_id,
                        "active_key_id": active_key}), 503

    # 2. 读模板
    manifest = json.loads(template_path.read_text())

    # 3. 生成 task_id，覆盖车辆专属字段；不可变字段由签名服务与 grant 核对
    task_id = f"task-{datetime.utcnow().strftime('%Y%m%d%H%M%S%f')}-{vin[-6:]}"
    manifest["task_id"] = task_id
    manifest["vin"] = vin
    manifest["key_id"] = key_id
    manifest["issued_at"] = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

    # 3.5 查询预登记公钥；禁止在线生成车端私钥兜底
    st_gen, gen_resp = call_signing_service("/ecu_keygen", {"vin": vin})
    if st_gen != 200:
        audit_log("request-task", key_id, task_id, "ecu_keygen_fail", gen_resp)
        return jsonify({"error": "ecu keygen failed", "detail": gen_resp}), st_gen

    # 3.6 用该 VIN 的 ECU 公钥做 SM2 信封加密 SM4 会话密钥
    sm4_key_path = PACKAGES_DIR / "source" / "sm4_key.hex"
    if sm4_key_path.exists():
        sm4_key_hex = sm4_key_path.read_text().strip()
        st, enc_resp = call_signing_service(
            "/sm2_encrypt", {"data_hex": sm4_key_hex, "vin": vin})
        if st != 200:
            audit_log("request-task", key_id, task_id, "envelope_fail", enc_resp)
            return jsonify({"error": "envelope encrypt failed",
                            "detail": enc_resp}), st
        manifest["wrapped_key"] = enc_resp["wrapped_hex"]
    else:
        audit_log("request-task", key_id, task_id, "deny",
                  {"reason": "missing_sm4_key"})
        return jsonify({"error": "package has no encrypted payload"}), 500

    # 4. 现场签名：携带 grant，签名服务核对不可变字段后才签
    status, sig_data = call_signing_service("/sign-manifest", {
        "manifest": manifest,
        "grant": grant,
        "grant_sig_hex": grant_doc["grant_sig_hex"],
    })
    if status != 200:
        audit_log("request-task", key_id, task_id, "sign-deny", sig_data)
        http_status = 429 if status == 429 else 503
        return jsonify({"error": "signing denied", "detail": sig_data}), http_status
    sig_hex = sig_data["sig_hex"]

    audit_log("sign-manifest", key_id, task_id, "ok",
              {"sig_len": sig_data["sig_len"], "source": "request-task",
               "auth_id": sig_data.get("auth_id")})

    # 5. 分块哈希
    chunk_count = (manifest["encrypted_size"] + manifest["chunk_size"] - 1) // manifest["chunk_size"]
    chunk_hashes = []
    for i in range(chunk_count):
        sm3_file = PACKAGES_DIR / "chunks" / f"chunk-{i:06d}.sm3"
        chunk_hashes.append(sm3_file.read_text().split()[0] if sm3_file.exists() else None)

    # 6. 保存 task
    save_task(task_id, {
        "task_id": task_id, "vin": vin, "status": "issued",
        "key_id": key_id,
        "manifest": manifest,
        "manifest_sig_hex": sig_hex,
        "created_at": datetime.utcnow().isoformat() + "Z",
    })
    audit_log("request-task", key_id, task_id, "ok", {"vin": vin})

    return jsonify({
        "task_id": task_id,
        "manifest": manifest,
        "key_id": key_id,
        "manifest_sig_hex": sig_hex,
        "chunk_count": chunk_count,
        "chunk_size": manifest["chunk_size"],
        "chunk_hashes": chunk_hashes,
    })


@app.route("/download/<task_id>/<int:chunk_idx>", methods=["GET"])
def download_chunk(task_id, chunk_idx):
    task = load_task(task_id)
    if not task:
        return jsonify({"error": "unknown task"}), 404
    # 设备授权：token 绑定 VIN 必须与任务 VIN 一致
    bound_vin, auth_err = _require_auth(task.get("vin"))
    if auth_err:
        return jsonify({"error": auth_err[0]}), auth_err[1]
    manifest = json.loads((PACKAGES_DIR / "manifests" / "manifest-v1.json").read_text())
    chunk_size = manifest["chunk_size"]
    try:
        data, backend = fetch_chunk(chunk_idx, chunk_size)
        resp = Response(data, mimetype="application/octet-stream")
        resp.headers["X-Storage-Backend"] = backend
        return resp
    except Exception as e:
        return jsonify({"error": f"fetch chunk failed: {e}"}), 500


@app.route("/report-status", methods=["POST"])
def report_status():
    body = request.get_json(force=True)
    if not isinstance(body, dict) or not isinstance(body.get("task_id"), str):
        return jsonify({"error": "task_id_required"}), 400
    import re
    if not re.fullmatch(r"[A-Za-z0-9._:-]{8,80}", body["task_id"]):
        return jsonify({"error": "invalid_task_id"}), 400
    vin, err = _require_auth()
    if err:
        return jsonify({"error": err[0]}), err[1]
    task = load_task(body["task_id"])
    if not task:
        return jsonify({"error": "unknown_task"}), 404
    try:
        validate_report(body, vin, task)
    except SecurityError as exc:
        return jsonify({"error": str(exc)}), 400
    if not DATABASE_URL:
        return jsonify({"error": "report_store_unavailable"}), 503
    conn = None
    try:
        conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
        updated = persist_report(conn, body, task, vin)
    except (SecurityError, psycopg2.IntegrityError) as exc:
        return jsonify({"error": str(exc) if isinstance(exc, SecurityError) else "replayed_nonce"}), 409
    except Exception:
        app.logger.exception("report transaction failed")
        return jsonify({"error": "report_store_unavailable"}), 503
    finally:
        if conn is not None:
            conn.close()
    # DB is authoritative. JSON is only a compatibility projection for existing tools.
    try:
        atomic_json(task_path(task["task_id"]), updated)
    except OSError:
        app.logger.exception("report JSON projection failed; database commit retained")
    return jsonify({"ok": True, "task_id": task["task_id"], "status": body["status"]})

@app.route("/admin/devices", methods=["GET"])
def admin_devices():
    devices = []
    for path in sorted(DEVICE_REGISTRY.glob("*.json")):
        record = json.loads(path.read_text())
        devices.append({"vin": record["vin"], "enabled": record.get("enabled", False),
                        "enrolled": bool(r.exists("ota:registered:" + record["vin"]))})
    return jsonify({"count": len(devices), "devices": devices})


@app.route("/admin/summary", methods=["GET"])
def admin_summary():
    """管理后台概览：健康状态 + 密钥池 + 审计统计"""
    # 信任元数据
    trust = get_trust()
    status_count = {}
    for kid, info in trust["keys"].items():
        s = info["status"]
        status_count[s] = status_count.get(s, 0) + 1

    # 只统计公开登记；服务器不挂载 ECU 私钥目录。
    pool_size = len(list(DEVICE_REGISTRY.glob("*.json")))
    local_size = sum(bool(r.exists("ota:registered:" + p.stem))
                     for p in DEVICE_REGISTRY.glob("*.json"))

    # 审计统计
    audit_stats = {}
    if DATABASE_URL:
        try:
            conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM audit_log")
            audit_stats["total"] = cur.fetchone()[0]
            cur.execute("""
                SELECT action, result, COUNT(*) FROM audit_log
                GROUP BY action, result ORDER BY action, result
            """)
            audit_stats["by_action"] = [
                {"action": r[0], "result": r[1], "count": r[2]}
                for r in cur.fetchall()
            ]
            cur.close()
            conn.close()
        except Exception as e:
            audit_stats["error"] = str(e)

    return jsonify({
        "active_key_id": get_active_key_id(),
        "trust_status_count": status_count,
        "ecu_pool_size": pool_size,
        "ecu_local_size": local_size,
        "audit": audit_stats,
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
