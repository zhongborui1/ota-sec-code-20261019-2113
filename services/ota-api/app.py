#!/usr/bin/env python3
"""
OTA API：业务逻辑层，不接触私钥。
- 信任元数据：Redis 为权威源，本地短缓存 2s（防每请求打 Redis）
- 轮换：SET 新值 + PUBLISH 通知，所有 worker 立即刷新
- 审计：所有签名/验签操作写 Postgres audit_log
- ECU 密钥池：按 VIN 动态生成（一车一密钥），通过 signing-service 管理
"""
import os
import sys
import json
import hmac
import hashlib
import time
import threading
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

TRUST_REDIS_KEY = "ota:trust-metadata"
TRUST_CHANNEL = "ota:trust-update"
LOCAL_CACHE_TTL = 2.0   # 本地缓存 2 秒，防止每请求打 Redis

# 宽限期：旧密钥停止使用后多久转 revoked
GRACE_PERIOD_S = int(os.environ.get("GRACE_PERIOD_S", "240"))
CLEANUP_INTERVAL_S = int(os.environ.get("CLEANUP_INTERVAL_S", "10"))
assert GRACE_PERIOD_S + CLEANUP_INTERVAL_S < 300, (
    f"GRACE_PERIOD_S({GRACE_PERIOD_S}) + CLEANUP_INTERVAL_S({CLEANUP_INTERVAL_S}) 必须 < 300s"
)


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
_trust_cache = {"data": None, "loaded_at": 0.0}
_consistency_cache = {}
_trust_lock = threading.Lock()


def _default_trust():
    return {
        "trust_anchor_version": 1,
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "keys": {
            "ota-signing-v1": {"status": "active",
                               "not_before": "2026-09-28T00:00:00Z",
                               "not_after": "2027-09-28T00:00:00Z"},
            "ota-signing-v2": {"status": "prepared",
                               "not_before": "2026-09-28T00:00:00Z",
                               "not_after": "2028-09-28T00:00:00Z"},
        },
    }


def _read_trust_disk():
    if not TRUST_FILE.exists():
        TRUST_FILE.write_text(json.dumps(_default_trust(), indent=2))
    return json.loads(TRUST_FILE.read_text())


def get_trust(force_refresh=False):
    """
    信任元数据来源优先级：本地短缓存 → Redis → 磁盘
    - 本地缓存 TTL=2s，所有 worker 每隔 2s 最多打一次 Redis
    - Redis 是权威源；轮换时 SET + PUBLISH
    """
    now = time.time()
    with _trust_lock:
        if (not force_refresh and _trust_cache["data"] is not None
                and (now - _trust_cache["loaded_at"]) < LOCAL_CACHE_TTL):
            return _trust_cache["data"]

    # 读 Redis
    raw = None
    try:
        raw = r.get(TRUST_REDIS_KEY)
    except Exception:
        raw = None

    if raw:
        data = json.loads(raw)
    else:
        # Redis 空：从磁盘初始化
        data = _read_trust_disk()
        try:
            r.set(TRUST_REDIS_KEY, json.dumps(data))
        except Exception as e:
            print(f"[TRUST-REDIS-SET-ERROR] {type(e).__name__}: {e}", file=sys.stderr, flush=True)

    with _trust_lock:
        _trust_cache["data"] = data
        _trust_cache["loaded_at"] = now
    return data


def get_active_key_id():
    trust = get_trust()
    for key_id, info in trust["keys"].items():
        if info.get("status") == "active":
            return key_id
    return None


def _redis_subscriber():
    """后台订阅轮换通知，收到立即失效本地缓存。"""
    try:
        pubsub = r.pubsub()
        pubsub.subscribe(TRUST_CHANNEL)
        for msg in pubsub.listen():
            if msg["type"] == "message":
                with _trust_lock:
                    _trust_cache["loaded_at"] = 0
    except Exception as e:
        import traceback
        print(f"[REDIS-SUBSCRIBER-ERROR] {type(e).__name__}: {e}\n{traceback.format_exc()}", file=sys.stderr, flush=True)


def _run_cleanup_once():
    """扫描 trust，把宽限期已过的 deprecated 密钥转为 revoked。"""
    trust = get_trust(force_refresh=True)
    now = datetime.utcnow()
    changed = False
    for key_id, info in trust.get("keys", {}).items():
        if info.get("status") != "deprecated":
            continue
        dep_raw = info.get("deprecated_at")
        if not dep_raw:
            continue
        if dep_raw.endswith("Z"):
            dep_raw = dep_raw[:-1]
        try:
            dep_dt = datetime.fromisoformat(dep_raw)
        except ValueError:
            continue
        if (now - dep_dt).total_seconds() >= GRACE_PERIOD_S:
            info["status"] = "revoked"
            info["revoked_at"] = now.isoformat() + "Z"
            changed = True
    if not changed:
        return
    trust["updated_at"] = now.isoformat() + "Z"
    TRUST_FILE.write_text(json.dumps(trust, indent=2))
    r.set(TRUST_REDIS_KEY, json.dumps(trust))
    r.publish(TRUST_CHANNEL, json.dumps(trust))
    with _trust_lock:
        _trust_cache["loaded_at"] = 0
    print(f"[GRACE-CLEANUP] pid={os.getpid()} 已把到期 deprecated 密钥转为 revoked",
          flush=True)


def _grace_period_cleanup():
    """后台线程：每 CLEANUP_INTERVAL_S 秒触发一次清理。
    gunicorn 多 worker 下用 Redis SET NX 锁保证同一时刻只有一个 worker 真正执行。
    """
    lock_key = "ota:cleanup-lock"
    while True:
        time.sleep(CLEANUP_INTERVAL_S)
        try:
            got = r.set(lock_key, str(os.getpid()), nx=True,
                        ex=max(2, CLEANUP_INTERVAL_S * 2))
            if not got:
                continue
            try:
                _run_cleanup_once()
            finally:
                try:
                    r.delete(lock_key)
                except Exception:
                    pass
        except Exception as e:
            import traceback
            print(f"[GRACE-CLEANUP-ERROR] {type(e).__name__}: {e}\n"
                  f"{traceback.format_exc()}", file=sys.stderr, flush=True)


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
    return TASKS_DIR / f"{task_id}.json"


def load_task(task_id):
    p = task_path(task_id)
    return json.loads(p.read_text()) if p.exists() else None


def save_task(task_id, data):
    task_path(task_id).write_text(json.dumps(data, indent=2))


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
        "cache_age_s": round(time.time() - _trust_cache["loaded_at"], 2),
        "local_cache_ttl_s": LOCAL_CACHE_TTL,
    })


@app.route("/trust-metadata", methods=["GET"])
def get_trust_metadata():
    return jsonify(get_trust(force_refresh=True))


@app.route("/admin/rotate-trust", methods=["POST"])
def rotate_trust():
    """
    状态变更接口：必须带 X-Admin-Token。
    令牌文件只在运维主机与 ota-api 容器内可读，车辆与服务身份都拿不到。
    """
    supplied = request.headers.get("X-Admin-Token", "")
    expected = admin_token()
    if not expected or not supplied or not hmac.compare_digest(supplied, expected):
        audit_log("rotate-trust", None, None, "auth_reject",
                  {"reason": "bad_admin_token"})
        return jsonify({"error": "admin authentication required"}), 401

    body = request.get_json(force=True)

    if body.get("auto_rotate"):
        import random as _random
        current = _read_trust_disk()
        prepared = [k for k, v in current["keys"].items() if v["status"] == "prepared"]
        if not prepared:
            return jsonify({"ok": False, "reason": "no_prepared_key"}), 400
        new_active = _random.choice(prepared)
        for k, v in current["keys"].items():
            if v["status"] == "active":
                v["status"] = "deprecated"
                v["deprecated_at"] = datetime.utcnow().isoformat() + "Z"
        current["keys"][new_active]["status"] = "active"
        current["updated_at"] = datetime.utcnow().isoformat() + "Z"
        new_meta = current
    else:
        new_meta = _read_trust_disk()
        for key_id, updates in body.get("keys", {}).items():
            if key_id in new_meta["keys"]:
                new_meta["keys"][key_id].update(updates)
            else:
                new_meta["keys"][key_id] = updates
        new_meta["updated_at"] = datetime.utcnow().isoformat() + "Z"

    TRUST_FILE.write_text(json.dumps(new_meta, indent=2))
    r.set(TRUST_REDIS_KEY, json.dumps(new_meta))
    r.publish(TRUST_CHANNEL, json.dumps(new_meta))

    audit_log("rotate-trust", None, None, "ok", {"new_meta": new_meta})

    return jsonify({
        "ok": True,
        "updated_at": new_meta["updated_at"],
        "trust_metadata": new_meta,
        "note": "已 SET Redis + PUBLISH 通知，所有 worker 立即刷新",
    })


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
    return f"ota:token:{token}"


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
    return bound_vin, None


@app.route("/api/enrollment/challenge", methods=["POST"])
def enroll_challenge():
    """车辆请求注册挑战。返回一次性 nonce（120s 有效，Redis 存储）。"""
    body = request.get_json(force=True)
    vin = body.get("vin")
    if not vin:
        return jsonify({"error": "missing vin"}), 400
    nonce = os.urandom(32).hex()
    # 存 Redis，TTL 120s
    r.setex(_enroll_key(nonce), _ENROLL_TTL, vin)
    audit_log("enroll-challenge", None, vin, "ok", {"nonce_prefix": nonce[:8]})
    return jsonify({
        "nonce": nonce,
        "statement": f"enroll:{vin}:{nonce}",
        "expires_in": _ENROLL_TTL,
    })


@app.route("/api/enrollment/register", methods=["POST"])
def enroll_register():
    """车辆提交 PoP 证明 + 公钥，服务端验签后写 ecu.pub。"""
    body = request.get_json(force=True)
    vin = body.get("vin")
    nonce = body.get("nonce")
    sig_hex = body.get("sig_hex")
    pub_pem = body.get("pub_pem")
    if not all([vin, nonce, sig_hex, pub_pem]):
        return jsonify({"error": "missing fields"}), 400

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
    audit_log("enroll-register", None, vin, "ok", {"pub_received": True})
    return jsonify({"token": token, "vin": vin})




@app.route("/signing-pub/<key_id>", methods=["GET"])
def signing_pub(key_id):
    """代理 signing-service 的公钥拉取接口（车端信任锚更新用）。"""
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
    - 确保该 VIN 对应的 ECU 密钥存在（按需生成，一车一密钥）
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

    # 3.5 确保该 VIN 的 ECU 公钥存在（PoP 注册优先，服务端生成仅作兜底）
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
    chunk_count = manifest["size"] // manifest["chunk_size"]
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
    """
    状态上报：双重校验
    - nonce 唯一性（防重放）
    - sequence 严格递增（防乱序）
    - client_ts 时间窗 ±300s
    """
    body = request.get_json(force=True)
    task_id = body.get("task_id")
    vin = body.get("vin")
    nonce = body.get("nonce")
    client_ts = body.get("client_ts")
    sequence = body.get("sequence")

    if not task_id:
        return jsonify({"error": "missing task_id"}), 400

    task_data = load_task(task_id)
    if not task_data:
        return jsonify({"error": "unknown task"}), 404

    # 设备授权：token 绑定 VIN 必须与任务 VIN 一致
    bound_vin, auth_err = _require_auth(task_data.get("vin"))
    if auth_err:
        audit_log("report-status", task_data.get("key_id"), task_id,
                  "auth_reject", {"reason": auth_err[0]})
        return jsonify({"error": auth_err[0]}), auth_err[1]

    # 1. 时间窗校验
    if client_ts is not None:
        server_now = int(time.time())
        if abs(server_now - client_ts) > 300:
            audit_log("report-status", task_data.get("key_id"), task_id,
                      "timestamp_rejected",
                      {"client_ts": client_ts, "server_ts": server_now})
            return jsonify({
                "error": "timestamp out of window",
                "client_ts": client_ts,
                "server_ts": server_now,
                "window_s": 300,
            }), 400

    # 2. nonce 唯一性
    if nonce and vin and DATABASE_URL:
        try:
            conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO report_nonces (ecu_id, nonce) VALUES (%s, %s)",
                (vin, nonce))
            conn.commit()
            cur.close()
            conn.close()
        except psycopg2.IntegrityError:
            audit_log("report-status", task_data.get("key_id"), task_id,
                      "replay_rejected", {"vin": vin, "nonce": nonce[:16]})
            return jsonify({"error": "replay detected", "task_id": task_id}), 409
        except Exception as e:
            print(f"[WARN] nonce check failed: {e}", file=sys.stderr)

    # 3. sequence 严格递增
    if sequence is not None and vin and DATABASE_URL:
        try:
            conn = psycopg2.connect(DATABASE_URL, connect_timeout=3)
            cur = conn.cursor()
            cur.execute(
                "SELECT max_seq FROM report_sequences "
                "WHERE vin=%s AND task_id=%s FOR UPDATE",
                (vin, task_id))
            row = cur.fetchone()
            last_seq = row[0] if row else 0
            if sequence <= last_seq:
                conn.rollback()
                cur.close()
                conn.close()
                audit_log("report-status", task_data.get("key_id"), task_id,
                          "sequence_rejected",
                          {"vin": vin, "last_seq": last_seq, "got": sequence})
                return jsonify({
                    "error": "sequence rollback",
                    "last_seq": last_seq,
                    "got": sequence,
                }), 409
            cur.execute(
                """INSERT INTO report_sequences (vin, task_id, max_seq)
                   VALUES (%s, %s, %s)
                   ON CONFLICT (vin, task_id)
                   DO UPDATE SET max_seq = EXCLUDED.max_seq, updated_at = NOW()""",
                (vin, task_id, sequence))
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"[WARN] sequence check failed: {e}", file=sys.stderr)

    task_data["status"] = body.get("status")
    task_data["reported_at"] = datetime.utcnow().isoformat() + "Z"
    save_task(task_id, task_data)
    audit_log("report-status", task_data.get("key_id"), task_id,
              body.get("status"), body)
    return jsonify({"ok": True, "task_id": task_id,
                    "status": body.get("status")})

@app.route("/admin/devices", methods=["GET"])
def admin_devices():
    """列出所有设备：从 ecu-local（车辆本地）和 ecu-pool（服务端）扫描"""
    import os as _os
    devices = {}
    local_dir = Path("/keys/ecu-local")
    pool_dir = Path("/keys/ecu-pool")

    # 从 ecu-local 扫描
    if local_dir.exists():
        for d in sorted(local_dir.iterdir()):
            if not d.is_dir():
                continue
            vin = d.name
            devices[vin] = {
                "vin": vin,
                "has_local_key": (d / "ecu.key").exists(),
                "has_token": (d / "token").exists(),
                "has_local_pub": (d / "ecu.pub").exists(),
                "has_server_pub": (pool_dir / vin / "ecu.pub").exists(),
                "has_server_key": (pool_dir / vin / "ecu.key").exists(),
                "enrolled": (d / "token").exists() and (pool_dir / vin / "ecu.pub").exists(),
            }

    # 从 ecu-pool 补充（有 pub 但 local 里没有的）
    if pool_dir.exists():
        for d in sorted(pool_dir.iterdir()):
            if not d.is_dir() or d.name in devices:
                continue
            vin = d.name
            devices[vin] = {
                "vin": vin,
                "has_local_key": False,
                "has_token": False,
                "has_local_pub": False,
                "has_server_pub": (d / "ecu.pub").exists(),
                "has_server_key": (d / "ecu.key").exists(),
                "enrolled": False,
            }

    return jsonify({
        "count": len(devices),
        "devices": list(devices.values()),
    })


@app.route("/admin/summary", methods=["GET"])
def admin_summary():
    """管理后台概览：健康状态 + 密钥池 + 审计统计"""
    # 信任元数据
    trust = get_trust()
    status_count = {}
    for kid, info in trust["keys"].items():
        s = info["status"]
        status_count[s] = status_count.get(s, 0) + 1

    # 密钥池大小
    pool_dir = Path("/keys/ecu-pool")
    pool_size = len([d for d in pool_dir.iterdir() if d.is_dir()]) if pool_dir.exists() else 0
    local_dir = Path("/keys/ecu-local")
    local_size = len([d for d in local_dir.iterdir() if d.is_dir()]) if local_dir.exists() else 0

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


# 启动后台线程（gunicorn -w 16 下每个 worker 各自启动：
#   - 订阅线程：每个 worker 需独立订阅以刷新各自本地缓存
#   - 清理线程：通过 Redis 锁保证同一时刻仅一个 worker 真正执行清理）
_subscriber_thread = threading.Thread(target=_redis_subscriber, daemon=True)
_subscriber_thread.start()

_cleanup_thread = threading.Thread(target=_grace_period_cleanup, daemon=True)
_cleanup_thread.start()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
