#!/usr/bin/env python3
"""
签名服务的授权边界。

三条独立防线，任何一条不满足都不签：

1. 服务身份（调用方是谁）
   - 每个调用方一个 HMAC-SM3 密钥文件，按 method + path?query + timestamp
     + nonce + SM3(body) 计算签名，时间窗 ±90s，nonce 一次性（SQLite 去重）。
   - 身份到权限范围（scope）的映射在 identities.json，最小权限。

2. 发布授权（这次发布被谁批准）
   - 授权票据（grant）由独立的 release 私钥签名；release 公钥本身由离线
     root 密钥签发证书。签名服务只信任 root 证书里的 release 公钥。
   - grant 绑定包的不可变字段（package_id/version/rollback_index/sm3/
     encrypted_sm3/ecu_type 等）、允许使用的签名密钥、有效期、任务配额。

3. 内容策略（这次签的字节是否就是被批准的那次发布）
   - manifest 字段白名单，禁止夹带；
   - 不可变字段与 grant 逐项严格相等；
   - VIN/task_id/时间格式校验；
   - 配额与 task_id 幂等在 SQLite 里原子扣减，重复请求返回同一签名。

签名服务不提供"对任意字节签名"的接口：/sign 已移除。
"""
import fcntl
import hashlib
import hmac
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ota_common.trust import accept_policy, effective_policy, trusted_key

AUTH_DB = Path(os.environ.get("AUTH_DB", "/var/lib/ota-auth/authz.db"))
AUDIT_FILE = Path(os.environ.get("AUDIT_FILE", "/var/lib/ota-auth/audit.jsonl"))
REGISTRY_FILE = Path(os.environ.get("SERVICE_REGISTRY", "/keys/service-auth/identities.json"))
RELEASE_DIR = Path(os.environ.get("RELEASE_ANCHOR_DIR", "/keys/release-v1"))
ROOT_PUB = Path(os.environ.get("ROOT_PUB", "/keys/root.pub"))
TRUST_FILE = Path(os.environ.get("TRUST_FILE", "/data/trust/trust-metadata.json"))

TIME_SKEW_S = 90
NONCE_TTL_S = 600
MAX_BODY_BYTES = 64 * 1024
MAX_VERIFY_BYTES = 2 * 1024 * 1024

IMMUTABLE_FIELDS = [
    "package_id", "vehicle_models", "ecu_type", "component",
    "version", "min_version", "rollback_index",
    "size", "sm3", "encrypted_size", "encrypted_sm3",
    "sm4_iv", "chunk_size", "expires_at", "key_id",
]
MUTABLE_FIELDS = ["task_id", "vin", "issued_at", "wrapped_key"]
ALLOWED_FIELDS = set(IMMUTABLE_FIELDS) | set(MUTABLE_FIELDS)

VIN_RE = re.compile(r"^[A-HJ-NPR-Z0-9]{17}$")
TASK_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{8,80}$")
AUTH_ID_RE = re.compile(r"^[a-f0-9]{32}$")


class Deny(Exception):
    """带 HTTP 状态码的拒绝。"""

    def __init__(self, status, reason, detail=None):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.detail = detail or {}


# ---------- 通用 ----------

def canonical_json_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def now_utc():
    return datetime.now(timezone.utc)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(value):
    if not isinstance(value, str):
        raise ValueError("timestamp not a string")
    raw = value[:-1] if value.endswith("Z") else value
    dt = datetime.fromisoformat(raw)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def log_decision(**entry):
    entry.setdefault("ts", iso(now_utc()))
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
    print(f"[AUTHZ] {line}", flush=True)
    try:
        AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_FILE, "a") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        print(f"[AUTHZ-AUDIT-FAIL] {type(e).__name__}: {e}", flush=True)


# ---------- SQLite ----------

_db_lock = threading.Lock()


def _connect():
    AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(AUTH_DB), timeout=15, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA synchronous=FULL")
    return conn


def init_db():
    AUTH_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = _connect()
    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS used_nonces (
            nonce TEXT PRIMARY KEY,
            seen_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS grants (
            auth_id TEXT PRIMARY KEY,
            max_tasks INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            not_after TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS signed_tasks (
            auth_id TEXT NOT NULL,
            task_id TEXT NOT NULL,
            manifest_digest TEXT NOT NULL,
            sig_hex TEXT,
            signed_at TEXT NOT NULL,
            PRIMARY KEY (auth_id, task_id)
        );
        CREATE INDEX IF NOT EXISTS idx_signed_digest
            ON signed_tasks(manifest_digest);
        """)
    finally:
        conn.close()
    try:
        os.chmod(AUTH_DB, 0o600)
    except OSError:
        pass


def check_nonce(nonce):
    """nonce 一次性。DB 唯一约束是多 worker 之间的共享真相。"""
    now = int(time.time())
    conn = _connect()
    try:
        try:
            conn.execute("INSERT INTO used_nonces (nonce, seen_at) VALUES (?, ?)",
                         (nonce, now))
        except sqlite3.IntegrityError:
            raise Deny(409, "replayed_nonce", {"nonce": nonce[:12]})
        if int(time.time()) % 97 == 0:
            conn.execute("DELETE FROM used_nonces WHERE seen_at < ?",
                         (now - NONCE_TTL_S,))
    finally:
        conn.close()


# ---------- 1. 服务身份 ----------

_registry_cache = {"data": None, "at": 0.0, "mtime": None}


def load_registry():
    st = REGISTRY_FILE.stat()
    mtime = st.st_mtime
    if (_registry_cache["data"] is not None
            and _registry_cache["mtime"] == mtime
            and time.time() - _registry_cache["at"] < 60):
        return _registry_cache["data"]
    data = json.loads(REGISTRY_FILE.read_text())
    _registry_cache.update({"data": data, "at": time.time(), "mtime": mtime})
    return data


def _secret_for(entry):
    path = Path(entry["secret_file"])
    if not path.exists():
        raise Deny(500, "service_secret_missing", {"path": str(path)})
    return path.read_text().strip()


def verify_service_request(request, required_scope):
    """
    返回 caller 身份（service id 字符串）。
    失败抛 Deny，调用方只看到机器可读原因，不泄露期望值。
    """
    service = request.headers.get("X-OTA-Service", "")
    ts_raw = request.headers.get("X-OTA-Timestamp", "")
    nonce = request.headers.get("X-OTA-Nonce", "")
    sig_raw = request.headers.get("X-OTA-Signature", "")

    if not all([service, ts_raw, nonce, sig_raw]):
        raise Deny(401, "missing_auth_headers")

    try:
        ts = int(ts_raw)
    except ValueError:
        raise Deny(401, "bad_timestamp")
    if abs(time.time() - ts) > TIME_SKEW_S:
        raise Deny(401, "timestamp_out_of_window",
                   {"skew_s": int(time.time() - ts)})

    if not re.fullmatch(r"[a-f0-9]{16,64}", nonce):
        raise Deny(401, "bad_nonce")

    registry = load_registry()
    entry = registry.get("services", {}).get(service)
    if not entry:
        raise Deny(401, "unknown_service", {"service": service})

    body = request.get_data(cache=True) or b""
    if len(body) > MAX_BODY_BYTES:
        raise Deny(413, "body_too_large")

    path = request.path
    if request.query_string:
        path += "?" + request.query_string.decode("utf-8", "replace")

    canonical = "\n".join([
        request.method.upper(), path, str(ts), nonce, sm3_hex(body),
    ]).encode("utf-8")
    secret = _secret_for(entry).encode("utf-8")
    expected = hmac.new(secret, canonical, "sm3").hexdigest()
    if not hmac.compare_digest(expected, sig_raw):
        raise Deny(401, "bad_signature", {"service": service})

    check_nonce(nonce)

    scopes = set(entry.get("scopes", []))
    if required_scope not in scopes:
        raise Deny(403, "scope_denied",
                   {"service": service, "required": required_scope})
    return service


# ---------- 2. 发布授权链 ----------

_cert_cache = {"cert": None, "sig": None, "mtime": None, "at": 0.0}


def _verify_sm2(pub_pem_or_path, data_bytes, sig_bytes, signer_id):
    with tempfile.TemporaryDirectory() as tmpdir:
        d = Path(tmpdir)
        candidate = Path(pub_pem_or_path) if isinstance(pub_pem_or_path, (str, Path)) else None
        if candidate is not None and "\n" not in str(pub_pem_or_path) and candidate.exists():
            pub_path = candidate
        else:
            pub_path = d / "pub.pem"
            pub_path.write_text(str(pub_pem_or_path))
        in_path = d / "msg"
        in_path.write_bytes(data_bytes)
        sig_path = d / "msg.sig"
        sig_path.write_bytes(sig_bytes)
        r = subprocess.run([
            "gmssl", "sm2verify", "-pubkey", str(pub_path),
            "-id", signer_id, "-in", str(in_path), "-sig", str(sig_path),
        ], capture_output=True)
        return r.returncode == 0 and b"success" in r.stdout.lower()


def load_release_anchor():
    """
    读 release.cert.json + release.cert.sig，用离线 root 公钥验证。
    返回 cert（含 pubkey_pem）。失败抛 Deny，签名服务 fail-closed。
    """
    cert_path = RELEASE_DIR / "release.cert.json"
    sig_path = RELEASE_DIR / "release.cert.sig"
    if not cert_path.exists() or not sig_path.exists():
        raise Deny(500, "release_anchor_missing")
    mtime = max(cert_path.stat().st_mtime, sig_path.stat().st_mtime)
    if (_cert_cache["cert"] is not None
            and _cert_cache["mtime"] == mtime
            and time.time() - _cert_cache["at"] < 60):
        return _cert_cache["cert"]

    if not ROOT_PUB.exists():
        raise Deny(500, "root_pub_missing")
    cert = json.loads(cert_path.read_text())
    sig = sig_path.read_bytes()
    if not _verify_sm2(ROOT_PUB, canonical_json_bytes(cert), sig, "ota-root-v1"):
        raise Deny(500, "release_cert_bad_signature")
    if cert.get("role") != "release-authority":
        raise Deny(500, "release_cert_bad_role")
    try:
        if now_utc() > parse_ts(cert["not_after"]):
            raise Deny(500, "release_cert_expired")
        if now_utc() < parse_ts(cert["not_before"]):
            raise Deny(500, "release_cert_not_yet_valid")
    except (KeyError, ValueError):
        raise Deny(500, "release_cert_bad_validity")
    if not cert.get("pubkey_pem") or not cert.get("key_id"):
        raise Deny(500, "release_cert_incomplete")

    _cert_cache.update({"cert": cert, "sig": sig, "mtime": mtime,
                        "at": time.time()})
    return cert


def verify_grant(grant, sig_hex):
    required = set(IMMUTABLE_FIELDS) | {
        "grant_version", "auth_id", "release_key_id", "issued_at",
        "not_before", "not_after", "max_tasks",
    }
    if not isinstance(grant, dict):
        raise Deny(403, "grant_not_object")
    missing = required - set(grant)
    extra = set(grant) - required
    if missing or extra:
        raise Deny(403, "grant_schema", {"missing": sorted(missing),
                                         "extra": sorted(extra)})
    if grant["grant_version"] != 1:
        raise Deny(403, "grant_version_unsupported")
    if not AUTH_ID_RE.fullmatch(str(grant["auth_id"])):
        raise Deny(403, "grant_auth_id_invalid")

    cert = load_release_anchor()
    if grant["release_key_id"] != cert["key_id"]:
        raise Deny(403, "grant_wrong_release_key",
                   {"expected": cert["key_id"],
                    "got": grant["release_key_id"]})
    try:
        sig = bytes.fromhex(sig_hex or "")
    except ValueError:
        raise Deny(403, "grant_signature_malformed")
    if not _verify_sm2(cert["pubkey_pem"], canonical_json_bytes(grant), sig,
                        cert["key_id"]):
        raise Deny(403, "grant_bad_signature")

    try:
        nb = parse_ts(grant["not_before"])
        na = parse_ts(grant["not_after"])
        issued = parse_ts(grant["issued_at"])
    except (ValueError, TypeError):
        raise Deny(403, "grant_bad_timestamp")
    now = now_utc()
    if now < nb - timedelta(seconds=TIME_SKEW_S):
        raise Deny(403, "grant_not_yet_valid")
    if now > na:
        raise Deny(403, "grant_expired",
                   {"not_after": grant["not_after"]})
    if issued > na or issued < nb - timedelta(seconds=TIME_SKEW_S):
        raise Deny(403, "grant_issued_outside_validity")

    if not isinstance(grant["max_tasks"], int) or not 1 <= grant["max_tasks"] <= 100000:
        raise Deny(403, "grant_bad_quota")
    if not isinstance(grant["package_id"], str) or not grant["package_id"]:
        raise Deny(403, "grant_package_id_invalid")
    return cert


# ---------- 3. manifest 内容策略 ----------

def check_manifest(manifest, grant):
    if not isinstance(manifest, dict):
        raise Deny(403, "manifest_not_object")
    keys = set(manifest)
    missing = ALLOWED_FIELDS - keys
    extra = keys - ALLOWED_FIELDS
    if missing or extra:
        raise Deny(403, "manifest_schema", {"missing": sorted(missing),
                                            "extra": sorted(extra)})
    for field in IMMUTABLE_FIELDS:
        if manifest[field] != grant[field]:
            raise Deny(403, "manifest_not_authorized",
                       {"field": field, "authorized": grant[field],
                        "got": manifest[field]})

    vin = manifest.get("vin")
    if not isinstance(vin, str) or not VIN_RE.fullmatch(vin):
        raise Deny(403, "manifest_vin_invalid")
    task_id = manifest.get("task_id")
    if not isinstance(task_id, str) or not TASK_ID_RE.fullmatch(task_id):
        raise Deny(403, "manifest_task_id_invalid")
    try:
        issued = parse_ts(manifest.get("issued_at"))
    except (ValueError, TypeError):
        raise Deny(403, "manifest_issued_at_invalid")
    nb = parse_ts(grant["not_before"])
    na = parse_ts(grant["not_after"])
    if not (nb - timedelta(seconds=TIME_SKEW_S)
            <= issued <= na + timedelta(seconds=TIME_SKEW_S)):
        raise Deny(403, "manifest_issued_outside_grant")
    wrapped = manifest.get("wrapped_key")
    if not isinstance(wrapped, str) or not re.fullmatch(r"[0-9a-fA-F]{64,2048}", wrapped):
        raise Deny(403, "manifest_wrapped_key_invalid")


# ---------- 签名密钥状态（只信只读的信任元数据） ----------

_trust_cache = {"data": None, "mtime": None, "at": 0.0}


def signing_key_status(key_id):
    try:
        doc = json.loads(TRUST_FILE.read_text())
        policy = effective_policy(accept_policy(doc, ROOT_PUB, AUTH_DB.with_name("trust-state.sqlite3")))
        trusted_key(policy, key_id)
        return policy["keys"][key_id]["status"]
    except Exception:
        return "unknown"


# ---------- 配额与幂等 ----------

def reserve_task(grant, task_id, manifest_digest):
    """
    原子占用一个签名配额。
    返回 ("new", None) 或 ("replay", 已存储的 sig_hex)。
    """
    auth_id = grant["auth_id"]
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT max_tasks, used, not_after, revoked FROM grants WHERE auth_id=?",
            (auth_id,)).fetchone()
        if row is None:
            conn.execute(
                "INSERT INTO grants (auth_id, max_tasks, used, not_after, "
                "revoked, created_at) VALUES (?,?,0,?,0,?)",
                (auth_id, grant["max_tasks"], grant["not_after"], iso(now_utc())))
            max_tasks, used, revoked = grant["max_tasks"], 0, 0
        else:
            max_tasks, used, not_after, revoked = row
            if max_tasks != grant["max_tasks"] or not_after != grant["not_after"]:
                conn.execute("ROLLBACK")
                raise Deny(409, "grant_state_conflict",
                           {"auth_id": auth_id})
        if revoked:
            conn.execute("ROLLBACK")
            raise Deny(403, "grant_revoked", {"auth_id": auth_id})

        prev = conn.execute(
            "SELECT manifest_digest, sig_hex FROM signed_tasks "
            "WHERE auth_id=? AND task_id=?", (auth_id, task_id)).fetchone()
        if prev:
            if prev[0] != manifest_digest:
                conn.execute("ROLLBACK")
                raise Deny(409, "task_id_conflict", {"task_id": task_id})
            conn.execute("COMMIT")
            return ("replay", prev[1])

        if used >= max_tasks:
            conn.execute("ROLLBACK")
            raise Deny(429, "grant_quota_exhausted",
                       {"auth_id": auth_id, "max_tasks": max_tasks})

        conn.execute(
            "INSERT INTO signed_tasks (auth_id, task_id, manifest_digest, "
            "sig_hex, signed_at) VALUES (?,?,?,NULL,?)",
            (auth_id, task_id, manifest_digest, iso(now_utc())))
        conn.execute("UPDATE grants SET used=used+1 WHERE auth_id=?", (auth_id,))
        conn.execute("COMMIT")
        return ("new", None)
    except Deny:
        raise
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def store_signature(auth_id, task_id, sig_hex):
    conn = _connect()
    try:
        conn.execute(
            "UPDATE signed_tasks SET sig_hex=? WHERE auth_id=? AND task_id=?",
            (sig_hex, auth_id, task_id))
    finally:
        conn.close()


def release_reservation(auth_id, task_id):
    """签名失败时归还配额，避免因后端故障白白消耗授权。"""
    conn = _connect()
    try:
        conn.execute("BEGIN IMMEDIATE")
        cur = conn.execute(
            "DELETE FROM signed_tasks WHERE auth_id=? AND task_id=? AND sig_hex IS NULL",
            (auth_id, task_id))
        if cur.rowcount:
            conn.execute("UPDATE grants SET used=MAX(0, used-1) WHERE auth_id=?",
                         (auth_id,))
        conn.execute("COMMIT")
    finally:
        conn.close()


def revoke_grant(auth_id):
    conn = _connect()
    try:
        cur = conn.execute("UPDATE grants SET revoked=1 WHERE auth_id=?", (auth_id,))
        return cur.rowcount > 0
    finally:
        conn.close()


def grant_usage(auth_id=None):
    conn = _connect()
    try:
        if auth_id:
            rows = conn.execute(
                "SELECT auth_id, max_tasks, used, not_after, revoked "
                "FROM grants WHERE auth_id=?", (auth_id,)).fetchall()
        else:
            rows = conn.execute(
                "SELECT auth_id, max_tasks, used, not_after, revoked "
                "FROM grants ORDER BY created_at DESC").fetchall()
        return [dict(zip(["auth_id", "max_tasks", "used", "not_after", "revoked"], r))
                for r in rows]
    finally:
        conn.close()
