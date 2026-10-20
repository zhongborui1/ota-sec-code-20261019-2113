#!/usr/bin/env python3
"""
签名授权边界测试（第一条：签名权限与发布权限分离）。

覆盖：
  A. 服务身份：缺头 / 错签名 / 过期时间戳 / 重放 nonce
  B. 任意字节签名接口已移除
  C. 发布授权：缺 grant / 篡改 grant / 错误签发者 / 过期 grant / 已撤销密钥
  D. 内容策略：不可变字段被改 / 夹带字段 / 配额耗尽
  E. 正常工作流 + 幂等重放
  F. 密钥材料边界：容器内没有 root 私钥、没有 release 私钥
"""
import hashlib
import hmac
import json
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services/signing-service"))
sys.path.insert(0, str(ROOT / "services/ota-api"))

import security  # noqa: E402
from svc_client import SigningClient  # noqa: E402

SIGN_URL = "http://127.0.0.1:8081"
OTA_API = "http://127.0.0.1:8080"
SECRET = (ROOT / "pki/service-auth/ota-api.key").read_text().strip()
RELEASE_KEY = ROOT / "pki/release-v1/release.key"
RELEASE_PASS_FILE = ROOT / "pki/.secrets/release-v1.pass"
RELEASE_PASS = RELEASE_PASS_FILE.read_text().strip()
TEMPLATE = json.loads((ROOT / "packages/manifests/manifest-v1.json").read_text())
EVIDENCE = ROOT / "evidence/raw"

client = SigningClient(SIGN_URL, "ota-api", ROOT / "pki/service-auth/ota-api.key")
results = []


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def sm3_hex(b):
    h = hashlib.new("sm3")
    h.update(b)
    return h.hexdigest()


def signed_headers(path, body, ts=None, nonce=None):
    ts = str(ts if ts is not None else int(time.time()))
    nonce = nonce or uuid.uuid4().hex
    canonical = "\n".join(["POST", path, ts, nonce, sm3_hex(body)]).encode()
    sig = hmac.new(SECRET.encode(), canonical, "sm3").hexdigest()
    return {
        "X-OTA-Service": "ota-api", "X-OTA-Timestamp": ts,
        "X-OTA-Nonce": nonce, "X-OTA-Signature": sig,
        "Content-Type": "application/json",
    }


def http(method, url, body=None, headers=None):
    req = urllib.request.Request(url, data=body, headers=headers or {},
                                 method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:300]}
    except Exception as e:
        return 0, {"error": str(e)}


def post_signed(path, obj, headers=None):
    body = json.dumps(obj, separators=(",", ":")).encode()
    hdrs = signed_headers(path, body)
    hdrs.update(headers or {})
    return http("POST", f"{SIGN_URL}{path}", body, hdrs)


def sign_bytes(data, key_path, pass_file, key_id):
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        inp = f.name
    out = inp + ".sig"
    try:
        subprocess.run([
            "gmssl", "sm2sign", "-key", str(key_path),
            "-pass", pass_file.read_text().strip(), "-id", key_id,
            "-in", inp, "-out", out,
        ], check=True, capture_output=True)
        return Path(out).read_bytes().hex()
    finally:
        Path(inp).unlink(missing_ok=True)
        Path(out).unlink(missing_ok=True)


def make_grant(key_id="ota-signing-v2", max_tasks=5, hours=1,
               not_after=None, not_before=None, auth_id=None):
    now = datetime.now(timezone.utc)
    g = {
        "grant_version": 1,
        "auth_id": auth_id or uuid.uuid4().hex,
        "release_key_id": "ota-release-v1",
        "issued_at": iso(now),
        "not_before": iso(not_before or (now - timedelta(seconds=60))),
        "not_after": iso(not_after or (now + timedelta(hours=hours))),
        "max_tasks": max_tasks,
    }
    for f in security.IMMUTABLE_FIELDS:
        g[f] = TEMPLATE[f]
    g["key_id"] = key_id
    return g


def sign_grant(grant, key_path=RELEASE_KEY, key_id="ota-release-v1",
               pass_file=None):
    pass_file = pass_file or RELEASE_PASS_FILE
    return sign_bytes(security.canonical_json_bytes(grant), key_path,
                      pass_file, key_id)


def make_manifest(grant, vin="LSVAM4187C2TEST01", task_id=None):
    m = {f: grant[f] for f in security.IMMUTABLE_FIELDS}
    m["vin"] = vin
    m["task_id"] = task_id or f"task-{uuid.uuid4().hex[:24]}"
    m["issued_at"] = iso(datetime.now(timezone.utc))
    m["wrapped_key"] = "ab" * 113
    return m


def record(name, expected, status, payload, extra=None):
    ok = status == expected
    if extra:
        ok = ok and extra(payload)
    results.append({"name": name, "expected_http": expected,
                    "actual_http": status,
                    "reason": payload.get("error") or payload.get("reason"),
                    "pass": bool(ok)})
    print(f"[{'PASS' if ok else 'FAIL'}] {name:<46} http={status} "
          f"reason={payload.get('error') or payload.get('reason')}")
    return ok


def main():
    print("=" * 78)
    print("签名授权边界测试")
    print("=" * 78)

    good_grant = make_grant(max_tasks=10)
    good_sig = sign_grant(good_grant)
    good_manifest = make_manifest(good_grant)

    # A. 服务身份
    body = json.dumps({"manifest": good_manifest, "grant": good_grant,
                       "grant_sig_hex": good_sig}).encode()
    st, p = http("POST", f"{SIGN_URL}/sign-manifest", body,
                 {"Content-Type": "application/json"})
    record("A1 无服务身份头", 401, st, p)

    hdrs = signed_headers("/sign-manifest", body)
    hdrs["X-OTA-Signature"] = "00" * 32
    st, p = http("POST", f"{SIGN_URL}/sign-manifest", body, hdrs)
    record("A2 错误 HMAC 签名", 401, st, p)

    hdrs = signed_headers("/sign-manifest", body, ts=int(time.time()) - 1000)
    st, p = http("POST", f"{SIGN_URL}/sign-manifest", body, hdrs)
    record("A3 时间戳超出窗口", 401, st, p)

    nonce = uuid.uuid4().hex
    hdrs = signed_headers("/sign-manifest", body, nonce=nonce)
    st1, _ = http("POST", f"{SIGN_URL}/sign-manifest", body, hdrs)
    st2, p2 = http("POST", f"{SIGN_URL}/sign-manifest", body, hdrs)
    record("A4 重放 nonce", 409, st2, p2)

    # B. 任意字节签名接口
    st, p = post_signed("/sign", {"anything": True})
    record("B1 /sign 任意字节签名接口已移除", 404, st, p)

    # C. 发布授权
    st, p = post_signed("/sign-manifest", {"manifest": good_manifest})
    record("C1 缺少发布授权票据", 400, st, p)

    tampered = dict(good_grant)
    tampered["version"] = "9.9.9"
    st, p = post_signed("/sign-manifest", {
        "manifest": make_manifest(tampered), "grant": tampered,
        "grant_sig_hex": good_sig})
    record("C2 篡改 grant 字段", 403, st, p,
           extra=lambda x: x.get("error") == "grant_bad_signature")

    wrong_sig = sign_bytes(security.canonical_json_bytes(good_grant),
                           ROOT / "pki/signing-v2/signing.key",
                           ROOT / "pki/.secrets/signing-v2.pass",
                           "ota-signing-v2")
    st, p = post_signed("/sign-manifest", {
        "manifest": good_manifest, "grant": good_grant,
        "grant_sig_hex": wrong_sig})
    record("C3 用签名密钥冒充发布密钥签 grant", 403, st, p,
           extra=lambda x: x.get("error") == "grant_bad_signature")

    expired = make_grant(
        not_before=datetime.now(timezone.utc) - timedelta(hours=3),
        not_after=datetime.now(timezone.utc) - timedelta(hours=1))
    expired_sig = sign_grant(expired)
    st, p = post_signed("/sign-manifest", {
        "manifest": make_manifest(expired), "grant": expired,
        "grant_sig_hex": expired_sig})
    record("C4 过期 grant", 403, st, p,
           extra=lambda x: x.get("error") == "grant_expired")

    v1_grant = make_grant(key_id="ota-signing-v1")
    v1_sig = sign_grant(v1_grant)
    st, p = post_signed("/sign-manifest", {
        "manifest": make_manifest(v1_grant), "grant": v1_grant,
        "grant_sig_hex": v1_sig})
    record("C5 grant 指向已撤销的 v1", 403, st, p,
           extra=lambda x: x.get("error") == "key_not_active")

    # D. 内容策略
    bad_manifest = make_manifest(good_grant)
    bad_manifest["version"] = "2.4.2"
    st, p = post_signed("/sign-manifest", {
        "manifest": bad_manifest, "grant": good_grant, "grant_sig_hex": good_sig})
    record("D1 改 manifest 版本（授权外的发布）", 403, st, p,
           extra=lambda x: x.get("error") == "manifest_not_authorized")

    extra_manifest = make_manifest(good_grant)
    extra_manifest["debug"] = True
    st, p = post_signed("/sign-manifest", {
        "manifest": extra_manifest, "grant": good_grant,
        "grant_sig_hex": good_sig})
    record("D2 manifest 夹带额外字段", 403, st, p,
           extra=lambda x: x.get("error") == "manifest_schema")

    quota_grant = make_grant(max_tasks=1)
    quota_sig = sign_grant(quota_grant)
    st1, p1 = post_signed("/sign-manifest", {
        "manifest": make_manifest(quota_grant, vin="LSVAM4187C2PASS01"),
        "grant": quota_grant, "grant_sig_hex": quota_sig})
    st2, p2 = post_signed("/sign-manifest", {
        "manifest": make_manifest(quota_grant, vin="LSVAM4187C2PASS02"),
        "grant": quota_grant, "grant_sig_hex": quota_sig})
    record("D3 配额耗尽后拒绝第二个任务", 429, st2, p2,
           extra=lambda x: x.get("error") == "grant_quota_exhausted")

    # E. 正常工作流 + 幂等
    ok_manifest = make_manifest(good_grant, vin="LSVAM4187C2PASS03")
    st, p = post_signed("/sign-manifest", {
        "manifest": ok_manifest, "grant": good_grant, "grant_sig_hex": good_sig})
    record("E1 合法授权签名", 200, st, p)
    sig_hex = p.get("sig_hex") if st == 200 else None

    if sig_hex:
        st_v, p_v = post_signed("/verify", {
            "data_hex": security.canonical_json_bytes(ok_manifest).hex(),
            "sig_hex": sig_hex, "key_id": "ota-signing-v2"})
        record("E2 签名可被 v2 公钥验证", 200, st_v, p_v,
               extra=lambda x: x.get("valid") is True)

        st2, p2 = post_signed("/sign-manifest", {
            "manifest": ok_manifest, "grant": good_grant,
            "grant_sig_hex": good_sig})
        record("E3 同一 task_id 幂等重放返回同一签名", 200, st2, p2,
               extra=lambda x: x.get("sig_hex") == sig_hex
               and x.get("idempotent_replay") is True)

    # F. 管理接口与密钥边界
    st, p = http("POST", f"{OTA_API}/admin/rotate-trust", b'{"auto_rotate":true}',
                 {"Content-Type": "application/json"})
    record("F1 无管理令牌轮换信任元数据", 401, st, p)

    for container, path, label in [
        ("ota-signing-service", "/keys/root/root.key", "容器内无 root 私钥"),
        ("ota-signing-service", "/keys/release-v1/release.key",
         "容器内无 release 私钥"),
    ]:
        r = subprocess.run(["docker", "exec", container, "test", "-e", path])
        results.append({"name": label, "expected_http": None,
                        "actual_http": r.returncode, "reason": path,
                        "pass": r.returncode != 0})
        print(f"[{'PASS' if r.returncode != 0 else 'FAIL'}] {label:<46} "
              f"exists={r.returncode == 0}")

    # 汇总
    passed = sum(1 for r in results if r["pass"])
    total = len(results)
    print("\n" + "=" * 78)
    print(f"结果：{passed}/{total} 通过")
    print("=" * 78)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"authz-tests-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "passed": passed, "total": total, "results": results,
    }, indent=2, ensure_ascii=False))
    print(f"原始记录: {out}")
    if passed != total:
        sys.exit(1)


if __name__ == "__main__":
    main()
