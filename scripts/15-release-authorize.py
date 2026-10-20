#!/usr/bin/env python3
"""
发布授权票据（release grant）运维工具 —— 离线签发。

职责分离：
  - 本工具使用 release 私钥（pki/release-v1/release.key），只在运维主机上执行；
  - 签名服务只拿到 release 公钥证书（root 签发），用于验证票据；
  - ota-api 只拿到已签好的票据（data/release-grants/active.json，只读），
    即使被攻破也无法伪造或扩大授权范围。

用法：
  scripts/15-release-authorize.py issue --key-id ota-signing-v2 --max-tasks 500
  scripts/15-release-authorize.py show
  scripts/15-release-authorize.py status
  scripts/15-release-authorize.py revoke --auth-id <32hex>
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "signing-service"))

os.environ.setdefault("AUTH_DB", str(ROOT / "data/signing-auth/authz.db"))
os.environ.setdefault("AUDIT_FILE", str(ROOT / "data/signing-auth/audit.jsonl"))

import security  # noqa: E402

RELEASE_KEY = ROOT / "pki/release-v1/release.key"
RELEASE_PASS_FILE = ROOT / "pki/.secrets/release-v1.pass"
GRANT_DIR = ROOT / "data/release-grants"
TRUST_FILE = ROOT / "data/trust/trust-metadata.json"
DEFAULT_MANIFEST = ROOT / "packages/manifests/manifest-v1.json"


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def active_signing_key():
    from ota_common.trust import verify_policy, trusted_key
    trust = verify_policy(json.loads(TRUST_FILE.read_text()), ROOT / 'pki/root/root.pub')
    for key_id, info in trust['keys'].items():
        if info['status'] == 'active':
            trusted_key(trust, key_id)
            return key_id
    raise SystemExit('No trusted active signing key')


def sign_grant(grant):
    canonical = security.canonical_json_bytes(grant)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(canonical)
        in_path = f.name
    out_path = in_path + ".sig"
    try:
        r = subprocess.run([
            "gmssl", "sm2sign",
            "-key", str(RELEASE_KEY),
            "-pass", RELEASE_PASS_FILE.read_text().strip(),
            "-id", "ota-release-v1",
            "-in", in_path, "-out", out_path,
        ], capture_output=True, text=True)
        if r.returncode != 0:
            raise SystemExit(f"grant 签名失败: {r.stderr[:300]}")
        return Path(out_path).read_bytes().hex()
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


def cmd_issue(args):
    template = json.loads(Path(args.manifest).read_text())
    key_id = args.key_id or active_signing_key()

    missing = [f for f in security.IMMUTABLE_FIELDS if f not in template]
    if missing:
        raise SystemExit(f"模板缺少字段: {missing}")

    now = datetime.now(timezone.utc)
    auth_id = args.auth_id or uuid.uuid4().hex
    grant = {
        "grant_version": 1,
        "auth_id": auth_id,
        "release_key_id": "ota-release-v1",
        "issued_at": iso(now),
        "not_before": iso(now - timedelta(seconds=60)),
        "not_after": iso(now + timedelta(hours=args.validity_hours)),
        "max_tasks": args.max_tasks,
    }
    for field in security.IMMUTABLE_FIELDS:
        grant[field] = template[field]
    grant["key_id"] = key_id

    sig_hex = sign_grant(grant)
    doc = {
        "grant": grant,
        "grant_sig_hex": sig_hex,
        "issued_by": "ota-release-v1",
        "note": "signed offline; ota-api may only present this grant, never modify it",
    }

    GRANT_DIR.mkdir(parents=True, exist_ok=True)
    grant_path = GRANT_DIR / f"grant-{auth_id}.json"
    grant_path.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    os.chmod(grant_path, 0o644)

    active_path = GRANT_DIR / "active.json"
    tmp = active_path.with_name(active_path.name + ".tmp")
    tmp.write_text(json.dumps(doc, indent=2, ensure_ascii=False))
    os.replace(tmp, active_path)

    print("发布授权票据已签发")
    print(f"  auth_id:    {auth_id}")
    print(f"  package_id: {grant['package_id']}  version {grant['version']}")
    print(f"  key_id:     {key_id}")
    print(f"  有效期:     {grant['not_before']} → {grant['not_after']}")
    print(f"  配额:       {grant['max_tasks']} 次任务")
    print(f"  票据文件:   {grant_path}")
    print(f"  已激活:     {active_path}")


def load_active():
    p = GRANT_DIR / "active.json"
    if not p.exists():
        raise SystemExit("没有 active.json，请先 issue")
    return json.loads(p.read_text())


def cmd_show(_args):
    doc = load_active()
    g = doc["grant"]
    print(json.dumps(g, indent=2, ensure_ascii=False))
    print(f"\n签字: {doc['grant_sig_hex'][:32]}...  ({len(doc['grant_sig_hex'])//2} 字节)")


def cmd_status(_args):
    rows = security.grant_usage()
    if not rows:
        print("尚无已使用的授权（签名服务还未收到任何 grant）")
        return
    print(f"{'auth_id':<34} {'used':>6} {'max':>6} {'revoked':>8}  not_after")
    for r in rows:
        print(f"{r['auth_id']:<34} {r['used']:>6} {r['max_tasks']:>6} "
              f"{str(bool(r['revoked'])):>8}  {r['not_after']}")


def cmd_revoke(args):
    ok = security.revoke_grant(args.auth_id)
    print("已撤销" if ok else "未找到该 auth_id")
    if not ok:
        raise SystemExit(1)


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_issue = sub.add_parser("issue")
    p_issue.add_argument("--key-id")
    p_issue.add_argument("--max-tasks", type=int, default=500)
    p_issue.add_argument("--validity-hours", type=float, default=24)
    p_issue.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    p_issue.add_argument("--auth-id")
    p_issue.set_defaults(func=cmd_issue)

    sub.add_parser("show").set_defaults(func=cmd_show)
    sub.add_parser("status").set_defaults(func=cmd_status)

    p_rev = sub.add_parser("revoke")
    p_rev.add_argument("--auth-id", required=True)
    p_rev.set_defaults(func=cmd_revoke)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
