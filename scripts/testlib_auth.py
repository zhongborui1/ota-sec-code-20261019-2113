#!/usr/bin/env python3
"""测试脚本共用的运维辅助：管理令牌、发布授权票据重签。"""
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ADMIN_TOKEN_FILE = ROOT / "pki/service-auth/admin.token"
GRANT_FILE = ROOT / "data/release-grants/active.json"
OTA_API = "http://127.0.0.1:8080"


def admin_headers():
    token = ADMIN_TOKEN_FILE.read_text().strip()
    return {"X-Admin-Token": token}


def publish_policy(states, grace_seconds=60):
    """Only on the offline admin host; does not give root secrets to the API."""
    command = [sys.executable, str(ROOT / 'scripts/17-security-admin.py'), 'policy',
               '--grace-seconds', str(grace_seconds)]
    for kid, status in states.items():
        command += ['--key', f'{kid}={status}']
    subprocess.run(command, check=True)
    import urllib.request
    with urllib.request.urlopen(f'{OTA_API}/trust-metadata', timeout=10) as response:
        return {'trust_metadata': json.load(response)}


def ensure_devices(vins):
    """Preflight only: a test must not approve identities on the administrator's behalf."""
    missing = [vin for vin in vins if not (ROOT / 'pki/device-registry' / (vin + '.json')).exists()]
    if missing:
        raise SystemExit('Devices must be provisioned before this test. First missing VIN: ' +
                         missing[0] + '; use scripts/17-security-admin.py provision --vin VIN')


def issue_grant(key_id, max_tasks=1000, hours=2):
    r = subprocess.run([
        sys.executable, str(ROOT / "scripts/15-release-authorize.py"), "issue",
        "--key-id", key_id, "--max-tasks", str(max_tasks),
        "--validity-hours", str(hours),
    ], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"issue grant failed: {r.stdout}\n{r.stderr}")
    return r.stdout


def current_grant_key():
    try:
        return json.loads(GRANT_FILE.read_text())["grant"]["key_id"]
    except Exception:
        return None


def ensure_active_grant(max_tasks=2000, hours=6):
    """
    让 active grant 的 key_id 与 trust 里的 active key 一致。
    轮换演练中这是"用新密钥重新发布"的必要步骤，不是测试脚本在修状态。
    """
    import urllib.request
    with urllib.request.urlopen(f"{OTA_API}/health", timeout=10) as r:
        active = json.loads(r.read().decode())["active_key_id"]
    if current_grant_key() != active:
        print(f"[GRANT] active key = {active}，重签发布授权")
        print(issue_grant(active, max_tasks=max_tasks, hours=hours))
    return active
