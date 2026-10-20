#!/usr/bin/env bash
# Only check prerequisites. Never erase policies, identities or rollback ledgers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 - <<'PY'
import json, urllib.request
with urllib.request.urlopen('http://127.0.0.1:8080/trust-metadata', timeout=10) as response:
    policy = json.load(response)
if policy['keys'].get('ota-signing-v1', {}).get('status') != 'active':
    raise SystemExit('This v1-to-v2 test requires a fresh isolated deployment. Never reactivate revoked keys.')
if policy['keys'].get('ota-signing-v2', {}).get('status') != 'prepared':
    raise SystemExit('v2 must be prepared. See docs/02-security-migration.md.')
print('Policy prerequisites OK; no runtime state was reset.')
PY
python3 scripts/15-release-authorize.py issue --key-id ota-signing-v1 --max-tasks 2000 --validity-hours 6
