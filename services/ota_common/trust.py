"""Root-signed policy, durable anti-rollback and SM2 verification.

The root public key is installed out of band. Network responses never replace it.
SQLite transactions serialize policy acceptance across processes.
"""
import copy
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import tempfile
import time
from contextlib import closing
from datetime import datetime
from pathlib import Path


class SecurityError(ValueError):
    pass


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')


def atomic_json(path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + '.')
    try:
        with os.fdopen(fd, 'wb') as f:
            f.write(canonical(obj))
            f.flush()
            os.fsync(f.fileno())
        os.replace(name, path)
        if os.name != 'nt':
            d = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(d)
            finally:
                os.close(d)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def verify_sm2(pub, payload, signature, identity):
    try:
        sig = bytes.fromhex(signature)
        if not 1 <= len(sig) <= 256:
            return False
        with tempfile.TemporaryDirectory(prefix='ota-sm2-') as tmp:
            d = Path(tmp)
            (d / 'pub').write_text(pub, encoding='utf-8')
            (d / 'message').write_bytes(payload)
            (d / 'signature').write_bytes(sig)
            r = subprocess.run(['gmssl', 'sm2verify', '-pubkey', str(d/'pub'),
                                '-id', identity, '-in', str(d/'message'),
                                '-sig', str(d/'signature')], capture_output=True, timeout=30)
            return r.returncode == 0 and b'success' in r.stdout.lower()
    except (ValueError, TypeError, OSError, subprocess.SubprocessError):
        return False


def timestamp(value):
    if not isinstance(value, str):
        raise SecurityError('invalid_timestamp')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
        if dt.tzinfo is None:
            raise ValueError()
        return dt.timestamp()
    except ValueError as exc:
        raise SecurityError('invalid_timestamp') from exc


def verify_policy(doc, root_pub, now=None, allow_expired=False):
    now = time.time() if now is None else now
    if not isinstance(doc, dict) or set(doc) != {'signed', 'signature'}:
        raise SecurityError('signed_policy_required')
    p = doc['signed']
    if not isinstance(p, dict) or p.get('type') != 'ota-trust-v1':
        raise SecurityError('policy_schema')
    if not verify_sm2(Path(root_pub).read_text(), canonical(p), doc['signature'], 'ota-root-v1'):
        raise SecurityError('policy_bad_root_signature')
    if type(p.get('version')) is not int or p['version'] < 1:
        raise SecurityError('policy_version')
    issued, expiry = timestamp(p.get('issued_at')), timestamp(p.get('expires_at'))
    if issued > now + 60 or expiry <= issued or (not allow_expired and now >= expiry):
        raise SecurityError('policy_expired_or_not_yet_valid')
    keys = p.get('keys')
    if not isinstance(keys, dict) or not keys:
        raise SecurityError('policy_keys')
    if not all(isinstance(k, dict) for k in keys.values()):
        raise SecurityError('policy_key_schema')
    if sum(k.get('status') == 'active' for k in keys.values()) != 1:
        raise SecurityError('policy_requires_one_active_key')
    for kid, k in keys.items():
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,80}', kid):
            raise SecurityError('invalid_key_id')
        if k.get('status') not in {'prepared', 'active', 'deprecated', 'revoked'}:
            raise SecurityError('invalid_key_status')
        if not isinstance(k.get('public_key'), str) or 'PUBLIC KEY' not in k['public_key']:
            raise SecurityError('public_key_missing')
        if timestamp(k.get('not_after')) <= timestamp(k.get('not_before')):
            raise SecurityError('key_validity')
        if k['status'] == 'deprecated':
            timestamp(k.get('revoke_at'))
    return p


def accept_policy(doc, root_pub, state_db, now=None):
    p = verify_policy(doc, root_pub, now)
    state_db = Path(state_db)
    state_db.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(state_db, timeout=30)) as db, db:
        db.execute('PRAGMA synchronous=FULL')
        db.execute('CREATE TABLE IF NOT EXISTS trust (id INTEGER PRIMARY KEY, version INTEGER, document TEXT)')
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT version, document FROM trust WHERE id=1').fetchone()
        if row:
            old = json.loads(row[1])['signed']
            if p['version'] < row[0]:
                raise SecurityError('policy_rollback')
            if p['version'] == row[0] and canonical(p) != canonical(old):
                raise SecurityError('policy_same_version_conflict')
            rank = {'prepared': 0, 'active': 1, 'deprecated': 2, 'revoked': 3}
            for kid, prev in old['keys'].items():
                new = p['keys'].get(kid)
                if not new or new['public_key'] != prev['public_key']:
                    raise SecurityError('policy_key_removed_or_rebound')
                old_rank = rank[prev['status']]
                if prev['status'] == 'deprecated' and timestamp(prev['revoke_at']) <= (time.time() if now is None else now):
                    old_rank = 3
                if rank[new['status']] < old_rank and canonical(p) != canonical(old):
                    raise SecurityError('policy_key_reactivated')
                if prev['status'] == new['status'] == 'deprecated' and timestamp(new['revoke_at']) > timestamp(prev['revoke_at']):
                    raise SecurityError('revocation_deadline_extended')
        db.execute('INSERT OR REPLACE INTO trust VALUES (1,?,?)',
                   (p['version'], canonical(doc).decode()))
    return p


def cached_policy(state_db, root_pub, allow_expired=False):
    if not Path(state_db).exists():
        raise SecurityError('no_trusted_policy')
    with closing(sqlite3.connect(state_db)) as db:
        row = db.execute('SELECT document FROM trust WHERE id=1').fetchone()
    if not row:
        raise SecurityError('no_trusted_policy')
    return verify_policy(json.loads(row[0]), root_pub, allow_expired=allow_expired)


def effective_policy(p, now=None):
    now = time.time() if now is None else now
    p = copy.deepcopy(p)
    p['trust_anchor_version'] = p['version']
    p['updated_at'] = p['issued_at']
    for key in p['keys'].values():
        if key['status'] == 'deprecated' and now >= timestamp(key['revoke_at']):
            key['status'] = 'revoked'
    return p


def trusted_key(p, kid, now=None, installed=False):
    now = time.time() if now is None else now
    key = effective_policy(p, now)['keys'].get(kid)
    if not key:
        raise SecurityError('unknown_key')
    # 已确认分区可以离线启动；新安装/待确认分区必须执行当前撤销和有效期策略。
    if not installed:
        if key['status'] not in {'active', 'deprecated'}:
            raise SecurityError('key_' + key['status'])
        if not timestamp(key['not_before']) <= now < timestamp(key['not_after']):
            raise SecurityError('key_outside_validity')
    return key['public_key']


def device_record(directory, vin):
    if not isinstance(vin, str) or not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}', vin):
        raise SecurityError('invalid_vin')
    try:
        d = json.loads((Path(directory) / (vin + '.json')).read_text())
    except (OSError, ValueError) as exc:
        raise SecurityError('device_not_provisioned') from exc
    if not isinstance(d, dict) or d.get('vin') != vin or d.get('enabled') is not True or not isinstance(d.get('public_key'), str):
        raise SecurityError('device_disabled_or_invalid')
    return d


def enrollment_message(vin, nonce, pub):
    fingerprint = hashlib.sha256(pub.strip().encode()).hexdigest()
    return canonical({'purpose': 'ota-enrollment-v1', 'vin': vin, 'nonce': nonce,
                      'public_key_sha256': fingerprint})
