#!/usr/bin/env python3
"""Explicit offline administration. Private keys never enter the API container."""
import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from contextlib import closing

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services'))
from ota_common.trust import (atomic_json, canonical, accept_policy, effective_policy,
                              verify_policy, verify_sm2, SecurityError)


def iso(dt):
    return dt.strftime('%Y-%m-%dT%H:%M:%SZ')


def sign(root, payload):
    with tempfile.TemporaryDirectory() as tmp:
        d = Path(tmp)
        (d/'input').write_bytes(canonical(payload))
        try:
            subprocess.run(['gmssl', 'sm2sign', '-key', str(root/'pki/root/root.key'),
                            '-pass', (root/'pki/.secrets/root.pass').read_text().strip(),
                            '-id', 'ota-root-v1', '-in', str(d/'input'), '-out', str(d/'sig')],
                           check=True, capture_output=True)
        except subprocess.CalledProcessError:
            # A CalledProcessError includes command arguments, including -pass.
            raise SecurityError('root_signing_failed') from None
        return {'signed': payload, 'signature': (d/'sig').read_bytes().hex()}


def pin_root(root):
    src = root/'pki/root/root.pub'
    dst = root/'pki/vehicle-trust/root.pub'
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists() and dst.read_bytes() != src.read_bytes():
        raise SecurityError('pinned_root_mismatch: root rotation requires a separate recovery procedure')
    if not dst.exists():
        shutil.copyfile(src, dst)


def publish_policy(root, args):
    # Check the pinned anchor before changing any published policy or ledger.
    pin_root(root)
    folder = root/'data/trust'
    folder.mkdir(parents=True, exist_ok=True)
    # Lock all offline publishers; the API has a read-only mount of this directory.
    with closing(sqlite3.connect(folder/'publisher-lock.sqlite3', timeout=60)) as lock, lock:
        lock.execute('CREATE TABLE IF NOT EXISTS lock(id INTEGER PRIMARY KEY)')
        lock.execute('BEGIN IMMEDIATE')
        path = folder/'trust-metadata.json'
        old = json.loads(path.read_text()) if path.exists() else None
        ledger = folder/'publisher-state.sqlite3'
        if ledger.exists():
            with closing(sqlite3.connect(ledger)) as db:
                row = db.execute('SELECT version, document FROM trust WHERE id=1').fetchone()
            if row:
                recorded = json.loads(row[1])
                verify_policy(recorded, root/'pki/root/root.pub', allow_expired=True)
                if old and 'signed' in old and old['signed']['version'] == row[0] and canonical(old['signed']) != canonical(recorded['signed']):
                    raise SecurityError('publisher_same_version_conflict')
                if not old or 'signed' not in old or old['signed']['version'] < row[0]:
                    # Recover a crash between ledger commit and the atomic file replacement.
                    old = recorded
        if old and 'signed' not in old and not args.migrate_unsigned:
            raise SecurityError('unsigned_policy: review it, then use --migrate-unsigned explicitly')
        if old and 'signed' in old:
            previous = verify_policy(old, root/'pki/root/root.pub', allow_expired=True)
            policy = effective_policy(previous)
            policy.pop('trust_anchor_version', None)
            policy.pop('updated_at', None)
            policy['version'] += 1
        else:
            policy = {'type': 'ota-trust-v1', 'version': 1, 'keys': {}}
            # Only explicitly approved states are imported, never arbitrary old public keys.
        now = datetime.now(timezone.utc)
        policy.update(issued_at=iso(now), expires_at=iso(now + timedelta(hours=args.hours)))
        for assignment in args.key:
            kid, status = assignment.split('=', 1)
            if not kid.startswith('ota-signing-') or '/' in kid or '\\' in kid:
                raise SecurityError('invalid_key_id')
            pub = root/'pki'/kid.removeprefix('ota-')/'signing.pub'
            entry = policy['keys'].setdefault(kid, {
                'public_key': pub.read_text(), 'not_before': iso(now - timedelta(minutes=1)),
                'not_after': iso(now + timedelta(days=365))})
            entry['status'] = status
            if status == 'deprecated':
                entry.setdefault('revoke_at', iso(now + timedelta(seconds=args.grace_seconds)))
        doc = sign(root, policy)
        # Establish the previous high-water mark even on the first run of this tool.
        if old and 'signed' in old and not ledger.exists():
            # An expired previous policy is verified above; seed its version for anti-rollback.
            with closing(sqlite3.connect(ledger)) as db, db:
                db.execute('CREATE TABLE trust(id INTEGER PRIMARY KEY, version INTEGER, document TEXT)')
                db.execute('INSERT INTO trust VALUES(1,?,?)', (old['signed']['version'], json.dumps(old)))
        accept_policy(doc, root/'pki/root/root.pub', ledger)
        atomic_json(path, doc)
        # Public, signed metadata must be readable by the unprivileged signer container.
        os.chmod(path, 0o644)
        pin_root(root)
        print('Published root-signed trust version', policy['version'])


def provision(root, args):
    pin_root(root)
    registry = root/'pki/device-registry'
    registry.mkdir(parents=True, exist_ok=True)
    vins = [args.vin] if args.vin else [f'LSVAM4187C2{i:06d}' for i in range(args.start, args.start+args.count)]
    import re
    for vin in vins:
        if not re.fullmatch(r'[A-HJ-NPR-Z0-9]{17}', vin):
            raise SecurityError('invalid_vin')
        local = root/'pki/ecu-local'/vin
        local.mkdir(parents=True, exist_ok=True)
        key, pub = local/'ecu.key', local/'ecu.pub'
        registration = registry/(vin+'.json')
        if key.exists() and not registration.exists() and not args.approve_existing:
            raise SecurityError(f'{vin}: existing identity requires --approve-existing')
        if not key.exists():
            if registration.exists() or pub.exists():
                raise SecurityError(f'{vin}: incomplete identity; refusing replacement')
            subprocess.run(['gmssl','sm2keygen','-pass',f'localpass-{vin}',
                            '-out',str(key),'-pubout',str(pub)], check=True, capture_output=True)
            os.chmod(key, 0o600)
        # Check local private/public pair before approving it.
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            msg = os.urandom(32)
            (d/'msg').write_bytes(msg)
            subprocess.run(['gmssl','sm2sign','-key',str(key),'-pass',f'localpass-{vin}',
                            '-id',vin,'-in',str(d/'msg'),'-out',str(d/'sig')],check=True,capture_output=True)
            if not verify_sm2(pub.read_text(), msg, (d/'sig').read_bytes().hex(), vin):
                raise SecurityError('device_key_pair_mismatch')
        record = {'vin': vin, 'public_key': pub.read_text(), 'enabled': True}
        if registration.exists():
            if json.loads(registration.read_text()) != record:
                raise SecurityError(f'{vin}: registered key/status differs; refusing overwrite')
        else:
            atomic_json(registration, record)
        os.chmod(registration, 0o644)
    print('Provisioned/verified', len(vins), 'device identities. Private keys remain in ecu-local.')


def factory(root, args):
    pin_root(root)
    source = Path(args.file).resolve()
    d = root/'data/vehicle-state/_factory'
    d.mkdir(parents=True, exist_ok=True)
    if (d/'factory.json').exists():
        raise SecurityError('factory already approved; refusing overwrite')
    whole = hashlib.new('sm3')
    chunks = []
    with source.open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            whole.update(block)
            chunks.append(hashlib.new('sm3', block).hexdigest())
    meta = {'type': 'ota-factory-v1', 'version': args.version,
            'rollback_index': args.rollback_index, 'size': source.stat().st_size,
            'chunk_size': 1024*1024, 'chunk_count': len(chunks),
            'sm3': whole.hexdigest(), 'chunk_hashes': chunks}
    dest = d/'payload.bin'
    if source != dest.resolve():
        if dest.exists():
            raise SecurityError('existing factory image: approve that exact file or use isolated OTA_ROOT')
        shutil.copyfile(source, dest)
    atomic_json(d/'factory.json', sign(root, meta))
    print('Factory baseline explicitly approved:', meta['sm3'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('policy', help='Issue a root-signed monotonically versioned policy')
    p.add_argument('--key', action='append', default=[], help='ota-signing-v1=active (repeatable)')
    p.add_argument('--hours', type=int, default=168)
    p.add_argument('--grace-seconds', type=int, default=60)
    p.add_argument('--migrate-unsigned', action='store_true')
    p = sub.add_parser('provision')
    p.add_argument('--vin')
    p.add_argument('--count', type=int, default=1)
    p.add_argument('--start', type=int, default=0)
    p.add_argument('--approve-existing', action='store_true')
    p = sub.add_parser('factory')
    p.add_argument('--file', required=True)
    p.add_argument('--version', required=True)
    p.add_argument('--rollback-index', type=int, required=True)
    args = parser.parse_args()
    if args.command == 'policy' and (args.hours <= 0 or args.grace_seconds < 0):
        parser.error('hours must be positive and grace-seconds nonnegative')
    if args.command == 'provision' and (args.count < 1 or args.start < 0):
        parser.error('count must be positive and start nonnegative')
    if args.command == 'factory' and args.rollback_index < 0:
        parser.error('rollback-index must be nonnegative')
    {'policy':publish_policy, 'provision':provision, 'factory':factory}[args.command](args.root.resolve(), args)


if __name__ == '__main__':
    main()
