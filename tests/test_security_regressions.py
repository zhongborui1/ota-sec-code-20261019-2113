"""Run: python3 -m unittest discover -s tests -v

Real GmSSL keys/signatures, SQLite policy ledgers and boot processes. External
Redis/Postgres/MinIO transports are isolated test doubles in API tests. Optional
Postgres integration tests use OTA_TEST_DATABASE_URL in a dedicated test DB.
"""
import copy
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import types
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch, Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'services'))
sys.path.insert(0, str(ROOT / 'services/vehicle-sim'))
sys.path.insert(0, str(ROOT / 'services/ota-api'))
from ota_common.trust import (SecurityError, canonical, atomic_json, accept_policy,
                              verify_policy, trusted_key, effective_policy,
                              enrollment_message, device_record)
from ota_common.reports import validate_report, persist_report
import installer
import ota_client

VIN = 'LSVAM4187C2000000'
VIN2 = 'LSVAM4187C2000001'
K1, K2 = 'ota-signing-v1', 'ota-signing-v2'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def iso(seconds):
    return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class RealCrypto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gmssl'):
            raise RuntimeError('GmSSL is required; cryptographic tests are not simulated.')
        cls.work = tempfile.TemporaryDirectory(prefix='ota-security-')
        cls.base = Path(cls.work.name)
        cls.keypairs = {}
        for kid in ['root', K1, K2, 'device', 'attacker']:
            key, pub = cls.base / (kid + '.key'), cls.base / (kid + '.pub')
            subprocess.run(['gmssl', 'sm2keygen', '-pass', 'test-only-secret',
                            '-out', str(key), '-pubout', str(pub)],
                           check=True, capture_output=True)
            cls.keypairs[kid] = (key, pub)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def setUp(self):
        self.case = tempfile.TemporaryDirectory(dir=self.base)
        self.addCleanup(self.case.cleanup)
        self.folder = Path(self.case.name)
        self.now = int(time.time())
        self.rootpub = self.keypairs['root'][1]

    def sign(self, data, kid='root', identity='ota-root-v1'):
        with tempfile.TemporaryDirectory(dir=self.base) as tmp:
            d = Path(tmp)
            (d/'message').write_bytes(data)
            subprocess.run(['gmssl', 'sm2sign', '-key', str(self.keypairs[kid][0]),
                            '-pass', 'test-only-secret', '-id', identity,
                            '-in', str(d/'message'), '-out', str(d/'sig')],
                           check=True, capture_output=True)
            return (d/'sig').read_bytes().hex()

    def policy(self, version=1, statuses=None, revoke_at=None, expiry=None):
        statuses = statuses or {K1: 'active', K2: 'prepared'}
        keys = {}
        for kid, status in statuses.items():
            keys[kid] = {'status': status, 'public_key': self.keypairs[kid][1].read_text(),
                         'not_before': iso(self.now-60), 'not_after': iso(self.now+86400)}
            if status == 'deprecated':
                keys[kid]['revoke_at'] = iso(revoke_at or self.now+30)
        p = {'type': 'ota-trust-v1', 'version': version, 'issued_at': iso(self.now-10),
             'expires_at': iso(expiry or self.now+3600), 'keys': keys}
        return {'signed': p, 'signature': self.sign(canonical(p))}


class PolicyTests(RealCrypto):
    def test_valid_root_signature_and_persisted_high_water(self):
        doc = self.policy(3)
        ledger = self.folder/'trust.db'
        accept_policy(doc, self.rootpub, ledger)
        accept_policy(copy.deepcopy(doc), self.rootpub, ledger)
        with self.assertRaisesRegex(SecurityError, 'rollback'):
            accept_policy(self.policy(2), self.rootpub, ledger)

    def test_unsigned_policy_rejected(self):
        with self.assertRaisesRegex(SecurityError, 'signed_policy_required'):
            verify_policy(self.policy()['signed'], self.rootpub)

    def test_tampered_public_key_rejected(self):
        doc = self.policy()
        doc['signed']['keys'][K1]['public_key'] = self.keypairs['attacker'][1].read_text()
        with self.assertRaisesRegex(SecurityError, 'bad_root_signature'):
            verify_policy(doc, self.rootpub)

    def test_wrong_root_rejected(self):
        with self.assertRaisesRegex(SecurityError, 'bad_root_signature'):
            verify_policy(self.policy(), self.keypairs['attacker'][1])

    def test_expired_policy_rejected(self):
        with self.assertRaisesRegex(SecurityError, 'expired'):
            verify_policy(self.policy(expiry=self.now-1), self.rootpub)

    def test_same_version_different_contents_rejected(self):
        ledger = self.folder/'trust.db'
        accept_policy(self.policy(), self.rootpub, ledger)
        with self.assertRaisesRegex(SecurityError, 'same_version_conflict'):
            accept_policy(self.policy(statuses={K1:'revoked', K2:'active'}), self.rootpub, ledger)

    def test_revoked_key_cannot_be_reactivated(self):
        ledger = self.folder/'trust.db'
        accept_policy(self.policy(statuses={K1:'revoked', K2:'active'}), self.rootpub, ledger)
        with self.assertRaisesRegex(SecurityError, 'reactivated'):
            accept_policy(self.policy(2), self.rootpub, ledger)

    def test_key_id_cannot_be_rebound(self):
        ledger = self.folder/'trust.db'
        accept_policy(self.policy(), self.rootpub, ledger)
        doc = self.policy(2)
        doc['signed']['keys'][K1]['public_key'] = self.keypairs['attacker'][1].read_text()
        doc['signature'] = self.sign(canonical(doc['signed']))
        with self.assertRaisesRegex(SecurityError, 'rebound'):
            accept_policy(doc, self.rootpub, ledger)

    def test_revocation_deadline_enforced_without_cleanup_worker(self):
        doc = self.policy(statuses={K1:'deprecated', K2:'active'}, revoke_at=self.now+5)
        p = verify_policy(doc, self.rootpub)
        trusted_key(p, K1, now=self.now)
        with self.assertRaisesRegex(SecurityError, 'key_revoked'):
            trusted_key(p, K1, now=self.now+6)

    def test_revocation_deadline_cannot_be_extended(self):
        ledger = self.folder/'trust.db'
        accept_policy(self.policy(statuses={K1:'deprecated', K2:'active'}), self.rootpub, ledger)
        with self.assertRaisesRegex(SecurityError, 'extended'):
            accept_policy(self.policy(2, {K1:'deprecated', K2:'active'}, self.now+60), self.rootpub, ledger)

    def test_parallel_policy_acceptance(self):
        doc, ledger = self.policy(), self.folder/'trust.db'
        with ThreadPoolExecutor(max_workers=8) as pool:
            versions = list(pool.map(lambda _: accept_policy(doc, self.rootpub, ledger)['version'], range(16)))
        self.assertEqual(versions, [1]*16)


class BootTests(RealCrypto):
    def setUp(self):
        super().setUp()
        self.root = self.folder
        anchors = self.root/'pki/vehicle-trust'
        anchors.mkdir(parents=True)
        shutil.copyfile(self.rootpub, anchors/'root.pub')
        self.patch = patch.multiple(installer, ROOT=self.root,
            VEHICLE_STATE=self.root/'data/vehicle-state',
            FACTORY_DIR=self.root/'data/vehicle-state/_factory', TRUST_ANCHORS=anchors)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.payload = b'approved factory firmware\n' * 128
        factory = installer.FACTORY_DIR
        factory.mkdir(parents=True)
        (factory/'payload.bin').write_bytes(self.payload)
        self.factory_meta = {'type':'ota-factory-v1', 'version':'1.0', 'rollback_index':10,
            'size':len(self.payload), 'chunk_size':1024, 'chunk_count':4,
            'sm3':hashlib.new('sm3', self.payload).hexdigest(), 'chunk_hashes':[]}
        atomic_json(factory/'factory.json', {'signed':self.factory_meta,
            'signature':self.sign(canonical(self.factory_meta))})
        installer.init_vehicle(VIN, {}, None)
        accept_policy(self.policy(), anchors/'root.pub', installer.vehicle_dir(VIN)/'trust.sqlite3')

    def install(self):
        data = b'approved OTA firmware\n' * 128
        manifest = {'version':'2.0','rollback_index':11,'vin':VIN, 'key_id':K1,
                    'task_id':'task-test-0001', 'expires_at':iso(self.now+3600),
                    'size':len(data), 'chunk_size':1024, 'sm3':hashlib.new('sm3',data).hexdigest()}
        source = self.folder/'downloaded.bin'
        source.write_bytes(data)
        digest, chunks = installer.scan_file(source, 1024)
        sig = self.sign(canonical(manifest), K1, K1)
        slot = installer.install_standby(VIN, manifest, sig, source, digest, chunks)
        return slot, manifest

    def test_root_approved_factory_boots(self):
        self.assertTrue(installer.verify_slot(VIN, 'slot_a')['ok'])

    def test_valid_ota_commits_in_independent_boot_process(self):
        slot, _ = self.install()
        env = dict(os.environ, OTA_ROOT=str(self.root))
        proc = subprocess.run([sys.executable, str(ROOT/'services/vehicle-sim/boot_agent.py'),
                               '--vin',VIN], env=env, capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        info = json.loads(proc.stdout.strip().splitlines()[-1])
        self.assertEqual(info['result'], 'committed')
        state = json.loads(installer.boot_state_path(VIN).read_text())
        self.assertEqual(state['active_slot'], slot)
        self.assertEqual(state['rollback_index'], 11)

    def test_signature_verified_false_cannot_skip_verification(self):
        slot, _ = self.install()
        d = installer.slot_dir(VIN,slot)
        meta = json.loads((d/'meta.json').read_text())
        meta['signature_verified'] = False
        atomic_json(d/'meta.json',meta)
        (d/'manifest.sig').write_bytes(b'forged signature')
        check = installer.verify_slot(VIN,slot)
        self.assertFalse(check['ok'])
        self.assertIn('sm2_verify_failed',check['reason'])

    def test_payload_and_metadata_tampering_still_rejected(self):
        slot, _ = self.install()
        d = installer.slot_dir(VIN,slot)
        malicious = b'ATTACKER FIRMWARE'
        (d/'payload.bin').write_bytes(malicious)
        meta = json.loads((d/'meta.json').read_text())
        meta.update(sm3=hashlib.new('sm3',malicious).hexdigest(), size=len(malicious), signature_verified=False)
        atomic_json(d/'meta.json',meta)
        self.assertFalse(installer.verify_slot(VIN,slot)['ok'])

    def test_removed_manifest_cannot_claim_unsigned_factory(self):
        slot, _ = self.install()
        d = installer.slot_dir(VIN,slot)
        (d/'manifest.json').unlink()
        self.assertFalse(installer.verify_slot(VIN,slot)['ok'])

    def test_tampered_factory_descriptor_rejected(self):
        path = installer.FACTORY_DIR/'factory.json'
        doc = json.loads(path.read_text())
        doc['signed']['sm3'] = '0'*64
        atomic_json(path,doc)
        self.assertFalse(installer.verify_slot(VIN,'slot_a')['ok'])

    def test_corrupt_standby_rolls_back_after_three_attempts(self):
        slot, _ = self.install()
        installer.corrupt_slot(VIN,slot)
        self.assertEqual(installer.boot_once(VIN)['result'],'retry')
        self.assertEqual(installer.boot_once(VIN)['result'],'retry')
        self.assertEqual(installer.boot_once(VIN)['result'],'rolled_back')

    def test_revoked_key_rejects_pending_image(self):
        slot, _ = self.install()
        accept_policy(self.policy(2,{K1:'revoked',K2:'active'}),
                      installer.TRUST_ANCHORS/'root.pub',installer.vehicle_dir(VIN)/'trust.sqlite3')
        self.assertFalse(installer.verify_slot(VIN,slot)['ok'])

    def test_corrupt_policy_ledger_fails_closed_and_rolls_back(self):
        slot, _ = self.install()
        (installer.vehicle_dir(VIN)/'trust.sqlite3').write_bytes(b'corrupted SQLite')
        self.assertFalse(installer.verify_slot(VIN,slot)['ok'])
        self.assertEqual(installer.boot_once(VIN)['result'],'retry')
        self.assertEqual(installer.boot_once(VIN)['result'],'retry')
        self.assertEqual(installer.boot_once(VIN)['result'],'rolled_back')

    def test_signed_factory_cannot_replace_newer_committed_firmware(self):
        slot, _ = self.install()
        self.assertEqual(installer.boot_once(VIN)['result'],'committed')
        d = installer.slot_dir(VIN,slot)
        (d/'manifest.json').unlink()
        (d/'payload.bin').write_bytes(self.payload)
        atomic_json(d/'meta.json',dict(self.factory_meta,vin=VIN))
        check = installer.verify_slot(VIN,slot)
        self.assertFalse(check['ok'])
        self.assertEqual(check['reason'],'rollback_index_regression')


class EnrollmentTests(RealCrypto):
    def setUp(self):
        super().setUp()
        self.registry = self.folder/'devices'
        self.registry.mkdir()
        atomic_json(self.registry/(VIN+'.json'), {'vin':VIN,'enabled':True,
                    'public_key':self.keypairs['device'][1].read_text()})
        secret = self.folder/'service.key'
        secret.write_text('isolated-service-test-secret')
        identities = self.folder/'identities.json'
        atomic_json(identities, {'services':{'ota-api':{'secret_file':str(secret),
                    'scopes':['ecu:provision','ecu:wrap']}}})
        env = {'AUTH_DB':str(self.folder/'auth.db'), 'AUDIT_FILE':str(self.folder/'audit.jsonl'),
               'SERVICE_REGISTRY':str(identities), 'DEVICE_REGISTRY':str(self.registry)}
        self.envpatch = patch.dict(os.environ, env)
        self.envpatch.start(); self.addCleanup(self.envpatch.stop)
        # fcntl only protects JSONL audit appends; nonce/policy transactions use real SQLite.
        if os.name == 'nt':
            p = patch.dict(sys.modules, {'fcntl':types.SimpleNamespace(flock=lambda *_:None,LOCK_EX=2)})
            p.start(); self.addCleanup(p.stop)
        self.security = load_module('security', ROOT/'services/signing-service/security.py')
        self.service = load_module('security_test_signer', ROOT/'services/signing-service/app.py')
        self.client = self.service.app.test_client()

    def post(self, path, obj):
        raw = canonical(obj)
        ts, nonce = str(int(time.time())), uuid.uuid4().hex
        msg = '\n'.join(['POST',path,ts,nonce,hashlib.new('sm3',raw).hexdigest()]).encode()
        sig = hmac.new(b'isolated-service-test-secret',msg,'sm3').hexdigest()
        return self.client.post(path,data=raw,content_type='application/json',headers={
            'X-OTA-Service':'ota-api','X-OTA-Timestamp':ts,'X-OTA-Nonce':nonce,'X-OTA-Signature':sig})

    def pop(self,kid='device',pub=None):
        nonce = os.urandom(32).hex()
        pub = pub or self.keypairs['device'][1].read_text()
        sig = self.sign(enrollment_message(VIN,nonce,pub),kid,VIN)
        return {'vin':VIN,'nonce':nonce,'sig_hex':sig,'pub_pem':pub}

    def test_preapproved_device_proves_possession(self):
        response = self.post('/verify_device_pop',self.pop())
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json['valid'])

    def test_unknown_vin_is_not_eligible(self):
        body = self.pop(); body['vin'] = VIN2
        self.assertEqual(self.post('/verify_device_pop',body).status_code,403)

    def test_attacker_key_cannot_replace_preapproved_key(self):
        before = (self.registry/(VIN+'.json')).read_bytes()
        body = self.pop('attacker',self.keypairs['attacker'][1].read_text())
        self.assertEqual(self.post('/verify_device_pop',body).status_code,403)
        self.assertEqual(before,(self.registry/(VIN+'.json')).read_bytes())

    def test_failed_signature_cannot_delete_legitimate_key(self):
        before = (self.registry/(VIN+'.json')).read_bytes()
        self.assertEqual(self.post('/verify_device_pop',self.pop('attacker')).status_code,403)
        self.assertEqual(before,(self.registry/(VIN+'.json')).read_bytes())
        self.assertEqual(self.post('/verify_device_pop',self.pop()).status_code,200)

    def test_challenge_is_bound_to_vin_nonce_and_public_key(self):
        body = self.pop(); body['nonce'] = os.urandom(32).hex()
        self.assertEqual(self.post('/verify_device_pop',body).status_code,403)

    def test_disabled_device_rejected(self):
        path = self.registry/(VIN+'.json')
        doc = json.loads(path.read_text()); doc['enabled'] = False
        atomic_json(path,doc)
        self.assertEqual(self.post('/verify_device_pop',self.pop()).status_code,403)


def task_and_report():
    task = {'task_id':'task-test-0001','vin':VIN,'key_id':K1,'status':'issued',
            'manifest':{'version':'2.0','rollback_index':11,'sm3':'1'*64}}
    body = {'task_id':task['task_id'],'vin':VIN,'status':'PENDING_REBOOT',
            'new_version':'2.0','new_rollback_index':11,'payload_sm3':'1'*64,
            'nonce':uuid.uuid4().hex,'client_ts':int(time.time()),'sequence':1}
    return task,body


class AdminCLITests(RealCrypto):
    def setUp(self):
        super().setUp()
        self.root = self.folder/'isolated-project'
        for source, target in [('root','root/root'), (K1,'signing-v1/signing'),
                               (K2,'signing-v2/signing')]:
            for suffix, src in zip(['key','pub'], self.keypairs[source]):
                dst = self.root/'pki'/(target+'.'+suffix)
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(src, dst)
        secret = self.root/'pki/.secrets/root.pass'
        secret.parent.mkdir(parents=True, exist_ok=True)
        secret.write_text('test-only-secret')

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(ROOT/'scripts/17-security-admin.py'),
                                 '--root', str(self.root), *args], capture_output=True,
                                encoding='utf-8', errors='replace',
                                env=dict(os.environ, PYTHONIOENCODING='utf-8'))
        if ok:
            self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def test_policy_publish_rotate_and_reactivation_rejected(self):
        self.cli('policy','--key',K1+'=active','--key',K2+'=prepared')
        self.cli('policy','--key',K1+'=revoked','--key',K2+'=active')
        path = self.root/'data/trust/trust-metadata.json'
        before = path.read_bytes()
        self.assertEqual(verify_policy(json.loads(before), self.rootpub)['version'], 2)
        self.cli('policy','--key',K1+'=active','--key',K2+'=revoked',ok=False)
        self.assertEqual(path.read_bytes(), before)

    def test_unsigned_migration_requires_explicit_approval(self):
        path = self.root/'data/trust/trust-metadata.json'
        atomic_json(path, {'keys':{K1:{'status':'revoked'},K2:{'status':'active'}}})
        self.cli('policy','--key',K2+'=active',ok=False)
        self.cli('policy','--migrate-unsigned','--key',K1+'=revoked','--key',K2+'=active')
        p = verify_policy(json.loads(path.read_text()), self.rootpub)
        self.assertEqual(p['keys'][K1]['status'],'revoked')

    def test_root_signing_failure_does_not_print_password(self):
        wrong_password = 'isolated-wrong-password-' + uuid.uuid4().hex
        (self.root/'pki/.secrets/root.pass').write_text(wrong_password)
        result = self.cli('policy', '--key', K1+'=active', ok=False)
        output = result.stdout + result.stderr
        self.assertIn('root_signing_failed', output)
        self.assertNotIn(wrong_password, output)
        self.assertFalse((self.root/'data/trust/trust-metadata.json').exists())

    def test_local_device_provision_is_idempotent_and_cannot_reenable(self):
        self.cli('provision','--vin',VIN)
        key = self.root/'pki/ecu-local'/VIN/'ecu.key'
        before = key.read_bytes()
        self.cli('provision','--vin',VIN)
        record = self.root/'pki/device-registry'/(VIN+'.json')
        doc = json.loads(record.read_text()); doc['enabled'] = False
        atomic_json(record, doc)
        self.cli('provision','--vin',VIN,'--approve-existing',ok=False)
        self.assertEqual(key.read_bytes(),before)
        self.assertFalse(json.loads(record.read_text())['enabled'])

    def test_root_anchor_cannot_be_replaced_by_policy_publication(self):
        pin = self.root/'pki/vehicle-trust/root.pub'
        pin.parent.mkdir(parents=True)
        shutil.copyfile(self.keypairs['attacker'][1], pin)
        self.cli('policy','--key',K1+'=active',ok=False)
        self.assertFalse((self.root/'data/trust/trust-metadata.json').exists())

    def test_factory_requires_explicit_signed_approval(self):
        source = self.folder/'baseline.bin'; source.write_bytes(os.urandom(3073))
        self.cli('factory','--file',str(source),'--version','factory-1','--rollback-index','10')
        doc = json.loads((self.root/'data/vehicle-state/_factory/factory.json').read_text())
        from ota_common.trust import verify_sm2
        self.assertTrue(verify_sm2(self.rootpub.read_text(),canonical(doc['signed']),
                                   doc['signature'],'ota-root-v1'))
        self.assertEqual(doc['signed']['sm3'],hashlib.new('sm3',source.read_bytes()).hexdigest())
        self.cli('factory','--file',str(source),'--version','fake','--rollback-index','0',ok=False)


class ReportValidationTests(unittest.TestCase):
    def test_mandatory_replay_fields_cannot_be_omitted(self):
        task,body = task_and_report()
        validate_report(body,VIN,task)
        for field in ['nonce','sequence','client_ts']:
            with self.subTest(field=field), self.assertRaises(SecurityError):
                doc = dict(body); doc.pop(field)
                validate_report(doc,VIN,task)

    def test_cross_vehicle_report_rejected(self):
        task,body = task_and_report()
        with self.assertRaisesRegex(SecurityError,'vin_mismatch'):
            validate_report(body,VIN2,task)

    def test_unbound_firmware_metadata_rejected(self):
        task,body = task_and_report(); body['new_rollback_index'] = 999
        with self.assertRaisesRegex(SecurityError,'manifest_mismatch'):
            validate_report(body,VIN,task)

    def test_old_timestamp_and_false_commit_rejected(self):
        task,body = task_and_report(); body['client_ts'] -= 1000
        with self.assertRaisesRegex(SecurityError,'timestamp'):
            validate_report(body,VIN,task)
        body['client_ts'] = int(time.time()); body['status'] = 'CONFIRMED'
        with self.assertRaisesRegex(SecurityError,'commit'):
            validate_report(body,VIN,task)


class RedisDouble:
    def __init__(self,*args,**kwargs): self.values = {}
    def get(self,key): return self.values.get(key)
    def setex(self,key,ttl,value): self.values[key] = value
    def set(self,key,value): self.values[key] = value
    def getdel(self,key): return self.values.pop(key,None)
    def exists(self,key): return key in self.values


class APITests(unittest.TestCase):
    """HTTP validation/failure behavior; no running Redis or Postgres claimed."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ota-api-test-')
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        env = {'TASKS_DIR':str(self.folder/'tasks'), 'TRUST_FILE':str(self.folder/'trust/policy.json'),
               'AUDIT_FALLBACK':str(self.folder/'audit.jsonl'),
               'DEVICE_REGISTRY':str(self.folder/'devices'), 'DATABASE_URL':'test-only',
               'STORAGE_BACKEND':'local'}
        p = patch.dict(os.environ,env); p.start(); self.addCleanup(p.stop)
        # Test doubles are explicitly limited to external transport modules.
        self.driver = types.ModuleType('psycopg2')
        self.driver.IntegrityError = type('IntegrityError',(Exception,),{})
        self.driver.connect = Mock(side_effect=OSError('database down'))
        extras = types.ModuleType('psycopg2.extras'); extras.Json = json.dumps
        redis_mod = types.ModuleType('redis'); redis_mod.Redis = RedisDouble
        minio = types.ModuleType('minio'); minio.Minio = Mock()
        errors = types.ModuleType('minio.error'); errors.S3Error = type('S3Error',(Exception,),{})
        p = patch.dict(sys.modules, {'psycopg2':self.driver,'psycopg2.extras':extras,
            'redis':redis_mod,'minio':minio,'minio.error':errors})
        p.start(); self.addCleanup(p.stop)
        self.api = load_module('security_test_api',ROOT/'services/ota-api/app.py')
        self.client = self.api.app.test_client()
        self.task,self.body = task_and_report()
        self.api.save_task(self.task['task_id'],self.task)
        atomic_json(self.api.DEVICE_REGISTRY/(VIN+'.json'),
                    {'vin':VIN,'enabled':True,'public_key':'PUBLIC KEY test transport record'})
        self.api.r.setex(self.api._token_key('test-token'),86400,VIN)

    def post(self,body):
        return self.client.post('/report-status',json=body,
                                headers={'Authorization':'Bearer test-token'})

    def test_database_outage_is_503_and_task_is_unchanged(self):
        response = self.post(self.body)
        self.assertEqual(response.status_code,503)
        self.assertEqual(self.api.load_task(self.task['task_id'])['status'],'issued')

    def test_missing_report_field_rejected_before_database(self):
        self.body.pop('nonce')
        self.assertEqual(self.post(self.body).status_code,400)
        self.driver.connect.assert_not_called()

    def test_conflicting_report_is_409(self):
        connection = Mock()
        self.driver.connect.side_effect = None; self.driver.connect.return_value = connection
        with patch.object(self.api,'persist_report',side_effect=SecurityError('sequence_replay')):
            self.assertEqual(self.post(self.body).status_code,409)
        connection.close.assert_called_once()

    def test_unknown_device_cannot_obtain_challenge(self):
        self.assertEqual(self.client.post('/api/enrollment/challenge',json={'vin':VIN2}).status_code,403)

    def test_bad_pop_consumes_challenge_and_does_not_issue_token(self):
        response = self.client.post('/api/enrollment/challenge',json={'vin':VIN})
        nonce = response.json['nonce']
        with patch.object(self.api,'call_signing_service',return_value=(403,{'valid':False})):
            result = self.client.post('/api/enrollment/register',json={'vin':VIN,'nonce':nonce,
                'pub_pem':'PUBLIC KEY test transport record','sig_hex':'00'})
        self.assertEqual(result.status_code,400)
        self.assertNotIn('token',result.json)
        self.assertIsNone(self.api.r.get(self.api._enroll_key(nonce)))

    def test_token_storage_uses_hash(self):
        self.assertNotIn('test-token',self.api._token_key('test-token'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
