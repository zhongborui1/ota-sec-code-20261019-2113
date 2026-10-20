"""Optional REAL PostgreSQL transaction tests; never use the operating OTA database.

OTA_TEST_DATABASE_URL must point to a dedicated test database. Each case creates
and removes its own UUID schema; normal tables and vehicle data are untouched.
"""
import json
import os
import sys
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'services'))
from ota_common.reports import persist_report
from ota_common.trust import SecurityError


@unittest.skipUnless(os.environ.get('OTA_TEST_DATABASE_URL'),
                     'Set OTA_TEST_DATABASE_URL to a dedicated PostgreSQL test database')
class PostgresReportTests(unittest.TestCase):
    def setUp(self):
        import psycopg2
        self.driver = psycopg2
        self.url = os.environ['OTA_TEST_DATABASE_URL']
        self.schema = 'ota_test_'+uuid.uuid4().hex
        conn = self.driver.connect(self.url)
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute('CREATE SCHEMA '+self.schema)
        finally:
            conn.close()
        self.addCleanup(self.remove_schema)
        conn = self.connection()
        try:
            with conn.cursor() as cur:
                cur.execute((ROOT/'data/postgres-init/01-schema.sql').read_text())
                cur.execute((ROOT/'data/postgres-init/03-report-security.sql').read_text())
            conn.commit()
        finally:
            conn.close()
        self.task = {'task_id':'test-'+uuid.uuid4().hex, 'vin':'LSVAM4187C2000000',
                     'key_id':'ota-signing-v1','status':'issued','manifest':{}}

    def remove_schema(self):
        conn = self.driver.connect(self.url)
        try:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute('DROP SCHEMA '+self.schema+' CASCADE')
        finally:
            conn.close()

    def connection(self):
        return self.driver.connect(self.url, options='-c search_path='+self.schema)

    def report(self, status='PENDING_REBOOT', sequence=1, nonce=None):
        body = {'status':status,'sequence':sequence,'nonce':nonce or uuid.uuid4().hex}
        conn = self.connection()
        try:
            return persist_report(conn,body,self.task,self.task['vin'])
        finally:
            conn.close()

    def query(self, query):
        conn = self.connection()
        try:
            with conn.cursor() as cur:
                cur.execute(query)
                return cur.fetchall()
        finally:
            conn.close()

    def test_pending_then_confirmed_commits_audit_and_sequence(self):
        self.report()
        self.report('CONFIRMED',2)
        self.assertEqual(self.query('SELECT status FROM tasks'),[('CONFIRMED',)])
        self.assertEqual(self.query('SELECT max_seq FROM report_sequences'),[(2,)])
        self.assertEqual(self.query('SELECT COUNT(*) FROM audit_log'),[(2,)])

    def test_cannot_skip_pending_state(self):
        with self.assertRaisesRegex(SecurityError,'state_transition'):
            self.report('CONFIRMED',1)
        self.assertEqual(self.query('SELECT COUNT(*) FROM report_nonces'),[(0,)])

    def test_reused_nonce_is_rejected_atomically(self):
        nonce = uuid.uuid4().hex
        self.report(nonce=nonce)
        with self.assertRaises(self.driver.IntegrityError):
            self.report('CONFIRMED',2,nonce)
        self.assertEqual(self.query('SELECT status FROM tasks'),[('PENDING_REBOOT',)])
        self.assertEqual(self.query('SELECT max_seq FROM report_sequences'),[(1,)])

    def test_decreasing_sequence_does_not_consume_new_nonce(self):
        self.report(sequence=5)
        with self.assertRaisesRegex(SecurityError,'sequence_replay'):
            self.report('CONFIRMED',4)
        self.assertEqual(self.query('SELECT COUNT(*) FROM report_nonces'),[(1,)])

    def test_two_workers_cannot_commit_different_terminal_states(self):
        self.report()
        def submit(status):
            try:
                self.report(status,2)
                return True
            except SecurityError:
                return False
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(submit,['CONFIRMED','ROLLED_BACK']))
        self.assertEqual(sum(results),1)
        self.assertEqual(self.query('SELECT COUNT(*) FROM audit_log'),[(2,)])

    def test_missing_audit_table_rolls_back_entire_report(self):
        conn = self.connection()
        try:
            with conn, conn.cursor() as cur:
                cur.execute('DROP TABLE audit_log')
        finally:
            conn.close()
        with self.assertRaises(self.driver.Error):
            self.report()
        for table in ('tasks','report_nonces','report_sequences'):
            self.assertEqual(self.query('SELECT COUNT(*) FROM '+table),[(0,)])
