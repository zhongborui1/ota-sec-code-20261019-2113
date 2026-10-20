"""Report validation and one PostgreSQL transaction for replay/state protection."""
import re
import time
import json
from .trust import SecurityError


def validate_report(body, vin, task, now=None):
    if not isinstance(body, dict) or body.get('vin') != vin or task.get('vin') != vin:
        raise SecurityError('vin_mismatch')
    if body.get('task_id') != task.get('task_id'):
        raise SecurityError('task_mismatch')
    if not isinstance(body.get('nonce'), str) or not re.fullmatch(r'[a-f0-9]{32,64}', body['nonce']):
        raise SecurityError('nonce_required')
    if type(body.get('sequence')) is not int or not 1 <= body['sequence'] <= 2147483647:
        raise SecurityError('sequence_required')
    if type(body.get('client_ts')) is not int or abs((time.time() if now is None else now) - body['client_ts']) > 300:
        raise SecurityError('timestamp_out_of_window')
    if body.get('status') not in {'PENDING_REBOOT', 'CONFIRMED', 'ROLLED_BACK', 'FAILED'}:
        raise SecurityError('invalid_status')
    for field, mf in [('new_version', 'version'), ('new_rollback_index', 'rollback_index'), ('payload_sm3', 'sm3')]:
        if body.get(field) != task['manifest'].get(mf):
            raise SecurityError('report_manifest_mismatch')
    if body['status'] == 'CONFIRMED' and body.get('commit') is not True:
        raise SecurityError('commit_required')


def persist_report(conn, body, task, vin):
    """Caller owns connection; exceptions roll back nonce, sequence and status together."""
    with conn:
        with conn.cursor() as cur:
            # Shared by all gunicorn workers, also serializes the first report.
            cur.execute('SELECT pg_advisory_xact_lock(hashtext(%s))', ('ota-report:' + task['task_id'],))
            cur.execute('SELECT status, detail FROM tasks WHERE task_id=%s FOR UPDATE', (task['task_id'],))
            previous = cur.fetchone()
            current = previous[0] if previous else task['status']
            transitions = {'issued': {'PENDING_REBOOT', 'FAILED'},
                           'PENDING_REBOOT': {'CONFIRMED', 'ROLLED_BACK', 'FAILED'}}
            if body['status'] not in transitions.get(current, set()):
                raise SecurityError('invalid_state_transition')
            cur.execute('INSERT INTO report_nonces(ecu_id,nonce) VALUES (%s,%s)', (vin, body['nonce']))
            cur.execute('SELECT max_seq FROM report_sequences WHERE vin=%s AND task_id=%s FOR UPDATE',
                        (vin, task['task_id']))
            row = cur.fetchone()
            if body['sequence'] <= (row[0] if row else 0):
                raise SecurityError('sequence_replay')
            cur.execute('INSERT INTO report_sequences(vin,task_id,max_seq) VALUES (%s,%s,%s) '
                        'ON CONFLICT(vin,task_id) DO UPDATE SET max_seq=EXCLUDED.max_seq, updated_at=NOW()',
                        (vin, task['task_id'], body['sequence']))
            updated = dict(task, status=body['status'], last_report=body)
            cur.execute('INSERT INTO tasks(task_id,vin,key_id,status,detail) VALUES (%s,%s,%s,%s,%s::jsonb) '
                        'ON CONFLICT(task_id) DO UPDATE SET status=EXCLUDED.status, detail=EXCLUDED.detail, updated_at=NOW()',
                        (task['task_id'], vin, task.get('key_id'), body['status'], json.dumps(updated)))
            cur.execute('INSERT INTO audit_log(action,key_id,resource_id,result,detail) VALUES (%s,%s,%s,%s,%s::jsonb)',
                        ('report-status', task.get('key_id'), task['task_id'], body['status'], json.dumps(body)))
    return updated
