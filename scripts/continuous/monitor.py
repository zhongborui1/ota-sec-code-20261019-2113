#!/usr/bin/env python3
"""监控采样器：每 30s 记录时间序列。"""
import json, subprocess, sys, time
import urllib.request
from datetime import datetime
from pathlib import Path

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
OUT = ROOT / "data" / "continuous" / "metrics.jsonl"
OUT.parent.mkdir(parents=True, exist_ok=True)

DURATION_S = int(sys.argv[1]) if len(sys.argv) > 1 else 3600 * 6
SAMPLE_INTERVAL_S = 30


def get_health():
    try:
        with urllib.request.urlopen(f"{OTA_API}/health", timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception:
        return {}


def get_audit_count():
    try:
        r = subprocess.run(
            ["docker", "exec", "ota-postgres", "psql", "-U", "ota", "-d", "ota",
             "-t", "-c", "SELECT COUNT(*) FROM audit_log;"],
            capture_output=True, text=True, timeout=10)
        return int(r.stdout.strip())
    except Exception:
        return -1


def count_keys():
    return len([d for d in (ROOT / "pki").glob("signing-*") if d.is_dir()])


def count_lines(fname):
    f = ROOT / "data" / "continuous" / fname
    if not f.exists():
        return 0
    return sum(1 for _ in open(f))


def main():
    print(f"[monitor] interval={SAMPLE_INTERVAL_S}s, duration={DURATION_S}s")
    t_end = time.time() + DURATION_S
    while time.time() < t_end:
        h = get_health()
        row = {
            "ts": datetime.utcnow().isoformat() + "Z",
            "active_key_id": h.get("active_key_id"),
            "redis_ok": h.get("redis_ok"),
            "minio_ok": h.get("minio_ok"),
            "payload_consistency_ok": h.get("payload_consistency", {}).get("ok"),
            "key_pool_size": count_keys(),
            "audit_count": get_audit_count(),
            "workload_count": count_lines("workload-results.jsonl"),
            "attack_count": count_lines("attack-results.jsonl"),
            "rotation_count": count_lines("rotation-results.jsonl"),
        }
        with open(OUT, "a") as f:
            f.write(json.dumps(row) + "\n")
        print(f"[monitor] {row['ts']}  keys={row['key_pool_size']} "
              f"audit={row['audit_count']} rotation={row['rotation_count']}")
        time.sleep(SAMPLE_INTERVAL_S)


if __name__ == "__main__":
    main()
