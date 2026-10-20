#!/usr/bin/env python3
"""持续压测器：泊松过程车辆升级请求。"""
import hashlib, json, random, sys, threading, time
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/home/rjh/ota-sec/services/vehicle-sim")
from simulator import (validate_received_manifest, request_task,
                       download_chunk, report_status)  # noqa

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
AVG_INTERVAL_S = 0.2
MAX_CONCURRENT = 50
RUN_DURATION_S = int(sys.argv[1]) if len(sys.argv) > 1 else 3600 * 6

LOG = ROOT / "data" / "continuous" / "workload.log"
RESULTS = ROOT / "data" / "continuous" / "workload-results.jsonl"
LOG.parent.mkdir(parents=True, exist_ok=True)


def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def http_post(url, obj, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def http_get_bytes(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


_counter = {"total": 0, "ok": 0, "fail": 0}
_lock = threading.Lock()


def one_upgrade():
    vin = f"LSVAM4187C2W{random.randint(0, 9999999):07d}"
    t0 = time.time()
    result = {"vin": vin, "ts": t0, "ok": False}
    try:
        _, task = request_task(vin)
        task_id = task["task_id"]
        manifest = task["manifest"]
        key_id = task["key_id"]
        sig = task["manifest_sig_hex"]
        chunk_count = task["chunk_count"]
        chunk_hashes = task["chunk_hashes"]
        local_rollback = random.randint(8, 11)
        accepted, reason = validate_received_manifest(
            vin=vin, manifest=manifest, sig_hex=sig,
            key_id=key_id, local_rollback=local_rollback)
        if not accepted:
            result["error"] = f"manifest_reject: {reason}"
            return result
        h = hashlib.new("sm3")
        for i in range(chunk_count):
            data = download_chunk(vin, task_id, i)
            if sm3_hex(data) != chunk_hashes[i]:
                result["error"] = f"chunk_{i}_mismatch"
                return result
            h.update(data)
            del data
        if h.hexdigest() != manifest["sm3"]:
            result["error"] = "sm3_mismatch"
            return result
        report_status(vin,
                      {"task_id": task_id, "vin": vin, "status": "CONFIRMED"})
        result["ok"] = True
        result["elapsed_ms"] = round((time.time() - t0) * 1000, 2)
        result["key_id"] = key_id
        return result
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"
        return result


def worker():
    while True:
        r = one_upgrade()
        with _lock:
            _counter["total"] += 1
            if r["ok"]:
                _counter["ok"] += 1
            else:
                _counter["fail"] += 1
        with open(RESULTS, "a") as f:
            f.write(json.dumps(r) + "\n")
        time.sleep(random.expovariate(1.0 / AVG_INTERVAL_S))


def monitor_thread():
    while True:
        time.sleep(30)
        with _lock:
            t, o, f_ = _counter["total"], _counter["ok"], _counter["fail"]
        rate = o / t * 100 if t else 0
        log(f"[STAT] total={t} ok={o} fail={f_} rate={rate:.2f}%")


def main():
    log("=" * 50)
    log(f"持续压测器启动 (λ={1/AVG_INTERVAL_S:.2f}/s, 运行 {RUN_DURATION_S}s)")
    log("=" * 50)
    for _ in range(MAX_CONCURRENT):
        threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=monitor_thread, daemon=True).start()
    time.sleep(RUN_DURATION_S)
    with _lock:
        log(f"[END] total={_counter['total']} ok={_counter['ok']} fail={_counter['fail']}")


if __name__ == "__main__":
    main()
