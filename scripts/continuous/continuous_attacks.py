#!/usr/bin/env python3
"""持续攻击注入器：泊松过程随机攻击。"""
import hashlib, json, random, subprocess, sys, tempfile, threading, time
import urllib.request
from datetime import datetime
from pathlib import Path

sys.path.insert(0, "/home/rjh/ota-sec/services/vehicle-sim")
from simulator import (validate_received_manifest, request_task,
                       download_chunk)  # noqa

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
AVG_INTERVAL_S = 45
RUN_DURATION_S = int(sys.argv[1]) if len(sys.argv) > 1 else 3600 * 6

LOG = ROOT / "data" / "continuous" / "attacks.log"
RESULTS = ROOT / "data" / "continuous" / "attack-results.jsonl"
LOG.parent.mkdir(parents=True, exist_ok=True)


def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def http_post(url, obj, timeout=60):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def http_get_bytes(url, timeout=60):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.read()


def sign_locally(manifest, key_id):
    suffix = key_id.replace("ota-signing-", "")
    keydir = f"signing-{suffix}"
    key_pass = f"{suffix}pass"
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(canonical)
        in_path = f.name
    out_path = in_path + ".sig"
    try:
        subprocess.run([
            "gmssl", "sm2sign",
            "-key", str(ROOT / "pki" / keydir / "signing.key"),
            "-pass", key_pass, "-id", key_id,
            "-in", in_path, "-out", out_path,
        ], check=True, capture_output=True)
        return Path(out_path).read_bytes().hex()
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


def attack_tampered_chunk():
    vin = f"LSVAM4187C2ATK{random.randint(0, 999999):06d}"
    _, task = request_task(vin)
    data = bytearray(download_chunk(vin, task['task_id'], 0))
    data[random.randint(0, len(data) - 1)] ^= 0xFF
    return (sm3_hex(bytes(data)) != task["chunk_hashes"][0]), "tampered_chunk"


def attack_tampered_manifest():
    vin = f"LSVAM4187C2ATK{random.randint(0, 999999):06d}"
    _, task = request_task(vin)
    manifest = dict(task["manifest"])
    manifest["version"] = "9.9.9"
    accepted, _ = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=task["manifest_sig_hex"],
        key_id=task["key_id"], local_rollback=10)
    return (not accepted), "tampered_manifest"


def attack_downgrade():
    vin = f"LSVAM4187C2ATK{random.randint(0, 999999):06d}"
    _, task = request_task(vin)
    manifest = dict(task["manifest"])
    current_ri = manifest["rollback_index"]
    manifest["rollback_index"] = current_ri - random.randint(1, 5)
    sig = sign_locally(manifest, task["key_id"])
    accepted, _ = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig,
        key_id=task["key_id"], local_rollback=current_ri)
    return (not accepted), "downgrade"


def attack_vin_mismatch():
    vin_a = f"LSVAM4187C2ATK{random.randint(0, 999999):06d}"
    vin_b = f"LSVAM4187C2ATK{random.randint(0, 999999):06d}"
    _, task = request_task(vin_a)
    sig = sign_locally(task["manifest"], task["key_id"])
    accepted, _ = validate_received_manifest(
        vin=vin_b, manifest=task["manifest"], sig_hex=sig,
        key_id=task["key_id"], local_rollback=10)
    return (not accepted), "vin_mismatch"


def attack_revoked_key():
    vin = f"LSVAM4187C2ATK{random.randint(0, 999999):06d}"
    _, task = request_task(vin)
    manifest = task["manifest"]
    try:
        sig = sign_locally(manifest, "ota-signing-v1")
    except Exception:
        return False, "v1_key_missing"
    accepted, _ = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig,
        key_id="ota-signing-v1", local_rollback=10)
    return (not accepted), "revoked_key"


ATTACKS = [attack_tampered_chunk, attack_tampered_manifest,
           attack_downgrade, attack_vin_mismatch, attack_revoked_key]
_counter = {"total": 0, "rejected": 0, "accepted": 0, "error": 0}
_lock = threading.Lock()


def one_attack():
    fn = random.choice(ATTACKS)
    try:
        rejected, name = fn()
        return {"name": name, "rejected": rejected}
    except Exception as e:
        return {"name": fn.__name__, "rejected": None,
                "error": f"{type(e).__name__}: {e}"}


def main():
    log("=" * 50)
    log(f"攻击注入器启动 (λ={1/AVG_INTERVAL_S:.2f}/s, 运行 {RUN_DURATION_S}s)")
    log("=" * 50)
    t_end = time.time() + RUN_DURATION_S
    while time.time() < t_end:
        r = one_attack()
        with _lock:
            _counter["total"] += 1
            if r["rejected"] is True:
                _counter["rejected"] += 1
            elif r["rejected"] is False:
                _counter["accepted"] += 1
            else:
                _counter["error"] += 1
        with open(RESULTS, "a") as f:
            f.write(json.dumps({"ts": datetime.utcnow().isoformat() + "Z", **r}) + "\n")
        if _counter["total"] % 10 == 0:
            with _lock:
                c = dict(_counter)
            log(f"[STAT] total={c['total']} rejected={c['rejected']} "
                f"accepted={c['accepted']} error={c['error']}")
        time.sleep(random.expovariate(1.0 / AVG_INTERVAL_S))
    with _lock:
        log(f"[END] {_counter}")


if __name__ == "__main__":
    main()
