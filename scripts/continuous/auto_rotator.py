#!/usr/bin/env python3
"""自动轮换器：持续轮换 active 密钥，泊松间隔。"""
import json, random, time
import urllib.request
from datetime import datetime
from pathlib import Path

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
AVG_INTERVAL_S = 90
MAX_ROTATIONS = 200

LOG = ROOT / "data" / "continuous" / "auto-rotator.log"
RESULTS = ROOT / "data" / "continuous" / "rotation-results.jsonl"
LOG.parent.mkdir(parents=True, exist_ok=True)


def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def get_trust():
    with urllib.request.urlopen(f"{OTA_API}/trust-metadata", timeout=10) as r:
        return json.loads(r.read().decode())


def http_post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"},
                                 method="POST")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, json.loads(r.read().decode())


def http_get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def wait_converge(target_key_id, max_wait=10):
    t0 = time.time()
    seen_pids = set()
    converged_pids = set()
    while time.time() - t0 < max_wait:
        for _ in range(10):
            try:
                st = http_get(f"{OTA_API}/rotation-state")
                pid = st["worker_pid"]
                seen_pids.add(pid)
                if st["active_key_id"] == target_key_id:
                    converged_pids.add(pid)
            except Exception:
                pass
        if len(seen_pids) >= 2 and seen_pids == converged_pids:
            return round(time.time() - t0, 3), len(seen_pids)
        time.sleep(0.2)
    return round(time.time() - t0, 3), len(seen_pids)


def rotate_once():
    """
    轮换一次：让 ota-api 的 auto_rotate 分支处理状态转换。
    这样 active → deprecated → revoked 的宽限期逻辑由 ota-api 统一管理。
    """
    trust = get_trust()
    prepared = [k for k, v in trust["keys"].items() if v["status"] == "prepared"]
    if not prepared:
        return {"ok": False, "reason": "no_prepared_key"}

    t0 = time.time()
    # 用 auto_rotate 模式，让 ota-api 选 active 并处理 deprecated
    _, resp = http_post(f"{OTA_API}/admin/rotate-trust", {"auto_rotate": True})
    new_active = None
    for kid, info in resp.get("trust_metadata", {}).get("keys", {}).items():
        if info["status"] == "active":
            new_active = kid
            break

    # 等收敛
    converge_s, n_workers = wait_converge(new_active)

    # 找被 deprecated 的 key（原来的 active）
    old_active = None
    for kid, info in resp.get("trust_metadata", {}).get("keys", {}).items():
        if info["status"] == "deprecated":
            old_active = kid
            break

    return {"timestamp": datetime.utcnow().isoformat() + "Z",
            "old_active": old_active, "new_active": new_active,
            "triggered_at": t0, "converge_s": converge_s,
            "workers_observed": n_workers, "ok": converge_s < 5.0}


def main():
    log("=" * 50)
    log(f"自动轮换器启动 (泊松 λ=1/{AVG_INTERVAL_S}s, 上限 {MAX_ROTATIONS})")
    log("=" * 50)
    count = 0
    with open(RESULTS, "a") as f:
        while count < MAX_ROTATIONS:
            wait = random.expovariate(1.0 / AVG_INTERVAL_S)
            log(f"[WAIT] 下次轮换在 {wait:.1f}s 后")
            time.sleep(wait)
            r = rotate_once()
            count += 1
            f.write(json.dumps(r) + "\n")
            f.flush()
            if r.get("ok"):
                log(f"[ROTATE #{count}] {r['old_active']} → {r['new_active']}, "
                    f"收敛 {r['converge_s']}s ({r['workers_observed']} workers)")
            else:
                log(f"[ROTATE #{count}] 失败: {r.get('reason', r.get('converge_s'))}")


if __name__ == "__main__":
    raise SystemExit("Legacy online key automation retired. Use offline scripts/17-security-admin.py policy; see docs/02-security-migration.md.")
