#!/usr/bin/env python3
"""
密钥轮换过渡期测量（工程化版本）。
测量：从轮换触发到所有 worker 收敛的完整时间线。
不掩盖过渡期，而是暴露、测量、报告它。
"""
import json, subprocess, time, urllib.request
from datetime import datetime
from pathlib import Path

import testlib_auth

OTA_API = "http://127.0.0.1:8080"
ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "raw"
EVIDENCE.mkdir(parents=True, exist_ok=True)
LOG = EVIDENCE / f"rotation-measure-{datetime.now().strftime('%Y%m%d-%H%M%S')}.log"


def log(msg):
    print(msg, flush=True)
    with open(LOG, "a") as f:
        f.write(msg + "\n")


def http_get_json(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def http_post_json(url, obj, headers=None, timeout=120):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json", **(headers or {})}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode())


def run_simulator(count):
    proc = subprocess.run(
        ["python3", str(ROOT / "services/vehicle-sim/simulator.py"), str(count)],
        capture_output=True, text=True)
    rate = None
    for line in proc.stdout.splitlines():
        if "成功率" in line:
            try:
                rate = float(line.split(":")[1].strip().rstrip("%"))
            except Exception:
                pass
    return rate, proc.stdout







def check_precondition():
    testlib_auth.ensure_devices([f"LSVAM4187C2{i:06d}" for i in range(100)])


def cleanup_test_vins():
    print("Registered identities retained; no keys or trust ledgers deleted.")


def main():
    log("=" * 60)
    log("密钥轮换过渡期测量（工程化版本）")
    log("=" * 60)
    log(f"开始时间：{datetime.now().isoformat()}")
    log(f"日志：{LOG}\n")

    # 阶段 0：初始状态
    log("--- 阶段 0：初始状态 ---")
    h = http_get_json(f"{OTA_API}/health")
    log(json.dumps(h, indent=2))
    initial_active = h["active_key_id"]
    log(f"初始 active key: {initial_active}\n")

    if initial_active != "ota-signing-v1":
        log(f"[FAIL] 初始状态不是 v1，实际是 {initial_active}")
        log("请使用全新隔离测试目录；禁止重置已撤销密钥")
        return

    # 前置检查：manifest 签名必须与当前 active key 一致
    check_precondition()
    testlib_auth.ensure_active_grant()

    # 阶段 1：v1 active，100 车升级
    log("--- 阶段 1：v1 active，100 车升级 ---")
    rate1, out1 = run_simulator(100)
    log(out1)
    log(f"阶段 1 成功率: {rate1}%\n")

    # 阶段 2：触发轮换
    log("--- 阶段 2：触发轮换 ---")
    t_rotate = time.time()
    t_rotate_iso = datetime.now().isoformat()
    log(f"轮换触发时间：{t_rotate_iso}")
    rotate_resp = testlib_auth.publish_policy({"ota-signing-v1": "deprecated", "ota-signing-v2": "active"})
    log(json.dumps(rotate_resp, indent=2) + "\n")

    # 阶段 3：测量过渡期
    log("--- 阶段 3：测量过渡期 ---")
    log("各 worker 验证同一根签名策略，保存最高版本号")
    log("测量各 worker 实际观察到新策略的时间\n")

    worker_first_v2 = {}
    all_seen_pids = set()
    deadline = t_rotate + 300

    while time.time() < deadline:
        elapsed = time.time() - t_rotate
        # 一次采样打 20 次，确保覆盖所有 worker
        for _ in range(20):
            try:
                st = http_get_json(f"{OTA_API}/rotation-state")
            except Exception:
                continue
            pid = st["worker_pid"]
            active = st["active_key_id"]
            all_seen_pids.add(pid)
            if active == "ota-signing-v2" and pid not in worker_first_v2:
                worker_first_v2[pid] = round(elapsed, 2)
                log(f"  [worker {pid}] T+{elapsed:6.1f}s 切换到 v2")
        # 必须看到所有采样过的 worker 都切换（严格判据，不设兜底）
        # 至少采样到 4 个 worker，且这 4 个 worker 都切到 v2
        if len(all_seen_pids) >= 4 and len(worker_first_v2) >= len(all_seen_pids):
            log(f"  [OK] 全部 {len(all_seen_pids)} 个 worker 收敛到 v2，T+{elapsed:.1f}s")
            break
        time.sleep(0.05)
    else:
        # 循环超时（300s）仍未收敛
        log(f"  [FAIL] 300s 内未全部收敛")
        log(f"         已采样 worker: {sorted(all_seen_pids)}")
        log(f"         已切 v2 worker: {sorted(worker_first_v2.keys())}")
        missing = set(all_seen_pids) - set(worker_first_v2.keys())
        if missing:
            log(f"         未切 v2 的 worker: {sorted(missing)}")
        raise SystemExit(1)

    t_converge = time.time() - t_rotate
    log("\n--- 过渡期分析 ---")
    log(f"参与 worker 数：{len(all_seen_pids)}")
    for pid in sorted(all_seen_pids):
        v2 = worker_first_v2.get(pid)
        log(f"  worker {pid}: 首次见 v2 = T+{v2}s" if v2 else f"  worker {pid}: 未切 v2")
    if worker_first_v2:
        first_t = min(worker_first_v2.values())
        last_t = max(worker_first_v2.values())
        log(f"过渡期窗口：T+{first_t}s → T+{last_t}s，共 {last_t-first_t:.1f}s")
    log(f"完整收敛时间：{t_converge:.3f}s（要求 < 300s）\n")

    # 阶段 4：宽限期验证（分两步）
    log("--- 阶段 4：宽限期 + 撤销验证 ---")

    manifest = {"ecu_type": "ECU_ENGINE", "package_id": "grace-test",
                "rollback_index": 12, "version": "2.4.1", "vin": "LSVAM4187C2999999"}
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    Path("/tmp/v1-manifest.json").write_text(canonical)
    subprocess.run([
        "gmssl", "sm2sign",
        "-key", str(ROOT / "pki/signing-v1/signing.key"), "-pass", (ROOT / "pki" / ".secrets" / "signing-v1.pass").read_text().strip(),
        "-id", "ota-signing-v1",
        "-in", "/tmp/v1-manifest.json", "-out", "/tmp/v1-manifest.sig",
    ], check=True)
    v1_sig_hex = Path("/tmp/v1-manifest.sig").read_bytes().hex()

    # 4.1 v1 现在是 deprecated，应通过（宽限期内允许验签）
    _, v1_grace = http_post_json(f"{OTA_API}/verify-manifest", {
        "manifest": manifest, "sig_hex": v1_sig_hex, "key_id": "ota-signing-v1"})
    grace_ok = v1_grace.get("valid") is True
    log(f"  [4.1] v1 deprecated 状态验签：{json.dumps(v1_grace)}")
    log(f"        → {'宽限期内通过 ✓' if grace_ok else '异常 ✗'}\n")

    # 4.2 强制 v1 → revoked，应拒绝
    testlib_auth.publish_policy({"ota-signing-v1": "revoked"})
    time.sleep(3)

    _, v1_revoked = http_post_json(f"{OTA_API}/verify-manifest", {
        "manifest": manifest, "sig_hex": v1_sig_hex, "key_id": "ota-signing-v1"})
    reject_ok = (not v1_revoked.get("valid")) and (v1_revoked.get("reason") == "key_revoked")
    log(f"  [4.2] v1 revoked 状态验签：{json.dumps(v1_revoked)}")
    log(f"        → {'撤销后拒绝 ✓' if reject_ok else '异常 ✗'}\n")

    v1_rejected = reject_ok

    # 阶段 5：v2 重签，100 车升级
    # 轮换后必须用新密钥重新发布授权；这是发布流程的一部分，不是测试脚本篡改状态。
    log("--- 阶段 5 前置：用 v2 重新签发发布授权 ---")
    log(testlib_auth.issue_grant("ota-signing-v2", max_tasks=2000, hours=6))

    log("--- 阶段 5：v2 已 active，100 车升级 ---")
    log("（/request-task 现场签名，无需重签磁盘 manifest）\n")

    rate5, out5 = run_simulator(100)
    log(out5)
    log(f"阶段 5 成功率: {rate5}%\n")

    # 汇总
    log("=" * 60)
    log("测试结果汇总")
    log("=" * 60)
    log(f"初始 active key:           {initial_active}")
    log(f"轮换触发时间：              {t_rotate_iso}")
    log(f"完整收敛时间：              {t_converge:.2f}s（要求 < 300s）")
    if worker_first_v2:
        log(f"过渡期窗口：                {max(worker_first_v2.values()) - min(worker_first_v2.values()):.1f}s")
    log(f"阶段 1（v1）成功率：        {rate1}%")
    log(f"阶段 5（v2）成功率：        {rate5}%")
    log(f"v1 停用后签发包拒绝：        {'是' if v1_rejected else '否'}")
    log("=" * 60)

    cleanup_test_vins()


if __name__ == "__main__":
    main()
