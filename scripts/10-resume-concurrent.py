#!/usr/bin/env python3
"""
断点续传 100 车并发测试。
阶段 A：100 车并发，各自随机下载 20~80 块后保存检查点（独立进程模拟）
阶段 B：100 车并发，各自从检查点恢复，下载剩余块
校验：所有车最终整包 SM3 = manifest sm3
"""
import hashlib, json, random, shutil, sys, time
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path("/home/rjh/ota-sec/services/vehicle-sim")))
from ota_client import request_task, download_chunk  # noqa: E402

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
STATE_BASE = ROOT / "data" / "vehicle-sim-resume-concurrent"
EVIDENCE = ROOT / "evidence" / "raw"

VEHICLE_COUNT = 100
STOP_RANGE = (20, 80)


def sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def http_post_json(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode())


def http_get_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def phase_a(vehicle_idx):
    vin = f"LSVAM4187C2RC{vehicle_idx:04d}"
    stop_at = random.randint(*STOP_RANGE)
    vstate = STATE_BASE / vin
    if vstate.exists():
        shutil.rmtree(vstate)
    chunks_dir = vstate / "chunks"
    chunks_dir.mkdir(parents=True)

    _, task = request_task(vin)
    task_id = task["task_id"]
    chunk_hashes = task["chunk_hashes"]

    t0 = time.time()
    for i in range(stop_at):
        data = download_chunk(vin, task_id, i)
        if sm3_hex(data) != chunk_hashes[i]:
            raise Exception(f"chunk {i} mismatch")
        (chunks_dir / f"chunk-{i:06d}").write_bytes(data)
        del data

    ckpt = {
        "vin": vin, "task_id": task_id,
        "manifest": task["manifest"], "chunk_hashes": chunk_hashes,
        "chunk_count": task["chunk_count"], "done_count": stop_at,
        "phase_a_at": datetime.now().isoformat(),
    }
    (vstate / "checkpoint.json").write_text(json.dumps(ckpt))

    return {"vin": vin, "stop_at": stop_at,
            "duration": round(time.time() - t0, 2)}


def phase_b(vehicle_idx):
    vin = f"LSVAM4187C2RC{vehicle_idx:04d}"
    vstate = STATE_BASE / vin
    ckpt = json.loads((vstate / "checkpoint.json").read_text())
    task_id = ckpt["task_id"]
    manifest = ckpt["manifest"]
    chunk_hashes = ckpt["chunk_hashes"]
    chunk_count = ckpt["chunk_count"]
    done = ckpt["done_count"]

    # 从磁盘重建 SM3 状态
    h = hashlib.new("sm3")
    for i in range(done):
        data = (vstate / "chunks" / f"chunk-{i:06d}").read_bytes()
        if sm3_hex(data) != chunk_hashes[i]:
            raise Exception(f"resume chunk {i} mismatch")
        h.update(data)
        del data

    # 从网络下载剩余
    t0 = time.time()
    for i in range(done, chunk_count):
        data = download_chunk(vin, task_id, i)
        if sm3_hex(data) != chunk_hashes[i]:
            raise Exception(f"chunk {i} mismatch")
        (vstate / "chunks" / f"chunk-{i:06d}").write_bytes(data)
        h.update(data)
        del data

    if h.hexdigest() != manifest["sm3"]:
        raise Exception(f"payload sm3 mismatch")

    return {"vin": vin, "resumed_from": done,
            "new_downloaded": chunk_count - done,
            "duration": round(time.time() - t0, 2)}


def main():
    print("=" * 70)
    print("断点续传 100 车并发测试")
    print("=" * 70)
    print(f"VIN 数:      {VEHICLE_COUNT}")
    print(f"停车位置:    {STOP_RANGE[0]}~{STOP_RANGE[1]} 块（随机）")
    print(f"开始:        {datetime.now().isoformat()}\n")

    if STATE_BASE.exists():
        shutil.rmtree(STATE_BASE)
    STATE_BASE.mkdir(parents=True)

    # 阶段 A
    print("--- 阶段 A：100 车并发下载（随机停车）---")
    t_a = time.time()
    results_a = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(phase_a, i): i for i in range(VEHICLE_COUNT)}
        for f in as_completed(futures):
            try:
                results_a.append(f.result())
            except Exception as e:
                print(f"  [FAIL] vehicle {futures[f]}: {type(e).__name__}: {e}")
    t_a = time.time() - t_a
    total_a = sum(r["stop_at"] for r in results_a)
    print(f"阶段 A：{len(results_a)}/{VEHICLE_COUNT} 车成功，"
          f"总下载 {total_a} 块，耗时 {t_a:.2f}s\n")

    time.sleep(0.5)

    # 阶段 B
    print("--- 阶段 B：100 车并发恢复 ---")
    t_b = time.time()
    results_b = []
    with ThreadPoolExecutor(max_workers=100) as ex:
        futures = {ex.submit(phase_b, i): i for i in range(VEHICLE_COUNT)}
        for f in as_completed(futures):
            try:
                results_b.append(f.result())
            except Exception as e:
                print(f"  [FAIL] vehicle {futures[f]}: {type(e).__name__}: {e}")
    t_b = time.time() - t_b
    total_b = sum(r["new_downloaded"] for r in results_b)
    print(f"阶段 B：{len(results_b)}/{VEHICLE_COUNT} 车成功，"
          f"新下载 {total_b} 块，耗时 {t_b:.2f}s\n")

    # 汇总
    total = total_a + total_b
    # 无断点续传对照：阶段 A 下载的块被丢弃，恢复后每车从 0 重下 100 块
    baseline_no_resume = total_a + VEHICLE_COUNT * 100
    saved = baseline_no_resume - total
    avg_stop = sum(r["stop_at"] for r in results_a) / len(results_a) if results_a else 0
    # 恢复阶段的节省（对比恢复后从 0 重下）
    phase_b_baseline = VEHICLE_COUNT * 100
    phase_b_saved = phase_b_baseline - total_b
    phase_b_saved_pct = phase_b_saved / phase_b_baseline * 100

    print("=" * 70)
    print("结果汇总")
    print("=" * 70)
    print(f"车辆总数:                       {VEHICLE_COUNT}")
    print(f"阶段 A 成功:                    {len(results_a)}/{VEHICLE_COUNT}")
    print(f"阶段 B 成功:                    {len(results_b)}/{VEHICLE_COUNT}")
    print()
    print(f"阶段 A 下载 (保留):             {total_a} 块")
    print(f"阶段 B 下载 (续传):             {total_b} 块")
    print(f"实际总下载量:                   {total} 块")
    print()
    print(f"无断点续传对照 (理论):           {baseline_no_resume} 块")
    print(f"  阶段 A 下载 {total_a} (丢弃)")
    print(f"  恢复后从 0 重下 100×100 = {VEHICLE_COUNT * 100}")
    print(f"  合计 = {total_a} + {VEHICLE_COUNT * 100} = {baseline_no_resume}")
    print()
    print(f"实际节省 (全局):                {saved} 块 ({saved/baseline_no_resume*100:.1f}%)")
    print(f"恢复阶段节省:                   {phase_b_saved} 块 ({phase_b_saved_pct:.1f}%)")
    print(f"平均停车位置:                   {avg_stop:.1f} 块")
    print(f"总耗时:                         {t_a+t_b:.2f}s")
    print("=" * 70)

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"resume-concurrent-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "vehicle_count": VEHICLE_COUNT,
        "stop_range": list(STOP_RANGE),
        "phase_a": {"success": len(results_a), "downloaded": total_a,
                    "duration_s": round(t_a, 2)},
        "phase_b": {"success": len(results_b), "downloaded": total_b,
                    "duration_s": round(t_b, 2)},
        "totals": {
            "actual": total,
            "baseline_no_resume": baseline_no_resume,
            "saved_global": saved,
            "saved_global_percent": round(saved/baseline_no_resume*100, 2),
            "phase_b_saved": phase_b_saved,
            "phase_b_saved_percent": round(phase_b_saved_pct, 2),
        },
    }, indent=2, ensure_ascii=False))
    print(f"\n证据已保存: {out}")

    shutil.rmtree(STATE_BASE, ignore_errors=True)


if __name__ == "__main__":
    main()
