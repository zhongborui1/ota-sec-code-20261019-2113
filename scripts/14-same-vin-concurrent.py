#!/usr/bin/env python3
"""
同一 VIN 并发请求任务：验证 task_id 唯一性与状态一致性。
"""
import json, sys, time
import urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path("/home/rjh/ota-sec/services/vehicle-sim")))
from ota_client import enroll, request_task  # noqa: E402

OTA_API = "http://127.0.0.1:8080"
EVIDENCE = Path("/home/rjh/ota-sec/evidence/raw")

VIN = "LSVAM4187C2SAMEVIN"
CONCURRENT = 20  # 同一 VIN 并发 20 次请求


def http_post_json(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, json.loads(r.read().decode())


def one_request(i):
    try:
        _, task = request_task(VIN)
        return {"i": i, "ok": True,
                "task_id": task["task_id"],
                "manifest_vin": task["manifest"]["vin"],
                "manifest_task_id": task["manifest"]["task_id"],
                "sig_prefix": task["manifest_sig_hex"][:16]}
    except Exception as e:
        return {"i": i, "ok": False, "error": f"{type(e).__name__}: {e}"}


def main():
    print("=" * 70)
    print("同一 VIN 并发请求任务测试")
    print("=" * 70)
    print(f"VIN: {VIN}")
    print(f"并发数: {CONCURRENT}")
    print(f"开始: {datetime.now().isoformat()}\n")

    enroll(VIN)  # 预注册，避免 20 并发同 VIN 首次注册竞争

    t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENT) as ex:
        futures = [ex.submit(one_request, i) for i in range(CONCURRENT)]
        for f in as_completed(futures):
            results.append(f.result())
    elapsed = time.time() - t0

    ok = [r for r in results if r["ok"]]
    fail = [r for r in results if not r["ok"]]
    task_ids = [r["task_id"] for r in ok]

    print("-" * 70)
    print(f"成功: {len(ok)}/{CONCURRENT}")
    print(f"失败: {len(fail)}")
    print(f"总耗时: {elapsed:.2f}s")
    print(f"唯一 task_id 数: {len(set(task_ids))}")
    print(f"重复 task_id 数: {len(task_ids) - len(set(task_ids))}")

    # 校验 manifest.vin 一致性
    vin_consistent = all(r["manifest_vin"] == VIN for r in ok)
    print(f"manifest.vin 全部等于 {VIN}: {vin_consistent}")

    # 校验 task_id 在 manifest 里和顶层一致
    task_id_consistent = all(r["task_id"] == r["manifest_task_id"] for r in ok)
    print(f"顶层 task_id 与 manifest.task_id 一致: {task_id_consistent}")

    print()
    print("结论:")
    if len(set(task_ids)) == len(task_ids) and vin_consistent and task_id_consistent:
        print("  ✓ 每次请求生成唯一 task_id，无冲突，状态一致")
    else:
        print("  ✗ 存在问题")

    if fail:
        print("\n失败详情:")
        for r in fail[:5]:
            print(f"  #{r['i']}: {r['error']}")

    # 保存
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"same-vin-concurrent-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "vin": VIN,
        "concurrent": CONCURRENT,
        "elapsed_s": round(elapsed, 2),
        "success": len(ok), "fail": len(fail),
        "unique_task_ids": len(set(task_ids)),
        "duplicate_task_ids": len(task_ids) - len(set(task_ids)),
        "vin_consistent": vin_consistent,
        "task_id_consistent": task_id_consistent,
        "results": results,
    }, indent=2, ensure_ascii=False))
    print(f"\n证据已保存: {out}")


if __name__ == "__main__":
    main()
