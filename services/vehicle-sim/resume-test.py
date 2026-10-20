#!/usr/bin/env python3
"""
断点续传演示（真实版本，SM4 密文分块）。
用法：
  python3 resume-test.py A    # 阶段A：下载 30 块后强制退出
  python3 resume-test.py B    # 阶段B：读检查点继续下载 70 块
  python3 resume-test.py all  # 一键跑 A+B，展示两次独立进程
"""
import hashlib, json, os, subprocess, sys, time, urllib.request
from datetime import datetime
from pathlib import Path

# 复用共享车端客户端（注册 + 鉴权请求）
from ota_client import request_task, download_chunk

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
STATE_DIR = ROOT / "data" / "vehicle-sim-state"
EVIDENCE = ROOT / "evidence" / "raw"

VIN = "LSVAM4187C2RESUME"
STOP_AT = 30  # 阶段A 下载到 30% 停下


def state_paths():
    base = STATE_DIR / VIN
    return {
        "base": base,
        "chunks": base / "chunks",       # 模拟 ECU 的 Slot B flash 分区
        "checkpoint": base / "checkpoint.json",
        "net_log": base / "network-requests.json",
    }


def sm3_hex(data: bytes) -> str:
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def http_post_json(url, obj):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode())


def http_get_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def log_network_request(paths, phase, idx):
    """记录每个分块下载，用于事后统计网络请求。"""
    log_file = paths["net_log"]
    entries = json.loads(log_file.read_text()) if log_file.exists() else []
    entries.append({
        "phase": phase,
        "chunk_idx": idx,
        "timestamp": datetime.now().isoformat(),
        "pid": os.getpid(),
    })
    log_file.write_text(json.dumps(entries, indent=2))


def do_phase_a():
    print("=" * 60)
    print(f"阶段 A：独立进程 PID={os.getpid()}")
    print("=" * 60)
    print(f"VIN: {VIN}")
    print(f"目标：下载分块 0~{STOP_AT-1}，写入本地存储，然后强制退出")
    print(f"开始: {datetime.now().isoformat()}\n")

    paths = state_paths()
    # 清空旧状态，从头开始
    import shutil
    if paths["base"].exists():
        shutil.rmtree(paths["base"])
    paths["chunks"].mkdir(parents=True, exist_ok=True)

    # 请求任务
    _, task = request_task(VIN)
    task_id = task["task_id"]
    manifest = task["manifest"]
    chunk_count = task["chunk_count"]
    chunk_hashes = task["chunk_hashes"]
    print(f"任务: {task_id}，共 {chunk_count} 块\n")

    # 下载 0~STOP_AT-1，逐块写入磁盘（模拟 ECU 写入 Slot B flash）
    t0 = time.time()
    for i in range(STOP_AT):
        data = download_chunk(VIN, task_id, i)
        log_network_request(paths, "A", i)
        if sm3_hex(data) != chunk_hashes[i]:
            raise Exception(f"chunk {i} 校验失败")
        # 关键：写入磁盘，而不是留在内存
        (paths["chunks"] / f"chunk-{i:06d}").write_bytes(data)
        del data
    t_dl = time.time() - t0

    # 保存检查点
    checkpoint = {
        "vin": VIN, "task_id": task_id,
        "manifest": manifest,
        "chunk_hashes": chunk_hashes,
        "chunk_count": chunk_count,
        "done_count": STOP_AT,
        "phase_a_finished_at": datetime.now().isoformat(),
        "phase_a_pid": os.getpid(),
        "phase_a_duration_s": round(t_dl, 2),
    }
    paths["checkpoint"].write_text(json.dumps(checkpoint, indent=2))

    print(f"已下载 {STOP_AT} 块，每块已写入磁盘")
    print(f"磁盘占用: {sum(f.stat().st_size for f in paths['chunks'].iterdir()) / 1024 / 1024:.2f} MB")
    print(f"检查点已保存: {paths['checkpoint']}")
    print(f"耗时: {t_dl:.2f}s")
    print()

    print("[模拟断电/断网：强制退出进程，内存全部丢失，磁盘保留]")
    sys.stdout.flush()
    os._exit(0)  # 强制退出，不执行任何清理


def do_phase_b():
    print("=" * 60)
    print(f"阶段 B：新进程 PID={os.getpid()}")
    print("=" * 60)
    print(f"VIN: {VIN}")
    print(f"目标：读检查点，从第 {STOP_AT} 块继续")
    print(f"开始: {datetime.now().isoformat()}\n")

    paths = state_paths()
    if not paths["checkpoint"].exists():
        raise Exception(f"检查点不存在: {paths['checkpoint']}")

    ckpt = json.loads(paths["checkpoint"].read_text())
    task_id = ckpt["task_id"]
    manifest = ckpt["manifest"]
    chunk_hashes = ckpt["chunk_hashes"]
    chunk_count = ckpt["chunk_count"]
    done = ckpt["done_count"]

    print(f"检查点：")
    print(f"  task_id:      {task_id}")
    print(f"  已下载:       {done}/{chunk_count}")
    print(f"  阶段 A PID:   {ckpt['phase_a_pid']}")
    print(f"  完成时间:     {ckpt['phase_a_finished_at']}")
    print(f"  当前 PID:     {os.getpid()}  ← 与阶段A不同，证明是独立进程")
    print()

    # 1. 从磁盘读回已存分块，重建 SM3 状态（模拟 ECU 从 flash 读回）
    print(f"从磁盘读回已存的 {done} 块，重建 SM3 状态...")
    h_resume = hashlib.new("sm3")
    t_rebuild_start = time.time()
    for i in range(done):
        local = paths["chunks"] / f"chunk-{i:06d}"
        if not local.exists():
            raise Exception(f"本地分块缺失: {local}")
        data = local.read_bytes()
        if sm3_hex(data) != chunk_hashes[i]:
            raise Exception(f"本地分块 {i} 校验失败")
        h_resume.update(data)
        del data
    t_rebuild = time.time() - t_rebuild_start
    print(f"[OK] 磁盘重建完成，耗时 {t_rebuild:.2f}s（不消耗网络）\n")

    # 2. 从网络继续下载缺失分块
    print(f"从网络继续下载第 {done}~{chunk_count-1} 块...")
    t0 = time.time()
    for i in range(done, chunk_count):
        data = download_chunk(VIN, task_id, i)
        log_network_request(paths, "B", i)
        if sm3_hex(data) != chunk_hashes[i]:
            raise Exception(f"chunk {i} 校验失败")
        (paths["chunks"] / f"chunk-{i:06d}").write_bytes(data)
        h_resume.update(data)
        del data
    t_dl = time.time() - t0
    print(f"[OK] 网络下载完成，耗时 {t_dl:.2f}s\n")

    # 3. 增量 SM3 结果校验（密文分块 → encrypted_sm3）
    if h_resume.hexdigest() != manifest["encrypted_sm3"]:
        raise Exception(f"增量 SM3 校验失败: {h_resume.hexdigest()} != {manifest['encrypted_sm3']}")
    print(f"[OK] 增量密文 SM3 = {h_resume.hexdigest()}")

    # 4. 最终从磁盘读回全部 100 块做整包校验（模拟 ECU 重启后从 Slot B 校验）
    print("最终从磁盘读回全部 100 块做整包 SM3 校验...")
    h_final = hashlib.new("sm3")
    for i in range(chunk_count):
        h_final.update((paths["chunks"] / f"chunk-{i:06d}").read_bytes())
    final_sm3 = h_final.hexdigest()

    if final_sm3 != manifest["encrypted_sm3"]:
        raise Exception(f"最终校验失败: {final_sm3} != {manifest['encrypted_sm3']}")
    print(f"[OK] 最终整包密文 SM3 = {final_sm3}")
    print(f"[OK] manifest 密文 SM3 = {manifest['encrypted_sm3']}")
    print("[OK] 整包密文摘要一致\n")

    # 统计网络请求
    net_log = json.loads(paths["net_log"].read_text())
    phase_a_reqs = [e for e in net_log if e["phase"] == "A"]
    phase_b_reqs = [e for e in net_log if e["phase"] == "B"]
    a_indices = sorted(set(e["chunk_idx"] for e in phase_a_reqs))
    b_indices = sorted(set(e["chunk_idx"] for e in phase_b_reqs))

    # 汇总
    print("=" * 60)
    print("断点续传结果")
    print("=" * 60)
    print(f"总块数:              {chunk_count}")
    print(f"阶段 A 请求分块:      {len(a_indices)} 块（索引 {min(a_indices)}~{max(a_indices)}）")
    print(f"阶段 B 请求分块:      {len(b_indices)} 块（索引 {min(b_indices)}~{max(b_indices)}）")
    print(f"网络请求总数:         {len(a_indices) + len(b_indices)}")
    print(f"重复请求数:           {len(set(a_indices) & set(b_indices))}")
    print(f"无断点续传将请求:     {chunk_count} 块")
    print(f"实际节省:             {chunk_count - len(b_indices)} 块 "
          f"({(chunk_count - len(b_indices)) * 100 // chunk_count}%)")
    print(f"最终整包校验:         通过")
    print(f"磁盘已保存:           {sum(f.stat().st_size for f in paths['chunks'].iterdir()) / 1024 / 1024:.2f} MB")
    print("=" * 60)

    # 保存证据
    evidence = {
        "timestamp": datetime.now().isoformat(),
        "vin": VIN,
        "task_id": task_id,
        "chunk_count": chunk_count,
        "phase_a": {
            "pid": ckpt["phase_a_pid"],
            "finished_at": ckpt["phase_a_finished_at"],
            "duration_s": ckpt["phase_a_duration_s"],
            "requested_chunks": a_indices,
            "requested_count": len(a_indices),
        },
        "phase_b": {
            "pid": os.getpid(),
            "started_at": datetime.now().isoformat(),
            "duration_s": round(t_dl, 2),
            "requested_chunks": b_indices,
            "requested_count": len(b_indices),
        },
        "network": {
            "total_requests": len(a_indices) + len(b_indices),
            "duplicate_requests": len(set(a_indices) & set(b_indices)),
            "saved_vs_full": chunk_count - len(b_indices),
            "saved_percent": round((chunk_count - len(b_indices)) * 100 / chunk_count, 1),
        },
        "final_sm3": final_sm3,
        "manifest_encrypted_sm3": manifest["encrypted_sm3"],
        "disk_bytes": sum(f.stat().st_size for f in paths["chunks"].iterdir()),
    }
    out = EVIDENCE / f"resume-test-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False))
    print(f"\n证据已保存: {out}")


def do_all():
    """一键跑：启两个独立子进程，中间真断"""
    print("#" * 60)
    print("# 断点续传完整演示（两个独立进程）")
    print("#" * 60)
    print()

    # 阶段 A：独立进程，会 os._exit()
    r = subprocess.run([sys.executable, __file__, "A"])
    print(f"\n[阶段 A 退出码: {r.returncode}]")

    # 检查 A 阶段留下的状态
    paths = state_paths()
    if not paths["checkpoint"].exists():
        print("[FAIL] 阶段 A 未生成检查点")
        return
    local_chunks = len(list(paths["chunks"].glob("chunk-[0-9][0-9][0-9][0-9][0-9][0-9]")))
    print(f"[检查] 检查点存在，本地已存 {local_chunks} 块")
    print(f"[检查] 阶段 A 进程已退出，接下来由新进程 B 恢复\n")

    print("-" * 60)
    print()

    # 阶段 B：另一个独立进程
    r = subprocess.run([sys.executable, __file__, "B"])
    print(f"\n[阶段 B 退出码: {r.returncode}]")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "all"
    if cmd == "A":
        do_phase_a()
    elif cmd == "B":
        do_phase_b()
    elif cmd == "all":
        do_all()
    else:
        print(f"未知命令: {cmd}")
        sys.exit(1)
