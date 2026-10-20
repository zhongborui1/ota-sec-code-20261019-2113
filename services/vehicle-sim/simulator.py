#!/usr/bin/env python3
"""
完整升级流程模拟器（P0-P2 落地版）。

  P0-1 车端本地验签    verify_manifest_vehicle_side：
                       VIN 绑定 + 防回滚 + 信任锚状态 + 本地 SM2 验签（不再委托云端 /verify-manifest）
  P0-2 升级授权        enroll PoP 拿 Bearer token，request-task / download / report-status 全部带鉴权
  P1-1 防回滚持久化    本地 rollback_index 落盘，成功后递增（替代 random.randint）
  P1-2 并发            max_workers = min(100, VEHICLE_COUNT)
  P2   断点续传        分块落盘 + checkpoint，重跑跳过已下载分块
  P2   失败恢复        启动确认：安装镜像损坏时回滚（不提交新版本号），保留上一好版本
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from ota_client import (
    OTA_API, ROOT, VEHICLE_STATE, ECU_LOCAL,
    enroll, request_task, report_status, download_chunk,
    verify_manifest_vehicle_side, validate_received_manifest,
    load_rollback, save_rollback, sm3_hex, _safe_vin, http_post_json,
)
from installer import (
    init_vehicle, install_standby, corrupt_slot, scan_file,
    MAX_BOOT_ATTEMPTS,
)

# 向后兼容别名：旧脚本（13-mixed-scenario）仍 `from simulator import ensure_enrolled`
ensure_enrolled = enroll

VEHICLE_COUNT = int(sys.argv[1]) if len(sys.argv) > 1 else 10
START_IDX = int(os.environ.get("OTA_SIM_START_IDX", "0"))
EVIDENCE_DIR = ROOT / "evidence" / "raw"

# ---------- ECU 密钥池 ----------
ECU_POOL = ROOT / "pki" / "ecu-pool"
ECU_DEMO_KEY = ROOT / "pki" / "ecu-demo" / "ecu.key"
ECU_DEMO_PASS = "ecupass"
TIME_PUB = ROOT / "pki" / "time-v1" / "time.pub"

# SM4 密钥缓存（同一 (vin, wrapped_hex) 只解一次）
_SM4_KEY_CACHE = {}


def _ecu_key_path(vin: str):
    """返回 (key_path, key_pass)。优先本地 PoP 密钥，其次服务端池，最后 demo。"""
    safe = _safe_vin(vin)
    local_key = ECU_LOCAL / safe / "ecu.key"
    if local_key.exists():
        return local_key, f"localpass-{safe}"
    key = ECU_POOL / safe / "ecu.key"
    if key.exists():
        return key, f"ecupass-{safe}"
    return ECU_DEMO_KEY, ECU_DEMO_PASS


def sm2_decrypt(wrapped_hex: str, vin: str) -> str:
    """解 SM2 信封，返回明文 hex（SM4 会话密钥）。"""
    key_path, key_pass = _ecu_key_path(vin)
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(bytes.fromhex(wrapped_hex))
        in_path = f.name
    out_path = in_path + ".plain"
    try:
        subprocess.run([
            "gmssl", "sm2decrypt",
            "-key", str(key_path), "-pass", key_pass,
            "-in", in_path, "-out", out_path,
        ], check=True, capture_output=True)
        return Path(out_path).read_bytes().hex()
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


def get_sm4_key(wrapped_hex: str, vin: str) -> str:
    """缓存：同一 (vin, wrapped_hex) 只解一次。"""
    cache_key = (vin, wrapped_hex)
    if cache_key in _SM4_KEY_CACHE:
        return _SM4_KEY_CACHE[cache_key]
    key = sm2_decrypt(wrapped_hex, vin)
    _SM4_KEY_CACHE[cache_key] = key
    return key


def sm4_decrypt_file(enc_path, sm4_key_hex, iv_hex):
    """SM4-CTR 解密（文件级，避免 100MB 进内存）。返回解密文件路径。"""
    out_path = enc_path.with_suffix(enc_path.suffix + ".dec")
    subprocess.run([
        "gmssl", "sm4_ctr",
        "-key", sm4_key_hex, "-iv", iv_hex,
        "-decrypt", "-in", str(enc_path), "-out", str(out_path),
    ], check=True, capture_output=True)
    return out_path


def get_trusted_time():
    """
    通过签名时间证明获取可信时间（不信任本地时钟）。
    用预置 time.pub 本地验签，校验 nonce 一致后返回 server_ts。
    """
    nonce = os.urandom(16).hex()
    _, resp = http_post_json(f"{OTA_API}/time-attestation", {"nonce": nonce})
    if resp.get("nonce") != nonce:
        raise Exception("time attestation nonce mismatch")

    payload = {"nonce": resp["nonce"], "server_ts": resp["server_ts"]}
    canonical = json.dumps(payload, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(canonical)
        in_path = f.name
    sig_path = in_path + ".sig"
    Path(sig_path).write_bytes(bytes.fromhex(resp["sig_hex"]))
    try:
        r = subprocess.run([
            "gmssl", "sm2verify",
            "-pubkey", str(TIME_PUB),
            "-id", "ota-time-v1",
            "-in", in_path,
            "-sig", sig_path,
        ], capture_output=True)
        if r.returncode != 0 or b"success" not in r.stdout.lower():
            raise Exception(
                f"time attestation verify failed: "
                f"{r.stderr.decode(errors='ignore')[:80]}")
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)
    return resp["server_ts"]


def _write_checkpoint(path, data):
    """原子写 checkpoint：断电时要么是旧值，要么是新值，不会半行。"""
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, path)


def _download_with_resume(vin, task_id, manifest, chunk_hashes, chunk_count,
                          state_dir, result):
    """
    分块下载到单个 payload.enc + checkpoint（P2 断点续传）。
    - 每个分块下载后立即校验 SM3，再追加落盘
    - checkpoint 记录已完成分块数；"重跑"时先顺序读回已落盘前缀逐块校验，
      坏的块之后全部截断重下（不信任磁盘上的旧数据）
    - 不再为每块单独存一份文件：100 车时磁盘占用从 200 MB/车降到 100 MB/车
    """
    ckpt_file = state_dir / "checkpoint.json"
    payload_enc = state_dir / "payload.enc"
    enc_sm3 = manifest["encrypted_sm3"]
    chunk_size = int(manifest["chunk_size"])

    start = 0
    h_enc = hashlib.new("sm3")

    if ckpt_file.exists() and payload_enc.exists():
        try:
            ckpt = json.loads(ckpt_file.read_text())
        except (ValueError, OSError):
            ckpt = {}
        if (ckpt.get("encrypted_sm3") == enc_sm3
                and ckpt.get("chunk_count") == chunk_count):
            saved = min(int(ckpt.get("done_chunks", 0)), chunk_count)
            with open(payload_enc, "rb") as f:
                for i in range(saved):
                    data = f.read(chunk_size)
                    if not data or (chunk_hashes[i] and sm3_hex(data) != chunk_hashes[i]):
                        break
                    h_enc.update(data)
                    start += 1

    network_chunks = 0
    mode = "r+b" if payload_enc.exists() else "wb"
    with open(payload_enc, mode) as out:
        out.seek(start * chunk_size)
        out.truncate()
        for i in range(start, chunk_count):
            data = download_chunk(vin, task_id, i)
            if chunk_hashes[i] and sm3_hex(data) != chunk_hashes[i]:
                raise Exception(f"chunk_{i}_hash_mismatch")
            out.write(data)
            out.flush()
            h_enc.update(data)
            network_chunks += 1
            _write_checkpoint(ckpt_file, {
                "task_id": task_id, "encrypted_sm3": enc_sm3,
                "chunk_count": chunk_count, "done_chunks": i + 1,
            })
            del data

    result["resumed"] = start > 0
    result["resumed_from_chunk"] = start
    result["network_chunks"] = network_chunks
    result["saved_chunks"] = chunk_count - network_chunks
    return payload_enc, h_enc.hexdigest()


def _cleanup_checkpoint(state_dir):
    """释放下载/解密临时文件（slot 里的已安装镜像必须保留）。"""
    (state_dir / "checkpoint.json").unlink(missing_ok=True)
    (state_dir / "payload.enc").unlink(missing_ok=True)
    shutil.rmtree(state_dir / "chunks", ignore_errors=True)


def _report(vin, task_id, manifest, trusted_ts, status, sequence, extra=None):
    """上报状态。PENDING_REBOOT=1，最终态（CONFIRMED/ROLLED_BACK/FAILED）=2。"""
    payload = {
        "task_id": task_id, "vin": vin, "status": status,
        "new_version": manifest["version"],
        "new_rollback_index": manifest["rollback_index"],
        "payload_sm3": manifest["sm3"],
        "nonce": os.urandom(16).hex(),
        "client_ts": trusted_ts,
        "sequence": sequence,
    }
    payload.update(extra or {})
    return report_status(vin, payload)


def _run_boot_sequence(vin, max_attempts=MAX_BOOT_ATTEMPTS):
    """
    模拟真实重启：每次尝试都是一个独立的 boot_agent 进程（新 PID），
    读取持久化 boot_state，对备用分区做自检，然后提交或累计失败。
    """
    agent = Path(__file__).resolve().parent / "boot_agent.py"
    attempts = []
    for _ in range(max_attempts):
        proc = subprocess.run(
            [sys.executable, str(agent), "--vin", vin],
            capture_output=True, text=True, timeout=300)
        info = {}
        for line in reversed((proc.stdout or "").strip().splitlines()):
            try:
                info = json.loads(line)
                break
            except ValueError:
                continue
        if not info:
            info = {"result": "error",
                    "error": (proc.stderr or proc.stdout or "")[-300:]}
        info["exit_code"] = proc.returncode
        attempts.append(info)
        if info.get("result") in ("committed", "rolled_back", "bricked", "error"):
            break
    return attempts


def simulate_one_vehicle(idx):
    vin = f"LSVAM4187C2{idx:06d}"
    safe = _safe_vin(vin)
    local_rollback = load_rollback(vin)   # P1-1：持久化防回滚索引（替代随机值）
    state_dir = VEHICLE_STATE / safe
    state_dir.mkdir(parents=True, exist_ok=True)
    result = {"vehicle_id": idx, "vin": vin,
              "local_rollback": local_rollback, "success": False}
    t0 = time.time()

    try:
        # 0. PoP 注册（首次；已有 token 秒过）
        was_new = not (ECU_LOCAL / safe / "token").exists()
        enroll(vin)
        result["ecu_key_created"] = was_new

        # 0.5 可信时间（本地验签）
        trusted_ts = get_trusted_time()

        # 1. 申请升级任务（带 token）
        st, task = request_task(vin)
        if st != 200:
            raise Exception(f"request_task_http_{st}: {task}")
        task_id = task["task_id"]
        manifest = task["manifest"]
        key_id = task["key_id"]
        chunk_count = task["chunk_count"]
        chunk_hashes = task["chunk_hashes"]
        result["task_id"] = task_id
        result["key_id"] = key_id

        # 2. 车端本地验签（P0-1）：VIN 绑定 + 防回滚 + 信任状态 + 本地 SM2 验签
        t_v = time.time()
        ok, reason = verify_manifest_vehicle_side(
            vin, manifest, task["manifest_sig_hex"], key_id, local_rollback)
        if not ok:
            raise Exception(f"manifest_rejected: {reason}")
        if manifest.get("task_id") != task_id:
            raise Exception("task_id_mismatch")
        result["verify_ms"] = round((time.time() - t_v) * 1000, 2)

        # 3. 下载 + 断点续传（P2）
        t_dl = time.time()
        payload_enc, h_enc_hex = _download_with_resume(
            vin, task_id, manifest, chunk_hashes, chunk_count, state_dir, result)
        result["download_ms"] = round((time.time() - t_dl) * 1000, 2)
        if h_enc_hex != manifest["encrypted_sm3"]:
            raise Exception("encrypted_sm3_mismatch")

        # 4. 解 SM2 信封 → SM4 会话密钥（按 VIN 选对应 ECU 私钥）
        wrapped_hex = manifest.get("wrapped_key")
        if not wrapped_hex:
            raise Exception("missing wrapped_key")
        sm4_key_hex = get_sm4_key(wrapped_hex, vin)

        # 5. SM4-CTR 解密 + 明文整包 SM3（一次顺序读，同时得到每块摘要）
        dec_path = sm4_decrypt_file(payload_enc, sm4_key_hex, manifest["sm4_iv"])
        t_d = time.time()
        plain_sm3, plain_chunk_hashes = scan_file(dec_path, int(manifest["chunk_size"]))
        result["digest_ms"] = round((time.time() - t_d) * 1000, 2)
        if plain_sm3 != manifest["sm3"]:
            dec_path.unlink(missing_ok=True)
            raise Exception("plaintext_sm3_mismatch")
        result["plaintext_chunk_count"] = len(plain_chunk_hashes)

        # 5.5 初始化车端分区（首次：出厂 Slot A + boot_state）
        init_vehicle(vin, manifest, dec_path)

        # 6. 写备用分区：只有下载 + 验签 + 完整性全部通过后才落盘
        t_i = time.time()
        target_slot = install_standby(
            vin, manifest, task["manifest_sig_hex"], dec_path,
            plain_sm3, plain_chunk_hashes)
        result["standby_slot"] = target_slot
        result["install_ms"] = round((time.time() - t_i) * 1000, 2)

        # 6.5 释放下载临时文件（保留已安装的 slot）
        _cleanup_checkpoint(state_dir)

        # 6.6 故障注入（仅测试）：真实翻转备用分区镜像中的一个字节
        corrupt_count = int(os.environ.get("OTA_SIM_CORRUPT_COUNT", "0"))
        corrupt_vin = os.environ.get("OTA_SIM_CORRUPT_VIN", "")
        if (os.environ.get("OTA_SIM_CORRUPT_BOOT") == "1"
                or (corrupt_vin and vin == corrupt_vin)
                or idx < corrupt_count):
            corrupt_slot(vin, target_slot)
            result["injected_fault"] = "standby_payload_byte_flipped"

        # 7. 备用分区就绪：上报 PENDING_REBOOT（此时还不是成功）
        st, resp = _report(vin, task_id, manifest, trusted_ts,
                           "PENDING_REBOOT", 1, {"standby_slot": target_slot})
        if st != 200:
            raise Exception(f"report_pending_reboot_http_{st}: {resp}")

        # 8. 模拟重启：独立进程上电自检，最多 3 次；失败自动回退
        t_b = time.time()
        boots = _run_boot_sequence(vin)
        result["boot_attempts"] = boots
        result["boot_ms"] = round((time.time() - t_b) * 1000, 2)
        final = boots[-1] if boots else {"result": "error"}
        result["boot_result"] = final.get("result")
        result["active_slot"] = final.get("active_slot")
        result["vehicle_available"] = final.get("result") in ("committed", "rolled_back")

        # 9. 自检通过并提交后才上报 CONFIRMED；回退则上报 ROLLED_BACK
        if final.get("result") == "committed":
            save_rollback(vin, manifest["rollback_index"])
            result["new_rollback_index"] = manifest["rollback_index"]
            st, resp = _report(vin, task_id, manifest, trusted_ts,
                               "CONFIRMED", 2,
                               {"active_slot": final.get("active_slot"),
                                "boot_attempts": len(boots), "commit": True})
            if st != 200:
                raise Exception(f"report_confirmed_http_{st}: {resp}")
            result["success"] = True
        elif final.get("result") == "rolled_back":
            reason = (final.get("check") or {}).get("reason", "boot_selfcheck_failed")
            _report(vin, task_id, manifest, trusted_ts, "ROLLED_BACK", 2,
                    {"active_slot": final.get("active_slot"),
                     "failed_slot": target_slot, "reason": reason,
                     "boot_attempts": len(boots), "commit": False})
            result["error"] = f"boot_selfcheck_failed_rolled_back: {reason}"
        else:
            _report(vin, task_id, manifest, trusted_ts, "FAILED", 2,
                    {"reason": final.get("result"), "detail": final.get("check")})
            result["error"] = f"boot_failed_{final.get('result')}"
    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    result["total_ms"] = round((time.time() - t0) * 1000, 2)
    return result


def main():
    print("=" * 60)
    print("  车辆完整升级流程模拟器（验签→写备用分区→重启自检→提交/回退）")
    print("=" * 60)
    print(f"OTA API:       {OTA_API}")
    print(f"Vehicle count: {VEHICLE_COUNT}  (start_idx={START_IDX})")
    print(f"Start:         {datetime.now().isoformat()}\n")

    t_start = time.time()
    results = []
    # P1-2：并发上限 100
    with ThreadPoolExecutor(max_workers=min(100, VEHICLE_COUNT)) as ex:
        futures = [ex.submit(simulate_one_vehicle, START_IDX + i)
                   for i in range(VEHICLE_COUNT)]
        for f in as_completed(futures):
            results.append(f.result())
    t_total = time.time() - t_start

    success = sum(1 for r in results if r["success"])
    fail = len(results) - success
    rate = success / len(results) * 100

    print("-" * 60)
    print(f"总耗时:       {t_total:.2f} s")
    print(f"成功:         {success}/{len(results)}")
    print(f"失败:         {fail}")
    print(f"成功率:       {rate:.2f}%")
    print("-" * 60)

    for key, label in [("download_ms", "下载+密文SM3"),
                       ("digest_ms", "明文100MB摘要"),
                       ("verify_ms", "车端本地验签"),
                       ("install_ms", "写备用分区"),
                       ("boot_ms", "重启+自检+提交"),
                       ("total_ms", "单车总耗时")]:
        vals = [r[key] for r in results if key in r]
        if vals:
            print(f"{label:20s} 平均 {sum(vals)/len(vals):7.2f}ms  最大 {max(vals):7.2f}ms")

    created = sum(1 for r in results if r.get("ecu_key_created"))
    resumed = sum(1 for r in results if r.get("resumed"))
    committed = sum(1 for r in results if r.get("boot_result") == "committed")
    rolled_back = sum(1 for r in results if r.get("boot_result") == "rolled_back")
    unavailable = sum(1 for r in results if r.get("vehicle_available") is False)
    print(f"\nECU 密钥：{created} 把新建（其余复用已存在）")
    print(f"断点续传：{resumed} 辆车命中 checkpoint（重跑时跳过已下载分块）")
    print(f"启动自检：COMMITTED {committed} 辆 / ROLLED_BACK {rolled_back} 辆 / "
          f"不可用 {unavailable} 辆")
    if ECU_POOL.exists():
        pool_size = len([d for d in ECU_POOL.iterdir() if d.is_dir()])
        print(f"ECU 密钥池总量：{pool_size} 把")
    print()

    if fail > 0:
        print("=" * 60); print("  失败详情"); print("=" * 60)
        for r in results:
            if not r["success"]:
                print(f"  vehicle {r['vehicle_id']:3d}: {r.get('error','unknown')}")
        print()

    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    out = EVIDENCE_DIR / f"full-upgrade-{VEHICLE_COUNT}-{ts}.json"
    json.dump({
        "timestamp": datetime.now().isoformat(),
        "vehicle_count": VEHICLE_COUNT,
        "total_time_s": round(t_total, 2),
        "success": success, "fail": fail, "success_rate": round(rate, 2),
        "committed": committed, "rolled_back": rolled_back,
        "vehicle_unavailable": unavailable,
        "ecu_keys_created": created,
        "resumed": resumed,
        "notes": ["车端本地验签", "Bearer token 鉴权", "防回滚持久化",
                  "断点续传", "写备用分区", "独立进程模拟重启自检",
                  "自检通过才提交并上报 CONFIRMED"],
        "results": results,
    }, open(out, "w"), indent=2)
    print(f"原始记录已保存: {out}")


if __name__ == "__main__":
    main()
