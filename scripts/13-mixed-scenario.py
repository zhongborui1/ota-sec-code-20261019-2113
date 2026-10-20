#!/usr/bin/env python3
"""
混合场景测试：100 车随机有真有假。
支持多轮运行：
  python3 13-mixed-scenario.py          # 默认 1 轮
  python3 13-mixed-scenario.py 5        # 5 轮
每次运行的分布随机生成，每轮输出完整表格，最后输出多轮汇总。
"""
import hashlib, json, random, shutil, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path("/home/rjh/ota-sec/services/vehicle-sim")))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import testlib_auth  # noqa: E402
from simulator import (validate_received_manifest, ensure_enrolled,
                       sm2_decrypt, get_trusted_time,
                       request_task, download_chunk)  # noqa

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
EVIDENCE = ROOT / "evidence" / "raw"
VEHICLE_COUNT = 100

# 13 使用 10 个固定 VIN（模拟"同一批车辆多次请求"）
# 跑完自动清理这些 VIN 的 ECU 密钥，避免污染主密钥池
MIX_VINS = [f"LSVAM4187C2MIX{i:04d}" for i in range(10)]

NORMAL_TYPES = ["normal"]
ATTACK_TYPES = ["tampered_chunk", "forged_signature", "downgrade",
                "vin_mismatch", "revoked_key"]


def sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def http_post_json(url, obj, headers=None):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode())


def http_get_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def sign_manifest_locally(manifest, key_id):
    SECRETS = ROOT / "pki" / ".secrets"
    key_map = {"ota-signing-v1": ("signing-v1", SECRETS / "signing-v1.pass"),
               "ota-signing-v2": ("signing-v2", SECRETS / "signing-v2.pass")}
    key_dir, pass_file = key_map[key_id]
    key_pass = pass_file.read_text().strip() if pass_file.exists() else f"{key_dir}pass"
    canonical = json.dumps(manifest, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        f.write(canonical)
        in_path = f.name
    out_path = in_path + ".sig"
    try:
        subprocess.run([
            "gmssl", "sm2sign",
            "-key", str(ROOT / "pki" / key_dir / "signing.key"),
            "-pass", key_pass, "-id", key_id,
            "-in", in_path, "-out", out_path,
        ], check=True, capture_output=True)
        return Path(out_path).read_bytes().hex()
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(out_path).unlink(missing_ok=True)


def ensure_v1_revoked_v2_active():
    """
    确保 v1=revoked, v2=active。
    优先用 auto_rotate（如果有 prepared 密钥），
    否则手动设置状态（避免 no_prepared_key 报错）。
    """
    with urllib.request.urlopen(f"{OTA_API}/trust-metadata", timeout=10) as r:
        trust = json.loads(r.read().decode())
    keys = trust.get("keys", {})
    v1 = keys.get("ota-signing-v1", {}).get("status")
    v2 = keys.get("ota-signing-v2", {}).get("status")
    if v1 == "revoked" and v2 == "active":
        return

    prepared = [k for k, v in keys.items() if v.get("status") == "prepared"]
    if prepared:
        try:
            http_post_json(f"{OTA_API}/admin/rotate-trust", {"auto_rotate": True},
                           headers=testlib_auth.admin_headers())
            return
        except Exception:
            pass

    update = {}
    if v1 != "revoked":
        update["ota-signing-v1"] = {"status": "revoked"}
    if v2 != "active":
        for k, v in keys.items():
            if v.get("status") == "active" and k != "ota-signing-v2":
                update[k] = {"status": "revoked"}
        update["ota-signing-v2"] = {"status": "active"}

    if update:
        http_post_json(f"{OTA_API}/admin/rotate-trust", {"keys": update},
                       headers=testlib_auth.admin_headers())


def generate_task_assignments(n):
    """随机分配：normal 占 40%~85%，攻击在 5 类中均匀随机。"""
    ratio = random.uniform(0.40, 0.85)
    n_normal = int(n * ratio)
    tasks = ["normal"] * n_normal
    for _ in range(n - n_normal):
        tasks.append(random.choice(ATTACK_TYPES))
    random.shuffle(tasks)
    return tasks


# ============ 具体攻击/正常场景 ============

def full_normal_flow(vin):
    """
    正常车辆：密文 SM3 → 解信封（按 VIN 从池子选 ECU 私钥）→ 解密 → 明文 SM3 → 验签。
    流式处理，不缓存全 payload。
    """
    import subprocess, tempfile
    from pathlib import Path as _P

    # 0. PoP 注册
    ensure_enrolled(vin)

    # 0.5 获取时间证明（不信任本地时钟）
    trusted_ts = get_trusted_time()

    _, task = request_task(vin)
    task_id = task["task_id"]
    manifest = task["manifest"]
    key_id = task["key_id"]
    sig_hex = task["manifest_sig_hex"]
    chunk_count = task["chunk_count"]
    chunk_hashes = task["chunk_hashes"]

    if manifest.get("vin") != vin:
        return False, "vin_mismatch"
    if manifest.get("task_id") != task_id:
        return False, "task_id_mismatch"

    local_rollback = random.randint(8, 11)
    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_hex,
        key_id=key_id, local_rollback=local_rollback)
    if not accepted:
        return False, f"manifest_reject: {reason}"

    # 流式下载密文到临时文件
    with tempfile.NamedTemporaryFile(delete=False) as f:
        enc_path = f.name
    plain_path = enc_path + ".plain"
    wrapped_path = enc_path + ".wrapped"
    sm4_key_path = wrapped_path + ".plain"

    try:
        h_enc = hashlib.new("sm3")
        with open(enc_path, "wb") as fout:
            for i in range(chunk_count):
                data = download_chunk(vin, task_id, i)
                if sm3_hex(data) != chunk_hashes[i]:
                    return False, f"chunk_{i}_mismatch"
                h_enc.update(data)
                fout.write(data)
                del data

        if h_enc.hexdigest() != manifest.get("encrypted_sm3"):
            return False, "encrypted_sm3_mismatch"

        # SM2 解信封：按 VIN 从池子选 ECU 私钥
        wrapped_hex = manifest.get("wrapped_key")
        if not wrapped_hex:
            return False, "missing_wrapped_key"
        _P(wrapped_path).write_bytes(bytes.fromhex(wrapped_hex))

        # SM2 解信封：复用 simulator.sm2_decrypt（内部按 VIN 优先 ecu-local 的 PoP 私钥）
        sm4_key_hex = sm2_decrypt(wrapped_hex, vin)

        # SM4 解密
        subprocess.run([
            "gmssl", "sm4_ctr",
            "-key", sm4_key_hex, "-iv", manifest["sm4_iv"],
            "-decrypt", "-in", enc_path, "-out", plain_path,
        ], check=True, capture_output=True)

        # 明文 SM3（流式读）
        h_plain = hashlib.new("sm3")
        with open(plain_path, "rb") as fin:
            while True:
                buf = fin.read(4 * 1024 * 1024)
                if not buf:
                    break
                h_plain.update(buf)
        if h_plain.hexdigest() != manifest["sm3"]:
            return False, "plaintext_sm3_mismatch"

        return True, "ok"
    finally:
        for p in [enc_path, plain_path, wrapped_path, sm4_key_path]:
            _P(p).unlink(missing_ok=True)


def attack_tampered_chunk(vin):
    """篡改分块：客户端下载后 SM3 不匹配（分块现在是密文）。"""
    _, task = request_task(vin)
    task_id = task["task_id"]
    chunk_hashes = task["chunk_hashes"]

    data = bytearray(download_chunk(vin, task_id, 0))
    pos = random.randint(0, len(data) - 1)
    data[pos] ^= 0xFF
    if sm3_hex(bytes(data)) != chunk_hashes[0]:
        return False, f"chunk_0_tamper_detected"
    return True, "tamper_not_detected"


def attack_forged_signature(vin):
    _, task = request_task(vin)
    manifest = task["manifest"]
    sig_v1 = sign_manifest_locally(manifest, "ota-signing-v1")
    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_v1,
        key_id="ota-signing-v2", local_rollback=10)
    if accepted:
        return True, "forgery_accepted"
    return False, f"forgery_rejected"


def attack_downgrade(vin):
    """
    降级攻击（完整验证）：
    - 服务端 /verify-manifest：应通过（签名有效、key 状态合法）
    - 客户端 validate_received_manifest：应拒绝（rollback check）
    """
    _, task = request_task(vin)
    manifest = dict(task["manifest"])
    key_id = task["key_id"]
    current_ri = manifest["rollback_index"]
    manifest["rollback_index"] = current_ri - random.randint(1, 5)
    sig_hex = sign_manifest_locally(manifest, key_id)

    _, server_vr = http_post_json(f"{OTA_API}/verify-manifest", {
        "manifest": manifest, "sig_hex": sig_hex, "key_id": key_id,
    })
    server_accepted = bool(server_vr.get("valid"))

    client_accepted, client_reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_hex,
        key_id=key_id, local_rollback=current_ri)

    if server_accepted and not client_accepted:
        return False, f"rejected_by_client (server_accepted=True, client={client_reason})"
    if not server_accepted and not client_accepted:
        return False, f"rejected_by_both (server={server_vr.get('reason','?')}, client={client_reason})"
    if server_accepted and client_accepted:
        return True, "downgrade_fully_accepted"
    return False, "server_rejected_client_accepted (异常)"


def attack_vin_mismatch(vin_a, vin_b):
    """
    VIN 不匹配攻击（完整验证）：
    - 服务端 /verify-manifest：应通过（这是 A 车合法包）
    - 客户端（B 车）validate_received_manifest：应拒绝（vin check）
    """
    _, task = request_task(vin_a)
    manifest = task["manifest"]
    key_id = task["key_id"]
    sig_hex = sign_manifest_locally(manifest, key_id)

    _, server_vr = http_post_json(f"{OTA_API}/verify-manifest", {
        "manifest": manifest, "sig_hex": sig_hex, "key_id": key_id,
    })
    server_accepted = bool(server_vr.get("valid"))

    client_accepted, client_reason = validate_received_manifest(
        vin=vin_b, manifest=manifest, sig_hex=sig_hex,
        key_id=key_id, local_rollback=10)

    if server_accepted and not client_accepted:
        return False, f"rejected_by_client (server_accepted=True, client={client_reason})"
    if server_accepted and client_accepted:
        return True, "vin_mismatch_fully_accepted"
    return False, f"unexpected (server={server_accepted}, client={client_accepted})"


def attack_revoked_key(vin):
    _, task = request_task(vin)
    manifest = task["manifest"]
    sig_v1 = sign_manifest_locally(manifest, "ota-signing-v1")
    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_v1,
        key_id="ota-signing-v1", local_rollback=10)
    if accepted:
        return True, "revoked_key_accepted"
    return False, f"revoked_key_rejected"


def simulate_vehicle(idx, task_type):
    # 从 10 个固定 VIN 池取（不同 idx 可能复用同一 VIN，模拟重复请求）
    vin = f"LSVAM4187C2MIX{idx:04d}"
    vin_other = f"LSVAM4187C2MIX{(idx + 50) % VEHICLE_COUNT:04d}"
    result = {"idx": idx, "task_type": task_type,
              "accepted": None, "reason": None, "elapsed_ms": 0}
    t0 = time.time()
    try:
        if task_type == "normal":
            accepted, reason = full_normal_flow(vin)
        elif task_type == "tampered_chunk":
            accepted, reason = attack_tampered_chunk(vin)
        elif task_type == "forged_signature":
            accepted, reason = attack_forged_signature(vin)
        elif task_type == "downgrade":
            accepted, reason = attack_downgrade(vin)
        elif task_type == "vin_mismatch":
            accepted, reason = attack_vin_mismatch(vin, vin_other)
        elif task_type == "revoked_key":
            accepted, reason = attack_revoked_key(vin)
        else:
            accepted, reason = False, f"unknown_{task_type}"
        result["accepted"] = accepted
        result["reason"] = reason
    except Exception as e:
        result["accepted"] = None
        result["reason"] = f"EXC: {type(e).__name__}: {e}"
    result["elapsed_ms"] = round((time.time() - t0) * 1000, 2)
    return result


def print_run_table(run_i, assignments, results, elapsed):
    """输出单轮完整表格。"""
    print()
    print(f"┌─── 第 {run_i} 轮 ────────────────────────────────────────────")
    print(f"│ 本次随机分配（无预设概率）:")
    dist = Counter(assignments)
    for name in ["normal"] + ATTACK_TYPES:
        cnt = dist.get(name, 0)
        pct = cnt / len(assignments) * 100
        print(f"│   {name:20s} {cnt:3d} 车 ({pct:5.1f}%)")
    print(f"│ 总耗时: {elapsed:.2f}s")
    print(f"│")
    print(f"│ 结果表:")
    print(f"│   {'任务类型':<22s} {'数量':>4} {'预期':>7} {'accepted':>9} "
          f"{'rejected':>9} {'异常':>5} {'状态':>6}")
    print(f"│   {'-'*76}")

    by_type = {}
    for r in results:
        by_type.setdefault(r["task_type"], []).append(r)

    total_correct = 0
    total_count = 0
    for task_type in sorted(by_type.keys()):
        items = by_type[task_type]
        accepted = sum(1 for r in items if r["accepted"] is True)
        rejected = sum(1 for r in items if r["accepted"] is False)
        errors = sum(1 for r in items if r["accepted"] is None)
        expected = "accept" if task_type == "normal" else "reject"
        expected_count = accepted if task_type == "normal" else rejected
        ok = (expected_count == len(items)) and errors == 0
        total_correct += expected_count
        total_count += len(items)
        status = "✓ OK" if ok else "✗ 异常"
        print(f"│   {task_type:<22s} {len(items):>4} {expected:>7} "
              f"{accepted:>9} {rejected:>9} {errors:>5} {status:>6}")

    print(f"│   {'-'*76}")
    pct = total_correct / total_count * 100 if total_count else 0
    print(f"│   总计: {total_correct}/{total_count} = {pct:.2f}%")
    print(f"└{'─'*76}")
    return total_correct, total_count




def cleanup_mix_keys():
    """
    清理 MIX 前缀的 ECU 密钥（13 脚本产生的临时数据）。
    避免污染主 ECU 密钥池（当前应只保留演示用的 10 台固定 VIN）。
    """
    pool = ROOT / "pki" / "ecu-pool"
    local = ROOT / "pki" / "ecu-local"
    cleaned = 0
    if pool.exists():
        for d in pool.iterdir():
            if d.is_dir() and d.name.startswith("LSVAM4187C2MIX"):
                shutil.rmtree(d, ignore_errors=True)
                cleaned += 1
    if local.exists():
        for d in local.iterdir():
            if d.is_dir() and d.name.startswith("LSVAM4187C2MIX"):
                shutil.rmtree(d, ignore_errors=True)
    if cleaned:
        print(f"[清理] 移除 {cleaned} 个 MIX VIN 的 ECU 密钥")


def main():
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 1

    print("=" * 80)
    print(f"混合场景测试（{runs} 轮，每轮 100 车随机有真有假）")
    print("=" * 80)
    print(f"OTA API: {OTA_API}")
    print(f"轮数:    {runs}")
    print(f"开始:    {datetime.now().isoformat()}")

    ensure_v1_revoked_v2_active()
    testlib_auth.ensure_active_grant()
    print(f"[前置] v1=revoked, v2=active")

    # 预注册 MIX VIN 的 PoP（避免 100 车并发时同一 VIN 重复注册冲突）


    all_runs = []
    t_global = time.time()

    for run_i in range(1, runs + 1):
        assignments = generate_task_assignments(VEHICLE_COUNT)
        t0 = time.time()
        results = []
        with ThreadPoolExecutor(max_workers=min(20, VEHICLE_COUNT)) as ex:
            futures = [ex.submit(simulate_vehicle, i, assignments[i])
                       for i in range(VEHICLE_COUNT)]
            for f in as_completed(futures):
                results.append(f.result())
        elapsed = time.time() - t0

        correct, total = print_run_table(run_i, assignments, results, elapsed)
        all_runs.append({
            "run": run_i,
            "distribution": dict(Counter(assignments)),
            "correct": correct,
            "total": total,
            "elapsed_s": round(elapsed, 2),
            "results": results,
        })

    t_global = time.time() - t_global

    print()
    print("=" * 80)
    print(f"{runs} 轮汇总")
    print("=" * 80)
    print(f"{'轮次':>4} | {'normal':>6} | {'tampered':>8} | {'forged':>6} | "
          f"{'downgrade':>9} | {'vin_mm':>6} | {'revoked':>7} | "
          f"{'结果':>9} | {'耗时(s)':>8}")
    print("-" * 100)
    for r in all_runs:
        d = r["distribution"]
        result = f"{r['correct']}/{r['total']}"
        print(f"{r['run']:>4} | {d.get('normal',0):>6} | "
              f"{d.get('tampered_chunk',0):>8} | "
              f"{d.get('forged_signature',0):>6} | "
              f"{d.get('downgrade',0):>9} | "
              f"{d.get('vin_mismatch',0):>6} | "
              f"{d.get('revoked_key',0):>7} | "
              f"{result:>9} | {r['elapsed_s']:>8.2f}")
    print("-" * 100)

    total_correct = sum(r["correct"] for r in all_runs)
    total_count = sum(r["total"] for r in all_runs)
    print(f"\n全局: {total_correct}/{total_count} = "
          f"{total_correct/total_count*100:.2f}%")
    print(f"总耗时: {t_global:.2f}s")

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"mixed-scenario-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "runs": runs,
        "vehicle_count_per_run": VEHICLE_COUNT,
        "total_time_s": round(t_global, 2),
        "all_runs": all_runs,
    }, indent=2, ensure_ascii=False))
    print(f"\n证据已保存: {out}")

    # 清理 MIX VIN 的临时 ECU 密钥
    cleanup_mix_keys()


if __name__ == "__main__":
    main()
