#!/usr/bin/env python3
"""
A/B 分区失败恢复演示（真实版本 v3）。

设计：
- Slot A：已安装的旧版本（v2.3.0, ri=11），payload 与新版不同（后 10 块内容不同）
- Slot B：升级写入的新版本（v2.4.1, ri=12），payload 完整
- 每个 Slot 独立存 chunk_hashes.json，boot 时从自己目录读参照
- 首次安装校验含验签；回退启动只做完整性校验（符合 ECU 实践）
"""
import hashlib, json, os, shutil, subprocess, sys, time, urllib.request
from datetime import datetime
from pathlib import Path

# 复用共享车端客户端（注册 + 鉴权请求 + 本地验签）
from ota_client import request_task, download_chunk, verify_manifest_vehicle_side

OTA_API = "http://127.0.0.1:8080"
ROOT = Path("/home/rjh/ota-sec")
STATE_BASE = ROOT / "data" / "vehicle-sim-ab"
EVIDENCE = ROOT / "evidence" / "raw"

VIN = "LSVAM4187C2ABTEST"
MAX_BOOT_ATTEMPTS = 3
OLD_VERSION_DIVERGE_FROM = 90   # 前 90 块与新版相同，后 10 块不同


def sm3_hex(data: bytes) -> str:
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def http_get_json(url, timeout=30):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def http_post_json(url, obj):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.status, json.loads(r.read().decode())


def http_get_bytes(url):
    with urllib.request.urlopen(url, timeout=120) as r:
        return r.read()


def slot_dir(slot):
    return STATE_BASE / VIN / slot


def boot_state_path():
    return STATE_BASE / VIN / "boot_state.json"


def load_boot_state():
    p = boot_state_path()
    if not p.exists():
        return {"vin": VIN, "active_slot": "slot_a", "boot_counter": 0,
                "max_boot_attempts": MAX_BOOT_ATTEMPTS,
                "confirmed_slot": "slot_a", "history": []}
    return json.loads(p.read_text())


def save_boot_state(state):
    boot_state_path().parent.mkdir(parents=True, exist_ok=True)
    boot_state_path().write_text(json.dumps(state, indent=2))


def build_old_version_payload(src_dir: Path, dst_dir: Path,
                              n_chunks: int, diverge_from: int):
    """
    构造一个"旧版本"的 payload：
    - 前 diverge_from 块：复制自当前版本
    - 后 n_chunks-diverge_from 块：用不同内容替换（模拟旧版本不同的二进制）
    - 返回 (chunk_hashes: list, payload_sm3: str)
    """
    dst_dir.mkdir(parents=True, exist_ok=True)
    chunk_hashes = []
    for i in range(n_chunks):
        src = src_dir / f"chunk-{i:06d}"
        if i < diverge_from:
            data = src.read_bytes()
        else:
            size = src.stat().st_size if src.exists() else 1048576
            data = b'\xAA' * size
        (dst_dir / f"chunk-{i:06d}").write_bytes(data)
        chunk_hashes.append(sm3_hex(data))

    h = hashlib.new("sm3")
    for i in range(n_chunks):
        h.update((dst_dir / f"chunk-{i:06d}").read_bytes())
    return chunk_hashes, h.hexdigest()


def write_slot(slot, manifest, chunks_src_dir, sig_hex, sign_key_id, chunk_hashes):
    """把版本写入指定 slot。分块真落盘，chunk_hashes.json 存在 slot 目录里。"""
    d = slot_dir(slot)
    if d.exists():
        shutil.rmtree(d)
    d.mkdir(parents=True, exist_ok=True)
    (d / "chunks").mkdir()

    for f in sorted(chunks_src_dir.glob("chunk-[0-9][0-9][0-9][0-9][0-9][0-9]")):
        shutil.copy(f, d / "chunks" / f.name)

    (d / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    canonical = json.dumps(manifest, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    (d / "manifest-canonical.json").write_text(canonical)
    (d / "manifest.sig").write_bytes(bytes.fromhex(sig_hex))
    (d / "version").write_text(manifest["version"])
    (d / "rollback_index").write_text(str(manifest["rollback_index"]))
    (d / "sign_key_id").write_text(sign_key_id)
    (d / "status").write_text("INSTALLED")
    (d / "chunk_hashes.json").write_text(json.dumps(chunk_hashes))


def boot_from(slot, check_signature=False, corrupt_chunk=None):
    """
    从指定 slot 启动。校验从 slot 自己的 chunk_hashes.json 读参照。
    check_signature=True：首次安装新版本时验证 manifest 签名。
    check_signature=False：回退启动只做完整性校验。
    """
    d = slot_dir(slot)
    if not d.exists() or not (d / "status").exists():
        return {"slot": slot, "boot_ok": False, "reason": "slot_empty"}

    manifest = json.loads((d / "manifest.json").read_text())
    sign_key_id = (d / "sign_key_id").read_text().strip()
    chunk_hashes = json.loads((d / "chunk_hashes.json").read_text())

    if corrupt_chunk is not None:
        target = d / "chunks" / f"chunk-{corrupt_chunk:06d}"
        if target.exists():
            data = bytearray(target.read_bytes())
            data[0] ^= 0xFF
            target.write_bytes(bytes(data))

    # 1. 分块逐块 SM3
    chunk_files = sorted((d / "chunks").glob("chunk-[0-9][0-9][0-9][0-9][0-9][0-9]"))
    if len(chunk_files) != len(chunk_hashes):
        return {"slot": slot, "boot_ok": False,
                "reason": f"chunk_count_mismatch: {len(chunk_files)} != {len(chunk_hashes)}"}
    for i, cf in enumerate(chunk_files):
        actual = sm3_hex(cf.read_bytes())
        if actual != chunk_hashes[i]:
            return {"slot": slot, "boot_ok": False,
                    "reason": f"chunk_{i}_hash_mismatch"}

    # 2. 整包 SM3（优先密文 SM3；老版本没有 encrypted_sm3 时回退明文 SM3）
    h_payload = hashlib.new("sm3")
    for cf in chunk_files:
        h_payload.update(cf.read_bytes())
    expected_sm3 = manifest.get("encrypted_sm3") or manifest["sm3"]
    if h_payload.hexdigest() != expected_sm3:
        return {"slot": slot, "boot_ok": False,
                "reason": "payload_sm3_mismatch"}

    # 3. 可选：manifest 验签（车端本地验签，不委托云端）
    if check_signature:
        sig_hex = (d / "manifest.sig").read_bytes().hex()
        accepted, reason = verify_manifest_vehicle_side(
            VIN, manifest, sig_hex, manifest.get("key_id", sign_key_id),
            local_rollback=0)  # 本演示聚焦 A/B 失败恢复，防回滚由 08 负向测试覆盖
        if not accepted:
            return {"slot": slot, "boot_ok": False,
                    "reason": f"manifest_verify_failed: {reason}"}

    return {"slot": slot, "boot_ok": True, "reason": "ok",
            "version": (d / "version").read_text(),
            "rollback_index": int((d / "rollback_index").read_text()),
            "signature_checked": check_signature}


def sync_manifest_with_active_key():
    active = http_get_json(f"{OTA_API}/health")["active_key_id"]
    print(f"[准备] 当前 active key: {active}")

    m_json = ROOT / "packages/manifests/manifest-v1.json"
    m_canon = ROOT / "packages/manifests/manifest-canonical.json"
    m_sig = ROOT / "packages/manifests/manifest-v1.sig"

    manifest = json.loads(m_json.read_text())
    manifest["key_id"] = active
    m_json.write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
    m_canon.write_text(canonical)

    SECRETS = ROOT / "pki" / ".secrets"
    key_map = {"ota-signing-v1": ("signing-v1", SECRETS / "signing-v1.pass"),
               "ota-signing-v2": ("signing-v2", SECRETS / "signing-v2.pass")}
    keydir, pass_file = key_map[active]
    keypass = pass_file.read_text().strip() if pass_file.exists() else f"{keydir}pass"
    subprocess.run([
        "gmssl", "sm2sign",
        "-key", str(ROOT / "pki" / keydir / "signing.key"),
        "-pass", keypass, "-id", active,
        "-in", str(m_canon), "-out", str(m_sig),
    ], check=True)
    print(f"[准备] manifest 已用 {active} 重签\n")
    return active


def init_vehicle(active_key):
    """
    初始化车辆：
    - Slot A：旧版本（v2.3.0, ri=11），后 10 块 payload 与新版本不同
    - Slot B：空
    """
    base = STATE_BASE / VIN
    if base.exists():
        shutil.rmtree(base)
    base.mkdir(parents=True, exist_ok=True)

    # 1. 构造旧版本 payload
    old_chunks_dir = base / "old_version_chunks"
    old_chunk_hashes, old_payload_sm3 = build_old_version_payload(
        ROOT / "packages/chunks", old_chunks_dir,
        n_chunks=100, diverge_from=OLD_VERSION_DIVERGE_FROM)

    # 2. 构造旧版本 manifest（payload sm3 是旧版自己的）
    old_manifest = json.loads(
        (ROOT / "packages/manifests/manifest-v1.json").read_text())
    old_manifest["version"] = "2.3.0"
    old_manifest["min_version"] = "2.0.0"
    old_manifest["rollback_index"] = 11
    old_manifest["sm3"] = old_payload_sm3
    # 关键修复：删掉新版本才有的 SM4 字段，让 boot_from 回退到明文 SM3
    old_manifest.pop("encrypted_sm3", None)
    old_manifest.pop("encrypted_size", None)
    old_manifest.pop("sm4_iv", None)
    old_manifest.pop("wrapped_key", None)
    old_manifest["key_id"] = active_key
    old_manifest["task_id"] = "task-initial-slot-a"
    old_manifest["vin"] = VIN

    # 3. 签旧版本 manifest
    canonical = json.dumps(old_manifest, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=False)
    tmp_canon = base / "tmp-old-canon.json"
    tmp_canon.write_text(canonical)
    SECRETS = ROOT / "pki" / ".secrets"
    key_map = {"ota-signing-v1": ("signing-v1", SECRETS / "signing-v1.pass"),
               "ota-signing-v2": ("signing-v2", SECRETS / "signing-v2.pass")}
    keydir, pass_file = key_map[active_key]
    keypass = pass_file.read_text().strip() if pass_file.exists() else f"{keydir}pass"
    tmp_sig = base / "tmp-old.sig"
    subprocess.run([
        "gmssl", "sm2sign",
        "-key", str(ROOT / "pki" / keydir / "signing.key"),
        "-pass", keypass, "-id", active_key,
        "-in", str(tmp_canon), "-out", str(tmp_sig),
    ], check=True)
    old_sig_hex = tmp_sig.read_bytes().hex()

    # 4. 写入 Slot A
    write_slot("slot_a", old_manifest, old_chunks_dir,
               old_sig_hex, active_key, old_chunk_hashes)
    (slot_dir("slot_a") / "status").write_text("CONFIRMED")

    shutil.rmtree(old_chunks_dir, ignore_errors=True)
    tmp_canon.unlink(missing_ok=True)
    tmp_sig.unlink(missing_ok=True)

    save_boot_state({
        "vin": VIN, "active_slot": "slot_a", "boot_counter": 0,
        "max_boot_attempts": MAX_BOOT_ATTEMPTS,
        "confirmed_slot": "slot_a",
        "history": [{"at": datetime.now().isoformat(),
                     "event": "vehicle_initialized",
                     "slot_a_version": "2.3.0",
                     "slot_a_rollback_index": 11}],
    })

    new_sm3 = json.loads((ROOT / "packages/manifests/manifest-v1.json").read_text())["sm3"]
    print(f"[初始化] Slot A 装好旧版本 v2.3.0")
    print(f"         旧 payload SM3: {old_payload_sm3[:24]}...")
    print(f"         新 payload SM3: {new_sm3[:24]}...")
    print(f"         后 {100-OLD_VERSION_DIVERGE_FROM} 块内容不同")
    print(f"         已剔除 SM4 字段（旧版本无密文）\n")


def scenario_happy_path():
    print("=" * 60)
    print("场景 1：正常升级到 Slot B，首次启动完整校验")
    print("=" * 60)

    state = load_boot_state()
    print(f"当前: active_slot={state['active_slot']}\n")

    _, task = request_task(VIN)
    task_id = task["task_id"]
    manifest = task["manifest"]
    key_id = task["key_id"]
    sig_hex = task["manifest_sig_hex"]
    print(f"任务: {task_id}")
    print(f"目标: v{manifest['version']}, ri={manifest['rollback_index']}\n")

    tmp = STATE_BASE / VIN / "tmp_download"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    for i in range(task["chunk_count"]):
        data = download_chunk(VIN, task_id, i)
        (tmp / f"chunk-{i:06d}").write_bytes(data)

    write_slot("slot_b", manifest, tmp, sig_hex, key_id, task["chunk_hashes"])
    print(f"[1/4] 分块写入 Slot B，状态 INSTALLED")

    state["active_slot"] = "slot_b"
    state["boot_counter"] = 1
    state["history"].append({"at": datetime.now().isoformat(),
                             "event": "switch_to_b", "boot_counter": 1})
    save_boot_state(state)
    print(f"[2/4] 切换到 Slot B，boot_counter=1")

    boot = boot_from("slot_b", check_signature=True)
    print(f"[3/4] 首次启动 Slot B（含验签）: {boot}")

    if boot["boot_ok"]:
        state["boot_counter"] = 0
        state["confirmed_slot"] = "slot_b"
        state["history"].append({"at": datetime.now().isoformat(),
                                 "event": "boot_ok_and_confirmed"})
        save_boot_state(state)
        print(f"[4/4] 启动成功，CONFIRMED\n")

    shutil.rmtree(tmp, ignore_errors=True)


def scenario_failure_and_rollback():
    print("=" * 60)
    print("场景 2：新版本启动失败，3 次后自动回退")
    print("=" * 60)

    _, task = request_task(VIN)
    task_id = task["task_id"]
    manifest = task["manifest"]
    sig_hex = task["manifest_sig_hex"]
    key_id = task["key_id"]

    tmp = STATE_BASE / VIN / "tmp_download2"
    if tmp.exists():
        shutil.rmtree(tmp)
    tmp.mkdir(parents=True)
    for i in range(task["chunk_count"]):
        data = download_chunk(VIN, task_id, i)
        (tmp / f"chunk-{i:06d}").write_bytes(data)

    write_slot("slot_b", manifest, tmp, sig_hex, key_id, task["chunk_hashes"])
    shutil.rmtree(tmp, ignore_errors=True)

    b_chunk5 = slot_dir("slot_b") / "chunks" / "chunk-000005"
    data = bytearray(b_chunk5.read_bytes())
    data[0] ^= 0xFF
    b_chunk5.write_bytes(bytes(data))
    print(f"[准备] Slot B 重新写入 + 损坏 chunk-000005\n")

    state = load_boot_state()
    state["active_slot"] = "slot_b"
    save_boot_state(state)

    for attempt in range(1, MAX_BOOT_ATTEMPTS + 1):
        print(f"--- 启动尝试 {attempt}/{MAX_BOOT_ATTEMPTS} ---")
        boot = boot_from("slot_b", check_signature=False)
        if boot["boot_ok"]:
            print(f"  启动成功")
            break
        print(f"  启动失败: {boot['reason']}")
        state["boot_counter"] = attempt
        state["history"].append({"at": datetime.now().isoformat(),
                                 "event": f"boot_failed_attempt_{attempt}",
                                 "reason": boot["reason"]})
        save_boot_state(state)

        if attempt >= MAX_BOOT_ATTEMPTS:
            print(f"\n[回退触发] boot_counter={attempt} >= {MAX_BOOT_ATTEMPTS}")
            state["active_slot"] = "slot_a"
            state["boot_counter"] = 0
            state["history"].append({"at": datetime.now().isoformat(),
                                     "event": "auto_rollback",
                                     "from": "slot_b", "to": "slot_a"})
            save_boot_state(state)
            print(f"[回退完成] active_slot=slot_a\n")

            print("--- 从回退后的 Slot A 启动（真实校验，不重复验签）---")
            boot_a = boot_from("slot_a", check_signature=False)
            print(f"启动结果: {boot_a}")
            if boot_a["boot_ok"]:
                state["confirmed_slot"] = "slot_a"
                state["history"].append({"at": datetime.now().isoformat(),
                                         "event": "boot_ok_after_rollback"})
                save_boot_state(state)
                print(f"[OK] 车辆从 Slot A 正常启动（v2.3.0），回退成功\n")
            break


def print_final_state():
    state = load_boot_state()
    print("=" * 60)
    print("最终状态")
    print("=" * 60)
    print(f"active_slot:      {state['active_slot']}")
    print(f"confirmed_slot:   {state['confirmed_slot']}")
    print(f"boot_counter:     {state['boot_counter']}")
    print(f"事件历史:")
    for e in state["history"]:
        line = f"  {e['at']}  {e['event']}"
        if e.get("reason"):
            line += f"  ({e['reason']})"
        print(line)
    print("=" * 60)


def main():
    print("=" * 60)
    print("A/B 分区失败恢复演示（真实版本 v3）")
    print("=" * 60)
    print(f"VIN: {VIN}")
    print(f"时间: {datetime.now().isoformat()}\n")

    active_key = sync_manifest_with_active_key()
    init_vehicle(active_key)
    scenario_happy_path()
    scenario_failure_and_rollback()
    print_final_state()

    state = load_boot_state()
    a_dir = slot_dir("slot_a")
    b_dir = slot_dir("slot_b")
    evidence = {
        "timestamp": datetime.now().isoformat(),
        "vin": VIN,
        "final_state": state,
        "slot_a": {
            "version": (a_dir / "version").read_text(),
            "rollback_index": (a_dir / "rollback_index").read_text(),
            "status": (a_dir / "status").read_text(),
            "chunk_count": len(list((a_dir / "chunks").glob("chunk-[0-9]*[0-9]"))),
            "payload_sm3": hashlib.new("sm3",
                b"".join((a_dir / "chunks" / f"chunk-{i:06d}").read_bytes()
                         for i in range(100))).hexdigest(),
        },
        "slot_b": {
            "version": (b_dir / "version").read_text() if (b_dir / "version").exists() else None,
            "rollback_index": (b_dir / "rollback_index").read_text() if (b_dir / "rollback_index").exists() else None,
            "status": (b_dir / "status").read_text() if (b_dir / "status").exists() else None,
        },
    }
    out = EVIDENCE / f"ab-recovery-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps(evidence, indent=2, ensure_ascii=False))
    print(f"\n证据已保存: {out}")


if __name__ == "__main__":
    main()
