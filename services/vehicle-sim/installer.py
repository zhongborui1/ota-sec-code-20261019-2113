#!/usr/bin/env python3
"""
车端 A/B 分区安装器（模拟 ECU 的 standby slot）。

职责边界：
  - 下载与云端验签在 simulator.py 完成；
  - 本模块只负责：初始化出厂 Slot A、把已验证的明文镜像写入备用 Slot、
    持久化 boot_state、由独立进程执行"重启 + 自检 + 提交/回滚"。

磁盘布局（每个 VIN）：
  data/vehicle-state/<VIN>/
      boot_state.json                 # active_slot / pending_slot / phase / boot_counter / history
      slots/slot_a/{payload.bin,manifest.json,manifest.sig,meta.json}
      slots/slot_b/{...}

出厂基线：
  首个升级包到达时，用它的明文镜像生成一份"旧版本"基线（版本取 min_version，
  rollback_index 取新版本 -1，后 10 个分块内容不同），只保留一份
  data/vehicle-state/_factory/payload.bin（100 MB），各车 slot_a 用硬链接引用。
  这样 100 辆车不会为回滚目标多占 10 GB，同时 Slot A 仍是可独立校验的完整镜像。
  出厂镜像没有 OTA 签名，启动自检只校验完整性（与真实 ECU 回退启动一致）。
"""
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

ROOT = Path(os.environ.get("OTA_ROOT", "/home/rjh/ota-sec"))
VEHICLE_STATE = ROOT / "data" / "vehicle-state"
FACTORY_DIR = VEHICLE_STATE / "_factory"
TRUST_ANCHORS = ROOT / "pki" / "vehicle-trust"

MAX_BOOT_ATTEMPTS = 3
FACTORY_DIVERGE_LAST = 10          # 出厂镜像与新版不同的最后 N 个分块


def _now():
    return datetime.utcnow().isoformat() + "Z"


def _sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def _safe_vin(vin):
    return "".join(c for c in vin if c.isalnum())


def vehicle_dir(vin):
    return VEHICLE_STATE / _safe_vin(vin)


def slot_dir(vin, slot):
    return vehicle_dir(vin) / "slots" / slot


def boot_state_path(vin):
    return vehicle_dir(vin) / "boot_state.json"


def _atomic_write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(obj, indent=2, ensure_ascii=False))
    os.replace(tmp, path)


def _md5_of_file(path):
    """仅用于硬链接去重判断，不是安全校验。"""
    h = hashlib.md5()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(4 * 1024 * 1024), b""):
            h.update(b)
    return h.hexdigest()


def scan_file(path, chunk_size):
    """单次顺序读：返回 (整文件 SM3, 每块 SM3 列表)。"""
    whole = hashlib.new("sm3")
    chunks = []
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            whole.update(b)
            h = hashlib.new("sm3")
            h.update(b)
            chunks.append(h.hexdigest())
    return whole.hexdigest(), chunks


# ---------- 出厂基线 ----------

def ensure_factory_image(source_plain, manifest, lock_timeout=120):
    """
    幂等创建共享出厂镜像。source_plain 是本次已验证的明文 payload。
    只有第一个线程真正构建，其余等待后复用。
    """
    chunk_size = int(manifest["chunk_size"])
    meta_path = FACTORY_DIR / "meta.json"
    payload_path = FACTORY_DIR / "payload.bin"

    if meta_path.exists() and payload_path.exists():
        meta = json.loads(meta_path.read_text())
        if meta.get("chunk_size") == chunk_size:
            return meta

    FACTORY_DIR.mkdir(parents=True, exist_ok=True)
    lock_path = FACTORY_DIR / ".lock"
    with open(lock_path, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        # 双检：等锁期间别人可能已经建好
        if meta_path.exists() and payload_path.exists():
            meta = json.loads(meta_path.read_text())
            if meta.get("chunk_size") == chunk_size:
                return meta

        tmp = FACTORY_DIR / f"payload.bin.tmp.{os.getpid()}"
        shutil.copyfile(source_plain, tmp)

        size = tmp.stat().st_size
        n_chunks = (size + chunk_size - 1) // chunk_size

        # 把最后 N 块改成不同内容，让它成为"另一份镜像"而不是新版的副本
        with open(tmp, "r+b") as f:
            for i in range(max(0, n_chunks - FACTORY_DIVERGE_LAST), n_chunks):
                offset = i * chunk_size
                length = min(chunk_size, size - offset)
                f.seek(offset)
                f.write(b"\xAA" * length)
            f.flush()
            os.fsync(f.fileno())

        sm3, chunk_hashes = scan_file(tmp, chunk_size)
        os.replace(tmp, payload_path)

        meta = {
            "kind": "factory_baseline",
            "version": manifest.get("min_version") or "0.0.0",
            "rollback_index": max(0, int(manifest["rollback_index"]) - 1),
            "size": size,
            "chunk_size": chunk_size,
            "chunk_count": n_chunks,
            "sm3": sm3,
            "chunk_hashes": chunk_hashes,
            "diverge_last_chunks": FACTORY_DIVERGE_LAST,
            "created_at": _now(),
            "source_package": manifest.get("package_id"),
        }
        _atomic_write_json(meta_path, meta)
        return meta


def _link_factory_payload(vin):
    """把共享出厂镜像硬链接到该车的 slot_a；返回 False 表示无法硬链接。"""
    src = FACTORY_DIR / "payload.bin"
    dst = slot_dir(vin, "slot_a") / "payload.bin"
    dst.parent.mkdir(parents=True, exist_ok=True)
    if dst.exists():
        if os.stat(dst).st_ino == os.stat(src).st_ino:
            return True
        if dst.stat().st_size == src.stat().st_size and _md5_of_file(dst) == _md5_of_file(src):
            return True
        dst.unlink()
    try:
        os.link(src, dst)
        return True
    except OSError:
        shutil.copyfile(src, dst)
        return False


def init_vehicle(vin, manifest, source_plain):
    """
    幂等初始化：出厂 Slot A + boot_state。
    返回 (state, factory_meta)。
    """
    meta = ensure_factory_image(source_plain, manifest)
    factory_meta_path = FACTORY_DIR / "meta.json"
    if not factory_meta_path.exists():
        raise RuntimeError("factory meta missing")

    d = slot_dir(vin, "slot_a")
    d.mkdir(parents=True, exist_ok=True)

    slot_meta_path = d / "meta.json"
    if not slot_meta_path.exists() or not (d / "payload.bin").exists():
        linked = _link_factory_payload(vin)
        slot_meta = {
            "vin": vin,
            "slot": "slot_a",
            "version": meta["version"],
            "rollback_index": meta["rollback_index"],
            "size": meta["size"],
            "chunk_size": meta["chunk_size"],
            "chunk_count": meta["chunk_count"],
            "sm3": meta["sm3"],
            "chunk_hashes": meta["chunk_hashes"],
            "provenance": "factory_baseline",
            "shared_payload": linked,
            "signature_verified": False,
            "installed_at": _now(),
        }
        _atomic_write_json(slot_meta_path, slot_meta)

    p = boot_state_path(vin)
    if p.exists():
        state = json.loads(p.read_text())
    else:
        state = {
            "vin": vin,
            "active_slot": "slot_a",
            "confirmed_slot": "slot_a",
            "pending_slot": None,
            "phase": "COMMITTED",
            "boot_counter": 0,
            "max_boot_attempts": MAX_BOOT_ATTEMPTS,
            "history": [{
                "at": _now(),
                "event": "vehicle_initialized",
                "slot_a_version": meta["version"],
                "slot_a_rollback_index": meta["rollback_index"],
            }],
        }
        _atomic_write_json(p, state)

    # 防回滚下限：出厂分区自身就是 ri=11，本地计数器不能停留在更低的默认值，
    # 否则回退后仍会接受 ri=11 的"降级包"。
    ri_file = vehicle_dir(vin) / "rollback_index"
    if not ri_file.exists():
        ri_file.write_text(str(meta["rollback_index"]))
    elif int(ri_file.read_text().strip() or 0) < int(meta["rollback_index"]):
        ri_file.write_text(str(meta["rollback_index"]))

    return state, meta


# ---------- 安装到备用分区 ----------

def install_standby(vin, manifest, sig_hex, plain_path, plain_sm3,
                    plain_chunk_hashes):
    """
    把已验证的明文镜像写入非活动分区。payload 最后落盘；只有 payload 就位后
    才把 boot_state 置为 INSTALLED/PENDING_REBOOT。返回目标 slot 名。
    """
    state = json.loads(boot_state_path(vin).read_text())
    active = state["active_slot"]
    target = "slot_b" if active == "slot_a" else "slot_a"

    d = slot_dir(vin, target)
    d.mkdir(parents=True, exist_ok=True)

    _atomic_write_json(d / "manifest.json", manifest)
    (d / "manifest.sig").write_bytes(bytes.fromhex(sig_hex))
    meta = {
        "vin": vin,
        "slot": target,
        "version": manifest["version"],
        "rollback_index": int(manifest["rollback_index"]),
        "task_id": manifest.get("task_id"),
        "key_id": manifest.get("key_id"),
        "size": int(manifest["size"]),
        "chunk_size": int(manifest["chunk_size"]),
        "chunk_count": len(plain_chunk_hashes),
        "sm3": plain_sm3,
        "encrypted_sm3": manifest.get("encrypted_sm3"),
        "chunk_hashes": plain_chunk_hashes,
        "provenance": "ota",
        "signature_verified": True,
        "installed_at": _now(),
    }
    _atomic_write_json(d / "meta.json", meta)

    # 原子落位：同一文件系统内 rename，不会出现半个镜像
    os.replace(plain_path, d / "payload.bin")
    _fsync_dir(d)

    state["pending_slot"] = target
    state["phase"] = "INSTALLED"
    state["boot_counter"] = 0
    state.setdefault("history", []).append({
        "at": _now(), "event": "standby_written", "slot": target,
        "version": manifest["version"],
        "rollback_index": int(manifest["rollback_index"]),
    })
    _atomic_write_json(boot_state_path(vin), state)
    return target


def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass


def corrupt_slot(vin, slot, chunk_idx=5, offset=123):
    """测试注入：真实翻转备用分区镜像中的一个字节。"""
    p = slot_dir(vin, slot) / "payload.bin"
    size = p.stat().st_size
    pos = min(size - 1, chunk_idx * 1024 * 1024 + offset)
    with open(p, "r+b") as f:
        f.seek(pos)
        b = f.read(1)
        f.seek(pos)
        f.write(bytes([b[0] ^ 0xFF]))
        f.flush()
        os.fsync(f.fileno())
    return pos


# ---------- 启动自检 ----------

def _verify_manifest_signature(manifest, sig_hex, key_id):
    """离线验签：只用本地信任锚，启动阶段不访问云端。"""
    anchor = TRUST_ANCHORS / f"{key_id}.pub"
    if not anchor.exists():
        return False, f"trust_anchor_missing: {anchor.name}"
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(canonical)
        in_path = f.name
    sig_path = in_path + ".sig"
    Path(sig_path).write_bytes(bytes.fromhex(sig_hex))
    try:
        r = subprocess.run([
            "gmssl", "sm2verify",
            "-pubkey", str(anchor), "-id", key_id,
            "-in", in_path, "-sig", sig_path,
        ], capture_output=True)
        ok = (r.returncode == 0 and b"success" in r.stdout.lower())
        return ok, "ok" if ok else f"sm2_verify_failed: {r.stderr.decode(errors='ignore')[:120]}"
    finally:
        Path(in_path).unlink(missing_ok=True)
        Path(sig_path).unlink(missing_ok=True)


def verify_slot(vin, slot, reference_slot=None):
    """
    启动自检：完整性 → 元数据一致性 → 防回滚 → （OTA 镜像）离线验签。
    返回 {ok, reason, version, rollback_index, detail}。
    """
    d = slot_dir(vin, slot)
    meta_path = d / "meta.json"
    payload = d / "payload.bin"
    if not meta_path.exists() or not payload.exists():
        return {"ok": False, "reason": "slot_empty", "slot": slot}

    meta = json.loads(meta_path.read_text())
    chunk_size = int(meta["chunk_size"])
    expected_chunks = meta["chunk_hashes"]

    # 1. 逐块 + 整包 SM3，一次顺序读
    whole = hashlib.new("sm3")
    idx = 0
    with open(payload, "rb") as f:
        while True:
            b = f.read(chunk_size)
            if not b:
                break
            whole.update(b)
            if idx >= len(expected_chunks):
                return {"ok": False, "slot": slot,
                        "reason": f"chunk_count_overflow: {idx}"}
            actual = _sm3_hex(b)
            if actual != expected_chunks[idx]:
                return {"ok": False, "slot": slot,
                        "reason": f"chunk_{idx}_hash_mismatch"}
            idx += 1

    if idx != len(expected_chunks):
        return {"ok": False, "slot": slot,
                "reason": f"chunk_count_mismatch: {idx} != {len(expected_chunks)}"}
    if whole.hexdigest() != meta["sm3"]:
        return {"ok": False, "slot": slot, "reason": "payload_sm3_mismatch"}
    if payload.stat().st_size != int(meta["size"]):
        return {"ok": False, "slot": slot, "reason": "payload_size_mismatch"}

    # 2. manifest 与 slot 元数据一致
    manifest = json.loads((d / "manifest.json").read_text()) if (d / "manifest.json").exists() else None
    if meta.get("provenance") == "ota":
        if manifest is None:
            return {"ok": False, "slot": slot, "reason": "manifest_missing"}
        if manifest.get("vin") != vin or meta.get("vin") != vin:
            return {"ok": False, "slot": slot, "reason": "vin_mismatch"}
        if manifest.get("version") != meta.get("version"):
            return {"ok": False, "slot": slot, "reason": "version_mismatch"}
        if int(manifest.get("rollback_index", -1)) != int(meta.get("rollback_index", -2)):
            return {"ok": False, "slot": slot, "reason": "rollback_index_mismatch"}

    # 3. 防回滚：待启动镜像的 rollback_index 不得低于当前活动分区
    if reference_slot and reference_slot != slot:
        ref_meta_path = slot_dir(vin, reference_slot) / "meta.json"
        if ref_meta_path.exists():
            ref = json.loads(ref_meta_path.read_text())
            if int(meta["rollback_index"]) < int(ref.get("rollback_index", 0)):
                return {"ok": False, "slot": slot,
                        "reason": f"rollback_index_regression: "
                                  f"{ref.get('rollback_index')} -> {meta['rollback_index']}"}

    # 4. OTA 镜像离线验签
    if meta.get("signature_verified"):
        sig_path = d / "manifest.sig"
        if not sig_path.exists():
            return {"ok": False, "slot": slot, "reason": "signature_missing"}
        ok, reason = _verify_manifest_signature(
            manifest, sig_path.read_bytes().hex().strip(),
            manifest.get("key_id") or meta.get("key_id"))
        if not ok:
            return {"ok": False, "slot": slot, "reason": reason}

    return {"ok": True, "slot": slot, "reason": "ok",
            "version": meta.get("version"),
            "rollback_index": meta.get("rollback_index"),
            "signature_checked": bool(meta.get("signature_verified")),
            "provenance": meta.get("provenance")}


def boot_once(vin):
    """
    单次"上电启动"。由 boot_agent.py 在独立进程中调用。
    返回 {result: committed|retry|rolled_back|bricked, ...}
    """
    p = boot_state_path(vin)
    state = json.loads(p.read_text())
    pending = state.get("pending_slot")
    phase = state.get("phase", "COMMITTED")
    attempt = int(state.get("boot_counter", 0)) + 1
    max_attempts = int(state.get("max_boot_attempts", MAX_BOOT_ATTEMPTS))

    if not pending:
        # 正常启动：只校验当前活动分区
        check = verify_slot(vin, state["active_slot"])
        state.setdefault("history", []).append({
            "at": _now(), "event": "normal_boot", "slot": state["active_slot"],
            "ok": check["ok"], "reason": check.get("reason"),
        })
        _atomic_write_json(p, state)
        return {"result": "committed" if check["ok"] else "bricked",
                "check": check, "attempt": 0, "active_slot": state["active_slot"]}

    check = verify_slot(vin, pending, reference_slot=state["active_slot"])

    if check["ok"]:
        state["active_slot"] = pending
        state["confirmed_slot"] = pending
        state["pending_slot"] = None
        state["phase"] = "COMMITTED"
        state["boot_counter"] = 0
        state.setdefault("history", []).append({
            "at": _now(), "event": "boot_ok_and_confirmed", "slot": pending,
            "attempt": attempt, "version": check.get("version"),
        })
        _atomic_write_json(p, state)
        return {"result": "committed", "check": check, "attempt": attempt,
                "active_slot": pending, "confirmed_slot": pending}

    # 自检失败：累计启动失败次数
    state["boot_counter"] = attempt
    state["phase"] = "BOOT_FAILED"
    state.setdefault("history", []).append({
        "at": _now(), "event": f"boot_failed_attempt_{attempt}",
        "slot": pending, "reason": check.get("reason"),
    })

    if attempt >= max_attempts:
        # 回退到原活动分区，并且必须重新校验旧分区可用
        old_slot = state["active_slot"]
        old_check = verify_slot(vin, old_slot)
        state["pending_slot"] = None
        state["boot_counter"] = 0
        state.setdefault("history", []).append({
            "at": _now(), "event": "auto_rollback",
            "from": pending, "to": old_slot,
            "reason": check.get("reason"),
            "old_slot_ok": old_check["ok"],
            "old_slot_reason": old_check.get("reason"),
        })
        if old_check["ok"]:
            state["phase"] = "ROLLED_BACK"
            state.setdefault("history", []).append({
                "at": _now(), "event": "boot_ok_after_rollback",
                "slot": old_slot, "version": old_check.get("version"),
            })
            result = "rolled_back"
        else:
            state["phase"] = "BRICKED"
            result = "bricked"
        _atomic_write_json(p, state)
        return {"result": result, "check": check, "old_slot_check": old_check,
                "attempt": attempt, "active_slot": old_slot}

    _atomic_write_json(p, state)
    return {"result": "retry", "check": check, "attempt": attempt,
            "active_slot": state["active_slot"]}
