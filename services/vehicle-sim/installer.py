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
  管理员离线审核并用根私钥签署 factory.json，不再从下载包自动生成可信基线。
  各车 Slot A 可硬链接共享 payload.bin，启动时验证根签名和实际镜像摘要。
"""
import hashlib
import json
import os
import shutil
import subprocess
import sqlite3
import time
from datetime import datetime
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ota_common.trust import (SecurityError, verify_sm2, canonical, cached_policy,
                              trusted_key, atomic_json, timestamp)
ROOT = Path(os.environ.get("OTA_ROOT", str(Path(__file__).resolve().parents[2])))
VEHICLE_STATE = ROOT / "data" / "vehicle-state"
FACTORY_DIR = VEHICLE_STATE / "_factory"
TRUST_ANCHORS = ROOT / "pki" / "vehicle-trust"

MAX_BOOT_ATTEMPTS = 3


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
    atomic_json(path, obj)


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

def ensure_factory_image(source_plain=None, manifest=None, lock_timeout=120):
    # Factory baseline is approved offline; never derived/trusted from a downloaded OTA.
    doc = json.loads((FACTORY_DIR / "factory.json").read_text())
    meta = doc["signed"]
    root_pub = (TRUST_ANCHORS / "root.pub").read_text()
    if meta.get("type") != "ota-factory-v1" or not verify_sm2(
            root_pub, canonical(meta), doc["signature"], "ota-root-v1"):
        raise SecurityError("factory_bad_root_signature")
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
            "rollback_index": int(meta["rollback_index"]),
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

    # 出厂基线也建立防回滚下限，不能从更低的默认值开始。
    ri_file = vehicle_dir(vin) / "rollback_index"
    if not ri_file.exists():
        atomic_json(ri_file, int(meta["rollback_index"]))
    elif int(ri_file.read_text().strip() or 0) < int(meta["rollback_index"]):
        atomic_json(ri_file, int(meta["rollback_index"]))

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
    except (OSError, AttributeError):
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

def verify_slot(vin, slot, reference_slot=None):
    """Authority is the signed manifest/root baseline, never mutable slot metadata."""
    try:
        d = slot_dir(vin, slot)
        payload = d / "payload.bin"
        meta = json.loads((d / "meta.json").read_text())
        if (d / "manifest.json").exists():
            manifest = json.loads((d / "manifest.json").read_text())
            if manifest.get("vin") != vin or manifest.get("key_id") != meta.get("key_id"):
                raise SecurityError("vin_or_key_mismatch")
            state = json.loads(boot_state_path(vin).read_text())
            installed = state.get("confirmed_slot") == slot and state.get("pending_slot") != slot
            if not installed and timestamp(manifest.get('expires_at')) <= time.time():
                raise SecurityError('manifest_expired')
            policy = cached_policy(vehicle_dir(vin) / "trust.sqlite3",
                                   TRUST_ANCHORS / "root.pub", allow_expired=installed)
            pub = trusted_key(policy, manifest.get("key_id"), installed=installed)
            sig = (d / "manifest.sig").read_bytes().hex()
            if not verify_sm2(pub, canonical(manifest), sig, manifest["key_id"]):
                raise SecurityError("sm2_verify_failed")
            authority = manifest
            signature_checked = True
        else:
            # Only the exact root-approved baseline qualifies for this branch.
            authority = ensure_factory_image()
            signature_checked = True
        for field in ('version', 'rollback_index', 'size', 'chunk_size', 'sm3'):
            if meta.get(field) != authority.get(field):
                raise SecurityError('metadata_manifest_mismatch:' + field)
        if meta.get('vin') != vin:
            raise SecurityError('vin_mismatch')
        state = json.loads(boot_state_path(vin).read_text())
        floor = int(state.get('rollback_index', 0))
        counter = vehicle_dir(vin) / 'rollback_index'
        if counter.exists():
            floor = max(floor, int(counter.read_text().strip()))
        if authority['rollback_index'] < floor:
            raise SecurityError('rollback_index_regression')
        if payload.stat().st_size != authority['size']:
            raise SecurityError('payload_size_mismatch')
        actual, _ = scan_file(payload, int(authority['chunk_size']))
        if actual != authority['sm3']:
            raise SecurityError('payload_sm3_mismatch')
        if reference_slot and reference_slot != slot:
            ref = verify_slot(vin, reference_slot)
            if not ref['ok']:
                raise SecurityError('reference_slot_invalid')
            if authority['rollback_index'] < ref['rollback_index']:
                raise SecurityError('rollback_index_regression')
        return {'ok': True, 'slot': slot, 'reason': 'ok',
                'version': authority['version'], 'rollback_index': authority['rollback_index'],
                'signature_checked': signature_checked}
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error) as exc:
        return {'ok': False, 'slot': slot, 'reason': str(exc)}


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
        # 和提交状态一起落盘，避免主进程在 save_rollback 前中断后降低防降级下限。
        state["rollback_index"] = max(int(state.get("rollback_index", 0)), check["rollback_index"])
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
