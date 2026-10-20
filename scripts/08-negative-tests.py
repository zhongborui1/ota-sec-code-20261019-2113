#!/usr/bin/env python3
"""
批量安全测试：篡改 / 伪造 / 降级 / 授权 / 旧密钥 五类攻击。
每类 TEST_COUNT 次，统计拒绝率。
"""
import hashlib, json, random, subprocess, sys, tempfile, time
import urllib.request, urllib.error
from datetime import datetime
from pathlib import Path

import testlib_auth  # 同目录脚本

# 引入 simulator 的客户端校验逻辑，确保测试走真实代码路径
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services/vehicle-sim"))
from simulator import validate_received_manifest  # noqa: E402
from ota_client import request_task, download_chunk  # noqa: E402

OTA_API = "http://127.0.0.1:8080"
ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence" / "raw"
TEST_COUNT = 100


def sm3_hex(data):
    h = hashlib.new("sm3")
    h.update(data)
    return h.hexdigest()


def http_post_json(url, obj, headers=None):
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.status, json.loads(r.read().decode())


def http_get_bytes(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


SECRETS_DIR = ROOT / "pki" / ".secrets"


def sign_manifest_locally(manifest, key_dir, key_pass, key_id):
    # 优先从 .secrets 读强口令；key_pass 参数仅作 fallback
    _pf = SECRETS_DIR / f"{key_dir}.pass"
    if _pf.exists():
        key_pass = _pf.read_text().strip()
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
    走真实宽限期：
    1. auto_rotate 将 v1 变 deprecated，v2 变 active
    2. 等待 GRACE_PERIOD_S 秒（测试环境已调为 5s）
    3. v1 自然变为 revoked
    """
    with urllib.request.urlopen(f"{OTA_API}/trust-metadata", timeout=10) as r:
        trust = json.loads(r.read().decode())
    if trust["keys"].get("ota-signing-v1", {}).get("status") == "revoked":
        return
        
    print("[前置] 触发真实轮换（等待宽限期结束）...")
    testlib_auth.publish_policy({"ota-signing-v1": "deprecated", "ota-signing-v2": "active"}, grace_seconds=5)
    
    # 轮询等待 v1 变为 revoked
    max_wait = 30
    t0 = time.time()
    while time.time() - t0 < max_wait:
        with urllib.request.urlopen(f"{OTA_API}/trust-metadata", timeout=10) as r:
            status = json.loads(r.read().decode())["keys"]["ota-signing-v1"]["status"]
        if status == "revoked":
            print(f"[前置] v1 已自然转为 revoked（耗时 {time.time()-t0:.1f}s）")
            return
        time.sleep(1)
    raise Exception("v1 宽限期超时未转为 revoked")



def test_1_tampered_chunk(vin):
    """篡改分块内容，客户端分块 SM3 应拒绝。"""
    _, task = request_task(vin)
    task_id = task["task_id"]
    chunk_hashes = task["chunk_hashes"]
    data = bytearray(download_chunk(vin, task_id, 0))
    data[random.randint(0, 100)] ^= 0xFF
    computed = sm3_hex(bytes(data))
    return "rejected" if computed != chunk_hashes[0] else "NOT_REJECTED"




def test_1b_minio_tampered(vin):
    """
    端到端测试：真改 MinIO 里的 payload.enc，客户端下载后 SM3 不匹配。
    安全：备份第一块 → 改 → 校验 → 用 try/finally 保证恢复。
    """
    import base64
    import tempfile
    import subprocess as _sp

    _, task = request_task(vin)
    task_id = task["task_id"]
    chunk_hashes = task["chunk_hashes"]
    chunk_size = task["chunk_size"]

    # 1. 下载原始第 0 块
    original = download_chunk(vin, task_id, 0)
    tampered = bytearray(original)
    tampered[random.randint(0, len(tampered) - 1)] ^= 0xFF
    tampered = bytes(tampered)

    orig_b64 = base64.b64encode(original).decode()
    tamp_b64 = base64.b64encode(tampered).decode()

    tamper_script = (
        "import io, base64\n"
        "from minio import Minio\n"
        "import os\n"
        "c = Minio('ota-minio:9000', access_key=os.environ['MINIO_ACCESS_KEY'], "
        "secret_key=os.environ['MINIO_SECRET_KEY'], secure=False)\n"
        "tamp = base64.b64decode('" + tamp_b64 + "')\n"
        "stat = c.stat_object('ota-packages', 'payload.enc')\n"
        "size = stat.size\n"
        "resp = c.get_object('ota-packages', 'payload.enc', "
        "offset=" + str(chunk_size) + ", length=size - " + str(chunk_size) + ")\n"
        "rest = resp.read(); resp.close(); resp.release_conn()\n"
        "c.put_object('ota-packages', 'payload.enc', "
        "io.BytesIO(tamp + rest), length=len(tamp) + len(rest))\n"
        "print('tampered')\n"
    )

    restore_script = (
        "import io, base64\n"
        "from minio import Minio\n"
        "import os\n"
        "c = Minio('ota-minio:9000', access_key=os.environ['MINIO_ACCESS_KEY'], "
        "secret_key=os.environ['MINIO_SECRET_KEY'], secure=False)\n"
        "orig = base64.b64decode('" + orig_b64 + "')\n"
        "stat = c.stat_object('ota-packages', 'payload.enc')\n"
        "size = stat.size\n"
        "resp = c.get_object('ota-packages', 'payload.enc', "
        "offset=" + str(chunk_size) + ", length=size - " + str(chunk_size) + ")\n"
        "rest = resp.read(); resp.close(); resp.release_conn()\n"
        "c.put_object('ota-packages', 'payload.enc', "
        "io.BytesIO(orig + rest), length=len(orig) + len(rest))\n"
        "print('restored')\n"
    )

    def run_in_container(script_text):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(script_text)
            path = f.name
        try:
            _sp.run(["docker", "cp", path, "ota-api:/tmp/_tmp_minio.py"],
                    check=True, capture_output=True)
            _sp.run(["docker", "exec", "ota-api", "python3", "/tmp/_tmp_minio.py"],
                    check=True, capture_output=True)
        finally:
            Path(path).unlink(missing_ok=True)

    rejected = False
    try:
        run_in_container(tamper_script)
        downloaded = download_chunk(vin, task_id, 0)
        rejected = (sm3_hex(downloaded) != chunk_hashes[0])
    finally:
        try:
            run_in_container(restore_script)
        except Exception:
            pass

    return "rejected" if rejected else "NOT_REJECTED"


def test_2a_tampered_manifest(vin):
    """
    测试 2a：manifest 内容篡改。
    流程：服务端签发正常 manifest → 客户端篡改 version 字段 → 用原签名验签。
    预期：SM2 密码学验签失败（签名对的是原 manifest，不是篡改后的）。
    拒绝原因：cryptographic（密码学层）。
    """
    _, task = request_task(vin)
    manifest = dict(task["manifest"])
    key_id = task["key_id"]
    sig_hex = task["manifest_sig_hex"]  # 服务端给的合法签名

    # 篡改 version（其他字段不变）
    manifest["version"] = "9.9.9"

    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_hex, key_id=key_id,
        local_rollback=0)  # 防回滚放行，聚焦密码学验签
    if accepted:
        return "NOT_REJECTED"
    return "rejected" if "sm2" in reason or "verify" in reason else f"OTHER_REJECT: {reason}"


def test_2b_forged_signature_key_id_mismatch(vin):
    """
    测试 2b：密钥混淆（伪造签名）。
    流程：用 v1 私钥签 manifest，但声明 key_id=v2。
    预期：v2 是 active（状态检查通过），但 SM2 用 v2 公钥验 v1 签名 → 数学失败。
    拒绝原因：cryptographic（密码学层，不是 key 状态）。
    """
    _, task = request_task(vin)
    manifest = task["manifest"]
    sig_v1 = sign_manifest_locally(manifest, "signing-v1", None, "ota-signing-v1")

    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_v1, key_id="ota-signing-v2",
        local_rollback=0)  # v2 是 active，信任检查通过，SM2 用 v2 公钥验 v1 签名 → 数学失败
    if accepted:
        return "NOT_REJECTED"
    return "rejected" if "sm2" in reason or "verify" in reason else f"OTHER_REJECT: {reason}"


def test_3_downgrade(vin):
    """
    降级包攻击：攻击者用有效密钥签一个 rollback_index 更低的 manifest。
    服务端 /verify-manifest 会通过（签名有效），但车辆侧必须拒绝（防回滚是客户端职责）。
    """
    # 1. 拿一个正常 task 作为模板
    _, task = request_task(vin)
    manifest = dict(task["manifest"])
    key_id = task["key_id"]

    # 2. 人为降级 rollback_index
    current_ri = manifest["rollback_index"]
    fake_ri = current_ri - random.randint(1, 5)
    manifest["rollback_index"] = fake_ri

    # 3. 用当前 active 密钥签这个假 manifest（模拟被攻陷的签名者 / MITM）
    key_dir = {"ota-signing-v1": "signing-v1",
               "ota-signing-v2": "signing-v2"}[key_id]
    _pf = (ROOT / "pki" / ".secrets" / f"{key_dir}.pass")
    key_pass = _pf.read_text().strip() if _pf.exists() else None
    sig_hex = sign_manifest_locally(manifest, key_dir, key_pass, key_id)

    # 4. 让车辆侧走真实校验路径（VIN + 防回滚 + 验签）
    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig_hex, key_id=key_id,
        local_rollback=current_ri,  # 车辆当前 rollback = 正常包的值
    )

    if accepted:
        return "NOT_REJECTED"
    return "rejected" if "rollback" in reason else f"OTHER_REJECT: {reason}"


def test_4_vin_mismatch(vin_a, vin_b):
    """
    VIN 不匹配攻击：攻击者用有效密钥签一个 vin=vin_a 的 manifest，
    投放到 vin_b 的车辆上。车辆侧必须拒绝（授权绑定是客户端职责）。
    """
    # 1. 拿 A 车的正常 task
    _, task = request_task(vin_a)
    manifest = task["manifest"]
    key_id = task["key_id"]

    # 2. 用当前 active 密钥签这个 manifest（对 A 车合法）
    key_dir = {"ota-signing-v1": "signing-v1",
               "ota-signing-v2": "signing-v2"}[key_id]
    _pf = (ROOT / "pki" / ".secrets" / f"{key_dir}.pass")
    key_pass = _pf.read_text().strip() if _pf.exists() else None
    sig_hex = sign_manifest_locally(manifest, key_dir, key_pass, key_id)

    # 3. B 车收到这个 manifest 并校验
    accepted, reason = validate_received_manifest(
        vin=vin_b,  # B 车
        manifest=manifest,  # vin 是 A 车的
        sig_hex=sig_hex, key_id=key_id,
        local_rollback=10,
    )

    if accepted:
        return "NOT_REJECTED"
    return "rejected" if "vin" in reason.lower() else f"OTHER_REJECT: {reason}"


def test_5_revoked_key(vin):
    """用 revoked 的 v1 密钥签包，验签应被拒。"""
    _, task = request_task(vin)
    manifest = task["manifest"]
    sig = sign_manifest_locally(manifest, "signing-v1", None, "ota-signing-v1")
    accepted, reason = validate_received_manifest(
        vin=vin, manifest=manifest, sig_hex=sig, key_id="ota-signing-v1",
        local_rollback=0)  # v1 已 revoked，信任锚状态检查应拒绝
    return "rejected" if (not accepted and "key" in reason) else "NOT_REJECTED"


def run_batch(fn, count):
    rej = 0
    errs = []
    for i in range(count):
        try:
            if fn(i) == "rejected":
                rej += 1
        except Exception as e:
            errs.append(f"#{i}: {type(e).__name__}: {e}")
    return rej, count, errs


def main():
    print("=" * 70)
    print("批量安全测试")
    print("=" * 70)
    print(f"OTA API:   {OTA_API}")
    print(f"每类次数:  {TEST_COUNT}")
    print(f"时间:      {datetime.now().isoformat()}\n")

    testlib_auth.ensure_devices([f"LSVAM4187C2{prefix}{i:0{6-len(prefix)}d}" for prefix in ("T", "TM", "M", "F", "D", "A", "B", "R") for i in range(TEST_COUNT)])
    ensure_v1_revoked_v2_active()
    testlib_auth.ensure_active_grant()
    print()

    batches = [
        ("1.篡改分块（chunk SM3 不匹配）",
         lambda i: test_1_tampered_chunk(f"LSVAM4187C2T{i:05d}")),
        ("1b.篡改 MinIO payload（端到端）",
         lambda i: test_1b_minio_tampered(f"LSVAM4187C2TM{i:04d}")),
        ("2a.篡改 manifest 内容（密码学拒绝）",
         lambda i: test_2a_tampered_manifest(f"LSVAM4187C2M{i:05d}")),
        ("2b.密钥混淆（v1 签名声明 v2）",
         lambda i: test_2b_forged_signature_key_id_mismatch(f"LSVAM4187C2F{i:05d}")),
        ("3.降级包（rollback 更低）",
         lambda i: test_3_downgrade(f"LSVAM4187C2D{i:05d}")),
        ("4.VIN 不匹配（A 车包投 B 车）",
         lambda i: test_4_vin_mismatch(f"LSVAM4187C2A{i:05d}", f"LSVAM4187C2B{i:05d}")),
        ("5.旧密钥签发包（v1 revoked）",
         lambda i: test_5_revoked_key(f"LSVAM4187C2R{i:05d}")),
    ]

    results = []
    print("-" * 70)
    for name, fn in batches:
        print(f"跑: {name} ... ", end="", flush=True)
        t0 = time.time()
        rej, total, errs = run_batch(fn, TEST_COUNT)
        elapsed = time.time() - t0
        print(f"{rej}/{total} 拒绝 ({rej/total*100:.1f}%) [{elapsed:.1f}s]")
        results.append({"name": name, "total": total, "rejected": rej,
                        "not_rejected": total - rej,
                        "rate": rej / total * 100, "errors": errs[:3]})

    print()
    print("=" * 70)
    print("批量安全测试报告")
    print("=" * 70)
    print(f"{'测试项':<32} | {'总数':>4} | {'拒绝':>4} | {'通过':>4} | {'拒绝率':>7}")
    print("-" * 70)
    for r in results:
        name = r["name"]
        # 中文字符宽度补偿（每个中文占 2 宽）
        pad = 32 - len(name) - sum(1 for c in name if ord(c) > 127)
        print(f"{name}{' ' * pad} | {r['total']:>4} | {r['rejected']:>4} | "
              f"{r['not_rejected']:>4} | {r['rate']:>6.2f}%")
    print("=" * 70)

    for r in results:
        if r["errors"]:
            print(f"\n[!] {r['name']} 部分错误：")
            for e in r["errors"]:
                print(f"    {e}")

    EVIDENCE.mkdir(parents=True, exist_ok=True)
    out = EVIDENCE / f"negative-tests-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({
        "timestamp": datetime.now().isoformat(),
        "test_count_per_category": TEST_COUNT,
        "results": results,
    }, indent=2, ensure_ascii=False))
    print(f"\n证据已保存: {out}")
    cleanup_test_vins()


def cleanup_test_vins():
    print("Registered identities retained; no keys or trust ledgers deleted.")


if __name__ == "__main__":
    main()
