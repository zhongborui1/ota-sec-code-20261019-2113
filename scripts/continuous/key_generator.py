#!/usr/bin/env python3
"""
密钥生成器：持续生成新密钥，随机间隔（泊松过程）。

生成算法依据：
- GB/T 32918.1-2016《SM2椭圆曲线公钥密码算法 第1部分：总则》
  第6章 密钥对生成：随机数 d ∈ [1, n-1]，计算 P = [d]G
- 私钥随机数来源：GmSSL 底层 OpenSSL CSPRNG
  符合 GM/T 0005-2021《随机性检测规范》要求

密钥生命周期依据：
- GM/T 0034-2014 覆盖：生成 → 注册(prepared) → 激活(active) → 撤销(revoked) → 归档
"""
import json, os, random, subprocess, time
import urllib.request
from datetime import datetime
from pathlib import Path

ROOT = Path("/home/rjh/ota-sec")
PKI_DIR = ROOT / "pki"
OTA_API = "http://127.0.0.1:8080"

AVG_INTERVAL_S = 120
MAX_KEYS = 50

LOG = ROOT / "data" / "continuous" / "key-generator.log"
LOG.parent.mkdir(parents=True, exist_ok=True)


def log(msg):
    line = f"[{datetime.now().isoformat()}] {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def count_existing_keys():
    return len([d for d in PKI_DIR.glob("signing-*") if d.is_dir()])


def gen_key_id():
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    suffix = "%04x" % random.randint(0, 0xFFFF)
    return f"{ts}-{suffix}"


def generate_key(key_id):
    d = PKI_DIR / f"signing-{key_id}"
    if d.exists():
        log(f"[SKIP] {key_id} 已存在")
        return None
    d.mkdir(parents=True)
    key_file = d / "signing.key"
    pub_file = d / "signing.pub"
    key_pass = f"{key_id}pass"

    log(f"[STD] 依据 GB/T 32918.1-2016 第6章生成密钥对")
    log(f"[STD] 随机数源：GmSSL/OpenSSL CSPRNG（GM/T 0005-2021 合规）")

    r = subprocess.run([
        "gmssl", "sm2keygen",
        "-pass", key_pass,
        "-out", str(key_file),
        "-pubout", str(pub_file),
    ], capture_output=True, text=True)
    if r.returncode != 0:
        log(f"[FAIL] 生成 {key_id}: {r.stderr}")
        return None

    os.chmod(key_file, 0o600)
    os.chmod(pub_file, 0o644)
    log(f"[NEW] 密钥 {key_id} 已生成")
    return key_id


def register_to_trust(key_id):
    try:
        with urllib.request.urlopen(f"{OTA_API}/trust-metadata", timeout=10) as r:
            trust = json.loads(r.read().decode())
        kid = f"ota-signing-{key_id}"
        if kid in trust["keys"]:
            log(f"[SKIP] {kid} 已在 trust")
            return
        body = json.dumps({"keys": {
            kid: {"status": "prepared",
                  "not_before": datetime.utcnow().isoformat() + "Z",
                  "not_after": "2030-01-01T00:00:00Z"}
        }}).encode()
        req = urllib.request.Request(f"{OTA_API}/admin/rotate-trust",
                                     data=body,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
        log(f"[TRUST] {kid} 已注册为 prepared")
    except Exception as e:
        log(f"[FAIL] 注册 {key_id}: {type(e).__name__}: {e}")


def main():
    log("=" * 50)
    log(f"密钥生成器启动 (泊松 λ=1/{AVG_INTERVAL_S}s, 上限 {MAX_KEYS})")
    log("=" * 50)
    while True:
        n = count_existing_keys()
        if n >= MAX_KEYS:
            log(f"[WAIT] 密钥池已满 ({n}/{MAX_KEYS})")
            time.sleep(AVG_INTERVAL_S)
            continue
        wait = random.expovariate(1.0 / AVG_INTERVAL_S)
        log(f"[WAIT] 下次生成在 {wait:.1f}s 后")
        time.sleep(wait)
        key_id = gen_key_id()
        if generate_key(key_id):
            register_to_trust(key_id)


if __name__ == "__main__":
    main()
