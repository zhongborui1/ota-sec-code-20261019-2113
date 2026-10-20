#!/usr/bin/env python3
"""
单次"上电启动"进程。

由 simulator.py 以独立子进程方式拉起（每个进程 = 一次重启），
读取持久化的 boot_state，对备用分区做启动自检，然后：
  - 通过：切换 active_slot、phase=COMMITTED        退出码 0
  - 失败未达阈值：phase=BOOT_FAILED，等待下次重启     退出码 3
  - 达到阈值：回退到原分区并校验旧分区                退出码 2
  - 旧分区也不可用：BRICKED                          退出码 4

只做本地校验：不访问云端，不依赖网络（真实 ECU 启动阶段就是离线的）。
"""
import argparse
import json
import os
import sys

from installer import boot_once, boot_state_path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--vin", required=True)
    args = ap.parse_args()

    try:
        out = boot_once(args.vin)
    except Exception as e:
        print(json.dumps({"result": "error", "error": f"{type(e).__name__}: {e}"},
                         ensure_ascii=False))
        return 5

    state = json.loads(boot_state_path(args.vin).read_text())
    out["pid"] = os.getpid()
    out["phase"] = state.get("phase")
    out["active_slot"] = state.get("active_slot")
    out["boot_counter"] = state.get("boot_counter")
    print(json.dumps(out, ensure_ascii=False))

    return {"committed": 0, "rolled_back": 2, "retry": 3,
            "bricked": 4}.get(out["result"], 5)


if __name__ == "__main__":
    sys.exit(main())
