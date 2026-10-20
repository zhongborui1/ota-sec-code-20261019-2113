#!/usr/bin/env bash
# 压力测试：100 车 × 3 次 + 500 车 × 1 次
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo "压力测试"
echo "============================================================"
echo "开始: $(date -Iseconds)"
echo

mkdir -p evidence/raw

for run in 1 2 3; do
  echo "--- 100 车第 $run 次 ---"
  python3 services/vehicle-sim/simulator.py 100 2>&1 | tee /tmp/stress-100-$run.txt | \
    grep -E "总耗时|成功|失败|成功率" || true
  echo
done

echo "--- 500 车 ---"
python3 services/vehicle-sim/simulator.py 500 2>&1 | tee /tmp/stress-500.txt | \
  grep -E "总耗时|成功|失败|成功率" || true

echo
echo "============================================================"
echo "完成: $(date -Iseconds)"
echo "============================================================"
