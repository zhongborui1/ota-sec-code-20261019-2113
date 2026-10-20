#!/usr/bin/env bash
# 500 车 × 3 次，统计方差
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "============================================================"
echo "500 车 × 3 次压力测试"
echo "============================================================"
echo "开始: $(date -Iseconds)"
echo

declare -a totals
declare -a rates

for run in 1 2 3; do
  echo "--- 第 $run 次 ---"
  out=$(python3 services/vehicle-sim/simulator.py 500 2>&1)
  total=$(echo "$out" | grep "^总耗时" | awk '{print $2}')
  rate=$(echo "$out" | grep "^成功率" | awk '{print $2}' | tr -d '%')
  success=$(echo "$out" | grep "^成功:" | awk '{print $2}')
  totals+=("$total")
  rates+=("$rate")
  echo "  总耗时: ${total}s，成功率: ${rate}%，$success"
  echo
done

echo "============================================================"
echo "统计"
echo "============================================================"
python3 -c "
import sys
totals = [$(IFS=,; echo "${totals[*]}")]
rates = [$(IFS=,; echo "${rates[*]}")]
import statistics
print(f'总耗时: {totals}')
print(f'  平均: {statistics.mean(totals):.2f}s')
print(f'  标准差: {statistics.stdev(totals):.2f}s')
print(f'  最小/最大: {min(totals):.2f}s / {max(totals):.2f}s')
print(f'成功率: {rates}')
print(f'  全部: {all(r==100.0 for r in rates)}')
"

echo "完成: $(date -Iseconds)"
