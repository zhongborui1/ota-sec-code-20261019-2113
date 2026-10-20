#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"

DURATION="${1:-21600}"
LOGDIR="$ROOT/data/continuous"
mkdir -p "$LOGDIR"

echo "=== 启动持续运行系统 (运行 ${DURATION}s) ==="

"$ROOT/scripts/continuous/stop.sh" >/dev/null 2>&1 || true

# 记录本次运行的基线（用于计算本次增量）
for f in workload-results attack-results rotation-results; do
  if [ -f "$LOGDIR/$f.jsonl" ]; then
    wc -l < "$LOGDIR/$f.jsonl" | tr -d ' ' > "$LOGDIR/$f.baseline"
  else
    echo 0 > "$LOGDIR/$f.baseline"
  fi
done
echo "[OK] 已记录本次运行的基线（用于计算增量）"

nohup python3 "$ROOT/scripts/continuous/key_generator.py" \
  > "$LOGDIR/key_generator.out" 2>&1 &
echo $! > "$LOGDIR/key_generator.pid"
echo "[OK] key_generator (pid $(cat $LOGDIR/key_generator.pid))"

nohup python3 "$ROOT/scripts/continuous/auto_rotator.py" \
  > "$LOGDIR/auto_rotator.out" 2>&1 &
echo $! > "$LOGDIR/auto_rotator.pid"
echo "[OK] auto_rotator (pid $(cat $LOGDIR/auto_rotator.pid))"

nohup python3 "$ROOT/scripts/continuous/continuous_workload.py" "$DURATION" \
  > "$LOGDIR/workload.out" 2>&1 &
echo $! > "$LOGDIR/workload.pid"
echo "[OK] continuous_workload (pid $(cat $LOGDIR/workload.pid))"

nohup python3 "$ROOT/scripts/continuous/continuous_attacks.py" "$DURATION" \
  > "$LOGDIR/attacks.out" 2>&1 &
echo $! > "$LOGDIR/attacks.pid"
echo "[OK] continuous_attacks (pid $(cat $LOGDIR/attacks.pid))"

nohup python3 "$ROOT/scripts/continuous/monitor.py" "$DURATION" \
  > "$LOGDIR/monitor.out" 2>&1 &
echo $! > "$LOGDIR/monitor.pid"
echo "[OK] monitor (pid $(cat $LOGDIR/monitor.pid))"

echo
echo "所有组件已启动。日志：$LOGDIR/"
