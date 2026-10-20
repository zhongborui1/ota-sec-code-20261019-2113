#!/usr/bin/env bash
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOGDIR="$ROOT/data/continuous"

echo "=== 持续运行状态 ==="
for name in key_generator auto_rotator workload attacks monitor; do
  pidfile="$LOGDIR/$name.pid"
  if [ -f "$pidfile" ] && kill -0 "$(cat $pidfile)" 2>/dev/null; then
    echo "  [RUN]  $name (pid $(cat $pidfile))"
  else
    echo "  [STOP] $name"
  fi
done

echo
echo "=== 关键统计（历史累计）==="
[ -f "$LOGDIR/workload-results.jsonl" ] && \
  echo "workload: $(wc -l < $LOGDIR/workload-results.jsonl) 次升级"
[ -f "$LOGDIR/attack-results.jsonl" ] && \
  echo "attacks:  $(wc -l < $LOGDIR/attack-results.jsonl) 次攻击"
[ -f "$LOGDIR/rotation-results.jsonl" ] && \
  echo "rotation: $(wc -l < $LOGDIR/rotation-results.jsonl) 次轮换"
echo
echo "密钥池: $(ls -d $ROOT/pki/signing-* 2>/dev/null | wc -l) 把"

echo
echo "=== 本次测试增量（相对上次 start.sh）==="
calc_delta() {
  local name=$1
  local jsonl="$LOGDIR/$name.jsonl"
  local baseline="$LOGDIR/$name.baseline"
  local total=0 base=0
  [ -f "$jsonl" ] && total=$(wc -l < "$jsonl" | tr -d ' ')
  [ -f "$baseline" ] && base=$(cat "$baseline")
  echo $((total - base))
}

wl_delta=$(calc_delta workload-results)
at_delta=$(calc_delta attack-results)
ro_delta=$(calc_delta rotation-results)

echo "workload: ${wl_delta} 次升级"
echo "attacks:  ${at_delta} 次攻击"
echo "rotation: ${ro_delta} 次轮换"
