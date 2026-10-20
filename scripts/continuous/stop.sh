#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
LOGDIR="$ROOT/data/continuous"

for name in key_generator auto_rotator workload attacks monitor; do
  pidfile="$LOGDIR/$name.pid"
  if [ -f "$pidfile" ]; then
    pid=$(cat "$pidfile")
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
      echo "[OK] 停止 $name (pid $pid)"
    fi
    rm -f "$pidfile"
  fi
done
