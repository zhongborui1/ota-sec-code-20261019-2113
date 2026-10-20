#!/usr/bin/env bash
# 审计表汇总查询
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

mkdir -p evidence/docker/2026-10-10/audit
OUT="evidence/docker/2026-10-10/audit/comprehensive-audit-report.txt"

{
  echo "============================================================"
  echo "审计表综合报告"
  echo "============================================================"
  echo "时间：$(date -Iseconds)"
  echo

  echo "--- 1. 总记录数 ---"
  docker exec ota-postgres psql -U ota -d ota -c "SELECT COUNT(*) FROM audit_log;"
  echo

  echo "--- 2. 按 action/result 分组 ---"
  docker exec ota-postgres psql -U ota -d ota -c "
    SELECT action, result, COUNT(*) AS count FROM audit_log
    GROUP BY action, result ORDER BY action, result;"
  echo

  echo "--- 3. 按 key_id 分组 ---"
  docker exec ota-postgres psql -U ota -d ota -c "
    SELECT COALESCE(key_id, '(system)') AS key_id, action, COUNT(*) 
    FROM audit_log GROUP BY key_id, action ORDER BY key_id, action;"
  echo

  echo "--- 4. v1 vs v2 签名与验签对比 ---"
  docker exec ota-postgres psql -U ota -d ota -c "
    SELECT key_id,
           COUNT(*) FILTER (WHERE action='sign-manifest') AS signs,
           COUNT(*) FILTER (WHERE action='verify-manifest' AND result='ok') AS verify_ok,
           COUNT(*) FILTER (WHERE action='verify-manifest' AND result='reject') AS verify_reject
    FROM audit_log
    WHERE key_id IS NOT NULL
    GROUP BY key_id ORDER BY key_id;"
  echo

  echo "--- 5. reject 原因分布 ---"
  docker exec ota-postgres psql -U ota -d ota -c "
    SELECT detail->>'reason' AS reason, COUNT(*) 
    FROM audit_log 
    WHERE result='reject' AND detail ? 'reason'
    GROUP BY reason ORDER BY count DESC;"
  echo

  echo "--- 6. 密钥轮换时间线 ---"
  docker exec ota-postgres psql -U ota -d ota -c "
    SELECT created_at, action, result FROM audit_log
    WHERE action='rotate-trust' ORDER BY created_at;"
  echo

  echo "--- 7. 最近 10 条记录 ---"
  docker exec ota-postgres psql -U ota -d ota -c "
    SELECT id, created_at, action, key_id, result FROM audit_log
    ORDER BY id DESC LIMIT 10;"
  echo

  echo "============================================================"
} | tee "$OUT"

echo
echo "报告已保存: $OUT"
