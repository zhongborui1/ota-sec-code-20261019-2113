-- 审计表索引（追加到已有 schema）
CREATE INDEX IF NOT EXISTS idx_audit_log_created_at ON audit_log(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_log_key_id ON audit_log(key_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_result ON audit_log(result);
CREATE INDEX IF NOT EXISTS idx_audit_log_resource_id ON audit_log(resource_id);
-- 复合索引：常用查询模式
CREATE INDEX IF NOT EXISTS idx_audit_log_action_created
    ON audit_log(action, created_at DESC);
-- JSONB 索引：按 detail.reason 查询
CREATE INDEX IF NOT EXISTS idx_audit_log_detail_reason
    ON audit_log((detail->>'reason'))
    WHERE detail ? 'reason';
