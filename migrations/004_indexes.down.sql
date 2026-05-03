-- 004_indexes.down.sql
DROP INDEX IF EXISTS idx_audit_anchors_pending;
DROP INDEX IF EXISTS idx_audit_anchors_ledger_range;
DROP INDEX IF EXISTS idx_audit_log_event_type_created;
DROP INDEX IF EXISTS idx_audit_log_ledger_seq;
