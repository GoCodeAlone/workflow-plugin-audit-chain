-- 004_indexes.sql: performance and uniqueness indexes
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_log_ledger_seq
    ON audit_log(ledger, sequence);

CREATE INDEX IF NOT EXISTS idx_audit_log_event_type_created
    ON audit_log(ledger, event_type, created_at);

CREATE INDEX IF NOT EXISTS idx_audit_anchors_ledger_range
    ON audit_anchors(ledger, range_start, range_end);

-- Partial index for polling pending/confirmed anchors (skip finalized rows).
CREATE INDEX IF NOT EXISTS idx_audit_anchors_pending
    ON audit_anchors(provider, confirmation)
    WHERE confirmation != 'finalized';
