-- 002_audit_ledgers.sql: ledger state cursor (FOR UPDATE serialization target)
CREATE TABLE IF NOT EXISTS audit_ledgers (
    ledger                VARCHAR(64)  PRIMARY KEY,
    last_sequence         BIGINT       NOT NULL DEFAULT 0,
    last_entry_hash       VARCHAR(128) NOT NULL DEFAULT '',
    description           TEXT,
    anchor_provider_names TEXT[],
    anchor_schedule       VARCHAR(64)
);
