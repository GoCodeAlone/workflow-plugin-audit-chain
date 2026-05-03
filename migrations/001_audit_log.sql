-- 001_audit_log.sql: append-only hash-chained event log
CREATE TABLE IF NOT EXISTS audit_log (
    id                BIGSERIAL PRIMARY KEY,
    sequence          BIGINT        NOT NULL,
    ledger            VARCHAR(64)   NOT NULL,
    event_type        VARCHAR(100)  NOT NULL,
    payload           JSONB         NOT NULL,
    payload_hash      VARCHAR(128)  NOT NULL,
    prev_entry_hash   VARCHAR(128)  NOT NULL DEFAULT '',
    entry_hash        VARCHAR(128)  NOT NULL,
    created_at        TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    appended_by_actor VARCHAR(255),
    metadata          JSONB
);
