-- 003_audit_anchors.sql: external anchor records per provider
CREATE TABLE IF NOT EXISTS audit_anchors (
    id            BIGSERIAL    PRIMARY KEY,
    ledger        VARCHAR(64)  NOT NULL,
    range_start   BIGINT       NOT NULL,
    range_end     BIGINT       NOT NULL,
    merkle_root   VARCHAR(128) NOT NULL,
    provider      VARCHAR(50)  NOT NULL,
    external_id   VARCHAR(512),
    proof_data    BYTEA,
    confirmation  VARCHAR(20)  NOT NULL DEFAULT 'pending',
    anchored_at   TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    confirmed_at  TIMESTAMPTZ,
    finalized_at  TIMESTAMPTZ
);
