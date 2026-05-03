package chain

import (
	"context"
	"database/sql"
	"fmt"
)

// Appender writes hash-chained audit entries to Postgres.
// It serialises concurrent appends to the same ledger via a
// SELECT … FOR UPDATE on the audit_ledgers row, which guarantees
// gap-free monotonic sequences without application-level locking.
type Appender struct {
	db *sql.DB
}

// NewAppender returns an Appender backed by db.
func NewAppender(db *sql.DB) *Appender {
	return &Appender{db: db}
}

// Append opens its own transaction, appends one entry to ledger, and commits.
// metadata is stored as-is in audit_log.metadata (JSONB); pass nil if not needed.
// Returns (sequence, entryHash, error).
func (a *Appender) Append(ctx context.Context, ledger, eventType string, payload, metadata []byte, actor string) (int64, string, error) {
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, "", fmt.Errorf("chain.Append: begin tx: %w", err)
	}
	seq, hash, err := a.AppendTx(ctx, tx, ledger, eventType, payload, metadata, actor)
	if err != nil {
		_ = tx.Rollback()
		return 0, "", err
	}
	if err := tx.Commit(); err != nil {
		return 0, "", fmt.Errorf("chain.Append: commit: %w", err)
	}
	return seq, hash, nil
}

// AppendTx appends one entry within the caller-supplied transaction tx.
// The caller is responsible for commit/rollback. This is the primitive used
// by BMW PR 11 Task 47 (step.bmw.audit_append_with_map) so that the audit
// entry and the business record land in a single atomic transaction.
// metadata is stored as-is in audit_log.metadata (JSONB); pass nil if not needed.
func (a *Appender) AppendTx(ctx context.Context, tx *sql.Tx, ledger, eventType string, payload, metadata []byte, actor string) (int64, string, error) {
	// 0. Enforce a server-side lock timeout so a stalled holder surfaces as an
	//    error rather than blocking indefinitely.
	if _, err := tx.ExecContext(ctx, `SET LOCAL lock_timeout = '5s'`); err != nil {
		return 0, "", fmt.Errorf("chain.AppendTx: set lock_timeout: %w", err)
	}

	// 1. Lock the ledger row and read the current cursor.
	var lastSeq int64
	var lastHash string
	err := tx.QueryRowContext(ctx,
		`SELECT last_sequence, last_entry_hash
		   FROM audit_ledgers
		  WHERE ledger = $1
		    FOR UPDATE`,
		ledger,
	).Scan(&lastSeq, &lastHash)
	if err == sql.ErrNoRows {
		return 0, "", fmt.Errorf("chain.AppendTx: unknown ledger %q", ledger)
	}
	if err != nil {
		return 0, "", fmt.Errorf("chain.AppendTx: lock ledger: %w", err)
	}

	// 2. Compute hashes.
	payloadHash, err := PayloadHash(payload)
	if err != nil {
		return 0, "", fmt.Errorf("chain.AppendTx: %w", err)
	}
	seq := lastSeq + 1
	// For the genesis entry, prevHash is empty ("").
	entryHash := EntryHash(seq, ledger, eventType, payloadHash, lastHash)

	// 3. Insert the audit log row.
	// created_at uses DB-server NOW() to avoid application clock skew in
	// multi-node deployments.
	_, err = tx.ExecContext(ctx,
		`INSERT INTO audit_log
		        (sequence, ledger, event_type, payload, payload_hash,
		         prev_entry_hash, entry_hash, created_at, appended_by_actor, metadata)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, $9)`,
		seq, ledger, eventType, payload, payloadHash,
		lastHash, entryHash, actor, metadata,
	)
	if err != nil {
		return 0, "", fmt.Errorf("chain.AppendTx: insert audit_log: %w", err)
	}

	// 4. Advance the ledger cursor.
	_, err = tx.ExecContext(ctx,
		`UPDATE audit_ledgers
		    SET last_sequence = $2, last_entry_hash = $3
		  WHERE ledger = $1`,
		ledger, seq, entryHash,
	)
	if err != nil {
		return 0, "", fmt.Errorf("chain.AppendTx: update audit_ledgers: %w", err)
	}

	return seq, entryHash, nil
}
