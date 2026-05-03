package chain_test

import (
	"context"
	"database/sql"
	"os"
	"sort"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
)

// ── test infrastructure ───────────────────────────────────────────────────────

// setupTestDB starts an ephemeral Postgres container, applies all migrations in
// order, and returns a connected *sql.DB. The container and db are terminated /
// closed via t.Cleanup.
func setupTestDB(t *testing.T) *sql.DB {
	t.Helper()
	ctx := context.Background()

	pgc, err := tcpostgres.Run(ctx, "postgres:16-alpine",
		tcpostgres.WithDatabase("testaudit"),
		tcpostgres.WithUsername("testuser"),
		tcpostgres.WithPassword("testpass"),
		tcpostgres.BasicWaitStrategies(),
	)
	if err != nil {
		t.Fatalf("start postgres container: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(pgc); err != nil {
			t.Logf("terminate container: %v", err)
		}
	})

	connStr, err := pgc.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}

	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	applyMigrations(t, ctx, db)
	return db
}

// applyMigrations runs 001–004 .sql files from the migrations/ directory.
// The test working directory is chain/, so migrations are at ../migrations/.
func applyMigrations(t *testing.T, ctx context.Context, db *sql.DB) {
	t.Helper()
	migrations := []string{
		"../migrations/001_audit_log.sql",
		"../migrations/002_audit_ledgers.sql",
		"../migrations/003_audit_anchors.sql",
		"../migrations/004_indexes.sql",
	}
	for _, f := range migrations {
		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", f, err)
		}
	}
}

// createLedger inserts an audit_ledgers row for use in tests.
func createLedger(t *testing.T, db *sql.DB, ledger string) {
	t.Helper()
	ctx := context.Background()
	_, err := db.ExecContext(ctx,
		`INSERT INTO audit_ledgers (ledger, last_sequence, last_entry_hash)
		 VALUES ($1, 0, '')
		 ON CONFLICT (ledger) DO NOTHING`,
		ledger,
	)
	if err != nil {
		t.Fatalf("create ledger %q: %v", ledger, err)
	}
}

// ── TestMigrations ────────────────────────────────────────────────────────────

// TestMigrations verifies that migrations apply cleanly and that down migrations
// cleanly remove all objects (used by make test-migrations).
func TestMigrations_UpAndDown(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t) // already applied up

	// Verify tables exist.
	for _, table := range []string{"audit_log", "audit_ledgers", "audit_anchors"} {
		var n int
		err := db.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.tables
			 WHERE table_schema='public' AND table_name=$1`, table).Scan(&n)
		if err != nil || n == 0 {
			t.Errorf("table %q not found after up migrations", table)
		}
	}

	// Apply down migrations in reverse.
	downs := []string{
		"../migrations/004_indexes.down.sql",
		"../migrations/003_audit_anchors.down.sql",
		"../migrations/002_audit_ledgers.down.sql",
		"../migrations/001_audit_log.down.sql",
	}
	for _, f := range downs {
		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read down migration %s: %v", f, err)
		}
		if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply down migration %s: %v", f, err)
		}
	}

	// Verify tables gone.
	for _, table := range []string{"audit_log", "audit_ledgers", "audit_anchors"} {
		var n int
		_ = db.QueryRowContext(ctx,
			`SELECT count(*) FROM information_schema.tables
			 WHERE table_schema='public' AND table_name=$1`, table).Scan(&n)
		if n != 0 {
			t.Errorf("table %q still exists after down migrations", table)
		}
	}

	// Re-apply up migrations to leave the DB in a usable state.
	applyMigrations(t, ctx, db)
}

// ── Append tests ──────────────────────────────────────────────────────────────

func TestAppend_FirstEntry_SetsEmptyPrevHash(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	createLedger(t, db, "test-ledger")
	a := chain.NewAppender(db)

	seq, hash, err := a.Append(ctx, "test-ledger", "event.x", []byte(`{"k":1}`), "actor")
	if err != nil {
		t.Fatal(err)
	}
	if seq != 1 {
		t.Errorf("expected sequence 1, got %d", seq)
	}
	if len(hash) != 64 {
		t.Errorf("expected 64-char hash, got %d: %s", len(hash), hash)
	}

	// First entry must have empty prev_entry_hash.
	var prev string
	err = db.QueryRowContext(ctx,
		"SELECT prev_entry_hash FROM audit_log WHERE ledger=$1 AND sequence=1", "test-ledger",
	).Scan(&prev)
	if err != nil {
		t.Fatal(err)
	}
	if prev != "" {
		t.Errorf("genesis entry prev_entry_hash = %q, want empty", prev)
	}
}

func TestAppend_SecondEntry_LinksPrevHash(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	createLedger(t, db, "test-ledger")
	a := chain.NewAppender(db)

	_, h1, err := a.Append(ctx, "test-ledger", "event.x", []byte(`{"k":1}`), "")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = a.Append(ctx, "test-ledger", "event.x", []byte(`{"k":2}`), "")
	if err != nil {
		t.Fatal(err)
	}

	var prev string
	db.QueryRowContext(ctx,
		"SELECT prev_entry_hash FROM audit_log WHERE ledger=$1 AND sequence=2", "test-ledger",
	).Scan(&prev)
	if prev != h1 {
		t.Errorf("expected prev_entry_hash=%s, got %s", h1, prev)
	}
}

func TestAppend_EntryHashMatchesChainComputation(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	createLedger(t, db, "test-ledger")
	a := chain.NewAppender(db)

	payload := []byte(`{"amount_cents":2000,"item_id":"abc"}`)
	seq, gotHash, err := a.Append(ctx, "test-ledger", "contribution.captured", payload, "stripe")
	if err != nil {
		t.Fatal(err)
	}

	// Recompute entry hash independently.
	ph, err := chain.PayloadHash(payload)
	if err != nil {
		t.Fatal(err)
	}
	wantHash := chain.EntryHash(seq, "test-ledger", "contribution.captured", ph, "")
	if gotHash != wantHash {
		t.Errorf("returned hash %s doesn't match independently computed %s", gotHash, wantHash)
	}
}

func TestAppend_UnknownLedger_ReturnsError(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	a := chain.NewAppender(db)

	_, _, err := a.Append(ctx, "no-such-ledger", "event.x", []byte(`{}`), "")
	if err == nil {
		t.Error("expected error for unknown ledger")
	}
}

// ── AppendTx tests ────────────────────────────────────────────────────────────

func TestAppendTx_ParticipatesInCallerTransaction(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	createLedger(t, db, "test-ledger")
	a := chain.NewAppender(db)

	// Caller starts a transaction, appends, then ROLLS BACK.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq, _, err := a.AppendTx(ctx, tx, "test-ledger", "event.x", []byte(`{}`), "actor")
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if seq == 0 {
		_ = tx.Rollback()
		t.Error("expected non-zero sequence")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	// After rollback, no row must exist for that sequence.
	var count int
	db.QueryRowContext(ctx,
		"SELECT count(*) FROM audit_log WHERE ledger=$1 AND sequence=$2",
		"test-ledger", seq,
	).Scan(&count)
	if count != 0 {
		t.Errorf("rolled-back entry still present: count=%d", count)
	}

	// Ledger cursor must also be rolled back (still 0).
	var lastSeq int64
	db.QueryRowContext(ctx,
		"SELECT last_sequence FROM audit_ledgers WHERE ledger=$1", "test-ledger",
	).Scan(&lastSeq)
	if lastSeq != 0 {
		t.Errorf("ledger last_sequence after rollback = %d, want 0", lastSeq)
	}
}

func TestAppendTx_CommitPersistsEntry(t *testing.T) {
	ctx := context.Background()
	db := setupTestDB(t)
	createLedger(t, db, "test-ledger")
	a := chain.NewAppender(db)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	seq, hash, err := a.AppendTx(ctx, tx, "test-ledger", "event.x", []byte(`{"v":1}`), "")
	if err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	var storedHash string
	db.QueryRowContext(ctx,
		"SELECT entry_hash FROM audit_log WHERE ledger=$1 AND sequence=$2",
		"test-ledger", seq,
	).Scan(&storedHash)
	if storedHash != hash {
		t.Errorf("stored hash %s != returned hash %s", storedHash, hash)
	}
}

// ── Concurrency test ──────────────────────────────────────────────────────────

func TestAppend_ConcurrentAppends_MonotonicSequence(t *testing.T) {
	// 50 goroutines × 10 entries each = 500 total.
	// Sequences must be 1..500 with no gaps or duplicates.
	const (
		goroutines      = 50
		entriesEach     = 10
		totalEntries    = goroutines * entriesEach
	)

	ctx := context.Background()
	db := setupTestDB(t)
	createLedger(t, db, "concurrent-ledger")
	a := chain.NewAppender(db)

	var (
		mu   sync.Mutex
		seqs []int64
		wg   sync.WaitGroup
		errs []error
	)

	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gID int) {
			defer wg.Done()
			for i := 0; i < entriesEach; i++ {
				seq, _, err := a.Append(ctx, "concurrent-ledger", "stress.event",
					[]byte(`{"g":1}`), "")
				mu.Lock()
				if err != nil {
					errs = append(errs, err)
				} else {
					seqs = append(seqs, seq)
				}
				mu.Unlock()
			}
		}(g)
	}
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d append errors; first: %v", len(errs), errs[0])
	}
	if len(seqs) != totalEntries {
		t.Fatalf("expected %d sequences, got %d", totalEntries, len(seqs))
	}

	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for i, seq := range seqs {
		if seq != int64(i+1) {
			t.Errorf("sequence gap at position %d: got %d, want %d", i, seq, i+1)
			break
		}
	}
}
