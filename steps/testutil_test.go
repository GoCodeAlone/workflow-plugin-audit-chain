package steps_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
)

// ── mock AnchorProvider ───────────────────────────────────────────────────────

// mockAnchorProvider lets tests control the result returned by Verify and
// records the most recent Anchor argument so tests can assert on the values
// the handler propagated from Config / Input.
type mockAnchorProvider struct {
	providerName string
	verifyResult providers.Verification
	verifyErr    error
	lastAnchor   providers.Anchor
}

func (m *mockAnchorProvider) Name() string { return m.providerName }

func (m *mockAnchorProvider) Anchor(_ context.Context, _ providers.MerkleRoot) (providers.Anchor, error) {
	return providers.Anchor{}, nil
}

func (m *mockAnchorProvider) Verify(_ context.Context, a providers.Anchor) (providers.Verification, error) {
	m.lastAnchor = a
	return m.verifyResult, m.verifyErr
}

func (m *mockAnchorProvider) Cost(_ int) providers.Cost {
	return providers.Cost{}
}

// ── fake SQL driver ───────────────────────────────────────────────────────────
//
// A minimal database/sql/driver implementation that returns a single row
// containing "pending" for any SELECT query. Used to get past the
// `SELECT confirmation FROM audit_anchors WHERE id = $1` read in
// PollAnchorConfirmationHandler without a real Postgres instance.

var fakeDriverCount int64

// openFakeDB returns a *sql.DB backed by a fake driver that returns
// confirmation="pending" for any SELECT and succeeds for any DML.
// The underlying connection is closed via t.Cleanup.
func openFakeDB(t *testing.T) *sql.DB {
	t.Helper()
	n := atomic.AddInt64(&fakeDriverCount, 1)
	name := fmt.Sprintf("audit-chain-fake-sql-%d", n)
	sql.Register(name, &fakeSQLDriver{})
	db, err := sql.Open(name, "fake://test")
	if err != nil {
		t.Fatalf("openFakeDB sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// fakeSQLDriver opens fakeSQLConn connections.
type fakeSQLDriver struct{}

func (d *fakeSQLDriver) Open(_ string) (driver.Conn, error) {
	return &fakeSQLConn{}, nil
}

// fakeSQLConn implements driver.Conn and driver.QueryerContext.
type fakeSQLConn struct{}

func (c *fakeSQLConn) Prepare(_ string) (driver.Stmt, error) {
	return &fakeSQLStmt{}, nil
}

func (c *fakeSQLConn) Close() error { return nil }

func (c *fakeSQLConn) Begin() (driver.Tx, error) {
	return &fakeSQLTx{}, nil
}

// QueryContext is the driver.QueryerContext fast path — bypasses Prepare.
func (c *fakeSQLConn) QueryContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	return &fakeSQLRows{}, nil
}

// ExecContext is the driver.ExecerContext fast path for INSERT/UPDATE/DELETE.
func (c *fakeSQLConn) ExecContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

// fakeSQLTx is a no-op transaction.
type fakeSQLTx struct{}

func (t *fakeSQLTx) Commit() error   { return nil }
func (t *fakeSQLTx) Rollback() error { return nil }

// fakeSQLStmt is a no-op prepared statement (fallback when QueryerContext is unused).
type fakeSQLStmt struct{}

func (s *fakeSQLStmt) Close() error                                    { return nil }
func (s *fakeSQLStmt) NumInput() int                                   { return -1 }
func (s *fakeSQLStmt) Exec(_ []driver.Value) (driver.Result, error)   { return driver.RowsAffected(1), nil }
func (s *fakeSQLStmt) Query(_ []driver.Value) (driver.Rows, error)    { return &fakeSQLRows{}, nil }

// fakeSQLRows returns one row: confirmation = "pending".
// Any scan destination beyond index 0 receives a zero time.Time value so that
// multi-column scans do not panic.
type fakeSQLRows struct {
	done bool
}

func (r *fakeSQLRows) Columns() []string { return []string{"confirmation"} }
func (r *fakeSQLRows) Close() error      { return nil }

func (r *fakeSQLRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	if len(dest) > 0 {
		dest[0] = "pending"
	}
	for i := 1; i < len(dest); i++ {
		dest[i] = time.Time{} // zero value for additional columns
	}
	return nil
}
