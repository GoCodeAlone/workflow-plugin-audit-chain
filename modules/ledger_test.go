package modules_test

import (
	"context"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
)

// TestNewLedgerModule_RejectsEmptyName verifies that NewLedgerModule fails when
// config.Name is empty.
func TestNewLedgerModule_RejectsEmptyName(t *testing.T) {
	cfg := &auditv1.LedgerConfig{
		Name: "",
		Dsn:  "postgres://user:pass@localhost/db?sslmode=disable",
	}
	_, err := modules.NewLedgerModule("test-instance", cfg)
	if err == nil {
		t.Fatal("expected error for empty name, got nil")
	}
}

// TestNewLedgerModule_RejectsEmptyDSN verifies that NewLedgerModule fails when
// no DSN is provided.
func TestNewLedgerModule_RejectsEmptyDSN(t *testing.T) {
	cfg := &auditv1.LedgerConfig{
		Name: "test-ledger",
		Dsn:  "",
	}
	_, err := modules.NewLedgerModule("test-ledger", cfg)
	if err == nil {
		t.Fatal("expected error for empty DSN, got nil")
	}
}

// TestNewLedgerModule_CreatesModule verifies the factory creates a non-nil module
// and that the module's metadata is correct.
func TestNewLedgerModule_CreatesModule(t *testing.T) {
	cfg := &auditv1.LedgerConfig{
		Name: "test-ledger",
		Dsn:  "postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable",
	}
	m, err := modules.NewLedgerModule("test-ledger", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil module")
	}
}

// TestLedgerModule_InitRegistersAppender verifies that Init registers the ledger
// appender in the global registry under the partition name. Since sql.Open is
// lazy (no real network call), this passes without a running Postgres instance.
func TestLedgerModule_InitRegistersAppender(t *testing.T) {
	ledgerName := "init-test-ledger"

	// Ensure registry is clean before test.
	modules.UnregisterLedger(ledgerName)
	t.Cleanup(func() { modules.UnregisterLedger(ledgerName) })

	cfg := &auditv1.LedgerConfig{
		Name: ledgerName,
		Dsn:  "postgres://user:pass@localhost:5432/db?sslmode=disable",
	}
	m, err := modules.NewLedgerModule("test-instance", cfg)
	if err != nil {
		t.Fatalf("NewLedgerModule: %v", err)
	}

	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// ProvidesServices: the ledger appender must be retrievable from the registry.
	a, ok := modules.GetLedger(ledgerName)
	if !ok {
		t.Fatal("GetLedger returned false after Init; appender not registered")
	}
	if a == nil {
		t.Fatal("GetLedger returned nil appender")
	}
}

// TestLedgerModule_StopUnregisters verifies that Stop removes the ledger from
// the registry.
func TestLedgerModule_StopUnregisters(t *testing.T) {
	ledgerName := "stop-test-ledger"

	modules.UnregisterLedger(ledgerName)
	t.Cleanup(func() { modules.UnregisterLedger(ledgerName) })

	cfg := &auditv1.LedgerConfig{
		Name: ledgerName,
		Dsn:  "postgres://user:pass@localhost:5432/db?sslmode=disable",
	}
	m, err := modules.NewLedgerModule("test-instance", cfg)
	if err != nil {
		t.Fatalf("NewLedgerModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	ctx := context.Background()
	if err := m.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	_, ok := modules.GetLedger(ledgerName)
	if ok {
		t.Fatal("GetLedger returned true after Stop; appender should have been unregistered")
	}
}

// TestLedgerModule_InitDoubleCallReturnsError verifies that calling Init twice
// returns an error rather than leaking the first DB connection pool.
func TestLedgerModule_InitDoubleCallReturnsError(t *testing.T) {
	ledgerName := "double-init-ledger"
	modules.UnregisterLedger(ledgerName)
	t.Cleanup(func() { modules.UnregisterLedger(ledgerName) })

	cfg := &auditv1.LedgerConfig{
		Name: ledgerName,
		Dsn:  "postgres://user:pass@localhost:5432/db?sslmode=disable",
	}
	m, err := modules.NewLedgerModule("test-instance", cfg)
	if err != nil {
		t.Fatalf("NewLedgerModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if err := m.Init(); err == nil {
		t.Fatal("expected error on second Init call, got nil")
	}
}

// TestLedgerModule_StartIsNoop verifies that Start does not error.
func TestLedgerModule_StartIsNoop(t *testing.T) {
	ledgerName := "start-test-ledger"
	modules.UnregisterLedger(ledgerName)
	t.Cleanup(func() { modules.UnregisterLedger(ledgerName) })

	cfg := &auditv1.LedgerConfig{
		Name: ledgerName,
		Dsn:  "postgres://user:pass@localhost:5432/db?sslmode=disable",
	}
	m, err := modules.NewLedgerModule("test-instance", cfg)
	if err != nil {
		t.Fatalf("NewLedgerModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Fatalf("Start: unexpected error: %v", err)
	}
}
