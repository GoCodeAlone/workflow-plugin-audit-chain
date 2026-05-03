// Package modules provides workflow modular.Module implementations for the
// audit-chain plugin.  Each module type wires a layer from the chain/ and
// providers/ packages into the workflow engine's dependency-injection system.
//
// The package exposes package-level registries (ledger and anchor-provider) so
// that step implementations can look up the handles they need without coupling
// to specific module instances.
package modules

import (
	"context"
	"database/sql"
	"fmt"
	"sync"

	_ "github.com/jackc/pgx/v5/stdlib" // register pgx driver

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// ── Ledger registry ───────────────────────────────────────────────────────────

var (
	ledgerMu       sync.RWMutex
	ledgerRegistry = make(map[string]*chain.Appender)
)

// ── DB registry ───────────────────────────────────────────────────────────────
// Steps that need raw SQL (verify, merkle_root, anchor, proof, public_receipt)
// look up the *sql.DB by the ledger partition name rather than rebuilding a
// separate connection pool.

var (
	dbMu       sync.RWMutex
	dbRegistry = make(map[string]*sql.DB)
)

// RegisterDB stores a *sql.DB under the given ledger partition name.
func RegisterDB(partitionName string, db *sql.DB) {
	dbMu.Lock()
	defer dbMu.Unlock()
	dbRegistry[partitionName] = db
}

// GetDB looks up a *sql.DB by ledger partition name.
func GetDB(partitionName string) (*sql.DB, bool) {
	dbMu.RLock()
	defer dbMu.RUnlock()
	db, ok := dbRegistry[partitionName]
	return db, ok
}

// UnregisterDB removes a DB from the registry (called on Stop and in tests).
func UnregisterDB(partitionName string) {
	dbMu.Lock()
	defer dbMu.Unlock()
	delete(dbRegistry, partitionName)
}

// RegisterLedger registers an Appender in the global ledger registry under the
// given partition name.
func RegisterLedger(partitionName string, a *chain.Appender) {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	ledgerRegistry[partitionName] = a
}

// GetLedger looks up an Appender by ledger partition name.
func GetLedger(partitionName string) (*chain.Appender, bool) {
	ledgerMu.RLock()
	defer ledgerMu.RUnlock()
	a, ok := ledgerRegistry[partitionName]
	return a, ok
}

// UnregisterLedger removes a ledger Appender from the registry (called on Stop
// and in tests).
func UnregisterLedger(partitionName string) {
	ledgerMu.Lock()
	defer ledgerMu.Unlock()
	delete(ledgerRegistry, partitionName)
}

// ── LedgerModule ─────────────────────────────────────────────────────────────

// LedgerModule implements sdk.ModuleInstance for the audit.ledger module type.
// It opens a Postgres connection, creates a chain.Appender, and registers it in
// the global ledger registry under LedgerConfig.Name (the partition key).
type LedgerModule struct {
	instanceName  string
	config        *auditv1.LedgerConfig
	db            *sql.DB
}

// Compile-time assertion.
var _ sdk.ModuleInstance = (*LedgerModule)(nil)

// NewLedgerModule creates a LedgerModule from a typed LedgerConfig proto.
// Returns an error if config.Name or config.Dsn is empty.
func NewLedgerModule(instanceName string, config *auditv1.LedgerConfig) (sdk.ModuleInstance, error) {
	if config.GetName() == "" {
		return nil, fmt.Errorf("audit.ledger %q: config.name is required", instanceName)
	}
	if config.GetDsn() == "" {
		return nil, fmt.Errorf("audit.ledger %q: config.dsn is required", instanceName)
	}
	return &LedgerModule{
		instanceName: instanceName,
		config:       config,
	}, nil
}

// Init opens the Postgres connection and registers the Appender.
// sql.Open is lazy: the connection string is validated at parse time but no
// network call is made until the first query. This keeps Init fast and allows
// unit tests to run without a real Postgres instance.
// Returns an error if called more than once to prevent connection pool leaks.
func (m *LedgerModule) Init() error {
	if m.db != nil {
		return fmt.Errorf("audit.ledger %q: already initialized", m.instanceName)
	}
	db, err := sql.Open("pgx", m.config.GetDsn())
	if err != nil {
		return fmt.Errorf("audit.ledger %q: open db: %w", m.instanceName, err)
	}
	m.db = db
	RegisterLedger(m.config.GetName(), chain.NewAppender(db))
	RegisterDB(m.config.GetName(), db)
	return nil
}

// Start is a no-op for the ledger module.
func (m *LedgerModule) Start(_ context.Context) error { return nil }

// Stop unregisters the ledger and DB, then closes the underlying DB connection.
func (m *LedgerModule) Stop(_ context.Context) error {
	UnregisterLedger(m.config.GetName())
	UnregisterDB(m.config.GetName())
	if m.db != nil {
		if err := m.db.Close(); err != nil {
			return fmt.Errorf("audit.ledger %q: close db: %w", m.instanceName, err)
		}
	}
	return nil
}
