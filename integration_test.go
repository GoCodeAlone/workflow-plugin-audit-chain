// Package integration_test provides an end-to-end integration test that loads
// the audit-chain plugin via its typed module/step factory chain, exercises the
// full audit scenario, and verifies cryptographic correctness.
//
// The test spins up an ephemeral Postgres container via testcontainers, applies
// all migrations, then drives the plugin through five steps:
//
//  1. Declare an audit.ledger via internal.NewPlugin().CreateTypedModule.
//  2. Append 5 entries via step.audit.append.
//  3. Verify chain integrity over all 5 entries via step.audit.verify.
//  4. Compute the Merkle root over entries 1–5 via step.audit.merkle_root.
//  5. Verify the Merkle inclusion proof for entry 3 via step.audit.proof.
package integration_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/steps"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// ── test infrastructure ───────────────────────────────────────────────────────

// startPostgres spins up an ephemeral Postgres 16 container via testcontainers
// and returns its connection string.  The container is terminated in t.Cleanup.
func startPostgres(t *testing.T) string {
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

	cs, err := pgc.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("get connection string: %v", err)
	}
	return cs
}

// openDB opens a sql.DB connection to connStr and registers Close in t.Cleanup.
func openDB(t *testing.T, connStr string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// applyMigrations applies all four up-migration SQL files from the migrations/
// directory.  Paths are relative to the module root (where the test runs).
func applyMigrations(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	for _, f := range []string{
		"migrations/001_audit_log.sql",
		"migrations/002_audit_ledgers.sql",
		"migrations/003_audit_anchors.sql",
		"migrations/004_indexes.sql",
	} {
		sqlBytes, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read migration %s: %v", f, err)
		}
		if _, err := db.ExecContext(ctx, string(sqlBytes)); err != nil {
			t.Fatalf("apply migration %s: %v", f, err)
		}
	}
}

// ── integration scenario ──────────────────────────────────────────────────────

// TestE2E_AuditChainScenario is the canonical end-to-end integration test.
// It exercises the full audit-chain workflow:
//
//  1. Declare an audit.ledger via internal.NewPlugin().CreateTypedModule.
//  2. Append 5 entries via step.audit.append.
//  3. Verify chain integrity via step.audit.verify.
//  4. Compute Merkle root over entries 1–5 via step.audit.merkle_root.
//  5. Record a mock anchor row for range 1–5 with the computed root.
//  6. Retrieve and cryptographically verify the inclusion proof for entry 3
//     via step.audit.proof + chain.VerifyInclusion.
func TestE2E_AuditChainScenario(t *testing.T) {
	const ledger = "e2e-ledger"
	ctx := context.Background()

	// ── 1. Infrastructure ────────────────────────────────────────────────────
	connStr := startPostgres(t)
	rawDB := openDB(t, connStr)
	applyMigrations(t, rawDB)

	// ── 2. Declare audit.ledger via the plugin's typed module factory ─────────
	//
	// This exercises the full wiring: NewPlugin() → CreateTypedModule →
	// modules.NewLedgerModule → sql.Open (lazy) → RegisterLedger + RegisterDB.
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TypedModuleProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TypedModuleProvider")
	}

	cfgProto := &auditv1.LedgerConfig{Name: ledger, Dsn: connStr}
	packed, err := anypb.New(cfgProto)
	if err != nil {
		t.Fatalf("anypb.New(LedgerConfig): %v", err)
	}

	mod, err := tp.CreateTypedModule("audit.ledger", "e2e-module", packed)
	if err != nil {
		t.Fatalf("CreateTypedModule audit.ledger: %v", err)
	}
	if err := mod.Init(); err != nil {
		t.Fatalf("LedgerModule.Init: %v", err)
	}
	t.Cleanup(func() { _ = mod.Stop(ctx) })

	if _, ok := modules.GetLedger(ledger); !ok {
		t.Fatal("appender not in ledger registry after Init")
	}
	if _, ok := modules.GetDB(ledger); !ok {
		t.Fatal("DB not in registry after Init")
	}

	// Insert the audit_ledgers cursor row (normally done by a provisioning step).
	if _, err := rawDB.ExecContext(ctx,
		`INSERT INTO audit_ledgers (ledger, last_sequence, last_entry_hash)
		 VALUES ($1, 0, '') ON CONFLICT (ledger) DO NOTHING`, ledger,
	); err != nil {
		t.Fatalf("create audit_ledgers row: %v", err)
	}

	// ── 3. Append 5 entries via step.audit.append ────────────────────────────
	entryHashes := make([]string, 5) // indexed 0–4, corresponds to seq 1–5
	for i := 1; i <= 5; i++ {
		payload := fmt.Appendf(nil, `{"n":%d,"ts":%d}`, i, time.Now().UnixNano())
		res, err := steps.AppendHandler(ctx, sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AppendRequest]{
			Config: &emptypb.Empty{},
			Input: &auditv1.AppendRequest{
				Ledger:    ledger,
				EventType: "e2e.event",
				Payload:   payload,
				Actor:     "integration-test",
			},
		})
		if err != nil {
			t.Fatalf("AppendHandler entry %d: %v", i, err)
		}
		out := res.Output
		if out.GetSequence() != int64(i) {
			t.Errorf("entry %d: expected sequence %d, got %d", i, i, out.GetSequence())
		}
		if len(out.GetEntryHash()) != 64 {
			t.Errorf("entry %d: expected 64-char hash, got %d", i, len(out.GetEntryHash()))
		}
		if out.GetCreatedAt() == "" {
			t.Errorf("entry %d: CreatedAt is empty (expected DB-assigned timestamp)", i)
		}
		entryHashes[i-1] = out.GetEntryHash()
	}

	// ── 4. Verify chain integrity via step.audit.verify ──────────────────────
	verRes, err := steps.VerifyHandler(ctx, sdk.TypedStepRequest[*emptypb.Empty, *auditv1.VerifyRequest]{
		Config: &emptypb.Empty{},
		Input: &auditv1.VerifyRequest{
			Ledger:        ledger,
			StartSequence: 1,
			EndSequence:   5,
		},
	})
	if err != nil {
		t.Fatalf("VerifyHandler: %v", err)
	}
	if !verRes.Output.GetValid() {
		t.Fatalf("chain integrity check failed at seq %d: %s",
			verRes.Output.GetFirstInvalidSequence(),
			verRes.Output.GetFailureReason())
	}
	if verRes.Output.GetEntriesVerified() != 5 {
		t.Errorf("expected 5 entries verified, got %d", verRes.Output.GetEntriesVerified())
	}

	// ── 5. Compute Merkle root over entries 1–5 ───────────────────────────────
	mrRes, err := steps.MerkleRootHandler(ctx, sdk.TypedStepRequest[*emptypb.Empty, *auditv1.MerkleRootRequest]{
		Config: &emptypb.Empty{},
		Input: &auditv1.MerkleRootRequest{
			Ledger:        ledger,
			StartSequence: 1,
			EndSequence:   5,
		},
	})
	if err != nil {
		t.Fatalf("MerkleRootHandler: %v", err)
	}
	merkleRoot := mrRes.Output.GetRoot()
	if len(merkleRoot) != 64 {
		t.Fatalf("expected 64-char Merkle root, got %d: %s", len(merkleRoot), merkleRoot)
	}
	if mrRes.Output.GetEntriesIncluded() != 5 {
		t.Errorf("expected 5 entries included, got %d", mrRes.Output.GetEntriesIncluded())
	}

	// Cross-check: independently compute the root from the entry hashes we
	// collected above; it must match what the handler returned.
	expectedRoot, err := chain.MerkleRoot(entryHashes)
	if err != nil {
		t.Fatalf("chain.MerkleRoot: %v", err)
	}
	if merkleRoot != expectedRoot {
		t.Errorf("MerkleRootHandler root %s != independently computed root %s", merkleRoot, expectedRoot)
	}

	// ── 6. Record a mock anchor for range 1–5 ────────────────────────────────
	//
	// In production, step.audit.anchor submits to an external provider and
	// writes this row.  Here we insert directly so ProofHandler has data to work
	// with.
	if _, err := rawDB.ExecContext(ctx, `
		INSERT INTO audit_anchors
			(ledger, range_start, range_end, merkle_root, provider,
			 external_id, proof_data, confirmation, anchored_at)
		VALUES ($1, 1, 5, $2, 'e2e-mock', 'mock-ext-id-001', NULL, 'pending', NOW())`,
		ledger, merkleRoot,
	); err != nil {
		t.Fatalf("insert mock anchor: %v", err)
	}

	// ── 7. Retrieve inclusion proof for entry 3 ───────────────────────────────
	proofRes, err := steps.ProofHandler(ctx, sdk.TypedStepRequest[*emptypb.Empty, *auditv1.ProofRequest]{
		Config: &emptypb.Empty{},
		Input: &auditv1.ProofRequest{
			Ledger:   ledger,
			Sequence: 3,
		},
	})
	if err != nil {
		t.Fatalf("ProofHandler: %v", err)
	}
	pOut := proofRes.Output

	// Entry 3 must be returned correctly.
	if pOut.GetEntry() == nil {
		t.Fatal("ProofHandler returned nil entry")
	}
	if seq := pOut.GetEntry().GetSequence(); seq != 3 {
		t.Errorf("proof entry sequence = %d, want 3", seq)
	}
	if h := pOut.GetEntry().GetEntryHash(); h != entryHashes[2] {
		t.Errorf("proof entry hash = %s, want %s", h, entryHashes[2])
	}

	// Merkle root matches what step.audit.merkle_root computed.
	if pOut.GetMerkleRoot() != merkleRoot {
		t.Errorf("proof merkle_root = %s, want %s", pOut.GetMerkleRoot(), merkleRoot)
	}

	// Inclusion proof must be non-empty (entry 3 of 5 has siblings).
	// Each node is a direction byte ('L'/'R') followed by 64 hex chars = 65 total.
	if len(pOut.GetMerklePath()) == 0 {
		t.Error("inclusion proof Merkle path is empty — expected sibling hashes for entry 3 of 5")
	}
	for i, node := range pOut.GetMerklePath() {
		if len(node) != 65 {
			t.Errorf("MerklePath[%d]: expected 65 chars (1 dir + 64 hex), got %d: %q", i, len(node), node)
		}
		dir := node[0]
		if dir != 'L' && dir != 'R' {
			t.Errorf("MerklePath[%d]: unexpected direction byte %q", i, dir)
		}
	}

	// Anchor record is present and references our mock provider.
	if len(pOut.GetAnchors()) == 0 {
		t.Error("proof has no anchors — expected the mock anchor inserted above")
	} else if pOut.GetAnchors()[0].GetProvider() != "e2e-mock" {
		t.Errorf("anchor provider = %q, want %q", pOut.GetAnchors()[0].GetProvider(), "e2e-mock")
	}

	// ── 8. Cryptographic verification of the inclusion proof ─────────────────
	//
	// chain.VerifyInclusion walks the L/R-prefixed sibling path and recomputes
	// the root using the same RFC 6962 hashing as chain.MerkleRoot. If the
	// proof is correct, the reconstructed root must equal the anchor's root.
	if !chain.VerifyInclusion(entryHashes[2], pOut.GetMerklePath(), merkleRoot) {
		t.Errorf("chain.VerifyInclusion failed: the inclusion proof for entry 3 does not reproduce the Merkle root %s", merkleRoot)
	}
}
