// Package integration_test provides an end-to-end integration test that starts
// the audit-chain plugin as a real binary subprocess, communicates with it over
// the gRPC transport layer (via go-plugin), and verifies the full cryptographic
// audit chain scenario.
//
// The test:
//  1. Spins up an ephemeral Postgres 16 container via testcontainers.
//  2. Compiles and starts the plugin binary as a subprocess via go-plugin.
//  3. Declares an audit.ledger by sending CreateModule → InitModule → StartModule
//     over gRPC — config is proto-serialised as anypb.Any(LedgerConfig).
//  4. Appends 5 audit entries via CreateStep / ExecuteStep (step.audit.append),
//     each with TypedInput = anypb.Any(AppendRequest) over the gRPC wire.
//  5. Verifies chain integrity via step.audit.verify.
//  6. Computes the Merkle root over entries 1–5 via step.audit.merkle_root.
//  7. Records a mock anchor row directly, then retrieves the inclusion proof for
//     entry 3 via step.audit.proof.
//  8. Cryptographically verifies the proof with chain.VerifyInclusion.
package integration_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	goplugin "github.com/GoCodeAlone/go-plugin"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/testcontainers/testcontainers-go"
	tcpostgres "github.com/testcontainers/testcontainers-go/modules/postgres"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	ext "github.com/GoCodeAlone/workflow/plugin/external"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
)

// ── go-plugin bridge ──────────────────────────────────────────────────────────

// testGRPCPlugin is a go-plugin Plugin implementation that dispenses
// pb.PluginServiceClient directly.  ext.GRPCPlugin wraps the client in
// *ext.PluginClient which has unexported fields; this variant bypasses that
// wrapper so the test can call RPC methods directly without depending on
// unexported types.
type testGRPCPlugin struct{ goplugin.Plugin }

func (p *testGRPCPlugin) GRPCServer(_ *goplugin.GRPCBroker, _ *grpc.Server) error { return nil }

func (p *testGRPCPlugin) GRPCClient(_ context.Context, _ *goplugin.GRPCBroker, c *grpc.ClientConn) (any, error) {
	return pb.NewPluginServiceClient(c), nil
}

// ── test infrastructure ───────────────────────────────────────────────────────

// startPostgres spins up an ephemeral Postgres 16 container and returns its
// connection string.
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

// openDB opens a sql.DB for direct SQL operations from the test process.
func openDB(t *testing.T, connStr string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", connStr)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// applyMigrations applies all four up-migration SQL files.
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

// buildBinary compiles the plugin binary into a temp directory and returns its
// path.  Skipped in short mode (go test -short).
func buildBinary(t *testing.T) string {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping binary build in short mode")
	}

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("runtime.Caller unavailable")
	}
	// thisFile is integration_test.go at the module root.
	projectRoot := filepath.Dir(thisFile)

	out := filepath.Join(t.TempDir(), "workflow-plugin-audit-chain")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/workflow-plugin-audit-chain/")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "GOWORK=off")

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin binary:\n%s\nerror: %v", output, err)
	}
	return out
}

// startPlugin starts the plugin binary as a go-plugin subprocess and returns a
// pb.PluginServiceClient connected to it over gRPC.
func startPlugin(t *testing.T, binaryPath string) pb.PluginServiceClient {
	t.Helper()

	client := goplugin.NewClient(&goplugin.ClientConfig{
		HandshakeConfig:  ext.Handshake,
		Plugins:          goplugin.PluginSet{"plugin": &testGRPCPlugin{}},
		Cmd:              exec.Command(binaryPath), //nolint:gosec // G204: test binary
		AllowedProtocols: []goplugin.Protocol{goplugin.ProtocolGRPC},
	})
	t.Cleanup(client.Kill)

	rpcClient, err := client.Client()
	if err != nil {
		t.Fatalf("connect to plugin subprocess: %v", err)
	}

	raw, err := rpcClient.Dispense("plugin")
	if err != nil {
		t.Fatalf("dispense plugin: %v", err)
	}

	pbClient, ok := raw.(pb.PluginServiceClient)
	if !ok {
		t.Fatalf("dispensed object is not pb.PluginServiceClient (got %T)", raw)
	}
	return pbClient
}

// mustNoRPCErr fatals the test if err != nil or the response error field is set.
func mustNoRPCErr(t *testing.T, label string, err error, respErr string) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: gRPC error: %v", label, err)
	}
	if respErr != "" {
		t.Fatalf("%s: plugin error: %s", label, respErr)
	}
}

// ── integration scenario ──────────────────────────────────────────────────────

// TestE2E_AuditChainScenario is the canonical end-to-end integration test.
//
// All step executions go through real gRPC proto serialisation: the test
// process packs each request as anypb.Any, sends it over a TCP gRPC connection
// to the plugin subprocess, and unpacks the typed response the same way.
func TestE2E_AuditChainScenario(t *testing.T) {
	const ledger = "e2e-ledger"
	ctx := context.Background()

	// ── 1. Infrastructure ─────────────────────────────────────────────────────
	connStr := startPostgres(t)
	rawDB := openDB(t, connStr)
	applyMigrations(t, rawDB)

	// ── 2. Build and start plugin subprocess ──────────────────────────────────
	binaryPath := buildBinary(t)
	pbClient := startPlugin(t, binaryPath)

	// ── 3. Declare audit.ledger via gRPC ──────────────────────────────────────
	// CreateModule → InitModule → StartModule with typed LedgerConfig over gRPC.
	cfgProto := &auditv1.LedgerConfig{Name: ledger, Dsn: connStr}
	packedCfg, err := anypb.New(cfgProto)
	if err != nil {
		t.Fatalf("pack LedgerConfig: %v", err)
	}

	createModResp, err := pbClient.CreateModule(ctx, &pb.CreateModuleRequest{
		Type:        "audit.ledger",
		Name:        "e2e-module",
		TypedConfig: packedCfg,
	})
	mustNoRPCErr(t, "CreateModule", err, createModResp.GetError())
	modHandle := createModResp.HandleId

	initResp, err := pbClient.InitModule(ctx, &pb.HandleRequest{HandleId: modHandle})
	mustNoRPCErr(t, "InitModule", err, initResp.GetError())

	startResp, err := pbClient.StartModule(ctx, &pb.HandleRequest{HandleId: modHandle})
	mustNoRPCErr(t, "StartModule", err, startResp.GetError())
	t.Cleanup(func() {
		_, _ = pbClient.StopModule(ctx, &pb.HandleRequest{HandleId: modHandle})
	})

	// Insert the audit_ledgers cursor row (normally done by a provisioning step).
	if _, err := rawDB.ExecContext(ctx,
		`INSERT INTO audit_ledgers (ledger, last_sequence, last_entry_hash)
		 VALUES ($1, 0, '') ON CONFLICT (ledger) DO NOTHING`, ledger,
	); err != nil {
		t.Fatalf("create audit_ledgers row: %v", err)
	}

	// ── 4. Create step.audit.append instance ──────────────────────────────────
	createAppendResp, err := pbClient.CreateStep(ctx, &pb.CreateStepRequest{
		Type: "step.audit.append",
		Name: "e2e-append",
	})
	mustNoRPCErr(t, "CreateStep(append)", err, createAppendResp.GetError())
	appendHandle := createAppendResp.HandleId

	// ── 5. Append 5 entries via gRPC ExecuteStep ──────────────────────────────
	entryHashes := make([]string, 5)
	for i := 1; i <= 5; i++ {
		payload := fmt.Appendf(nil, `{"n":%d,"ts":%d}`, i, time.Now().UnixNano())

		input, err := anypb.New(&auditv1.AppendRequest{
			Ledger:    ledger,
			EventType: "e2e.event",
			Payload:   payload,
			Actor:     "integration-test",
		})
		if err != nil {
			t.Fatalf("pack AppendRequest entry %d: %v", i, err)
		}

		execResp, err := pbClient.ExecuteStep(ctx, &pb.ExecuteStepRequest{
			HandleId:   appendHandle,
			TypedInput: input,
		})
		mustNoRPCErr(t, fmt.Sprintf("ExecuteStep(append) entry %d", i), err, execResp.GetError())

		var out auditv1.AppendResponse
		if err := execResp.GetTypedOutput().UnmarshalTo(&out); err != nil {
			t.Fatalf("unpack AppendResponse entry %d: %v", i, err)
		}
		if out.GetSequence() != int64(i) {
			t.Errorf("entry %d: expected sequence %d, got %d", i, i, out.GetSequence())
		}
		if len(out.GetEntryHash()) != 64 {
			t.Errorf("entry %d: expected 64-char hash, got %d", i, len(out.GetEntryHash()))
		}
		if out.GetCreatedAt() == "" {
			t.Errorf("entry %d: CreatedAt is empty", i)
		}
		entryHashes[i-1] = out.GetEntryHash()
	}

	// ── 6. Verify chain integrity via step.audit.verify ───────────────────────
	createVerifyResp, err := pbClient.CreateStep(ctx, &pb.CreateStepRequest{
		Type: "step.audit.verify",
		Name: "e2e-verify",
	})
	mustNoRPCErr(t, "CreateStep(verify)", err, createVerifyResp.GetError())

	verInput, err := anypb.New(&auditv1.VerifyRequest{
		Ledger:        ledger,
		StartSequence: 1,
		EndSequence:   5,
	})
	if err != nil {
		t.Fatalf("pack VerifyRequest: %v", err)
	}
	verExecResp, err := pbClient.ExecuteStep(ctx, &pb.ExecuteStepRequest{
		HandleId:   createVerifyResp.HandleId,
		TypedInput: verInput,
	})
	mustNoRPCErr(t, "ExecuteStep(verify)", err, verExecResp.GetError())

	var verOut auditv1.VerifyResponse
	if err := verExecResp.GetTypedOutput().UnmarshalTo(&verOut); err != nil {
		t.Fatalf("unpack VerifyResponse: %v", err)
	}
	if !verOut.GetValid() {
		t.Fatalf("chain integrity check failed at seq %d: %s",
			verOut.GetFirstInvalidSequence(), verOut.GetFailureReason())
	}
	if verOut.GetEntriesVerified() != 5 {
		t.Errorf("expected 5 entries verified, got %d", verOut.GetEntriesVerified())
	}

	// ── 7. Compute Merkle root via step.audit.merkle_root ─────────────────────
	createMRResp, err := pbClient.CreateStep(ctx, &pb.CreateStepRequest{
		Type: "step.audit.merkle_root",
		Name: "e2e-merkle-root",
	})
	mustNoRPCErr(t, "CreateStep(merkle_root)", err, createMRResp.GetError())

	mrInput, err := anypb.New(&auditv1.MerkleRootRequest{
		Ledger:        ledger,
		StartSequence: 1,
		EndSequence:   5,
	})
	if err != nil {
		t.Fatalf("pack MerkleRootRequest: %v", err)
	}
	mrExecResp, err := pbClient.ExecuteStep(ctx, &pb.ExecuteStepRequest{
		HandleId:   createMRResp.HandleId,
		TypedInput: mrInput,
	})
	mustNoRPCErr(t, "ExecuteStep(merkle_root)", err, mrExecResp.GetError())

	var mrOut auditv1.MerkleRootResponse
	if err := mrExecResp.GetTypedOutput().UnmarshalTo(&mrOut); err != nil {
		t.Fatalf("unpack MerkleRootResponse: %v", err)
	}
	merkleRoot := mrOut.GetRoot()
	if len(merkleRoot) != 64 {
		t.Fatalf("expected 64-char Merkle root, got %d: %s", len(merkleRoot), merkleRoot)
	}
	if mrOut.GetEntriesIncluded() != 5 {
		t.Errorf("expected 5 entries included, got %d", mrOut.GetEntriesIncluded())
	}

	// Cross-check: independently compute the root from locally-collected hashes.
	expectedRoot, err := chain.MerkleRoot(entryHashes)
	if err != nil {
		t.Fatalf("chain.MerkleRoot: %v", err)
	}
	if merkleRoot != expectedRoot {
		t.Errorf("merkle_root handler returned %s; independently computed %s", merkleRoot, expectedRoot)
	}

	// ── 8. Record a mock anchor for range 1–5 ─────────────────────────────────
	// In production, step.audit.anchor submits to an external provider and writes
	// this row.  Here we insert directly so ProofHandler has data to work with.
	if _, err := rawDB.ExecContext(ctx, `
		INSERT INTO audit_anchors
			(ledger, range_start, range_end, merkle_root, provider,
			 external_id, proof_data, confirmation, anchored_at)
		VALUES ($1, 1, 5, $2, 'e2e-mock', 'mock-ext-id-001', NULL, 'pending', NOW())`,
		ledger, merkleRoot,
	); err != nil {
		t.Fatalf("insert mock anchor: %v", err)
	}

	// ── 9. Retrieve inclusion proof for entry 3 via step.audit.proof ──────────
	createProofResp, err := pbClient.CreateStep(ctx, &pb.CreateStepRequest{
		Type: "step.audit.proof",
		Name: "e2e-proof",
	})
	mustNoRPCErr(t, "CreateStep(proof)", err, createProofResp.GetError())

	proofInput, err := anypb.New(&auditv1.ProofRequest{
		Ledger:   ledger,
		Sequence: 3,
	})
	if err != nil {
		t.Fatalf("pack ProofRequest: %v", err)
	}
	proofExecResp, err := pbClient.ExecuteStep(ctx, &pb.ExecuteStepRequest{
		HandleId:   createProofResp.HandleId,
		TypedInput: proofInput,
	})
	mustNoRPCErr(t, "ExecuteStep(proof)", err, proofExecResp.GetError())

	var pOut auditv1.ProofResponse
	if err := proofExecResp.GetTypedOutput().UnmarshalTo(&pOut); err != nil {
		t.Fatalf("unpack ProofResponse: %v", err)
	}

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

	// ── 10. Cryptographic verification of the inclusion proof ─────────────────
	//
	// chain.VerifyInclusion walks the L/R-prefixed sibling path and recomputes
	// the root using the same RFC 6962 hashing as chain.MerkleRoot.  If the
	// proof is correct, the reconstructed root must equal the anchor's root.
	if !chain.VerifyInclusion(entryHashes[2], pOut.GetMerklePath(), merkleRoot) {
		t.Errorf("chain.VerifyInclusion failed: inclusion proof for entry 3 does not reproduce Merkle root %s", merkleRoot)
	}
}
