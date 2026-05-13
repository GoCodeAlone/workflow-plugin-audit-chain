package steps_test

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/steps"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	_ "github.com/jackc/pgx/v5/stdlib" // register pgx driver for sql.Open in tests
)

func TestPollAnchorConfirmationHandler_EmptyLedger(t *testing.T) {
	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{},
		Input:  &auditv1.PollAnchorConfirmationRequest{Ledger: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty ledger, got nil")
	}
	if !strings.Contains(err.Error(), "ledger") {
		t.Errorf("error should mention ledger field, got: %v", err)
	}
}

func TestPollAnchorConfirmationHandler_DBNotRegistered(t *testing.T) {
	const ledger = "poll-test-unregistered"
	modules.UnregisterDB(ledger)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{},
		Input: &auditv1.PollAnchorConfirmationRequest{
			Ledger:     ledger,
			AnchorId:   "42",
			Provider:   "opentimestamps",
			ExternalId: "abc123",
		},
	})
	if err == nil {
		t.Fatal("expected error for unregistered DB, got nil")
	}
	if !strings.Contains(err.Error(), ledger) {
		t.Errorf("error should mention ledger name %q, got: %v", ledger, err)
	}
}

// TestPollAnchorConfirmationHandler_TransientError_Swallowed verifies that when
// the anchor provider returns Swallowed=true (transient network error), the
// handler returns success with swallowed=true and no gRPC error.
// This is the load-bearing contract from § 3.5c.
func TestPollAnchorConfirmationHandler_TransientError_Swallowed(t *testing.T) {
	const (
		ledger   = "poll-test-transient"
		provider = "poll-test-transient-provider"
	)

	// Register a fake DB: returns confirmation="pending" for any SELECT.
	db := openFakeDB(t)
	modules.RegisterDB(ledger, db)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	// Mock provider returns Swallowed=true (calendar server unreachable).
	mock := &mockAnchorProvider{
		providerName: provider,
		verifyResult: providers.Verification{
			Provider:     provider,
			Confirmation: providers.ConfirmationPending,
			Swallowed:    true,
			ErrorMessage: "calendar server timeout: dial tcp: connection refused",
		},
	}
	modules.RegisterAnchorProvider(provider, mock)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(provider) })

	result, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{},
		Input: &auditv1.PollAnchorConfirmationRequest{
			Ledger:     ledger,
			AnchorId:   "1",
			Provider:   provider,
			ExternalId: "abc123",
		},
	})

	if err != nil {
		t.Fatalf("expected no gRPC error for transient swallowed error, got: %v", err)
	}
	if result == nil || result.Output == nil {
		t.Fatal("expected non-nil result")
	}
	out := result.Output
	if !out.GetSwallowed() {
		t.Error("swallowed should be true for transient error")
	}
	if out.GetTransitioned() {
		t.Error("transitioned should be false when error is swallowed")
	}
	if out.GetErrorMessage() == "" {
		t.Error("error_message should be populated when swallowed=true")
	}
	if out.GetCurrentConfirmation() != out.GetPreviousConfirmation() {
		t.Errorf("current_confirmation should equal previous when swallowed: prev=%q cur=%q",
			out.GetPreviousConfirmation(), out.GetCurrentConfirmation())
	}
}

// TestPollAnchorConfirmationHandler_HardError_PropagatesGRPC verifies that when
// the anchor provider returns a non-nil error (hard error: invalid proof, 4xx),
// the handler propagates it as a gRPC error (non-nil return error).
func TestPollAnchorConfirmationHandler_HardError_PropagatesGRPC(t *testing.T) {
	const (
		ledger   = "poll-test-hard-error"
		provider = "poll-test-hard-error-provider"
	)

	db := openFakeDB(t)
	modules.RegisterDB(ledger, db)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	mock := &mockAnchorProvider{
		providerName: provider,
		verifyErr:    errors.New("4xx: proof rejected by provider — invalid merkle path"),
	}
	modules.RegisterAnchorProvider(provider, mock)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(provider) })

	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{},
		Input: &auditv1.PollAnchorConfirmationRequest{
			Ledger:     ledger,
			AnchorId:   "1",
			Provider:   provider,
			ExternalId: "abc123",
		},
	})

	if err == nil {
		t.Fatal("expected gRPC error for hard provider error, got nil")
	}
	if !strings.Contains(err.Error(), "4xx") {
		t.Errorf("error should propagate the provider's rejection message, got: %v", err)
	}
}

func TestPollAnchorConfirmationHandler_ProviderNotRegistered(t *testing.T) {
	const (
		ledger   = "poll-test-prov-unregistered"
		provider = "poll-test-missing-provider"
	)

	// Register a lazy DB (sql.Open is lazy — no real connection until first query).
	// The pgx driver is registered via the blank import above.
	db, err := sql.Open("pgx", "postgres://u:p@localhost:5432/db?sslmode=disable")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	modules.RegisterDB(ledger, db)
	t.Cleanup(func() {
		modules.UnregisterDB(ledger)
		_ = db.Close()
	})

	modules.UnregisterAnchorProvider(provider)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(provider) })

	_, err = steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{},
		Input: &auditv1.PollAnchorConfirmationRequest{
			Ledger:     ledger,
			AnchorId:   "99",
			Provider:   provider,
			ExternalId: "xyz",
		},
	})
	if err == nil {
		t.Fatal("expected error for unregistered provider, got nil")
	}
	if !strings.Contains(err.Error(), provider) {
		t.Errorf("error should mention provider name %q, got: %v", provider, err)
	}
}

// TestPollAnchorConfirmationHandler_ConfigPathTakesPrecedence verifies that
// when BMW-style YAML supplies parameters via the `config:` block (typed Config
// proto) the handler reads them and ignores the zero-value Input. This is the
// load-bearing contract for the v0.2.2 strict-proto-config-fields fix.
func TestPollAnchorConfirmationHandler_ConfigPathTakesPrecedence(t *testing.T) {
	const (
		ledger   = "poll-test-cfg-precedence"
		provider = "poll-test-cfg-provider"
	)

	db := openFakeDB(t)
	modules.RegisterDB(ledger, db)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	mock := &mockAnchorProvider{
		providerName: provider,
		verifyResult: providers.Verification{
			Provider:     provider,
			Confirmation: providers.ConfirmationConfirmed,
		},
	}
	modules.RegisterAnchorProvider(provider, mock)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(provider) })

	result, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{
			Ledger:     ledger,
			AnchorId:   "7",
			Provider:   provider,
			ExternalId: "anchor-from-config",
			ProofData:  "opaque-bytes",
		},
		Input: &auditv1.PollAnchorConfirmationRequest{},
	})
	if err != nil {
		t.Fatalf("expected no error reading from Config, got: %v", err)
	}
	if result == nil || result.Output == nil {
		t.Fatal("expected non-nil result when Config supplies all fields")
	}
	if mock.lastAnchor.ExternalID != "anchor-from-config" {
		t.Errorf("provider received external_id=%q, want %q", mock.lastAnchor.ExternalID, "anchor-from-config")
	}
}

// TestPollAnchorConfirmationHandler_StringProofDataPassedThrough verifies the
// v0.2.3 type-drift bridge: PollAnchorConfirmationConfig.proof_data is `string`
// (so BMW templated values pass strict-proto without base64-encoding) and the
// merge converts it to []byte by raw byte copy. The mock provider records the
// Anchor.ProofData it received and the test asserts it equals the raw string
// bytes (no base64 decoding applied).
func TestPollAnchorConfirmationHandler_StringProofDataPassedThrough(t *testing.T) {
	const (
		ledger   = "poll-test-string-proof"
		provider = "poll-test-string-proof-provider"
	)

	db := openFakeDB(t)
	modules.RegisterDB(ledger, db)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	mock := &mockAnchorProvider{
		providerName: provider,
		verifyResult: providers.Verification{Provider: provider, Confirmation: providers.ConfirmationConfirmed},
	}
	modules.RegisterAnchorProvider(provider, mock)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(provider) })

	const rawProof = "opaque-proof-bytes-not-base64-encoded"
	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{
			Ledger:     ledger,
			AnchorId:   "13",
			Provider:   provider,
			ExternalId: "string-proof-ext",
			ProofData:  rawProof,
		},
		Input: &auditv1.PollAnchorConfirmationRequest{},
	})
	if err != nil {
		t.Fatalf("expected no error with string proof_data, got: %v", err)
	}
	if string(mock.lastAnchor.ProofData) != rawProof {
		t.Errorf("provider received ProofData=%q, want raw bytes %q (no base64 decode)",
			string(mock.lastAnchor.ProofData), rawProof)
	}
}

// TestPollAnchorConfirmationHandler_ConfigOverridesInput verifies the merge
// precedence: when Config and Input both populate the same field, Config wins.
// Important for pipelines that re-shape `pc.Current` between iterations.
func TestPollAnchorConfirmationHandler_ConfigOverridesInput(t *testing.T) {
	const (
		ledger   = "poll-test-cfg-override"
		provider = "poll-test-override-provider"
	)

	db := openFakeDB(t)
	modules.RegisterDB(ledger, db)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	mock := &mockAnchorProvider{
		providerName: provider,
		verifyResult: providers.Verification{Provider: provider, Confirmation: providers.ConfirmationConfirmed},
	}
	modules.RegisterAnchorProvider(provider, mock)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(provider) })

	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest]{
		Config: &auditv1.PollAnchorConfirmationConfig{
			Ledger:     ledger,
			AnchorId:   "11",
			Provider:   provider,
			ExternalId: "cfg-ext-id",
		},
		Input: &auditv1.PollAnchorConfirmationRequest{
			Ledger:     "wrong-ledger",
			AnchorId:   "999",
			Provider:   "wrong-provider",
			ExternalId: "input-ext-id",
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if mock.lastAnchor.ExternalID != "cfg-ext-id" {
		t.Errorf("Config should win on field collision: got external_id=%q, want %q", mock.lastAnchor.ExternalID, "cfg-ext-id")
	}
}
