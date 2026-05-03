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
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestPollAnchorConfirmationHandler_EmptyLedger(t *testing.T) {
	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PollAnchorConfirmationRequest]{
		Config: &emptypb.Empty{},
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

	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PollAnchorConfirmationRequest]{
		Config: &emptypb.Empty{},
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

	result, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PollAnchorConfirmationRequest]{
		Config: &emptypb.Empty{},
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

	_, err := steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PollAnchorConfirmationRequest]{
		Config: &emptypb.Empty{},
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

	_, err = steps.PollAnchorConfirmationHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PollAnchorConfirmationRequest]{
		Config: &emptypb.Empty{},
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
