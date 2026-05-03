package steps_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
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
