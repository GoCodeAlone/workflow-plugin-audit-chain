package steps_test

import (
	"context"
	"strings"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/steps"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestAppendHandler_EmptyLedger(t *testing.T) {
	_, err := steps.AppendHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AppendRequest]{
		Config: &emptypb.Empty{},
		Input:  &auditv1.AppendRequest{Ledger: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty ledger, got nil")
	}
	if !strings.Contains(err.Error(), "ledger") {
		t.Errorf("error should mention ledger field, got: %v", err)
	}
}

func TestAppendHandler_LedgerNotRegistered(t *testing.T) {
	const ledger = "append-test-unregistered"
	modules.UnregisterLedger(ledger)
	t.Cleanup(func() { modules.UnregisterLedger(ledger) })

	_, err := steps.AppendHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AppendRequest]{
		Config: &emptypb.Empty{},
		Input: &auditv1.AppendRequest{
			Ledger:    ledger,
			EventType: "test.event",
			Payload:   []byte(`{"k":"v"}`),
		},
	})
	if err == nil {
		t.Fatal("expected error for unregistered ledger, got nil")
	}
	if !strings.Contains(err.Error(), ledger) {
		t.Errorf("error should mention ledger name %q, got: %v", ledger, err)
	}
}

func TestAppendHandler_EmptyEventType(t *testing.T) {
	const ledger = "append-test-empty-event-type"
	modules.UnregisterLedger(ledger)
	t.Cleanup(func() { modules.UnregisterLedger(ledger) })

	_, err := steps.AppendHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AppendRequest]{
		Config: &emptypb.Empty{},
		Input: &auditv1.AppendRequest{
			Ledger:    ledger,
			EventType: "",
			Payload:   []byte(`{"k":"v"}`),
		},
	})
	if err == nil {
		t.Fatal("expected error for empty event_type, got nil")
	}
}
