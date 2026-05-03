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

func TestAnchorHandler_EmptyLedger(t *testing.T) {
	_, err := steps.AnchorHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AnchorRequest]{
		Config: &emptypb.Empty{},
		Input:  &auditv1.AnchorRequest{Ledger: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty ledger, got nil")
	}
	if !strings.Contains(err.Error(), "ledger") {
		t.Errorf("error should mention ledger field, got: %v", err)
	}
}

func TestAnchorHandler_DBNotRegistered(t *testing.T) {
	const ledger = "anchor-test-unregistered"
	modules.UnregisterDB(ledger)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	_, err := steps.AnchorHandler(context.Background(), sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AnchorRequest]{
		Config: &emptypb.Empty{},
		Input: &auditv1.AnchorRequest{
			Ledger:        ledger,
			StartSequence: 1,
			EndSequence:   10,
		},
	})
	if err == nil {
		t.Fatal("expected error for unregistered DB, got nil")
	}
	if !strings.Contains(err.Error(), ledger) {
		t.Errorf("error should mention ledger name %q, got: %v", ledger, err)
	}
}
