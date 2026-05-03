// Package steps implements the seven audit-chain step types as typed proto
// handlers. All handler functions satisfy sdk.TypedStepHandler and are wired
// into sdk.TypedStepFactory instances in internal/plugin.go.
//
// Zero map[string]any: every handler receives a typed *auditv1.* input and
// returns a typed *auditv1.* output via sdk.TypedStepResult.
package steps

import (
	"context"
	"fmt"
	"time"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AppendHandler is the TypedStepHandler for step.audit.append.
// It appends one hash-chained entry to the named ledger and returns the
// assigned sequence number, entry hash, and server-side timestamp.
func AppendHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AppendRequest],
) (*sdk.TypedStepResult[*auditv1.AppendResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.append: ledger is required")
	}
	if input.GetEventType() == "" {
		return nil, fmt.Errorf("step.audit.append: event_type is required")
	}

	appender, ok := modules.GetLedger(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.append: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	seq, entryHash, err := appender.Append(
		ctx,
		input.GetLedger(),
		input.GetEventType(),
		input.GetPayload(),
		input.GetMetadata(),
		input.GetActor(),
	)
	if err != nil {
		return nil, fmt.Errorf("step.audit.append: %w", err)
	}

	return &sdk.TypedStepResult[*auditv1.AppendResponse]{
		Output: &auditv1.AppendResponse{
			Sequence:  seq,
			EntryHash: entryHash,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		},
	}, nil
}
