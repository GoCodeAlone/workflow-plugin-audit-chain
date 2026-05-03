package steps

import (
	"context"
	"fmt"
	"strconv"
	"time"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

// PollAnchorConfirmationHandler is the TypedStepHandler for
// step.audit.poll_anchor_confirmation.
//
// Swallow-transient-errors contract (§ 3.5c):
//   - Transient errors (network, 5xx, calendar unreachable) → successful response
//     with swallowed = true, error_message set, confirmation unchanged.
//   - Hard errors (invalid proof, 4xx semantic rejection) → gRPC error (returned
//     as a non-nil error from this handler).
func PollAnchorConfirmationHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PollAnchorConfirmationRequest],
) (*sdk.TypedStepResult[*auditv1.PollAnchorConfirmationResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: ledger is required")
	}

	db, ok := modules.GetDB(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	p, ok := modules.GetAnchorProvider(input.GetProvider())
	if !ok {
		return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: anchor provider %q not registered", input.GetProvider())
	}

	// Parse anchor_id (stored as string to be pipeline-friendly; DB primary key is BIGSERIAL).
	anchorID, err := strconv.ParseInt(input.GetAnchorId(), 10, 64)
	if err != nil {
		return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: invalid anchor_id %q: %w", input.GetAnchorId(), err)
	}

	// Read the current confirmation from the DB.
	var prevConfirmation string
	if err := db.QueryRowContext(ctx,
		`SELECT confirmation FROM audit_anchors WHERE id = $1`,
		anchorID,
	).Scan(&prevConfirmation); err != nil {
		return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: read anchor %d: %w", anchorID, err)
	}

	anchor := providers.Anchor{
		ProviderName: input.GetProvider(),
		ExternalID:   input.GetExternalId(),
		ProofData:    input.GetProofData(),
		Confirmation: providers.ConfirmationLevel(prevConfirmation),
	}

	v, err := p.Verify(ctx, anchor)
	if err != nil {
		// Hard error — abort step.
		return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: verify: %w", err)
	}

	updatedAt := v.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = time.Now().UTC()
	}

	// Transient error swallowed by the provider — return success without updating DB.
	if v.Swallowed {
		return &sdk.TypedStepResult[*auditv1.PollAnchorConfirmationResponse]{
			Output: &auditv1.PollAnchorConfirmationResponse{
				PreviousConfirmation: prevConfirmation,
				CurrentConfirmation:  prevConfirmation,
				Transitioned:         false,
				UpdatedAt:            updatedAt.UTC().Format(time.RFC3339),
				Swallowed:            true,
				ErrorMessage:         v.ErrorMessage,
			},
		}, nil
	}

	// Forward-only ordering guard: prevent downgrade (finalized→confirmed,
	// confirmed→pending). A provider returning a lower confirmation level must
	// not overwrite a more advanced state in the DB.
	confirmationOrder := map[string]int{"pending": 0, "confirmed": 1, "finalized": 2}
	currentConfirmation := string(v.Confirmation)
	transitioned := confirmationOrder[currentConfirmation] > confirmationOrder[prevConfirmation]

	if transitioned {
		_, err = db.ExecContext(ctx, `
			UPDATE audit_anchors
			   SET confirmation  = $1,
			       confirmed_at  = CASE WHEN $1 = 'confirmed' THEN NOW() ELSE confirmed_at END,
			       finalized_at  = CASE WHEN $1 = 'finalized' THEN NOW() ELSE finalized_at END
			 WHERE id = $2`,
			currentConfirmation, anchorID,
		)
		if err != nil {
			return nil, fmt.Errorf("step.audit.poll_anchor_confirmation: update anchor %d: %w", anchorID, err)
		}
	}

	return &sdk.TypedStepResult[*auditv1.PollAnchorConfirmationResponse]{
		Output: &auditv1.PollAnchorConfirmationResponse{
			PreviousConfirmation: prevConfirmation,
			CurrentConfirmation:  currentConfirmation,
			Transitioned:         transitioned,
			UpdatedAt:            updatedAt.UTC().Format(time.RFC3339),
		},
	}, nil
}
