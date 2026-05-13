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
)

// PollAnchorConfirmationHandler is the TypedStepHandler for
// step.audit.poll_anchor_confirmation.
//
// Swallow-transient-errors contract (§ 3.5c):
//   - Transient errors (network, 5xx, calendar unreachable) → successful response
//     with swallowed = true, error_message set, confirmation unchanged.
//   - Hard errors (invalid proof, 4xx semantic rejection) → gRPC error (returned
//     as a non-nil error from this handler).
//
// BMW-style YAML pipelines supply all parameters via the step's `config:`
// block, so the handler reads from req.Config first and falls back to req.Input
// for direct (integration-test) gRPC dispatch.
func PollAnchorConfirmationHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*auditv1.PollAnchorConfirmationConfig, *auditv1.PollAnchorConfirmationRequest],
) (*sdk.TypedStepResult[*auditv1.PollAnchorConfirmationResponse], error) {
	input := mergePollAnchorConfirmation(req.Config, req.Input)

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
	// NB: input.ProofData is []byte from the gRPC Input path. The Config path
	// supplies proof_data as a raw string (v0.2.3 — strict-proto rejects
	// non-base64 bytes from BMW templates); mergePollAnchorConfirmation
	// converts string→[]byte by direct byte copy (treats Config value as raw
	// opaque proof bytes; no base64 decode is applied). Providers currently
	// treat ProofData as opaque pass-through, so the raw-string semantics are
	// safe; if a future provider requires base64-encoded proof, that decode is
	// the provider's responsibility.

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

// mergePollAnchorConfirmation collapses the YAML-`config:`-sourced typed config
// and the runtime-sourced typed input into a single PollAnchorConfirmationRequest
// view that the rest of the handler can read uniformly.
//
// Precedence semantics: a non-zero value in Config overrides the corresponding
// Input field; a zero / empty / nil Config value falls back to Input. proto3
// scalars cannot distinguish "unset" from "explicit zero" without wrapper or
// `optional` types, so empty strings, the int64 zero value, and a zero-length
// bytes slice in Config cannot be used to clear an Input field. BMW pipelines
// populate every parameter via `config:` with non-zero values and leave Input
// empty (pc.Current carries no Request-shaped data), so this asymmetry does
// not bite production. Direct gRPC callers (integration_test.go) populate only
// Input.
//
// Type-drift bridge (v0.2.3): PollAnchorConfirmationConfig.proof_data is
// `string` (not `bytes`) so BMW templated values like
// `"{{ .item.proof_data }}"` pass strict-proto validation without requiring
// base64 encoding. PollAnchorConfirmationRequest.proof_data remains `bytes`
// for the gRPC Input path. The merge converts string→[]byte by raw byte
// copy (no base64 decode); providers treat ProofData as an opaque
// pass-through so the raw-string semantics are safe.
func mergePollAnchorConfirmation(cfg *auditv1.PollAnchorConfirmationConfig, in *auditv1.PollAnchorConfirmationRequest) *auditv1.PollAnchorConfirmationRequest {
	merged := &auditv1.PollAnchorConfirmationRequest{}
	if in != nil {
		merged.AnchorId = in.GetAnchorId()
		merged.Provider = in.GetProvider()
		merged.ExternalId = in.GetExternalId()
		merged.ProofData = in.GetProofData()
		merged.Ledger = in.GetLedger()
	}
	if cfg != nil {
		if v := cfg.GetAnchorId(); v != "" {
			merged.AnchorId = v
		}
		if v := cfg.GetProvider(); v != "" {
			merged.Provider = v
		}
		if v := cfg.GetExternalId(); v != "" {
			merged.ExternalId = v
		}
		if v := cfg.GetProofData(); v != "" {
			merged.ProofData = []byte(v)
		}
		if v := cfg.GetLedger(); v != "" {
			merged.Ledger = v
		}
	}
	return merged
}
