package steps

import (
	"context"
	"fmt"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

// AnchorHandler is the TypedStepHandler for step.audit.anchor.
// It computes the Merkle root over the requested sequence range, submits it
// to each configured anchor provider, and records the pending anchors in
// audit_anchors.
func AnchorHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.AnchorRequest],
) (*sdk.TypedStepResult[*auditv1.AnchorResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.anchor: ledger is required")
	}

	db, ok := modules.GetDB(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.anchor: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	// Resolve the sequence range. 0 end_sequence → latest from audit_ledgers.
	startSeq := input.GetStartSequence()
	endSeq := input.GetEndSequence()
	if endSeq == 0 {
		err := db.QueryRowContext(ctx,
			`SELECT last_sequence FROM audit_ledgers WHERE ledger = $1`,
			input.GetLedger(),
		).Scan(&endSeq)
		if err != nil {
			return nil, fmt.Errorf("step.audit.anchor: resolve last_sequence for %q: %w", input.GetLedger(), err)
		}
	}

	// Query entry hashes in range.
	rows, err := db.QueryContext(ctx, `
		SELECT entry_hash
		  FROM audit_log
		 WHERE ledger = $1
		   AND sequence >= $2
		   AND sequence <= $3
		 ORDER BY sequence ASC`,
		input.GetLedger(), startSeq, endSeq,
	)
	if err != nil {
		return nil, fmt.Errorf("step.audit.anchor: query entry hashes: %w", err)
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, fmt.Errorf("step.audit.anchor: scan: %w", err)
		}
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("step.audit.anchor: rows: %w", err)
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("step.audit.anchor: no entries in ledger %q sequence range [%d, %d]",
			input.GetLedger(), startSeq, endSeq)
	}

	merkleRoot, err := chain.MerkleRoot(hashes)
	if err != nil {
		return nil, fmt.Errorf("step.audit.anchor: %w", err)
	}

	// Determine which providers to use.
	providerNames := input.GetProviders()
	if len(providerNames) == 0 {
		// Empty = all configured anchor providers in the registry (snapshot names).
		providerNames = modules.AnchorProviderNames()
	}

	var anchorRecords []*auditv1.AnchorRecord
	for _, name := range providerNames {
		p, ok := modules.GetAnchorProvider(name)
		if !ok {
			return nil, fmt.Errorf("step.audit.anchor: anchor provider %q not registered", name)
		}

		a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: merkleRoot})
		if err != nil {
			return nil, fmt.Errorf("step.audit.anchor: provider %q: %w", name, err)
		}

		// Persist to audit_anchors. ON CONFLICT DO NOTHING makes this idempotent:
		// a retried anchor step for the same (ledger, provider, range) silently
		// skips the INSERT rather than failing with a unique-constraint violation.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO audit_anchors
				(ledger, range_start, range_end, merkle_root, provider, external_id, proof_data, confirmation, anchored_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (ledger, provider, range_start, range_end) DO NOTHING`,
			input.GetLedger(), startSeq, endSeq, merkleRoot,
			a.ProviderName, a.ExternalID, a.ProofData, string(a.Confirmation),
			a.AnchoredAt.UTC(),
		); err != nil {
			return nil, fmt.Errorf("step.audit.anchor: insert audit_anchors for provider %q: %w", name, err)
		}

		anchorRecords = append(anchorRecords, &auditv1.AnchorRecord{
			Provider:     a.ProviderName,
			ExternalId:   a.ExternalID,
			Confirmation: string(a.Confirmation),
			AnchoredAt:   a.AnchoredAt.UTC().Format(time.RFC3339),
		})
	}

	return &sdk.TypedStepResult[*auditv1.AnchorResponse]{
		Output: &auditv1.AnchorResponse{
			Anchors: anchorRecords,
		},
	}, nil
}
