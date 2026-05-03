package steps

import (
	"context"
	"fmt"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

// VerifyHandler is the TypedStepHandler for step.audit.verify.
// It scans the audit_log table in the requested sequence range and
// re-derives each entry hash, checking both hash integrity and chain linkage.
func VerifyHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.VerifyRequest],
) (*sdk.TypedStepResult[*auditv1.VerifyResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.verify: ledger is required")
	}

	db, ok := modules.GetDB(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.verify: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	rows, err := db.QueryContext(ctx, `
		SELECT sequence, event_type, payload_hash, prev_entry_hash, entry_hash
		  FROM audit_log
		 WHERE ledger = $1
		   AND sequence >= $2
		   AND ($3 = 0 OR sequence <= $3)
		 ORDER BY sequence ASC`,
		input.GetLedger(),
		input.GetStartSequence(),
		input.GetEndSequence(),
	)
	if err != nil {
		return nil, fmt.Errorf("step.audit.verify: query: %w", err)
	}
	defer rows.Close()

	var (
		verified  int64
		prevHash  string
		firstSeq  int64 = -1
	)
	for rows.Next() {
		var seq int64
		var eventType, payloadHash, prevEntryHash, entryHash string
		if err := rows.Scan(&seq, &eventType, &payloadHash, &prevEntryHash, &entryHash); err != nil {
			return nil, fmt.Errorf("step.audit.verify: scan: %w", err)
		}

		// Check chain linkage: prev_entry_hash must match the previous entry's hash
		// (or be empty for the genesis entry at sequence 1).
		if verified > 0 && prevEntryHash != prevHash {
			return &sdk.TypedStepResult[*auditv1.VerifyResponse]{
				Output: &auditv1.VerifyResponse{
					Valid:                 false,
					FirstInvalidSequence:  seq,
					FailureReason:         fmt.Sprintf("chain link broken at sequence %d: prev_entry_hash mismatch", seq),
					EntriesVerified:       verified,
				},
			}, nil
		}

		// Re-derive the entry hash and compare.
		expected := chain.EntryHash(seq, input.GetLedger(), eventType, payloadHash, prevEntryHash)
		if expected != entryHash {
			return &sdk.TypedStepResult[*auditv1.VerifyResponse]{
				Output: &auditv1.VerifyResponse{
					Valid:                 false,
					FirstInvalidSequence:  seq,
					FailureReason:         fmt.Sprintf("entry hash mismatch at sequence %d: stored=%s derived=%s", seq, entryHash, expected),
					EntriesVerified:       verified,
				},
			}, nil
		}

		if firstSeq < 0 {
			firstSeq = seq
		}
		prevHash = entryHash
		verified++
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("step.audit.verify: rows: %w", err)
	}

	return &sdk.TypedStepResult[*auditv1.VerifyResponse]{
		Output: &auditv1.VerifyResponse{
			Valid:            true,
			EntriesVerified:  verified,
		},
	}, nil
}
