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

// MerkleRootHandler is the TypedStepHandler for step.audit.merkle_root.
// It reads the entry hashes for the requested sequence range, builds a binary
// Merkle tree using RFC 6962 leaf/node hashing, and returns the root.
func MerkleRootHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.MerkleRootRequest],
) (*sdk.TypedStepResult[*auditv1.MerkleRootResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.merkle_root: ledger is required")
	}

	db, ok := modules.GetDB(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.merkle_root: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	rows, err := db.QueryContext(ctx, `
		SELECT sequence, entry_hash
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
		return nil, fmt.Errorf("step.audit.merkle_root: query: %w", err)
	}
	defer rows.Close()

	var (
		hashes    []string
		startSeq  int64
		endSeq    int64
		first     = true
	)
	for rows.Next() {
		var seq int64
		var entryHash string
		if err := rows.Scan(&seq, &entryHash); err != nil {
			return nil, fmt.Errorf("step.audit.merkle_root: scan: %w", err)
		}
		if first {
			startSeq = seq
			first = false
		}
		endSeq = seq
		hashes = append(hashes, entryHash)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("step.audit.merkle_root: rows: %w", err)
	}

	if len(hashes) == 0 {
		return nil, fmt.Errorf("step.audit.merkle_root: no entries found in ledger %q for sequence range [%d, %d]",
			input.GetLedger(), input.GetStartSequence(), input.GetEndSequence())
	}

	root, err := chain.MerkleRoot(hashes)
	if err != nil {
		return nil, fmt.Errorf("step.audit.merkle_root: %w", err)
	}

	return &sdk.TypedStepResult[*auditv1.MerkleRootResponse]{
		Output: &auditv1.MerkleRootResponse{
			Root:             root,
			EntriesIncluded:  int64(len(hashes)),
			StartSequence:    startSeq,
			EndSequence:      endSeq,
		},
	}, nil
}
