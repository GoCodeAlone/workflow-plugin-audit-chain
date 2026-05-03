package steps

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ProofHandler is the TypedStepHandler for step.audit.proof.
// It fetches the entry at the requested sequence, finds all anchors covering
// that sequence, and builds a Merkle inclusion proof for the first covering
// anchor range.
func ProofHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.ProofRequest],
) (*sdk.TypedStepResult[*auditv1.ProofResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.proof: ledger is required")
	}

	db, ok := modules.GetDB(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.proof: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	entry, err := fetchEntry(ctx, db, input.GetLedger(), input.GetSequence())
	if err != nil {
		return nil, fmt.Errorf("step.audit.proof: %w", err)
	}

	anchors, err := fetchAnchorsForSequence(ctx, db, input.GetLedger(), input.GetSequence())
	if err != nil {
		return nil, fmt.Errorf("step.audit.proof: %w", err)
	}

	var merklePath []string
	var merkleRoot string
	if len(anchors) > 0 {
		a := anchors[0]
		merkleRoot = a.merkleRootHex

		hashes, idx, err := queryEntryHashesWithIndex(ctx, db, input.GetLedger(), a.rangeStart, a.rangeEnd, input.GetSequence())
		if err != nil {
			return nil, fmt.Errorf("step.audit.proof: %w", err)
		}
		if idx >= 0 {
			merklePath, err = chain.InclusionProof(hashes, idx)
			if err != nil {
				return nil, fmt.Errorf("step.audit.proof: InclusionProof: %w", err)
			}
		}
	}

	anchorRecords := make([]*auditv1.AnchorRecord, 0, len(anchors))
	for _, a := range anchors {
		anchorRecords = append(anchorRecords, a.record)
	}

	return &sdk.TypedStepResult[*auditv1.ProofResponse]{
		Output: &auditv1.ProofResponse{
			Entry:      entry,
			MerklePath: merklePath,
			MerkleRoot: merkleRoot,
			Anchors:    anchorRecords,
		},
	}, nil
}

// ── shared query helpers ──────────────────────────────────────────────────────

// fetchEntry queries a single audit_log row and converts it to *auditv1.Entry.
func fetchEntry(ctx context.Context, db *sql.DB, ledger string, sequence int64) (*auditv1.Entry, error) {
	var (
		seq                                                      int64
		eventType, payloadHash, prevEntryHash, entryHash, actor string
		payload, metadata                                        []byte
		createdAt                                                time.Time
	)
	err := db.QueryRowContext(ctx, `
		SELECT sequence, event_type, payload, payload_hash,
		       prev_entry_hash, entry_hash, created_at, appended_by_actor, metadata
		  FROM audit_log
		 WHERE ledger = $1 AND sequence = $2`,
		ledger, sequence,
	).Scan(&seq, &eventType, &payload, &payloadHash,
		&prevEntryHash, &entryHash, &createdAt, &actor, &metadata)
	if err != nil {
		return nil, fmt.Errorf("fetch entry seq=%d ledger=%q: %w", sequence, ledger, err)
	}
	return &auditv1.Entry{
		Sequence:      seq,
		Ledger:        ledger,
		EventType:     eventType,
		Payload:       payload,
		EntryHash:     entryHash,
		PrevEntryHash: prevEntryHash,
		CreatedAt:     createdAt.UTC().Format(time.RFC3339),
		Actor:         actor,
		Metadata:      metadata,
	}, nil
}

// anchorRow holds data from audit_anchors for internal use.
type anchorRow struct {
	rangeStart, rangeEnd int64
	merkleRootHex        string
	record               *auditv1.AnchorRecord
}

// fetchAnchorsForSequence returns all audit_anchors rows whose range covers seq.
func fetchAnchorsForSequence(ctx context.Context, db *sql.DB, ledger string, seq int64) ([]anchorRow, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT range_start, range_end, merkle_root, provider, external_id, confirmation, anchored_at
		  FROM audit_anchors
		 WHERE ledger = $1
		   AND range_start <= $2
		   AND range_end   >= $2
		 ORDER BY id ASC`,
		ledger, seq,
	)
	if err != nil {
		return nil, fmt.Errorf("query anchors for seq=%d: %w", seq, err)
	}
	defer rows.Close()

	var result []anchorRow
	for rows.Next() {
		var (
			rangeStart, rangeEnd       int64
			merkleRoot, prov, extID, conf string
			anchoredAt                 time.Time
		)
		if err := rows.Scan(&rangeStart, &rangeEnd, &merkleRoot, &prov, &extID, &conf, &anchoredAt); err != nil {
			return nil, fmt.Errorf("scan anchor: %w", err)
		}
		result = append(result, anchorRow{
			rangeStart:    rangeStart,
			rangeEnd:      rangeEnd,
			merkleRootHex: merkleRoot,
			record: &auditv1.AnchorRecord{
				Provider:     prov,
				ExternalId:   extID,
				Confirmation: conf,
				AnchoredAt:   anchoredAt.UTC().Format(time.RFC3339),
			},
		})
	}
	return result, rows.Err()
}

// queryEntryHashesWithIndex queries entry hashes for [rangeStart, rangeEnd]
// and returns the slice of hashes plus the index of targetSeq (-1 if absent).
func queryEntryHashesWithIndex(ctx context.Context, db *sql.DB, ledger string, rangeStart, rangeEnd, targetSeq int64) ([]string, int, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT sequence, entry_hash
		  FROM audit_log
		 WHERE ledger = $1
		   AND sequence >= $2
		   AND sequence <= $3
		 ORDER BY sequence ASC`,
		ledger, rangeStart, rangeEnd,
	)
	if err != nil {
		return nil, -1, fmt.Errorf("query entry hashes [%d,%d]: %w", rangeStart, rangeEnd, err)
	}
	defer rows.Close()

	var hashes []string
	idx := -1
	i := 0
	for rows.Next() {
		var seq int64
		var h string
		if err := rows.Scan(&seq, &h); err != nil {
			return nil, -1, fmt.Errorf("scan entry hash: %w", err)
		}
		if seq == targetSeq {
			idx = i
		}
		hashes = append(hashes, h)
		i++
	}
	return hashes, idx, rows.Err()
}
