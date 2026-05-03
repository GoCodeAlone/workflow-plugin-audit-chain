package steps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/emptypb"
)

// PublicReceiptHandler is the TypedStepHandler for step.audit.public_receipt.
// It builds a self-contained verifiable receipt JSON that includes the audit
// entry, its Merkle inclusion proof, all covering anchor records, and an
// optional pseudonymisation map for redacted payload fields.
func PublicReceiptHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*emptypb.Empty, *auditv1.PublicReceiptRequest],
) (*sdk.TypedStepResult[*auditv1.PublicReceiptResponse], error) {
	input := req.Input

	if input.GetLedger() == "" {
		return nil, fmt.Errorf("step.audit.public_receipt: ledger is required")
	}

	db, ok := modules.GetDB(input.GetLedger())
	if !ok {
		return nil, fmt.Errorf("step.audit.public_receipt: ledger %q not registered; ensure the audit.ledger module is initialised", input.GetLedger())
	}

	entry, err := fetchEntry(ctx, db, input.GetLedger(), input.GetSequence())
	if err != nil {
		return nil, fmt.Errorf("step.audit.public_receipt: %w", err)
	}

	anchors, err := fetchAnchorsForSequence(ctx, db, input.GetLedger(), input.GetSequence())
	if err != nil {
		return nil, fmt.Errorf("step.audit.public_receipt: %w", err)
	}

	var merklePath []string
	var merkleRoot string
	if len(anchors) > 0 {
		a := anchors[0]
		merkleRoot = a.merkleRootHex

		hashes, idx, err := queryEntryHashesWithIndex(ctx, db, input.GetLedger(), a.rangeStart, a.rangeEnd, input.GetSequence())
		if err != nil {
			return nil, fmt.Errorf("step.audit.public_receipt: %w", err)
		}
		if idx >= 0 {
			merklePath, err = chain.InclusionProof(hashes, idx)
			if err != nil {
				return nil, fmt.Errorf("step.audit.public_receipt: InclusionProof: %w", err)
			}
		}
	}

	// Apply payload redactions if requested.
	redactedPayload, pseudonymMap, err := applyRedactions(entry.GetPayload(), input.GetRedactFields())
	if err != nil {
		return nil, fmt.Errorf("step.audit.public_receipt: redact: %w", err)
	}

	// Build anchor records.
	anchorRecords := make([]*auditv1.AnchorRecord, 0, len(anchors))
	for _, a := range anchors {
		anchorRecords = append(anchorRecords, a.record)
	}

	// Marshal the receipt document.
	receiptDoc := map[string]any{
		"entry": map[string]any{
			"sequence":        entry.GetSequence(),
			"ledger":          entry.GetLedger(),
			"event_type":      entry.GetEventType(),
			"entry_hash":      entry.GetEntryHash(),
			"prev_entry_hash": entry.GetPrevEntryHash(),
			"payload":         json.RawMessage(redactedPayload),
			"created_at":      entry.GetCreatedAt(),
		},
		"merkle_proof": map[string]any{
			"merkle_root": merkleRoot,
			"merkle_path": merklePath,
		},
		"anchors":      anchorRecordSlice(anchorRecords),
		"pseudonym_map": pseudonymMap,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
	}

	receiptBytes, err := json.Marshal(receiptDoc)
	if err != nil {
		return nil, fmt.Errorf("step.audit.public_receipt: marshal receipt: %w", err)
	}
	receiptJSON := string(receiptBytes)

	h := sha256.Sum256(receiptBytes)
	receiptHash := hex.EncodeToString(h[:])

	return &sdk.TypedStepResult[*auditv1.PublicReceiptResponse]{
		Output: &auditv1.PublicReceiptResponse{
			ReceiptJson: receiptJSON,
			ReceiptHash: receiptHash,
			// ReceiptUrl is empty until a serving layer is wired; the hash
			// and JSON are sufficient for offline verification.
		},
	}, nil
}

// applyRedactions removes the listed JSON path keys from payload and returns
// the redacted payload bytes plus a pseudonym map (key → stable placeholder).
// Only top-level keys are supported in this implementation.
// If redactFields is empty, the original payload is returned unchanged.
func applyRedactions(payload []byte, redactFields []string) ([]byte, map[string]string, error) {
	if len(redactFields) == 0 || len(payload) == 0 {
		return payload, nil, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	pseudonymMap := make(map[string]string, len(redactFields))
	for _, field := range redactFields {
		if _, exists := obj[field]; !exists {
			continue
		}
		// Stable pseudonym: SHA256 of the original value (hex-encoded).
		h := sha256.Sum256(obj[field])
		pseudonymMap[field] = "<redacted:" + hex.EncodeToString(h[:])[:16] + ">"
		delete(obj, field)
	}

	redacted, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal redacted payload: %w", err)
	}
	return redacted, pseudonymMap, nil
}

// anchorRecordSlice converts a slice of *auditv1.AnchorRecord to a
// []map[string]any for JSON serialisation in the receipt document.
func anchorRecordSlice(records []*auditv1.AnchorRecord) []map[string]any {
	out := make([]map[string]any, 0, len(records))
	for _, r := range records {
		out = append(out, map[string]any{
			"provider":     r.GetProvider(),
			"external_id":  r.GetExternalId(),
			"confirmation": r.GetConfirmation(),
			"anchored_at":  r.GetAnchoredAt(),
		})
	}
	return out
}
