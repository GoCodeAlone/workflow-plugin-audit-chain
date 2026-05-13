package steps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// ── receipt document types (no map[string]any) ────────────────────────────────

// receiptDocument is the top-level object serialised into receipt_json.
type receiptDocument struct {
	Entry        receiptEntry        `json:"entry"`
	MerkleProof  receiptMerkleProof  `json:"merkle_proof"`
	Anchors      []receiptAnchor     `json:"anchors"`
	PseudonymMap map[string]string   `json:"pseudonym_map,omitempty"`
	GeneratedAt  string              `json:"generated_at"`
}

// receiptEntry holds the audit log entry fields included in the receipt.
type receiptEntry struct {
	Sequence      int64           `json:"sequence"`
	Ledger        string          `json:"ledger"`
	EventType     string          `json:"event_type"`
	EntryHash     string          `json:"entry_hash"`
	PrevEntryHash string          `json:"prev_entry_hash"`
	Payload       json.RawMessage `json:"payload"`
	CreatedAt     string          `json:"created_at"`
}

// receiptMerkleProof holds the Merkle root and inclusion path.
type receiptMerkleProof struct {
	MerkleRoot string   `json:"merkle_root"`
	MerklePath []string `json:"merkle_path"`
}

// receiptAnchor holds a single anchor record for the receipt document.
type receiptAnchor struct {
	Provider     string `json:"provider"`
	ExternalID   string `json:"external_id"`
	Confirmation string `json:"confirmation"`
	AnchoredAt   string `json:"anchored_at"`
}

// ── handler ───────────────────────────────────────────────────────────────────

// PublicReceiptHandler is the TypedStepHandler for step.audit.public_receipt.
// It builds a self-contained verifiable receipt JSON that includes the audit
// entry, its Merkle inclusion proof, all covering anchor records, and an
// optional pseudonymisation map for redacted payload fields.
//
// BMW-style YAML pipelines supply all parameters via the step's `config:`
// block, so the handler reads from req.Config first and falls back to req.Input
// for direct (integration-test) gRPC dispatch.
func PublicReceiptHandler(
	ctx context.Context,
	req sdk.TypedStepRequest[*auditv1.PublicReceiptConfig, *auditv1.PublicReceiptRequest],
) (*sdk.TypedStepResult[*auditv1.PublicReceiptResponse], error) {
	input, err := mergePublicReceipt(req.Config, req.Input)
	if err != nil {
		return nil, fmt.Errorf("step.audit.public_receipt: %w", err)
	}

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
	if merklePath == nil {
		merklePath = []string{}
	}

	// Apply payload redactions if requested.
	redactedPayload, pseudonymMap, err := ApplyRedactions(entry.GetPayload(), input.GetRedactFields())
	if err != nil {
		return nil, fmt.Errorf("step.audit.public_receipt: redact: %w", err)
	}

	// Convert anchors to the receipt document format.
	anchorsForDoc := make([]receiptAnchor, 0, len(anchors))
	for _, a := range anchors {
		anchorsForDoc = append(anchorsForDoc, receiptAnchor{
			Provider:     a.record.GetProvider(),
			ExternalID:   a.record.GetExternalId(),
			Confirmation: a.record.GetConfirmation(),
			AnchoredAt:   a.record.GetAnchoredAt(),
		})
	}

	// Marshal the receipt document using typed structs (no map[string]any).
	receiptDoc := receiptDocument{
		Entry: receiptEntry{
			Sequence:      entry.GetSequence(),
			Ledger:        entry.GetLedger(),
			EventType:     entry.GetEventType(),
			EntryHash:     entry.GetEntryHash(),
			PrevEntryHash: entry.GetPrevEntryHash(),
			Payload:       json.RawMessage(redactedPayload),
			CreatedAt:     entry.GetCreatedAt(),
		},
		MerkleProof: receiptMerkleProof{
			MerkleRoot: merkleRoot,
			MerklePath: merklePath,
		},
		Anchors:      anchorsForDoc,
		PseudonymMap: pseudonymMap,
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
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
			// ReceiptUrl is empty until a serving layer is wired; hash + JSON
			// are sufficient for offline verification.
		},
	}, nil
}

// mergePublicReceipt collapses the YAML-`config:`-sourced typed config and the
// runtime-sourced typed input into a single PublicReceiptRequest view that the
// rest of the handler can read uniformly.
//
// Precedence semantics: a non-zero value in Config overrides the corresponding
// Input field; a zero / empty / nil Config value falls back to Input. proto3
// scalars cannot distinguish "unset" from "explicit zero" without wrapper or
// `optional` types, so empty strings, the int64 zero value, and an empty
// repeated field in Config cannot be used to clear an Input field. BMW
// pipelines populate every parameter via `config:` with non-zero values and
// leave Input empty (pc.Current carries no Request-shaped data), so this
// asymmetry does not bite production. Direct gRPC callers populate only
// Input.
//
// Type-drift bridge (v0.2.3): PublicReceiptConfig.sequence is `string` so
// BMW templated values like `"{{ .item.audit_sequence }}"` pass strict-proto
// validation. PublicReceiptRequest.sequence remains `int64` for the gRPC
// Input path. mergePublicReceipt parses the Config string to int64 here;
// the rest of the handler reads the int64 from PublicReceiptRequest. Errors
// returned to the caller as a non-nil error.
func mergePublicReceipt(cfg *auditv1.PublicReceiptConfig, in *auditv1.PublicReceiptRequest) (*auditv1.PublicReceiptRequest, error) {
	merged := &auditv1.PublicReceiptRequest{}
	if in != nil {
		merged.Ledger = in.GetLedger()
		merged.Sequence = in.GetSequence()
		merged.RedactFields = append(merged.RedactFields, in.GetRedactFields()...)
	}
	if cfg != nil {
		if v := cfg.GetLedger(); v != "" {
			merged.Ledger = v
		}
		if v := cfg.GetSequence(); v != "" {
			seq, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid sequence %q: %w", v, err)
			}
			merged.Sequence = seq
		}
		if v := cfg.GetRedactFields(); len(v) > 0 {
			merged.RedactFields = append([]string(nil), v...)
		}
	}
	return merged, nil
}

// ── redaction ─────────────────────────────────────────────────────────────────

// ApplyRedactions replaces the listed top-level JSON keys in payload with
// stable per-receipt pseudonyms of the form "contributor_N", where N increments
// once per unique original value within this receipt's scope (duplicate original
// values receive the same pseudonym). The field is REPLACED (not deleted) so
// the payload structure is preserved.
// Returns the modified payload bytes, a field→pseudonym mapping, and any error.
// Exported so it can be tested independently.
func ApplyRedactions(payload []byte, redactFields []string) ([]byte, map[string]string, error) {
	if len(redactFields) == 0 || len(payload) == 0 {
		return payload, nil, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(payload, &obj); err != nil {
		return nil, nil, fmt.Errorf("unmarshal payload: %w", err)
	}

	pseudonymMap := make(map[string]string, len(redactFields))
	// valueToCounter maps the raw JSON representation of a value to its assigned
	// pseudonym so that duplicate originals get the same contributor label.
	valueToCounter := make(map[string]string)
	counter := 1

	for _, field := range redactFields {
		raw, exists := obj[field]
		if !exists {
			continue
		}
		// Deduplicate: identical raw JSON values share one pseudonym in this receipt.
		key := string(raw)
		pseudonym, seen := valueToCounter[key]
		if !seen {
			pseudonym = "contributor_" + strconv.Itoa(counter)
			valueToCounter[key] = pseudonym
			counter++
		}
		pseudonymMap[field] = pseudonym
		// Replace (not delete) the field value with the pseudonym string.
		obj[field] = json.RawMessage(strconv.Quote(pseudonym))
	}

	redacted, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal redacted payload: %w", err)
	}
	return redacted, pseudonymMap, nil
}
