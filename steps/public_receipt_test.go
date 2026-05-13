package steps_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/steps"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestPublicReceiptHandler_EmptyLedger(t *testing.T) {
	_, err := steps.PublicReceiptHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PublicReceiptConfig, *auditv1.PublicReceiptRequest]{
		Config: &auditv1.PublicReceiptConfig{},
		Input:  &auditv1.PublicReceiptRequest{Ledger: ""},
	})
	if err == nil {
		t.Fatal("expected error for empty ledger, got nil")
	}
	if !strings.Contains(err.Error(), "ledger") {
		t.Errorf("error should mention ledger field, got: %v", err)
	}
}

func TestPublicReceiptHandler_DBNotRegistered(t *testing.T) {
	const ledger = "receipt-test-unregistered"
	modules.UnregisterDB(ledger)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	_, err := steps.PublicReceiptHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PublicReceiptConfig, *auditv1.PublicReceiptRequest]{
		Config: &auditv1.PublicReceiptConfig{},
		Input: &auditv1.PublicReceiptRequest{
			Ledger:   ledger,
			Sequence: 5,
		},
	})
	if err == nil {
		t.Fatal("expected error for unregistered DB, got nil")
	}
	if !strings.Contains(err.Error(), ledger) {
		t.Errorf("error should mention ledger name %q, got: %v", ledger, err)
	}
}

// TestPublicReceiptHandler_ConfigPathTakesPrecedence verifies that BMW-style
// YAML supplying parameters via `config:` lands in the handler when Input is
// the zero value. The handler reaches the DB-not-registered path using the
// ledger from Config, proving the merge picked Config up correctly. Load-
// bearing contract for the v0.2.2 strict-proto-config-fields fix.
func TestPublicReceiptHandler_ConfigPathTakesPrecedence(t *testing.T) {
	const ledger = "receipt-test-cfg-precedence"
	modules.UnregisterDB(ledger)
	t.Cleanup(func() { modules.UnregisterDB(ledger) })

	_, err := steps.PublicReceiptHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PublicReceiptConfig, *auditv1.PublicReceiptRequest]{
		Config: &auditv1.PublicReceiptConfig{
			Ledger:       ledger,
			Sequence:     42,
			RedactFields: []string{"contributor_user_id"},
		},
		Input: &auditv1.PublicReceiptRequest{},
	})
	if err == nil {
		t.Fatal("expected DB-not-registered error using Config ledger, got nil")
	}
	if !strings.Contains(err.Error(), ledger) {
		t.Errorf("error should mention ledger from Config (%q), got: %v", ledger, err)
	}
}

// TestPublicReceiptHandler_ConfigOverridesInput verifies the merge precedence:
// when Config and Input both populate the same field, Config wins.
func TestPublicReceiptHandler_ConfigOverridesInput(t *testing.T) {
	const cfgLedger = "receipt-test-cfg-override"
	const inputLedger = "receipt-test-input-loser"
	modules.UnregisterDB(cfgLedger)
	modules.UnregisterDB(inputLedger)
	t.Cleanup(func() {
		modules.UnregisterDB(cfgLedger)
		modules.UnregisterDB(inputLedger)
	})

	_, err := steps.PublicReceiptHandler(context.Background(), sdk.TypedStepRequest[*auditv1.PublicReceiptConfig, *auditv1.PublicReceiptRequest]{
		Config: &auditv1.PublicReceiptConfig{Ledger: cfgLedger, Sequence: 1},
		Input:  &auditv1.PublicReceiptRequest{Ledger: inputLedger, Sequence: 999},
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), cfgLedger) {
		t.Errorf("error should mention Config ledger (%q), got: %v", cfgLedger, err)
	}
	if strings.Contains(err.Error(), inputLedger) {
		t.Errorf("error should not mention Input ledger (%q): Config must win, got: %v", inputLedger, err)
	}
}

// ── ApplyRedactions tests ─────────────────────────────────────────────────────

// TestApplyRedactions_TwoDistinctFields verifies that two fields with different
// original values are replaced with contributor_1 and contributor_2 respectively,
// and the pseudonym map records both mappings.
func TestApplyRedactions_TwoDistinctFields(t *testing.T) {
	payload := []byte(`{"user_id":"alice","partner_id":"bob","amount":100}`)

	redacted, pseudonymMap, err := steps.ApplyRedactions(payload, []string{"user_id", "partner_id"})
	if err != nil {
		t.Fatalf("ApplyRedactions: %v", err)
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(redacted, &obj); err != nil {
		t.Fatalf("unmarshal redacted payload: %v", err)
	}

	// user_id → "contributor_1" (first unique value)
	var userID string
	if err := json.Unmarshal(obj["user_id"], &userID); err != nil {
		t.Fatalf("unmarshal user_id: %v", err)
	}
	if userID != "contributor_1" {
		t.Errorf("user_id: got %q, want %q", userID, "contributor_1")
	}

	// partner_id → "contributor_2" (second unique value)
	var partnerID string
	if err := json.Unmarshal(obj["partner_id"], &partnerID); err != nil {
		t.Fatalf("unmarshal partner_id: %v", err)
	}
	if partnerID != "contributor_2" {
		t.Errorf("partner_id: got %q, want %q", partnerID, "contributor_2")
	}

	// amount is unchanged
	var amount float64
	if err := json.Unmarshal(obj["amount"], &amount); err != nil {
		t.Fatalf("unmarshal amount: %v", err)
	}
	if amount != 100 {
		t.Errorf("amount should be unchanged: got %v", amount)
	}

	// pseudonym_map contains both mappings
	if pseudonymMap["user_id"] != "contributor_1" {
		t.Errorf("pseudonymMap[user_id]: got %q, want %q", pseudonymMap["user_id"], "contributor_1")
	}
	if pseudonymMap["partner_id"] != "contributor_2" {
		t.Errorf("pseudonymMap[partner_id]: got %q, want %q", pseudonymMap["partner_id"], "contributor_2")
	}
}

// TestApplyRedactions_DuplicateOriginalValue verifies that two fields sharing the
// same original value receive the same contributor pseudonym.
func TestApplyRedactions_DuplicateOriginalValue(t *testing.T) {
	payload := []byte(`{"first_name":"alice","display_name":"alice","amount":100}`)

	_, pseudonymMap, err := steps.ApplyRedactions(payload, []string{"first_name", "display_name"})
	if err != nil {
		t.Fatalf("ApplyRedactions: %v", err)
	}
	if pseudonymMap["first_name"] != "contributor_1" {
		t.Errorf("first_name: got %q, want contributor_1", pseudonymMap["first_name"])
	}
	// Same original value "alice" → same pseudonym
	if pseudonymMap["display_name"] != "contributor_1" {
		t.Errorf("display_name: got %q, want contributor_1 (duplicate of first_name)", pseudonymMap["display_name"])
	}
}

// TestApplyRedactions_NoRedactFields verifies that an empty redact list returns
// the original payload unchanged with a nil pseudonym map.
func TestApplyRedactions_NoRedactFields(t *testing.T) {
	payload := []byte(`{"user_id":"alice"}`)

	redacted, pseudonymMap, err := steps.ApplyRedactions(payload, nil)
	if err != nil {
		t.Fatalf("ApplyRedactions: %v", err)
	}
	if string(redacted) != string(payload) {
		t.Errorf("no-op redaction modified payload: got %s", redacted)
	}
	if len(pseudonymMap) != 0 {
		t.Errorf("no-op redaction returned non-empty pseudonym map: %v", pseudonymMap)
	}
}
