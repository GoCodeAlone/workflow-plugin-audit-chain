package chain_test

import (
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
)

// ── PayloadHash ───────────────────────────────────────────────────────────────

func TestPayloadHash_DeterministicCanonical(t *testing.T) {
	// Same logical JSON → same hash regardless of key order / whitespace.
	h1 := chain.PayloadHash([]byte(`{"a":1,"b":2}`))
	h2 := chain.PayloadHash([]byte(`{"b":2,"a":1}`))
	if h1 != h2 {
		t.Errorf("expected canonical hash equality; got %s vs %s", h1, h2)
	}
	if h1 == "" {
		t.Error("expected non-empty hash")
	}
}

func TestPayloadHash_Is64HexChars(t *testing.T) {
	h := chain.PayloadHash([]byte(`{"amount_cents":2000}`))
	if len(h) != 64 {
		t.Errorf("expected 64-char hex SHA256, got %d chars: %s", len(h), h)
	}
	for _, c := range h {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("non-hex char %q in hash %s", c, h)
			break
		}
	}
}

func TestPayloadHash_DifferentInputs_DifferentHash(t *testing.T) {
	h1 := chain.PayloadHash([]byte(`{"amount":100}`))
	h2 := chain.PayloadHash([]byte(`{"amount":200}`))
	if h1 == h2 {
		t.Error("different payloads must produce different hashes")
	}
}

// ── EntryHash ─────────────────────────────────────────────────────────────────

func TestEntryHash_LinksPrev(t *testing.T) {
	eh := chain.EntryHash(1, "ledger-a", "event.x", "payloadhash", "")
	if eh == "" {
		t.Error("expected non-empty entry hash")
	}
	if len(eh) != 64 {
		t.Errorf("expected 64-char hex, got %d: %s", len(eh), eh)
	}
}

func TestEntryHash_GenesisVsChained_Differ(t *testing.T) {
	// prev="" (genesis) and prev=<some hash> must produce different entry hashes.
	genesis := chain.EntryHash(1, "ledger-a", "event.x", "phash", "")
	chained := chain.EntryHash(1, "ledger-a", "event.x", "phash", "prevhash0001")
	if genesis == chained {
		t.Error("genesis and chained entries with same other fields must differ")
	}
}

func TestEntryHash_ChangingSeq_DifferentHash(t *testing.T) {
	e1 := chain.EntryHash(1, "l", "t", "ph", "prev")
	e2 := chain.EntryHash(2, "l", "t", "ph", "prev")
	if e1 == e2 {
		t.Error("different sequence numbers must produce different hashes")
	}
}

func TestEntryHash_ChangingLedger_DifferentHash(t *testing.T) {
	e1 := chain.EntryHash(1, "ledger-a", "t", "ph", "prev")
	e2 := chain.EntryHash(1, "ledger-b", "t", "ph", "prev")
	if e1 == e2 {
		t.Error("different ledgers must produce different hashes")
	}
}

func TestEntryHash_Deterministic(t *testing.T) {
	// Same inputs always produce same hash.
	e1 := chain.EntryHash(42, "bmw-financial", "contribution.captured", "abc123", "prev456")
	e2 := chain.EntryHash(42, "bmw-financial", "contribution.captured", "abc123", "prev456")
	if e1 != e2 {
		t.Error("EntryHash must be deterministic")
	}
}
