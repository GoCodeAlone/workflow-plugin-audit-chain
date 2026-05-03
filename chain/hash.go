package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// PayloadHash returns SHA-256(Canonicalize(data)) as a lowercase 64-char hex string.
// The input is canonicalized per RFC 8785 before hashing so that key order and
// whitespace in the caller's JSON do not affect the hash value.
// Panics if data is not valid JSON (payloads are always validated before storage).
func PayloadHash(data []byte) string {
	canonical, err := Canonicalize(data)
	if err != nil {
		panic(fmt.Sprintf("chain.PayloadHash: canonicalize: %v", err))
	}
	h := sha256.Sum256(canonical)
	return hex.EncodeToString(h[:])
}

// EntryHash computes the chain-integrity hash for an audit log entry.
//
// Preimage: RFC 8785 canonical JSON of
//
//	{"event_type":<et>,"ledger":<l>,"payload_hash":<ph>,"prev_entry_hash":<prev>,"sequence":<seq>}
//
// Keys are sorted lexicographically by encoding/json's map serialization.
// created_at, actor, and metadata are intentionally excluded from the preimage —
// they are stored for audit purposes but are not load-bearing for chain integrity.
// This matches the design doc: SHA256(sequence||ledger||event_type||payload_hash||prev_entry_hash).
func EntryHash(seq int64, ledger, eventType, payloadHash, prevEntryHash string) string {
	raw, err := json.Marshal(map[string]any{
		"event_type":      eventType,
		"ledger":          ledger,
		"payload_hash":    payloadHash,
		"prev_entry_hash": prevEntryHash,
		"sequence":        seq,
	})
	if err != nil {
		// Cannot fail: all values are string/int64.
		panic(fmt.Sprintf("chain.EntryHash: marshal: %v", err))
	}
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

// sha256Hex returns the SHA-256 of data as a 64-char lowercase hex string.
func sha256Hex(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}
