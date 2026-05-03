// Package chain implements the hash-chaining and Merkle tree primitives for
// the audit-chain plugin.
package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Canonicalize returns the RFC 8785 (JSON Canonicalization Scheme) encoding of
// data: all object keys sorted lexicographically at every nesting level,
// whitespace removed, array element order preserved.
//
// Numbers are decoded via json.Number (not float64) to prevent precision loss
// for large integers that cannot be represented exactly as float64 (e.g.
// integers > 2^53). The number bytes are re-emitted as-is by encoding/json.
//
// The resulting bytes are deterministic: two JSON documents with the same
// logical value always produce identical output.
func Canonicalize(data []byte) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()

	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, fmt.Errorf("canonical: unmarshal: %w", err)
	}

	out, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("canonical: marshal: %w", err)
	}
	return out, nil
}
