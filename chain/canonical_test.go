package chain_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
)

// ── Required TDD cases ────────────────────────────────────────────────────────

func TestCanonical_SortsKeys(t *testing.T) {
	in := `{"b":1,"a":2}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":2,"b":1}` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_RemovesWhitespace(t *testing.T) {
	in := `{ "x" : 1 }`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"x":1}` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_NestedObject(t *testing.T) {
	in := `{"b":{"y":1,"x":2},"a":1}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1,"b":{"x":2,"y":1}}` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_Idempotent(t *testing.T) {
	in1 := `{"a":1,"b":2}`
	in2 := `{"b":2,"a":1}`
	h1, err := chain.Canonicalize([]byte(in1))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := chain.Canonicalize([]byte(in2))
	if err != nil {
		t.Fatal(err)
	}
	if string(h1) != string(h2) {
		t.Errorf("expected canonical equality; got %s vs %s", h1, h2)
	}
}

// ── Edge cases ────────────────────────────────────────────────────────────────

func TestCanonical_ArrayPreservesOrder(t *testing.T) {
	// Arrays must NOT be sorted — element order is significant.
	in := `{"items":[3,1,2]}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"items":[3,1,2]}` {
		t.Errorf("array order changed: got %s", got)
	}
}

func TestCanonical_DeeplyNested(t *testing.T) {
	in := `{"z":{"c":{"b":1,"a":2},"a":3},"a":0}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":0,"z":{"a":3,"c":{"a":2,"b":1}}}`
	if string(got) != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestCanonical_Booleans(t *testing.T) {
	in := `{"y":false,"x":true}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"x":true,"y":false}` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_NullValue(t *testing.T) {
	in := `{"b":null,"a":1}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"a":1,"b":null}` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_EmptyObject(t *testing.T) {
	in := `{}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{}` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_LargeIntegerPreserved(t *testing.T) {
	// Integers too large for float64 exact representation must be preserved.
	// This catches float64 round-trip bugs (e.g. 9007199254740993 → 9007199254740992).
	in := `{"id":9007199254740993}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"id":9007199254740993}` {
		t.Errorf("large integer changed: got %s", got)
	}
}

func TestCanonical_ObjectInArray(t *testing.T) {
	// Objects inside arrays must also have sorted keys.
	in := `[{"b":2,"a":1},{"d":4,"c":3}]`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `[{"a":1,"b":2},{"c":3,"d":4}]` {
		t.Errorf("got %s", got)
	}
}

func TestCanonical_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := chain.Canonicalize([]byte(`{not json}`))
	if err == nil {
		t.Error("expected error for invalid JSON input")
	}
}

func TestCanonical_StringSpecialChars(t *testing.T) {
	// Unicode and escape sequences should round-trip intact.
	in := `{"key":"hello\nworld"}`
	got, err := chain.Canonicalize([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json re-encodes \n as \n — verify it's stable.
	got2, err := chain.Canonicalize(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(got2) {
		t.Errorf("not idempotent on strings: %s → %s", got, got2)
	}
}
