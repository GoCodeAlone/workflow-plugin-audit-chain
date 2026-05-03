package chain_test

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/chain"
)

// Domain-separation prefixes must match chain/merkle.go (RFC 6962 §2.1).
const leafPfx     = byte(0x00)
const internalPfx = byte(0x01)

// helper: compute leaf hash the same way MerkleRoot does internally.
// SHA-256(0x00 || []byte(s))
func leafHash(s string) [32]byte {
	h := sha256.New()
	h.Write([]byte{leafPfx})
	h.Write([]byte(s))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// helper: combine two raw-byte hashes the same way MerkleRoot does.
// SHA-256(0x01 || left || right)
func combineRaw(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{internalPfx})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// ── MerkleRoot ────────────────────────────────────────────────────────────────

func TestMerkleRoot_FourLeaves(t *testing.T) {
	leaves := []string{"a", "b", "c", "d"}
	root, err := chain.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if len(root) != 64 {
		t.Errorf("expected 64-hex-char SHA256 root, got %d: %s", len(root), root)
	}

	// Recompute manually and compare.
	ha, hb := leafHash("a"), leafHash("b")
	hc, hd := leafHash("c"), leafHash("d")
	hab := combineRaw(ha, hb)
	hcd := combineRaw(hc, hd)
	manualRoot := combineRaw(hab, hcd)
	want := hex.EncodeToString(manualRoot[:])
	if root != want {
		t.Errorf("root mismatch\ngot  %s\nwant %s", root, want)
	}
}

func TestMerkleRoot_OddLeaves_DuplicatesLast(t *testing.T) {
	leaves := []string{"a", "b", "c"}
	root, err := chain.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	if root == "" {
		t.Error("expected non-empty root for odd count")
	}
	if len(root) != 64 {
		t.Errorf("expected 64-hex-char root, got %d", len(root))
	}

	// Manual: c is duplicated → tree is h(h(a,b), h(c,c))
	ha, hb := leafHash("a"), leafHash("b")
	hc := leafHash("c")
	hab := combineRaw(ha, hb)
	hcc := combineRaw(hc, hc)
	manualRoot := combineRaw(hab, hcc)
	want := hex.EncodeToString(manualRoot[:])
	if root != want {
		t.Errorf("root mismatch for odd leaves\ngot  %s\nwant %s", root, want)
	}
}

func TestMerkleRoot_SingleLeaf(t *testing.T) {
	root, err := chain.MerkleRoot([]string{"only"})
	if err != nil {
		t.Fatal(err)
	}
	onlyH := leafHash("only")
	want := hex.EncodeToString(onlyH[:])
	if root != want {
		t.Errorf("single-leaf root should be leaf hash; got %s, want %s", root, want)
	}
}

func TestMerkleRoot_TwoLeaves(t *testing.T) {
	root, err := chain.MerkleRoot([]string{"x", "y"})
	if err != nil {
		t.Fatal(err)
	}
	xyRoot := combineRaw(leafHash("x"), leafHash("y"))
	want := hex.EncodeToString(xyRoot[:])
	if root != want {
		t.Errorf("two-leaf root mismatch\ngot  %s\nwant %s", root, want)
	}
}

func TestMerkleRoot_Deterministic(t *testing.T) {
	leaves := []string{"a", "b", "c", "d", "e"}
	r1, _ := chain.MerkleRoot(leaves)
	r2, _ := chain.MerkleRoot(leaves)
	if r1 != r2 {
		t.Error("MerkleRoot must be deterministic")
	}
}

func TestMerkleRoot_EmptyLeaves_ReturnsError(t *testing.T) {
	_, err := chain.MerkleRoot(nil)
	if err == nil {
		t.Error("expected error for empty leaf set")
	}
}

func TestMerkleRoot_DifferentLeaves_DifferentRoot(t *testing.T) {
	r1, _ := chain.MerkleRoot([]string{"a", "b"})
	r2, _ := chain.MerkleRoot([]string{"a", "c"})
	if r1 == r2 {
		t.Error("different leaf sets must produce different roots")
	}
}

// ── InclusionProof + VerifyInclusion ──────────────────────────────────────────

func TestMerkleProof_VerifyRoundTrip(t *testing.T) {
	leaves := []string{"a", "b", "c", "d", "e", "f", "g"}
	root, err := chain.MerkleRoot(leaves)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := chain.InclusionProof(leaves, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !chain.VerifyInclusion(leaves[3], proof, root) {
		t.Error("expected proof to verify")
	}
}

func TestMerkleProof_AllIndices_Verify(t *testing.T) {
	leaves := []string{"a", "b", "c", "d", "e", "f", "g"}
	root, _ := chain.MerkleRoot(leaves)
	for i, leaf := range leaves {
		proof, err := chain.InclusionProof(leaves, i)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		if !chain.VerifyInclusion(leaf, proof, root) {
			t.Errorf("proof for index %d (%q) failed to verify", i, leaf)
		}
	}
}

func TestMerkleProof_SingleLeaf_EmptyProof(t *testing.T) {
	leaves := []string{"solo"}
	root, _ := chain.MerkleRoot(leaves)
	proof, err := chain.InclusionProof(leaves, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 0 {
		t.Errorf("single-leaf proof should be empty, got %v", proof)
	}
	if !chain.VerifyInclusion("solo", proof, root) {
		t.Error("single-leaf verification failed")
	}
}

func TestMerkleProof_TamperedLeaf_Fails(t *testing.T) {
	leaves := []string{"a", "b", "c", "d"}
	root, _ := chain.MerkleRoot(leaves)
	proof, _ := chain.InclusionProof(leaves, 1)
	// Tamper: verify "b" proof against "TAMPERED"
	if chain.VerifyInclusion("TAMPERED", proof, root) {
		t.Error("tampered leaf should not verify")
	}
}

func TestMerkleProof_TamperedProof_Fails(t *testing.T) {
	leaves := []string{"a", "b", "c", "d"}
	root, _ := chain.MerkleRoot(leaves)
	proof, _ := chain.InclusionProof(leaves, 2)
	if len(proof) == 0 {
		t.Skip("no proof elements to tamper")
	}
	// Flip last hex char of the first proof element to a different valid hex digit.
	// The proof retains its full length and structure — only one nibble is wrong.
	flipHex := map[byte]byte{
		'0': '1', '1': '0', '2': '3', '3': '2', '4': '5', '5': '4',
		'6': '7', '7': '6', '8': '9', '9': '8',
		'a': 'b', 'b': 'a', 'c': 'd', 'd': 'c', 'e': 'f', 'f': 'e',
	}
	tampered := make([]string, len(proof))
	copy(tampered, proof)
	last := tampered[0]
	ch := last[len(last)-1]
	flipped, ok := flipHex[ch]
	if !ok {
		flipped = '0'
	}
	tampered[0] = last[:len(last)-1] + string(flipped)

	if chain.VerifyInclusion(leaves[2], tampered, root) {
		t.Error("tampered proof element (valid hex, wrong hash) should not verify")
	}
}

func TestInclusionProof_OutOfRange_ReturnsError(t *testing.T) {
	leaves := []string{"a", "b", "c"}
	_, err := chain.InclusionProof(leaves, 5)
	if err == nil {
		t.Error("out-of-range index should return error")
	}
	_, err = chain.InclusionProof(leaves, -1)
	if err == nil {
		t.Error("negative index should return error")
	}
}

func TestMerkleProof_FourLeaves_AllVerify(t *testing.T) {
	leaves := []string{"w", "x", "y", "z"}
	root, _ := chain.MerkleRoot(leaves)
	for i, leaf := range leaves {
		proof, err := chain.InclusionProof(leaves, i)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		if !chain.VerifyInclusion(leaf, proof, root) {
			t.Errorf("proof for index %d (%q) failed to verify", i, leaf)
		}
	}
}
