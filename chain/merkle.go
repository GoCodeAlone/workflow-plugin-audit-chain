package chain

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// leafNode returns the Merkle leaf node for a string value: SHA-256([]byte(s)).
func leafNode(s string) [32]byte {
	return sha256.Sum256([]byte(s))
}

// combineNodes returns SHA-256(left_bytes || right_bytes) — the parent node of
// two adjacent Merkle nodes. Both inputs are raw 32-byte SHA-256 digests.
func combineNodes(left, right [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], left[:])
	copy(buf[32:], right[:])
	return sha256.Sum256(buf[:])
}

// buildLevels constructs all levels of the Merkle tree from bottom to top.
// The first element is the leaf level; the last is a single-element slice
// holding the root. Odd-length levels duplicate the last node before pairing.
func buildLevels(leaves []string) [][][32]byte {
	current := make([][32]byte, len(leaves))
	for i, l := range leaves {
		current[i] = leafNode(l)
	}
	levels := [][][32]byte{current}
	for len(current) > 1 {
		next := make([][32]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			right := current[i] // duplicate last if odd
			if i+1 < len(current) {
				right = current[i+1]
			}
			next = append(next, combineNodes(left, right))
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// MerkleRoot builds a binary Merkle tree over the given leaf strings and returns
// the hex-encoded SHA-256 root (64 lowercase hex chars).
//
// Each leaf is hashed with SHA-256. Pairs are combined as SHA-256(left||right).
// When a level has an odd count, the last node is paired with itself.
// Returns an error if leaves is empty.
func MerkleRoot(leaves []string) (string, error) {
	if len(leaves) == 0 {
		return "", fmt.Errorf("chain: MerkleRoot requires at least one leaf")
	}
	levels := buildLevels(leaves)
	root := levels[len(levels)-1][0]
	return hex.EncodeToString(root[:]), nil
}

// InclusionProof returns the Merkle sibling path for the leaf at idx.
// Each element of the returned slice is a direction-prefixed hex-encoded node:
//   - "L" + 64 hex chars: sibling is to the LEFT — combine as SHA256(sibling||current)
//   - "R" + 64 hex chars: sibling is to the RIGHT — combine as SHA256(current||sibling)
//
// The returned proof can be verified with VerifyInclusion.
func InclusionProof(leaves []string, idx int) ([]string, error) {
	if idx < 0 || idx >= len(leaves) {
		return nil, fmt.Errorf("chain: index %d out of range [0, %d)", idx, len(leaves))
	}
	if len(leaves) == 1 {
		return []string{}, nil
	}

	levels := buildLevels(leaves)
	proof := make([]string, 0, len(levels)-1)
	pos := idx

	// Iterate over all levels except the root level.
	for _, nodes := range levels[:len(levels)-1] {
		var sibling [32]byte
		var dir byte

		if pos%2 == 0 {
			// Current node is the LEFT child. Sibling is to the right.
			dir = 'R'
			if pos+1 < len(nodes) {
				sibling = nodes[pos+1]
			} else {
				sibling = nodes[pos] // duplicate
			}
		} else {
			// Current node is the RIGHT child. Sibling is to the left.
			dir = 'L'
			sibling = nodes[pos-1]
		}

		proof = append(proof, string([]byte{dir})+hex.EncodeToString(sibling[:]))
		pos /= 2
	}
	return proof, nil
}

// VerifyInclusion returns true if leaf is a member of the Merkle tree with
// the given root, as attested by proof (as produced by InclusionProof).
func VerifyInclusion(leaf string, proof []string, root string) bool {
	current := leafNode(leaf)

	for _, p := range proof {
		if len(p) != 65 { // 1 direction byte + 64 hex chars
			return false
		}
		dir := p[0]
		siblingBytes, err := hex.DecodeString(p[1:])
		if err != nil || len(siblingBytes) != 32 {
			return false
		}
		var sibling [32]byte
		copy(sibling[:], siblingBytes)

		switch dir {
		case 'L': // sibling is left
			current = combineNodes(sibling, current)
		case 'R': // sibling is right
			current = combineNodes(current, sibling)
		default:
			return false
		}
	}

	return hex.EncodeToString(current[:]) == root
}
