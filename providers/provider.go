// Package providers defines the AnchorProvider interface implemented by each
// external anchor backend (OpenTimestamps, git, Sigstore, etc.).
package providers

import (
	"context"
	"time"
)

// ConfirmationLevel represents the confirmation state of an external anchor.
type ConfirmationLevel string

const (
	ConfirmationPending   ConfirmationLevel = "pending"
	ConfirmationConfirmed ConfirmationLevel = "confirmed"
	ConfirmationFinalized ConfirmationLevel = "finalized"
)

// MerkleRoot is the Merkle root hash to be anchored externally.
type MerkleRoot struct {
	Hex string // hex-encoded sha256 (64 lowercase chars)
}

// Anchor records a submitted anchor to an external provider.
type Anchor struct {
	ProviderName string
	AnchoredAt   time.Time
	ExternalID   string            // provider's anchor reference (Bitcoin tx hash, git commit sha, Rekor entry ID, etc.)
	ProofData    []byte            // provider-specific; opaque to caller; stored in audit_anchors.proof_data
	Confirmation ConfirmationLevel // pending | confirmed | finalized
}

// Verification is the result of polling an existing anchor's confirmation status.
type Verification struct {
	Provider     string
	Confirmation ConfirmationLevel
	UpdatedAt    time.Time
	Swallowed    bool   // true if a transient error occurred but state was preserved; no error returned
	ErrorMessage string // populated when Swallowed=true; describes the transient error
}

// Cost describes the cost model for anchoring via a provider.
type Cost struct {
	PerAnchorUSDCents int64
	Notes             string
}

// AnchorProvider is implemented by each anchor backend.
//
// Verify contract (§ 3.5c): transient errors (network failures, calendar-server
// unreachable, 5xx responses) MUST be returned as a successful Verification with
// Swallowed=true and ErrorMessage populated — NOT as an error. This lets the
// cron-audit-anchor-confirm step continue iterating across pending anchors when
// one calendar server is temporarily down.
//
// Hard errors (invalid/malformed proof data, 4xx semantic rejections) MUST be
// returned as errors and abort the parent step.
type AnchorProvider interface {
	// Name returns the provider's stable identifier (e.g. "opentimestamps", "git").
	Name() string

	// Anchor submits the Merkle root to the external anchor target and returns
	// an Anchor struct. The returned Confirmation is always ConfirmationPending
	// immediately after anchoring.
	Anchor(ctx context.Context, root MerkleRoot) (Anchor, error)

	// Verify polls the external target for the current confirmation state of a
	// previously-created Anchor. Follows the swallow-transient-errors contract
	// described above.
	Verify(ctx context.Context, anchor Anchor) (Verification, error)

	// Cost returns the cost model for the given number of anchors (for budgeting).
	Cost(numAnchors int) Cost
}
