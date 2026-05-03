// Package sigstore implements the AnchorProvider interface using the Sigstore
// Rekor transparent log (https://rekor.sigstore.dev).
//
// Rekor is a transparency log operated by the Linux Foundation / Sigstore
// project. Entries are append-only and immediately verifiable — once a log
// entry is created it is permanent, so Confirmation is returned as Finalized
// immediately after a successful Anchor call.
//
// # Implementation
//
// Each Anchor call generates an ephemeral ECDSA P-256 key pair, signs the
// Merkle root hash, and submits a hashedrekord v0.0.1 entry to Rekor via the
// github.com/sigstore/rekor Go client. The returned log entry UUID is stored
// as ExternalID and in ProofData for subsequent Verify calls.
//
// For pilot / proof-of-concept use, the ephemeral signing key is not
// persisted. In production, a stable identity key should be used so that the
// signing identity is independently verifiable.
package sigstore

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"time"

	runtimeclient "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
	rekor_client "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
)

const providerName = "sigstore"

// Config holds configuration for the Sigstore Rekor anchor provider.
type Config struct {
	// RekorURL is the base URL of the Rekor instance.
	// Defaults to "https://rekor.sigstore.dev" when empty.
	RekorURL string `json:"rekor_url,omitempty"`
}

// proofData is stored in Anchor.ProofData.
type proofData struct {
	EntryUUID string `json:"entry_uuid"`
	RekorURL  string `json:"rekor_url"`
}

// Provider implements providers.AnchorProvider using Rekor.
type Provider struct {
	cfg    Config
	client *rekor_client.Rekor
}

// Compile-time assertion.
var _ providers.AnchorProvider = (*Provider)(nil)

// NewProvider creates a new Sigstore Rekor anchor provider.
// Uses https://rekor.sigstore.dev by default.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.RekorURL == "" {
		cfg.RekorURL = "https://rekor.sigstore.dev"
	}

	u, err := url.Parse(cfg.RekorURL)
	if err != nil {
		return nil, fmt.Errorf("sigstore: invalid Rekor URL %q: %w", cfg.RekorURL, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("sigstore: invalid Rekor URL %q: missing host", cfg.RekorURL)
	}

	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}

	transport := runtimeclient.New(u.Host, "/", []string{scheme})
	rekorCli := rekor_client.New(transport, strfmt.Default)

	return &Provider{cfg: cfg, client: rekorCli}, nil
}

// Name returns the provider's stable identifier.
func (p *Provider) Name() string { return providerName }

// Anchor submits the Merkle root to the Rekor transparency log as a
// hashedrekord v0.0.1 entry. An ephemeral ECDSA P-256 key is generated per
// anchor to satisfy Rekor's signature requirement.
//
// Returns Confirmation: Finalized immediately — Rekor entries are permanent
// once accepted into the append-only log.
func (p *Provider) Anchor(ctx context.Context, root providers.MerkleRoot) (providers.Anchor, error) {
	hashBytes, err := hex.DecodeString(root.Hex)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("sigstore: invalid merkle root hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return providers.Anchor{}, fmt.Errorf(
			"sigstore: merkle root must be 32 bytes (64 hex chars), got %d bytes", len(hashBytes))
	}

	// Generate ephemeral ECDSA P-256 key pair.
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("sigstore: generate key: %w", err)
	}

	// Sign the SHA-256 of the merkle root bytes.
	digest := sha256.Sum256(hashBytes)
	sig, err := ecdsa.SignASN1(rand.Reader, privKey, digest[:])
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("sigstore: sign merkle root: %w", err)
	}

	// Encode public key as PEM for inclusion in the Rekor entry.
	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("sigstore: marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	// Build the hashedrekord v0.0.1 entry.
	algo := "sha256"
	hexVal := root.Hex
	entry := &models.Hashedrekord{
		APIVersion: strPtr("0.0.1"),
		Spec: &models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: &algo,
					Value:     &hexVal,
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(sig),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubPEM),
				},
			},
		},
	}

	params := entries.NewCreateLogEntryParamsWithContext(ctx).WithProposedEntry(entry)
	resp, err := p.client.Entries.CreateLogEntry(params)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("sigstore: create Rekor log entry: %w", err)
	}

	// The response is a map; the single key is the entry UUID.
	entryUUID := ""
	for k := range resp.Payload {
		entryUUID = k
		break
	}
	if entryUUID == "" {
		return providers.Anchor{}, fmt.Errorf("sigstore: empty response from Rekor (no entry UUID)")
	}

	now := time.Now().UTC()
	pd := proofData{
		EntryUUID: entryUUID,
		RekorURL:  p.cfg.RekorURL,
	}
	proofBytes, _ := json.Marshal(pd)

	return providers.Anchor{
		ProviderName: providerName,
		AnchoredAt:   now,
		ExternalID:   entryUUID,
		ProofData:    proofBytes,
		Confirmation: providers.ConfirmationFinalized, // Rekor = instant-final
	}, nil
}

// Verify checks that the Rekor log entry still exists (expected always true for
// a properly operating transparency log). Implements swallow-transient-errors
// contract (§ 3.5c):
//
//   - Network errors and 5xx responses → Swallowed=true, confirmation preserved.
//   - 404 (entry missing from transparency log) → hard error (unexpected: log is append-only).
//   - Malformed ProofData → hard error.
func (p *Provider) Verify(ctx context.Context, anchor providers.Anchor) (providers.Verification, error) {
	var pd proofData
	if err := json.Unmarshal(anchor.ProofData, &pd); err != nil {
		return providers.Verification{}, fmt.Errorf("sigstore: malformed proof data: %w", err)
	}

	now := time.Now().UTC()

	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx).WithEntryUUID(pd.EntryUUID)
	_, err := p.client.Entries.GetLogEntryByUUID(params)
	if err == nil {
		// Entry exists — finalized.
		return providers.Verification{
			Provider:     providerName,
			Confirmation: providers.ConfirmationFinalized,
			UpdatedAt:    now,
		}, nil
	}

	// Classify the error.
	var notFound *entries.GetLogEntryByUUIDNotFound
	var defErr *entries.GetLogEntryByUUIDDefault

	switch {
	case errors.As(err, &notFound):
		// 404: entry missing from transparency log → hard error.
		return providers.Verification{}, fmt.Errorf(
			"sigstore: Rekor entry %s not found (transparency log may have been tampered with): %w",
			pd.EntryUUID, err)

	case errors.As(err, &defErr) && defErr.IsServerError():
		// 5xx: server-side error → transient, swallow.
		return providers.Verification{
			Provider:     providerName,
			Confirmation: anchor.Confirmation,
			UpdatedAt:    now,
			Swallowed:    true,
			ErrorMessage: fmt.Sprintf("Rekor server error (HTTP %d): %v", defErr.Code(), err),
		}, nil

	default:
		// Network error or other unexpected failure → transient, swallow.
		return providers.Verification{
			Provider:     providerName,
			Confirmation: anchor.Confirmation,
			UpdatedAt:    now,
			Swallowed:    true,
			ErrorMessage: fmt.Sprintf("transient error contacting Rekor at %s: %v", pd.RekorURL, err),
		}, nil
	}
}

// Cost returns the cost model for Sigstore Rekor (always free).
func (p *Provider) Cost(_ int) providers.Cost {
	return providers.Cost{
		PerAnchorUSDCents: 0,
		Notes:             "Sigstore Rekor is free; operated by the Linux Foundation",
	}
}

func strPtr(s string) *string { return &s }
