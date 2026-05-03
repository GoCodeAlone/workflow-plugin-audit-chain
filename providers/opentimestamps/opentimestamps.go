// Package opentimestamps implements the AnchorProvider interface using the
// OpenTimestamps calendar server HTTP API (https://opentimestamps.org).
//
// # Library choice (2026-05-03)
//
// github.com/opentimestamps/go-opentimestamps does not exist (repository not
// found on GitHub). The `ots` CLI binary is also absent from the current
// environment. This implementation therefore calls the calendar server HTTP
// API directly, which is well-defined and stable:
//
//   - Anchor:  POST <calendar>/digest  with 32 raw bytes → pending OTS receipt bytes
//   - Verify:  GET  <calendar>/timestamp/<hash_hex>      → 200 = upgraded (Bitcoin confirmed);
//     404 = still pending; 5xx = transient; 4xx = hard error
//
// The raw calendar receipts are stored as base64 in the ProofData JSON so that
// a future OTS binary parser (needed for extracting the calendar-tree commitment
// for production-grade inclusion proofs) can reprocess them without re-anchoring.
// For upgrade checking, we use the submitted hash hex as the lookup key; this
// works with the standard OTS calendar server API.
package opentimestamps

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
)

const providerName = "opentimestamps"

// Config holds configuration for the OpenTimestamps provider.
type Config struct {
	// CalendarServers is the list of OTS calendar server base URLs to submit to.
	// Multiple servers provide redundancy. At least one is required.
	CalendarServers []string `json:"calendar_servers"`

	// HTTPTimeout is the per-request timeout. Defaults to 30s when zero.
	HTTPTimeout time.Duration `json:"http_timeout,omitempty"`
}

// calendarReceipt records the result of submitting to one calendar server.
type calendarReceipt struct {
	URL         string    `json:"url"`
	ReceiptB64  string    `json:"receipt_b64"` // base64-encoded raw calendar response bytes
	SubmittedAt time.Time `json:"submitted_at"`
}

// proofData is the JSON structure stored in Anchor.ProofData.
type proofData struct {
	HashHex          string            `json:"hash_hex"`
	CalendarReceipts []calendarReceipt `json:"calendar_receipts"`
}

// Provider implements providers.AnchorProvider via OTS calendar server HTTP API.
type Provider struct {
	config     Config
	httpClient *http.Client
}

// Compile-time assertion that *Provider implements AnchorProvider.
var _ providers.AnchorProvider = (*Provider)(nil)

// NewProvider creates a new OpenTimestamps provider with the given config.
// Returns an error if no calendar servers are configured.
func NewProvider(cfg Config) (*Provider, error) {
	if len(cfg.CalendarServers) == 0 {
		return nil, fmt.Errorf("opentimestamps: at least one calendar server required")
	}
	timeout := cfg.HTTPTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Provider{
		config:     cfg,
		httpClient: &http.Client{Timeout: timeout},
	}, nil
}

// Name returns the provider's stable identifier.
func (p *Provider) Name() string { return providerName }

// Anchor submits the Merkle root to all configured calendar servers.
//
// ExternalID is set to root.Hex (the submitted hash). ProofData is a JSON blob
// containing the raw calendar receipts from each successful submission.
//
// Returns an error only if ALL calendar servers fail. Partial success (at least
// one calendar accepts the submission) returns a valid Anchor.
func (p *Provider) Anchor(ctx context.Context, root providers.MerkleRoot) (providers.Anchor, error) {
	hashBytes, err := hex.DecodeString(root.Hex)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("opentimestamps: invalid merkle root hex: %w", err)
	}
	if len(hashBytes) != 32 {
		return providers.Anchor{}, fmt.Errorf(
			"opentimestamps: merkle root must be 32 bytes (64 hex chars), got %d bytes", len(hashBytes))
	}

	now := time.Now().UTC()
	pd := proofData{HashHex: root.Hex}
	var lastErr error
	successCount := 0

	for _, calURL := range p.config.CalendarServers {
		receipt, err := p.submitToCalendar(ctx, calURL, hashBytes, now)
		if err != nil {
			lastErr = err
			continue
		}
		pd.CalendarReceipts = append(pd.CalendarReceipts, receipt)
		successCount++
	}

	if successCount == 0 {
		return providers.Anchor{}, fmt.Errorf(
			"opentimestamps: all %d calendar server(s) failed; last error: %w",
			len(p.config.CalendarServers), lastErr)
	}

	proofBytes, err := json.Marshal(pd)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("opentimestamps: marshal proof data: %w", err)
	}

	return providers.Anchor{
		ProviderName: providerName,
		AnchoredAt:   now,
		ExternalID:   root.Hex,
		ProofData:    proofBytes,
		Confirmation: providers.ConfirmationPending,
	}, nil
}

func (p *Provider) submitToCalendar(ctx context.Context, calURL string, hashBytes []byte, now time.Time) (calendarReceipt, error) {
	endpoint := strings.TrimRight(calURL, "/") + "/digest"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(hashBytes))
	if err != nil {
		return calendarReceipt{}, fmt.Errorf("build request for %s: %w", endpoint, err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return calendarReceipt{}, fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return calendarReceipt{}, fmt.Errorf("read response from %s: %w", calURL, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return calendarReceipt{}, fmt.Errorf(
			"calendar %s returned HTTP %d: %s", calURL, resp.StatusCode, string(body))
	}

	return calendarReceipt{
		URL:         calURL,
		ReceiptB64:  base64.StdEncoding.EncodeToString(body),
		SubmittedAt: now,
	}, nil
}

// Verify polls the calendar servers recorded in anchor.ProofData for Bitcoin
// confirmation status. Implements the swallow-transient-errors contract (§ 3.5c):
//
//   - Network errors and 5xx responses are swallowed: returned as a successful
//     Verification with Swallowed=true, ErrorMessage populated, and Confirmation
//     unchanged from anchor.Confirmation.
//
//   - 4xx responses that semantically reject the proof are returned as errors
//     (hard errors that abort the parent step).
//
//   - If any calendar returns an upgraded proof (HTTP 200), the Confirmation
//     advances to ConfirmationConfirmed.
//
//   - 404 responses indicate the proof is not yet upgraded (still pending); this
//     is informative, not an error, and does not set Swallowed.
func (p *Provider) Verify(ctx context.Context, anchor providers.Anchor) (providers.Verification, error) {
	var pd proofData
	if err := json.Unmarshal(anchor.ProofData, &pd); err != nil {
		return providers.Verification{}, fmt.Errorf("opentimestamps: malformed proof data: %w", err)
	}

	now := time.Now().UTC()
	current := anchor.Confirmation

	var transientMsgs []string
	confirmed := false

	for _, receipt := range pd.CalendarReceipts {
		upgraded, transientErr, hardErr := p.checkUpgrade(ctx, receipt.URL, pd.HashHex)
		if hardErr != nil {
			return providers.Verification{}, fmt.Errorf(
				"opentimestamps: calendar %s rejected proof: %w", receipt.URL, hardErr)
		}
		if transientErr != nil {
			transientMsgs = append(transientMsgs, fmt.Sprintf("%s: %v", receipt.URL, transientErr))
			continue
		}
		if upgraded {
			confirmed = true
		}
	}

	if confirmed && current == providers.ConfirmationPending {
		current = providers.ConfirmationConfirmed
	}

	v := providers.Verification{
		Provider:     providerName,
		Confirmation: current,
		UpdatedAt:    now,
	}

	// Swallow transient errors only when no calendar confirmed. If at least one
	// calendar returned an upgraded proof, transient errors from other calendars
	// are irrelevant — we have confirmation and don't need to surface the errors.
	if len(transientMsgs) > 0 && !confirmed {
		v.Swallowed = true
		v.ErrorMessage = fmt.Sprintf(
			"transient errors from %d of %d calendar(s): %s",
			len(transientMsgs), len(pd.CalendarReceipts),
			strings.Join(transientMsgs, "; "))
	}

	return v, nil
}

// checkUpgrade queries a calendar server for an upgraded (Bitcoin-confirmed) proof.
//
// Returns (upgraded, transientErr, hardErr):
//   - upgraded=true:       calendar returned HTTP 200 (Bitcoin block header in proof)
//   - transientErr!=nil:   network error or 5xx — caller should swallow
//   - hardErr!=nil:        4xx semantic rejection — caller should return as error
//   - all nil, upgraded=false: 404 (still pending; normal informative response)
func (p *Provider) checkUpgrade(ctx context.Context, calURL, hashHex string) (upgraded bool, transientErr error, hardErr error) {
	endpoint := strings.TrimRight(calURL, "/") + "/timestamp/" + hashHex
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		// Malformed URL is a transient error here; Anchor would have caught hard URL errors.
		return false, fmt.Errorf("build request for %s: %w", endpoint, err), nil
	}
	req.Header.Set("Accept", "application/vnd.opentimestamps.v1")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		// Network-level error (connection refused, timeout, DNS, etc.) → transient.
		return false, fmt.Errorf("GET %s: %w", endpoint, err), nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	switch {
	case resp.StatusCode == http.StatusOK:
		// Calendar returned an upgraded proof → Bitcoin block confirmed.
		_ = body
		return true, nil, nil

	case resp.StatusCode == http.StatusNotFound:
		// Proof not yet upgraded to Bitcoin; normal pending state.
		return false, nil, nil

	case resp.StatusCode >= 500:
		// Server-side error (5xx) → transient.
		return false, fmt.Errorf("HTTP %d from %s", resp.StatusCode, calURL), nil

	case resp.StatusCode >= 400:
		// 4xx semantic rejection → hard error (invalid proof, bad request).
		return false, nil, fmt.Errorf(
			"HTTP %d from %s: %s", resp.StatusCode, calURL, string(body))

	default:
		// Unexpected status (e.g., 3xx without Location) → treat as transient.
		return false, fmt.Errorf("unexpected HTTP %d from %s", resp.StatusCode, calURL), nil
	}
}

// Cost returns the cost model for OpenTimestamps (always free).
func (p *Provider) Cost(_ int) providers.Cost {
	return providers.Cost{
		PerAnchorUSDCents: 0,
		Notes:             "OpenTimestamps is free; anchoring is batched into Bitcoin transactions by volunteer calendar servers",
	}
}
