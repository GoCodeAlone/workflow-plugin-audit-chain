package opentimestamps_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers/opentimestamps"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testRootHex is a valid 64-char hex string representing a 32-byte SHA256 hash.
const testRootHex = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"

// --- Constructor tests ---

func TestNewProvider_RequiresCalendars(t *testing.T) {
	_, err := opentimestamps.NewProvider(opentimestamps.Config{})
	require.Error(t, err, "empty CalendarServers must return error")
}

func TestNewProvider_DefaultTimeout(t *testing.T) {
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{"http://example.com"},
	})
	require.NoError(t, err)
	assert.NotNil(t, p)
}

// --- Name / Cost ---

func TestName(t *testing.T) {
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{"http://example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "opentimestamps", p.Name())
}

func TestCost_IsFree(t *testing.T) {
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{"http://example.com"},
	})
	require.NoError(t, err)
	c := p.Cost(100)
	assert.Equal(t, int64(0), c.PerAnchorUSDCents)
	assert.NotEmpty(t, c.Notes)
}

// --- Anchor validation ---

func TestAnchor_InvalidHex_ReturnsError(t *testing.T) {
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{"http://example.com"},
	})
	require.NoError(t, err)
	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: "not-valid-hex!"})
	require.Error(t, err)
}

func TestAnchor_WrongHashLength_ReturnsError(t *testing.T) {
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{"http://example.com"},
	})
	require.NoError(t, err)
	// Only 4 bytes (8 hex chars) — not 32 bytes
	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: "deadbeef"})
	require.Error(t, err)
}

// --- Anchor with mock calendar server ---

func TestAnchor_CalendarOK_ReturnsProofData(t *testing.T) {
	srv := newCalendarServer(t, http.StatusOK, http.StatusOK)
	defer srv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	assert.Equal(t, "opentimestamps", a.ProviderName)
	assert.Equal(t, testRootHex, a.ExternalID)
	assert.NotEmpty(t, a.ProofData)
	assert.Equal(t, providers.ConfirmationPending, a.Confirmation)
	assert.False(t, a.AnchoredAt.IsZero())
}

func TestAnchor_AllCalendarsFail_ReturnsError(t *testing.T) {
	srv := newCalendarServer(t, http.StatusInternalServerError, http.StatusInternalServerError)
	defer srv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.Error(t, err, "all-calendar-failure must return error")
}

func TestAnchor_PartialFailure_SucceedsWithAvailableCalendars(t *testing.T) {
	// One failing, one succeeding calendar
	failSrv := newCalendarServer(t, http.StatusServiceUnavailable, http.StatusOK)
	defer failSrv.Close()

	okSrv := newCalendarServer(t, http.StatusOK, http.StatusOK)
	defer okSrv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{failSrv.URL, okSrv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err, "partial failure should not error if at least one calendar succeeds")
	assert.Equal(t, providers.ConfirmationPending, a.Confirmation)
}

// --- Verify: swallow-transient-errors contract (§ 3.5c) ---

func TestVerify_TransientNetworkError_SwallowsAndPreservesState(t *testing.T) {
	// Use a server to do the initial anchor, then close it to simulate unreachability.
	srv := newCalendarServer(t, http.StatusOK, http.StatusOK)

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	// Make the calendar unreachable.
	srv.Close()

	v, err := p.Verify(context.Background(), a)
	require.NoError(t, err, "transient network error MUST NOT be returned as error")
	assert.True(t, v.Swallowed, "network failure must be swallowed")
	assert.NotEmpty(t, v.ErrorMessage, "swallowed error must have message")
	assert.Equal(t, providers.ConfirmationPending, v.Confirmation, "previous confirmation preserved")
	assert.Equal(t, "opentimestamps", v.Provider)
	assert.False(t, v.UpdatedAt.IsZero())
}

func TestVerify_CalendarReturns5xx_Swallowed(t *testing.T) {
	// /digest → 200 (anchor succeeds), /timestamp → 503 (transient verify error)
	srv := newCalendarServer(t, http.StatusOK, http.StatusServiceUnavailable)
	defer srv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(context.Background(), a)
	require.NoError(t, err, "5xx must be swallowed")
	assert.True(t, v.Swallowed)
	assert.NotEmpty(t, v.ErrorMessage)
	assert.Equal(t, providers.ConfirmationPending, v.Confirmation)
}

func TestVerify_CalendarReturns404_StillPending_NotSwallowed(t *testing.T) {
	// /digest → 200, /timestamp → 404 (not yet upgraded; normal pending state)
	srv := newCalendarServer(t, http.StatusOK, http.StatusNotFound)
	defer srv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(context.Background(), a)
	require.NoError(t, err)
	assert.False(t, v.Swallowed, "404 (still pending) is not an error, not swallowed")
	assert.Equal(t, providers.ConfirmationPending, v.Confirmation)
}

func TestVerify_CalendarReturnsUpgrade_Confirmed(t *testing.T) {
	// /digest → 200, /timestamp → 200 (Bitcoin proof confirmed)
	srv := newCalendarServer(t, http.StatusOK, http.StatusOK)
	defer srv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(context.Background(), a)
	require.NoError(t, err)
	assert.False(t, v.Swallowed)
	assert.Equal(t, providers.ConfirmationConfirmed, v.Confirmation)
}

func TestVerify_HardError_4xx_ReturnsError(t *testing.T) {
	// /digest → 200, /timestamp → 400 (semantically rejects the proof)
	srv := newCalendarServer(t, http.StatusOK, http.StatusBadRequest)
	defer srv.Close()

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{srv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	_, err = p.Verify(context.Background(), a)
	require.Error(t, err, "4xx hard error MUST be returned as error (not swallowed)")
}

func TestVerify_MalformedProofData_ReturnsError(t *testing.T) {
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{"http://example.com"},
	})
	require.NoError(t, err)

	badAnchor := providers.Anchor{
		ProviderName: "opentimestamps",
		ProofData:    []byte("this is not valid json {{{"),
		Confirmation: providers.ConfirmationPending,
	}

	_, err = p.Verify(context.Background(), badAnchor)
	require.Error(t, err, "malformed proof data must return hard error")
}

func TestVerify_MixedCalendars_ConfirmedWinsOverTransient(t *testing.T) {
	// One calendar confirms (200), another is transient (closed after anchor).
	confirmSrv := newCalendarServer(t, http.StatusOK, http.StatusOK)
	defer confirmSrv.Close()

	transientSrv := newCalendarServer(t, http.StatusOK, http.StatusOK)

	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{confirmSrv.URL, transientSrv.URL},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	// Close the transient server after anchoring.
	transientSrv.Close()

	v, err := p.Verify(context.Background(), a)
	require.NoError(t, err)
	// At least one calendar confirmed → confirmed wins even if another had transient error.
	assert.Equal(t, providers.ConfirmationConfirmed, v.Confirmation)
}

// --- Real network tests (gated by OTS_TEST=1) ---

func TestAnchor_RealCalendarServers_ReturnsProofData(t *testing.T) {
	if os.Getenv("OTS_TEST") != "1" {
		t.Skip("requires OTS_TEST=1 and network access to OpenTimestamps calendar servers")
	}
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{
			"https://alice.btc.calendar.opentimestamps.org",
			"https://bob.btc.calendar.opentimestamps.org",
		},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	assert.Equal(t, "opentimestamps", a.ProviderName)
	assert.Equal(t, testRootHex, a.ExternalID)
	assert.NotEmpty(t, a.ProofData)
	assert.Equal(t, providers.ConfirmationPending, a.Confirmation)
}

func TestVerify_RealCalendarServers_PendingStillPending(t *testing.T) {
	if os.Getenv("OTS_TEST") != "1" {
		t.Skip("requires OTS_TEST=1 and network access to OpenTimestamps calendar servers")
	}
	p, err := opentimestamps.NewProvider(opentimestamps.Config{
		CalendarServers: []string{
			"https://alice.btc.calendar.opentimestamps.org",
		},
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	// Immediately verify — Bitcoin takes ~24h so confirmation must still be pending.
	v, err := p.Verify(context.Background(), a)
	require.NoError(t, err)
	assert.Equal(t, providers.ConfirmationPending, v.Confirmation)
}

// --- helpers ---

// newCalendarServer creates a test HTTP server that responds to:
//   - POST /digest                → digestStatus
//   - GET  /timestamp/<anything> → upgradeStatus
func newCalendarServer(t *testing.T, digestStatus, upgradeStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/digest":
			w.WriteHeader(digestStatus)
			if digestStatus >= 200 && digestStatus < 300 {
				_, _ = w.Write([]byte("fake-ots-pending-proof"))
			}
		default:
			// GET /timestamp/<hash> — upgrade check
			w.WriteHeader(upgradeStatus)
			if upgradeStatus >= 200 && upgradeStatus < 300 {
				_, _ = w.Write([]byte("fake-ots-upgraded-proof-with-bitcoin-block"))
			} else {
				_, _ = w.Write([]byte("error response body"))
			}
		}
	}))
}
