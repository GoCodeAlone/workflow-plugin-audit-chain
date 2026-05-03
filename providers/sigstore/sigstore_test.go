package sigstore_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers/sigstore"
)

const testRootHex = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd"
const testUUID = "3b5b4dc7c1f8f7b0f7e5d9c8a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"

// fakeLogID is a 64-char hex string satisfying Rekor's logID pattern constraint.
const fakeLogID = "0000000000000000000000000000000000000000000000000000000000000000"

// --- Constructor ---

func TestNewProvider_DefaultsToPublicRekor(t *testing.T) {
	p, err := sigstore.NewProvider(sigstore.Config{})
	require.NoError(t, err)
	assert.NotNil(t, p)
}

func TestNewProvider_InvalidURL_ReturnsError(t *testing.T) {
	_, err := sigstore.NewProvider(sigstore.Config{RekorURL: "://bad-url"})
	require.Error(t, err)
}

// --- Name / Cost ---

func TestName(t *testing.T) {
	p, err := sigstore.NewProvider(sigstore.Config{})
	require.NoError(t, err)
	assert.Equal(t, "sigstore", p.Name())
}

func TestCost_IsFree(t *testing.T) {
	p, err := sigstore.NewProvider(sigstore.Config{})
	require.NoError(t, err)
	c := p.Cost(1)
	assert.Equal(t, int64(0), c.PerAnchorUSDCents)
	assert.NotEmpty(t, c.Notes)
}

// --- Anchor with mock Rekor server ---

func TestAnchor_SuccessfulSubmission_ReturnsFinalized(t *testing.T) {
	srv := newRekorServer(t, http.StatusCreated, http.StatusOK)
	defer srv.Close()

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	assert.Equal(t, "sigstore", a.ProviderName)
	assert.NotEmpty(t, a.ExternalID, "ExternalID must be Rekor entry UUID")
	assert.Equal(t, providers.ConfirmationFinalized, a.Confirmation)
	assert.NotEmpty(t, a.ProofData)
	assert.False(t, a.AnchoredAt.IsZero())
}

func TestAnchor_InvalidHex_ReturnsError(t *testing.T) {
	p, err := sigstore.NewProvider(sigstore.Config{})
	require.NoError(t, err)
	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: "not-valid-hex!"})
	require.Error(t, err)
}

func TestAnchor_WrongHashLength_ReturnsError(t *testing.T) {
	p, err := sigstore.NewProvider(sigstore.Config{})
	require.NoError(t, err)
	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: "deadbeef"})
	require.Error(t, err)
}

func TestAnchor_RekorRejectsEntry_ReturnsError(t *testing.T) {
	// Server returns 400 Bad Request for create
	srv := newRekorServer(t, http.StatusBadRequest, http.StatusOK)
	defer srv.Close()

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.Error(t, err)
}

// --- Verify: swallow-transient-errors contract (§ 3.5c) ---

func TestVerify_EntryExists_ReturnsFinalized(t *testing.T) {
	srv := newRekorServer(t, http.StatusCreated, http.StatusOK)
	defer srv.Close()

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, providers.ConfirmationFinalized, v.Confirmation)
	assert.Equal(t, "sigstore", v.Provider)
	assert.False(t, v.Swallowed)
}

func TestVerify_NetworkError_Swallowed(t *testing.T) {
	// Anchor via a working server, then close it to simulate network failure.
	srv := newRekorServer(t, http.StatusCreated, http.StatusOK)

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	srv.Close() // simulate unreachable Rekor

	v, err := p.Verify(ctx, a)
	require.NoError(t, err, "network error MUST be swallowed (§ 3.5c)")
	assert.True(t, v.Swallowed)
	assert.NotEmpty(t, v.ErrorMessage)
	assert.Equal(t, providers.ConfirmationFinalized, v.Confirmation, "previous confirmation preserved")
}

func TestVerify_Rekor5xx_Swallowed(t *testing.T) {
	// Create → 201 success; Verify → 503 (server error, transient)
	srv := newRekorServer(t, http.StatusCreated, http.StatusServiceUnavailable)
	defer srv.Close()

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(ctx, a)
	require.NoError(t, err, "5xx MUST be swallowed")
	assert.True(t, v.Swallowed)
	assert.NotEmpty(t, v.ErrorMessage)
	assert.Equal(t, providers.ConfirmationFinalized, v.Confirmation)
}

func TestVerify_Rekor400_HardError(t *testing.T) {
	// Non-404 4xx (e.g., 400 bad UUID) should be a hard error, not swallowed.
	srv := newRekorServer(t, http.StatusCreated, http.StatusBadRequest)
	defer srv.Close()

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	_, err = p.Verify(ctx, a)
	require.Error(t, err, "non-404 4xx MUST be a hard error (likely malformed ProofData)")
}

func TestVerify_Rekor404_HardError(t *testing.T) {
	// Create → 201 success; Verify → 404 (entry not found = hard error)
	srv := newRekorServer(t, http.StatusCreated, http.StatusNotFound)
	defer srv.Close()

	p, err := sigstore.NewProvider(sigstore.Config{RekorURL: srv.URL})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	_, err = p.Verify(ctx, a)
	require.Error(t, err, "404 missing entry MUST be a hard error (transparency log should be append-only)")
}

func TestVerify_MalformedProofData_HardError(t *testing.T) {
	p, err := sigstore.NewProvider(sigstore.Config{})
	require.NoError(t, err)

	badAnchor := providers.Anchor{
		ProviderName: "sigstore",
		ProofData:    []byte("not valid json {{{"),
		Confirmation: providers.ConfirmationFinalized,
	}
	_, err = p.Verify(context.Background(), badAnchor)
	require.Error(t, err, "malformed proof data must be a hard error")
}

// --- Real-network tests (gated by SIGSTORE_TEST=1) ---

func TestAnchor_RealRekor_AppendsToTransparencyLog(t *testing.T) {
	if os.Getenv("SIGSTORE_TEST") != "1" {
		t.Skip("requires SIGSTORE_TEST=1 and network access to rekor.sigstore.dev")
	}
	p, err := sigstore.NewProvider(sigstore.Config{
		RekorURL: "https://rekor.sigstore.dev",
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)
	assert.NotEmpty(t, a.ExternalID, "ExternalID should be Rekor log entry UUID")
	assert.Equal(t, providers.ConfirmationFinalized, a.Confirmation)
}

func TestVerify_RealRekor_EntryIsFinalized(t *testing.T) {
	if os.Getenv("SIGSTORE_TEST") != "1" {
		t.Skip("requires SIGSTORE_TEST=1 and network access to rekor.sigstore.dev")
	}
	p, err := sigstore.NewProvider(sigstore.Config{
		RekorURL: "https://rekor.sigstore.dev",
	})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, providers.ConfirmationFinalized, v.Confirmation)
}

// --- helpers ---

// newRekorServer creates a mock Rekor HTTP server.
//   - POST /api/v1/log/entries → createStatus (with log entry JSON body on 201)
//   - GET  /api/v1/log/entries/{uuid} → getStatus (with log entry JSON body on 200)
func newRekorServer(t *testing.T, createStatus, getStatus int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/log/entries":
			if createStatus == http.StatusCreated {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write(makeLogEntryJSON(testUUID))
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(createStatus)
				_, _ = w.Write([]byte(`{"code":400,"message":"bad request"}`))
			}

		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/api/v1/log/entries/"):
			if getStatus == http.StatusOK {
				// Extract UUID from path and return it as the key.
				parts := strings.Split(r.URL.Path, "/")
				uuid := parts[len(parts)-1]
				if uuid == "" {
					uuid = testUUID
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(makeLogEntryJSON(uuid))
			} else if getStatus == http.StatusNotFound {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"code":404,"message":"entry not found"}`))
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(getStatus)
				_, _ = w.Write([]byte(`{"code":503,"message":"service unavailable"}`))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

// makeLogEntryJSON creates a valid Rekor LogEntry JSON response with the given UUID.
func makeLogEntryJSON(uuid string) []byte {
	integratedTime := int64(1746302800)
	logIndex := int64(0)
	entry := map[string]interface{}{
		uuid: map[string]interface{}{
			"body":           "e30=", // base64("{}")
			"integratedTime": integratedTime,
			"logID":          fakeLogID,
			"logIndex":       logIndex,
		},
	}
	b, _ := json.Marshal(entry)
	return b
}
