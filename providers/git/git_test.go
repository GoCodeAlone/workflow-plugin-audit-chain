package git_test

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	gitprovider "github.com/GoCodeAlone/workflow-plugin-audit-chain/providers/git"
)

const testRootHex = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

// --- Constructor ---

func TestNewProvider_RequiresRemote(t *testing.T) {
	_, err := gitprovider.NewProvider(gitprovider.Config{})
	require.Error(t, err)
}

func TestNewProvider_InvalidCommitTemplate_ReturnsError(t *testing.T) {
	_, err := gitprovider.NewProvider(gitprovider.Config{
		Remote:         "/tmp/some-bare-repo",
		CommitTemplate: "{{.UnclosedBrace",
	})
	require.Error(t, err)
}

func TestNewProvider_DefaultBranchIsMain(t *testing.T) {
	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote: "/tmp/some-bare-repo",
	})
	require.NoError(t, err)
	assert.NotNil(t, p)
}

// --- Name / Cost ---

func TestName(t *testing.T) {
	p, err := gitprovider.NewProvider(gitprovider.Config{Remote: "/tmp/x"})
	require.NoError(t, err)
	assert.Equal(t, "git", p.Name())
}

func TestCost_IsFree(t *testing.T) {
	p, err := gitprovider.NewProvider(gitprovider.Config{Remote: "/tmp/x"})
	require.NoError(t, err)
	c := p.Cost(100)
	assert.Equal(t, int64(0), c.PerAnchorUSDCents)
	assert.NotEmpty(t, c.Notes)
}

// --- Anchor ---

func TestAnchor_CommitsRootToLocalBareRepo(t *testing.T) {
	bareRepo := setupLocalBareRepo(t)

	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote:         bareRepo,
		Branch:         "main",
		CommitTemplate: "anchor: {{.MerkleRoot}}",
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	// Commit SHA must be a 40-char hex string.
	assert.Len(t, a.ExternalID, 40, "ExternalID must be a git commit SHA (40 chars)")
	assert.Equal(t, "git", a.ProviderName)
	assert.Equal(t, providers.ConfirmationFinalized, a.Confirmation, "git push = instant finalization")
	assert.NotEmpty(t, a.ProofData)
	assert.False(t, a.AnchoredAt.IsZero())

	// Verify the commit landed in the bare repo with the right message.
	msg := latestCommitMessage(t, bareRepo)
	assert.Equal(t, "anchor: "+testRootHex, msg)
}

func TestAnchor_CommitMessageUsesTemplate(t *testing.T) {
	bareRepo := setupLocalBareRepo(t)

	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote:         bareRepo,
		Branch:         "main",
		CommitTemplate: "Anchor root={{.MerkleRoot}} at={{.AnchoredAt}}",
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	msg := latestCommitMessage(t, bareRepo)
	assert.True(t, strings.HasPrefix(msg, "Anchor root="+testRootHex+" at="),
		"commit message %q does not match template", msg)
	_ = a
}

func TestAnchor_AnchorFileExistsInRepo(t *testing.T) {
	bareRepo := setupLocalBareRepo(t)

	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote: bareRepo,
		Branch: "main",
	})
	require.NoError(t, err)

	a, err := p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	// The anchor file path is encoded in ProofData.
	var pd struct {
		FilePath string `json:"file_path"`
	}
	require.NoError(t, json.Unmarshal(a.ProofData, &pd))
	assert.NotEmpty(t, pd.FilePath)
	assert.True(t, strings.HasPrefix(pd.FilePath, "anchors/"), "file path must be under anchors/")

	// Inspect the bare repo: clone it and verify the file exists with correct content.
	cloneDir := t.TempDir()
	cloned, err := gogit.PlainClone(cloneDir, false, &gogit.CloneOptions{
		URL:           bareRepo,
		ReferenceName: plumbing.NewBranchReferenceName("main"),
	})
	require.NoError(t, err)

	head, err := cloned.Head()
	require.NoError(t, err)
	commit, err := cloned.CommitObject(head.Hash())
	require.NoError(t, err)

	f, err := commit.File(pd.FilePath)
	require.NoError(t, err, "anchor file %s must exist in the commit", pd.FilePath)

	content, err := f.Contents()
	require.NoError(t, err)

	var anchorContent struct {
		MerkleRoot string `json:"merkle_root"`
		Provider   string `json:"provider"`
	}
	require.NoError(t, json.Unmarshal([]byte(content), &anchorContent))
	assert.Equal(t, testRootHex, anchorContent.MerkleRoot)
	assert.Equal(t, "git", anchorContent.Provider)
}

func TestAnchor_MultipleAnchors_EachCommitDistinct(t *testing.T) {
	bareRepo := setupLocalBareRepo(t)

	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote: bareRepo,
		Branch: "main",
	})
	require.NoError(t, err)

	root2 := "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe"

	ctx := context.Background()
	a1, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	a2, err := p.Anchor(ctx, providers.MerkleRoot{Hex: root2})
	require.NoError(t, err)

	assert.NotEqual(t, a1.ExternalID, a2.ExternalID, "each anchor must produce a distinct commit SHA")
}

func TestAnchor_UnreachableRemote_ReturnsError(t *testing.T) {
	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote: "/nonexistent/path/to/bare-repo",
		Branch: "main",
	})
	require.NoError(t, err)

	_, err = p.Anchor(context.Background(), providers.MerkleRoot{Hex: testRootHex})
	require.Error(t, err, "unreachable remote must return error from Anchor")
}

// --- Verify ---

func TestVerify_AfterAnchor_ReturnsFinalized(t *testing.T) {
	bareRepo := setupLocalBareRepo(t)

	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote: bareRepo,
		Branch: "main",
	})
	require.NoError(t, err)

	ctx := context.Background()
	a, err := p.Anchor(ctx, providers.MerkleRoot{Hex: testRootHex})
	require.NoError(t, err)

	v, err := p.Verify(ctx, a)
	require.NoError(t, err)
	assert.Equal(t, providers.ConfirmationFinalized, v.Confirmation)
	assert.Equal(t, "git", v.Provider)
	assert.False(t, v.Swallowed)
}

func TestVerify_MalformedProofData_ReturnsHardError(t *testing.T) {
	p, err := gitprovider.NewProvider(gitprovider.Config{Remote: "/tmp/x"})
	require.NoError(t, err)

	badAnchor := providers.Anchor{
		ProviderName: "git",
		ProofData:    []byte("not json {{{"),
		Confirmation: providers.ConfirmationFinalized,
	}
	_, err = p.Verify(context.Background(), badAnchor)
	require.Error(t, err, "malformed proof data must be a hard error")
}

func TestVerify_UnreachableRemote_Swallowed(t *testing.T) {
	// Build a valid proof data pointing to a nonexistent remote.
	pd, _ := json.Marshal(map[string]string{
		"commit_sha": strings.Repeat("a", 40),
		"remote":     "/nonexistent/no/such/repo",
		"branch":     "main",
		"file_path":  "anchors/2026-05-03/deadbeef.json",
	})

	p, err := gitprovider.NewProvider(gitprovider.Config{Remote: "/nonexistent/no/such/repo"})
	require.NoError(t, err)

	anchor := providers.Anchor{
		ProviderName: "git",
		ExternalID:   strings.Repeat("a", 40),
		ProofData:    pd,
		Confirmation: providers.ConfirmationFinalized,
	}

	v, err := p.Verify(context.Background(), anchor)
	require.NoError(t, err, "unreachable remote must be swallowed, not returned as error")
	assert.True(t, v.Swallowed)
	assert.NotEmpty(t, v.ErrorMessage)
	assert.Equal(t, providers.ConfirmationFinalized, v.Confirmation, "previous confirmation preserved")
}

// --- helpers ---

// setupLocalBareRepo creates a temporary bare git repository and returns its path.
func setupLocalBareRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "bare.git")
	out, err := exec.Command("git", "init", "--bare", dir).CombinedOutput()
	require.NoError(t, err, "git init --bare: %s", string(out))
	return dir
}

// latestCommitMessage returns the HEAD commit message of the given bare repo.
func latestCommitMessage(t *testing.T, bareRepoPath string) string {
	t.Helper()
	cloneDir := t.TempDir()
	_, err := gogit.PlainClone(cloneDir, false, &gogit.CloneOptions{
		URL:           bareRepoPath,
		ReferenceName: plumbing.NewBranchReferenceName("main"),
	})
	require.NoError(t, err)

	repo, err := gogit.PlainOpen(cloneDir)
	require.NoError(t, err)
	head, err := repo.Head()
	require.NoError(t, err)
	commit, err := repo.CommitObject(head.Hash())
	require.NoError(t, err)
	return strings.TrimSpace(commit.Message)
}
