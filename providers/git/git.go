// Package git implements the AnchorProvider interface by committing the Merkle
// root to a git repository and pushing to a configured remote. Git anchoring
// provides near-instant finalization — once the push succeeds, the commit is
// permanent (assuming the remote is trustworthy). Confirmation is therefore
// returned as ConfirmationFinalized immediately after a successful push.
//
// Redundancy note: git anchoring is lightweight and free but depends on the
// trust of the repository hosting provider. BMW uses it alongside
// OpenTimestamps for fast redundant anchoring.
package git

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
)

const providerName = "git"

// Config holds configuration for the git anchor provider.
type Config struct {
	// Remote is the git remote URL (file path, https, ssh, etc.).
	Remote string `json:"remote"`

	// Branch is the branch to push anchors to. Defaults to "main".
	Branch string `json:"branch,omitempty"`

	// CommitTemplate is a Go text/template string for the commit message.
	// Template data: CommitTemplateData. Defaults to "anchor: {{.MerkleRoot}}".
	CommitTemplate string `json:"commit_template,omitempty"`

	// AuthorName is the git commit author name. Defaults to "audit-chain-bot".
	AuthorName string `json:"author_name,omitempty"`

	// AuthorEmail is the git commit author email. Defaults to "audit-chain-bot@localhost".
	AuthorEmail string `json:"author_email,omitempty"`
}

// CommitTemplateData is the data available to CommitTemplate.
type CommitTemplateData struct {
	MerkleRoot string // hex-encoded merkle root
	AnchoredAt string // RFC3339 timestamp of the anchor operation
}

// anchorFileContent is the JSON structure written to the anchor file in the repo.
type anchorFileContent struct {
	MerkleRoot string `json:"merkle_root"`
	AnchoredAt string `json:"anchored_at"`
	Provider   string `json:"provider"`
}

// proofData is stored in Anchor.ProofData.
type proofData struct {
	CommitSHA string `json:"commit_sha"`
	Remote    string `json:"remote"`
	Branch    string `json:"branch"`
	FilePath  string `json:"file_path"` // path within the repo to the anchor file
}

// Provider implements providers.AnchorProvider using a git remote.
type Provider struct {
	cfg            Config
	commitTemplate *template.Template
}

// Compile-time assertion.
var _ providers.AnchorProvider = (*Provider)(nil)

// NewProvider creates a new git anchor provider.
// Returns an error if Remote is empty or CommitTemplate is invalid.
func NewProvider(cfg Config) (*Provider, error) {
	if cfg.Remote == "" {
		return nil, fmt.Errorf("git provider: remote is required")
	}
	if cfg.Branch == "" {
		cfg.Branch = "main"
	}
	if cfg.CommitTemplate == "" {
		cfg.CommitTemplate = "anchor: {{.MerkleRoot}}"
	}
	if cfg.AuthorName == "" {
		cfg.AuthorName = "audit-chain-bot"
	}
	if cfg.AuthorEmail == "" {
		cfg.AuthorEmail = "audit-chain-bot@localhost"
	}

	tmpl, err := template.New("commit").Parse(cfg.CommitTemplate)
	if err != nil {
		return nil, fmt.Errorf("git provider: invalid commit template: %w", err)
	}

	return &Provider{cfg: cfg, commitTemplate: tmpl}, nil
}

// Name returns the provider's stable identifier.
func (p *Provider) Name() string { return providerName }

// Anchor commits the Merkle root to the configured git remote.
//
// It clones the remote into a temporary directory, writes an anchor JSON file
// to anchors/<YYYY-MM-DD>/<first16hexchars>.json, commits with the rendered
// CommitTemplate, and pushes. Returns Confirmation: Finalized immediately —
// a successful push is permanent in git.
func (p *Provider) Anchor(ctx context.Context, root providers.MerkleRoot) (providers.Anchor, error) {
	now := time.Now().UTC()

	// Render commit message from template.
	var msgBuf bytes.Buffer
	if err := p.commitTemplate.Execute(&msgBuf, CommitTemplateData{
		MerkleRoot: root.Hex,
		AnchoredAt: now.Format(time.RFC3339),
	}); err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: render commit template: %w", err)
	}
	commitMsg := msgBuf.String()

	// Work in a temp directory; always cleaned up.
	tmpDir, err := os.MkdirTemp("", "audit-chain-git-*")
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Clone or init (handles empty/new remotes).
	repo, err := p.cloneOrInit(tmpDir)
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: clone/init from %s: %w", p.cfg.Remote, err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: get worktree: %w", err)
	}

	// Write anchor file and stage it.
	// Path: anchors/<YYYY-MM-DD>/<first16hexchars>.json
	fileRelPath := fmt.Sprintf("anchors/%s/%s.json", now.Format("2006-01-02"), root.Hex[:16])
	if err := p.writeAnchorFile(tmpDir, fileRelPath, root.Hex, now); err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: write anchor file: %w", err)
	}
	if _, err := wt.Add(fileRelPath); err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: stage %s: %w", fileRelPath, err)
	}

	// Commit.
	commitHash, err := wt.Commit(commitMsg, &gogit.CommitOptions{
		Author: &object.Signature{
			Name:  p.cfg.AuthorName,
			Email: p.cfg.AuthorEmail,
			When:  now,
		},
	})
	if err != nil {
		return providers.Anchor{}, fmt.Errorf("git provider: commit: %w", err)
	}

	// Push to remote.
	refSpec := config.RefSpec(fmt.Sprintf(
		"refs/heads/%s:refs/heads/%s", p.cfg.Branch, p.cfg.Branch))
	pushErr := repo.PushContext(ctx, &gogit.PushOptions{
		RemoteName: "origin",
		RefSpecs:   []config.RefSpec{refSpec},
	})
	if pushErr != nil && pushErr != gogit.NoErrAlreadyUpToDate {
		return providers.Anchor{}, fmt.Errorf("git provider: push to %s: %w", p.cfg.Remote, pushErr)
	}

	pd := proofData{
		CommitSHA: commitHash.String(),
		Remote:    p.cfg.Remote,
		Branch:    p.cfg.Branch,
		FilePath:  fileRelPath,
	}
	proofBytes, _ := json.Marshal(pd)

	return providers.Anchor{
		ProviderName: providerName,
		AnchoredAt:   now,
		ExternalID:   commitHash.String(),
		ProofData:    proofBytes,
		Confirmation: providers.ConfirmationFinalized, // push = instant-final in git
	}, nil
}

// cloneOrInit clones the remote into dir. If the remote is empty (no commits),
// it initializes a fresh local repo with the remote configured as "origin".
func (p *Provider) cloneOrInit(dir string) (*gogit.Repository, error) {
	repo, err := gogit.PlainClone(dir, false, &gogit.CloneOptions{
		URL:           p.cfg.Remote,
		ReferenceName: plumbing.NewBranchReferenceName(p.cfg.Branch),
		SingleBranch:  true,
		Depth:         1,
	})
	if err == nil {
		return repo, nil
	}

	// Empty remote (first anchor) — initialize fresh local repo.
	if err == transport.ErrEmptyRemoteRepository ||
		strings.Contains(err.Error(), "remote repository is empty") ||
		strings.Contains(err.Error(), "couldn't find remote ref") {
		return p.initWithRemote(dir)
	}

	return nil, err
}

// initWithRemote initializes a new local git repo in dir with origin set to
// p.cfg.Remote, and HEAD pointing to p.cfg.Branch.
func (p *Provider) initWithRemote(dir string) (*gogit.Repository, error) {
	repo, err := gogit.PlainInit(dir, false)
	if err != nil {
		return nil, fmt.Errorf("init: %w", err)
	}

	if _, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{p.cfg.Remote},
	}); err != nil {
		return nil, fmt.Errorf("add remote origin: %w", err)
	}

	// Point HEAD at the configured branch so the first commit creates it.
	headRef := plumbing.NewSymbolicReference(
		plumbing.HEAD,
		plumbing.NewBranchReferenceName(p.cfg.Branch),
	)
	if err := repo.Storer.SetReference(headRef); err != nil {
		return nil, fmt.Errorf("set HEAD to %s: %w", p.cfg.Branch, err)
	}

	return repo, nil
}

// writeAnchorFile writes the anchor JSON to dir/relPath, creating parent dirs.
func (p *Provider) writeAnchorFile(dir, relPath, rootHex string, now time.Time) error {
	content := anchorFileContent{
		MerkleRoot: rootHex,
		AnchoredAt: now.Format(time.RFC3339),
		Provider:   providerName,
	}
	data, err := json.MarshalIndent(content, "", "  ")
	if err != nil {
		return err
	}
	fullPath := filepath.Join(dir, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0o644)
}

// Verify checks that the anchor's remote is reachable and returns
// ConfirmationFinalized. Git commits are permanent once pushed; transient
// connectivity errors are swallowed per § 3.5c.
//
// Swallow contract:
//   - Remote unreachable / network error → Swallowed=true, confirmation preserved.
//   - Malformed ProofData → hard error.
func (p *Provider) Verify(ctx context.Context, anchor providers.Anchor) (providers.Verification, error) {
	var pd proofData
	if err := json.Unmarshal(anchor.ProofData, &pd); err != nil {
		return providers.Verification{}, fmt.Errorf("git provider: malformed proof data: %w", err)
	}

	now := time.Now().UTC()

	// Check remote reachability via ls-remote (lightweight, no object download).
	remote := gogit.NewRemote(nil, &config.RemoteConfig{
		Name: "origin",
		URLs: []string{pd.Remote},
	})
	_, err := remote.ListContext(ctx, &gogit.ListOptions{})
	if err != nil {
		// Remote unreachable → transient error; swallow and preserve state.
		return providers.Verification{
			Provider:     providerName,
			Confirmation: anchor.Confirmation,
			UpdatedAt:    now,
			Swallowed:    true,
			ErrorMessage: fmt.Sprintf("remote %s unreachable: %v", pd.Remote, err),
		}, nil
	}

	// Remote reachable; git commits are immutable once pushed → finalized.
	return providers.Verification{
		Provider:     providerName,
		Confirmation: providers.ConfirmationFinalized,
		UpdatedAt:    now,
	}, nil
}

// Cost returns the cost model for git anchoring (always free).
func (p *Provider) Cost(_ int) providers.Cost {
	return providers.Cost{
		PerAnchorUSDCents: 0,
		Notes:             "git anchoring is free; trust depends on the git hosting provider",
	}
}
