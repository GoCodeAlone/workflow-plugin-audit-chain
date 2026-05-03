package modules

import (
	"context"
	"fmt"
	"sync"
	"time"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/providers"
	gitprovider "github.com/GoCodeAlone/workflow-plugin-audit-chain/providers/git"
	otsprovider "github.com/GoCodeAlone/workflow-plugin-audit-chain/providers/opentimestamps"
	sigprovider "github.com/GoCodeAlone/workflow-plugin-audit-chain/providers/sigstore"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// ── AnchorProvider registry ───────────────────────────────────────────────────

var (
	anchorProviderMu       sync.RWMutex
	anchorProviderRegistry = make(map[string]providers.AnchorProvider)
)

// RegisterAnchorProvider registers an AnchorProvider under the given instance
// name.
func RegisterAnchorProvider(instanceName string, p providers.AnchorProvider) {
	anchorProviderMu.Lock()
	defer anchorProviderMu.Unlock()
	anchorProviderRegistry[instanceName] = p
}

// GetAnchorProvider looks up an AnchorProvider by instance name.
func GetAnchorProvider(instanceName string) (providers.AnchorProvider, bool) {
	anchorProviderMu.RLock()
	defer anchorProviderMu.RUnlock()
	p, ok := anchorProviderRegistry[instanceName]
	return p, ok
}

// UnregisterAnchorProvider removes a provider from the registry (called on Stop
// and in tests).
func UnregisterAnchorProvider(instanceName string) {
	anchorProviderMu.Lock()
	defer anchorProviderMu.Unlock()
	delete(anchorProviderRegistry, instanceName)
}

// ── anchorProviderModule ──────────────────────────────────────────────────────

// anchorProviderModule is the shared sdk.ModuleInstance implementation for all
// audit.anchor_provider.* types. It holds a constructed AnchorProvider and
// registers / unregisters it on lifecycle calls.
type anchorProviderModule struct {
	instanceName string
	provider     providers.AnchorProvider
}

// Compile-time assertion.
var _ sdk.ModuleInstance = (*anchorProviderModule)(nil)

// Init registers the underlying AnchorProvider in the global registry.
func (m *anchorProviderModule) Init() error {
	RegisterAnchorProvider(m.instanceName, m.provider)
	return nil
}

// Start is a no-op for anchor provider modules.
func (m *anchorProviderModule) Start(_ context.Context) error { return nil }

// Stop unregisters the provider from the registry.
func (m *anchorProviderModule) Stop(_ context.Context) error {
	UnregisterAnchorProvider(m.instanceName)
	return nil
}

// ── OpenTimestamps factory ────────────────────────────────────────────────────

// NewOpenTimestampsProviderModule creates a ModuleInstance for
// audit.anchor_provider.opentimestamps from a typed OpenTimestampsProviderConfig.
func NewOpenTimestampsProviderModule(instanceName string, cfg *auditv1.OpenTimestampsProviderConfig) (sdk.ModuleInstance, error) {
	if len(cfg.GetCalendarServers()) == 0 {
		return nil, fmt.Errorf("audit.anchor_provider.opentimestamps %q: at least one calendar server required", instanceName)
	}
	timeout := time.Duration(cfg.GetHttpTimeoutMs()) * time.Millisecond
	p, err := otsprovider.NewProvider(otsprovider.Config{
		CalendarServers: cfg.GetCalendarServers(),
		HTTPTimeout:     timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("audit.anchor_provider.opentimestamps %q: %w", instanceName, err)
	}
	return &anchorProviderModule{instanceName: instanceName, provider: p}, nil
}

// ── Git factory ───────────────────────────────────────────────────────────────

// NewGitAnchorProviderModule creates a ModuleInstance for
// audit.anchor_provider.git from a typed GitAnchorProviderConfig.
func NewGitAnchorProviderModule(instanceName string, cfg *auditv1.GitAnchorProviderConfig) (sdk.ModuleInstance, error) {
	if cfg.GetRemote() == "" {
		return nil, fmt.Errorf("audit.anchor_provider.git %q: config.remote is required", instanceName)
	}
	p, err := gitprovider.NewProvider(gitprovider.Config{
		Remote:         cfg.GetRemote(),
		Branch:         cfg.GetBranch(),
		CommitTemplate: cfg.GetCommitTemplate(),
		AuthorName:     cfg.GetAuthorName(),
		AuthorEmail:    cfg.GetAuthorEmail(),
		UseSSHAgent:    cfg.GetUseSshAgent(),
		SSHKeyPath:     cfg.GetSshKeyPath(),
		SSHKeyPassword: cfg.GetSshKeyPassword(),
		HTTPUsername:   cfg.GetHttpUsername(),
		HTTPPassword:   cfg.GetHttpPassword(),
	})
	if err != nil {
		return nil, fmt.Errorf("audit.anchor_provider.git %q: %w", instanceName, err)
	}
	return &anchorProviderModule{instanceName: instanceName, provider: p}, nil
}

// ── Sigstore factory ──────────────────────────────────────────────────────────

// NewSigstoreProviderModule creates a ModuleInstance for
// audit.anchor_provider.sigstore from a typed SigstoreProviderConfig.
func NewSigstoreProviderModule(instanceName string, cfg *auditv1.SigstoreProviderConfig) (sdk.ModuleInstance, error) {
	p, err := sigprovider.NewProvider(sigprovider.Config{
		RekorURL: cfg.GetRekorUrl(),
	})
	if err != nil {
		return nil, fmt.Errorf("audit.anchor_provider.sigstore %q: %w", instanceName, err)
	}
	return &anchorProviderModule{instanceName: instanceName, provider: p}, nil
}
