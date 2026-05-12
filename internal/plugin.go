// Package internal implements the workflow-plugin-audit-chain plugin.
package internal

import (
	"errors"
	"fmt"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/steps"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-audit-chain/internal.Version=X.Y.Z".
// Default is a bare semver so plugin loaders that validate semver accept
// unreleased dev builds; goreleaser overrides with the real release tag.
var Version = "0.0.0"

// AuditChainPlugin implements sdk.PluginProvider, sdk.TypedModuleProvider, and
// sdk.TypedStepProvider. Zero map[string]any in plugin code: all module and
// step boundaries use typed proto messages (anypb.Any).
type AuditChainPlugin struct{}

// Compile-time assertions.
var (
	_ sdk.TypedModuleProvider = (*AuditChainPlugin)(nil)
	_ sdk.TypedStepProvider   = (*AuditChainPlugin)(nil)
	_ sdk.ContractProvider    = (*AuditChainPlugin)(nil)
)

// NewPlugin returns a new plugin instance. main.go calls sdk.Serve(NewPlugin()).
func NewPlugin() sdk.PluginProvider {
	return &AuditChainPlugin{}
}

// Manifest returns the plugin metadata used by the workflow engine for
// discovery and capability negotiation.
func (p *AuditChainPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-audit-chain",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Tamper-evident hash-chained audit logging with periodic Merkle root anchoring (OpenTimestamps/Bitcoin, git, Sigstore, Ethereum, AWS QLDB)",
	}
}

// ── Module provider (typed) ───────────────────────────────────────────────────

// knownModuleTypes is the full set of module types declared by this plugin.
// ethereum and aws_qldb are declared but deferred (not yet implemented).
var knownModuleTypes = []string{
	"audit.ledger",
	"audit.anchor_provider.opentimestamps",
	"audit.anchor_provider.git",
	"audit.anchor_provider.sigstore",
	"audit.anchor_provider.ethereum",
	"audit.anchor_provider.aws_qldb",
}

// TypedModuleTypes returns the module type names this plugin provides.
// The gRPC server prefers TypedModuleProvider over the legacy ModuleProvider.
func (p *AuditChainPlugin) TypedModuleTypes() []string {
	return knownModuleTypes
}

// CreateTypedModule creates a module instance from a typed proto config.
// No map[string]any is used; config is unpacked directly into the target proto.
func (p *AuditChainPlugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "audit.ledger":
		var cfg auditv1.LedgerConfig
		if config != nil {
			if err := config.UnmarshalTo(&cfg); err != nil {
				return nil, fmt.Errorf("audit.ledger %q: unmarshal config: %w", name, err)
			}
		}
		return modules.NewLedgerModule(name, &cfg)

	case "audit.anchor_provider.opentimestamps":
		var cfg auditv1.OpenTimestampsProviderConfig
		if config != nil {
			if err := config.UnmarshalTo(&cfg); err != nil {
				return nil, fmt.Errorf("audit.anchor_provider.opentimestamps %q: unmarshal config: %w", name, err)
			}
		}
		return modules.NewOpenTimestampsProviderModule(name, &cfg)

	case "audit.anchor_provider.git":
		var cfg auditv1.GitAnchorProviderConfig
		if config != nil {
			if err := config.UnmarshalTo(&cfg); err != nil {
				return nil, fmt.Errorf("audit.anchor_provider.git %q: unmarshal config: %w", name, err)
			}
		}
		return modules.NewGitAnchorProviderModule(name, &cfg)

	case "audit.anchor_provider.sigstore":
		var cfg auditv1.SigstoreProviderConfig
		if config != nil {
			if err := config.UnmarshalTo(&cfg); err != nil {
				return nil, fmt.Errorf("audit.anchor_provider.sigstore %q: unmarshal config: %w", name, err)
			}
		}
		return modules.NewSigstoreProviderModule(name, &cfg)

	case "audit.anchor_provider.ethereum",
		"audit.anchor_provider.aws_qldb":
		return nil, fmt.Errorf("audit-chain: module type %q not yet implemented (deferred for pilot)", typeName)

	default:
		return nil, fmt.Errorf("audit-chain: unknown module type %q", typeName)
	}
}

// ModuleTypes satisfies the legacy sdk.ModuleProvider interface. The gRPC
// server calls TypedModuleProvider first, so this is only reached if the engine
// does not support typed modules.
func (p *AuditChainPlugin) ModuleTypes() []string {
	return knownModuleTypes
}

// CreateModule satisfies the legacy sdk.ModuleProvider interface. Returns
// "not yet implemented" for known types (encouraging upgrade to typed path)
// and "unknown module type" for unrecognised types.
func (p *AuditChainPlugin) CreateModule(typeName, _ string, _ map[string]any) (sdk.ModuleInstance, error) {
	for _, known := range knownModuleTypes {
		if known == typeName {
			return nil, fmt.Errorf("audit-chain: module type %q not yet implemented via legacy path; engine must support TypedModuleProvider", typeName)
		}
	}
	return nil, fmt.Errorf("audit-chain: unknown module type %q", typeName)
}

// ── Step provider (typed) ─────────────────────────────────────────────────────

// stepFactories is the ordered list of TypedStepFactory instances, one per
// step type. CreateTypedStep iterates them, letting each factory accept or
// decline via ErrTypedContractNotHandled.
var stepFactories = []sdk.TypedStepProvider{
	sdk.NewTypedStepFactory(
		"step.audit.append",
		&emptypb.Empty{},
		&auditv1.AppendRequest{},
		steps.AppendHandler,
	),
	sdk.NewTypedStepFactory(
		"step.audit.verify",
		&emptypb.Empty{},
		&auditv1.VerifyRequest{},
		steps.VerifyHandler,
	),
	sdk.NewTypedStepFactory(
		"step.audit.merkle_root",
		&emptypb.Empty{},
		&auditv1.MerkleRootRequest{},
		steps.MerkleRootHandler,
	),
	sdk.NewTypedStepFactory(
		"step.audit.anchor",
		&emptypb.Empty{},
		&auditv1.AnchorRequest{},
		steps.AnchorHandler,
	),
	sdk.NewTypedStepFactory(
		"step.audit.poll_anchor_confirmation",
		&emptypb.Empty{},
		&auditv1.PollAnchorConfirmationRequest{},
		steps.PollAnchorConfirmationHandler,
	),
	sdk.NewTypedStepFactory(
		"step.audit.proof",
		&emptypb.Empty{},
		&auditv1.ProofRequest{},
		steps.ProofHandler,
	),
	sdk.NewTypedStepFactory(
		"step.audit.public_receipt",
		&emptypb.Empty{},
		&auditv1.PublicReceiptRequest{},
		steps.PublicReceiptHandler,
	),
}

// StepTypes returns the step type names this plugin provides.
// Satisfies the legacy sdk.StepProvider interface; TypedStepProvider is
// preferred by the gRPC server.
func (p *AuditChainPlugin) StepTypes() []string {
	return []string{
		"step.audit.append",
		"step.audit.verify",
		"step.audit.merkle_root",
		"step.audit.anchor",
		"step.audit.poll_anchor_confirmation",
		"step.audit.proof",
		"step.audit.public_receipt",
	}
}

// TypedStepTypes returns the step type names served via the typed gRPC path.
func (p *AuditChainPlugin) TypedStepTypes() []string {
	return p.StepTypes()
}

// CreateTypedStep creates a typed step instance. Each factory handles exactly
// one type; the first match wins. Unknown types return "unknown step type".
func (p *AuditChainPlugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	for _, f := range stepFactories {
		inst, err := f.CreateTypedStep(typeName, name, config)
		if err == nil {
			return inst, nil
		}
		if !errors.Is(err, sdk.ErrTypedContractNotHandled) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("audit-chain: unknown step type %q", typeName)
}

// CreateStep satisfies the legacy sdk.StepProvider interface. The gRPC server
// prefers TypedStepProvider, so this path is only reached by engines that do
// not support typed steps.
func (p *AuditChainPlugin) CreateStep(typeName, _ string, _ map[string]any) (sdk.StepInstance, error) {
	for _, s := range p.StepTypes() {
		if s == typeName {
			return nil, fmt.Errorf("audit-chain: step type %q not yet implemented via legacy path; engine must support TypedStepProvider", typeName)
		}
	}
	return nil, fmt.Errorf("audit-chain: unknown step type %q", typeName)
}

// TriggerTypes returns the trigger type names this plugin provides.
func (p *AuditChainPlugin) TriggerTypes() []string {
	return []string{
		"trigger.audit.entry_appended",
	}
}

// CreateTrigger creates a trigger instance of the given type.
func (p *AuditChainPlugin) CreateTrigger(typeName string, config map[string]any, cb sdk.TriggerCallback) (sdk.TriggerInstance, error) {
	switch typeName {
	case "trigger.audit.entry_appended":
		return nil, fmt.Errorf("audit-chain: trigger type %q not yet implemented", typeName)
	default:
		return nil, fmt.Errorf("audit-chain: unknown trigger type %q", typeName)
	}
}
