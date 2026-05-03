// Package internal implements the workflow-plugin-audit-chain plugin.
package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-audit-chain/internal.Version=X.Y.Z".
// Default is a bare semver so plugin loaders that validate semver accept
// unreleased dev builds; goreleaser overrides with the real release tag.
var Version = "0.0.0"

// AuditChainPlugin implements sdk.PluginProvider and the step/module/trigger
// provider interfaces for the audit-chain plugin.
type AuditChainPlugin struct{}

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

// ModuleTypes returns the module type names this plugin provides.
func (p *AuditChainPlugin) ModuleTypes() []string {
	return []string{
		"audit.ledger",
		"audit.anchor_provider.opentimestamps",
		"audit.anchor_provider.git",
		"audit.anchor_provider.sigstore",
		"audit.anchor_provider.ethereum",
		"audit.anchor_provider.aws_qldb",
	}
}

// CreateModule creates a module instance of the given type.
func (p *AuditChainPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "audit.ledger",
		"audit.anchor_provider.opentimestamps",
		"audit.anchor_provider.git",
		"audit.anchor_provider.sigstore",
		"audit.anchor_provider.ethereum",
		"audit.anchor_provider.aws_qldb":
		return nil, fmt.Errorf("audit-chain: module type %q not yet implemented", typeName)
	default:
		return nil, fmt.Errorf("audit-chain: unknown module type %q", typeName)
	}
}

// StepTypes returns the step type names this plugin provides.
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

// CreateStep creates a step instance of the given type.
func (p *AuditChainPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.audit.append",
		"step.audit.verify",
		"step.audit.merkle_root",
		"step.audit.anchor",
		"step.audit.poll_anchor_confirmation",
		"step.audit.proof",
		"step.audit.public_receipt":
		return nil, fmt.Errorf("audit-chain: step type %q not yet implemented", typeName)
	default:
		return nil, fmt.Errorf("audit-chain: unknown step type %q", typeName)
	}
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
