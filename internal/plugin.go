// Package internal implements the workflow-plugin-TEMPLATE plugin.
package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-TEMPLATE/internal.Version=X.Y.Z".
// Default is a bare semver so plugin loaders that validate semver accept
// unreleased dev builds; goreleaser overrides with the real release tag.
var Version = "0.0.0"

// TEMPLATEPlugin implements sdk.PluginProvider and optionally
// sdk.ModuleProvider, sdk.StepProvider, sdk.TriggerProvider, etc.
type TEMPLATEPlugin struct{}

// NewPlugin returns a new plugin instance. main.go calls sdk.Serve(NewPlugin()).
func NewPlugin() sdk.PluginProvider {
	return &TEMPLATEPlugin{}
}

// Manifest returns the plugin metadata used by the workflow engine for
// discovery and capability negotiation.
func (p *TEMPLATEPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-TEMPLATE",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "TEMPLATE plugin for the workflow engine",
	}
}

// ModuleTypes returns the module type names this plugin provides.
// Remove this method if the plugin does not provide any modules.
func (p *TEMPLATEPlugin) ModuleTypes() []string {
	return []string{
		// "example.module_type",
	}
}

// CreateModule creates a module instance of the given type.
// Remove this method if the plugin does not provide any modules.
func (p *TEMPLATEPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	// case "example.module_type":
	//     return newExampleModule(name, config)
	default:
		return nil, fmt.Errorf("TEMPLATE: unknown module type %q", typeName)
	}
}

// StepTypes returns the step type names this plugin provides.
// Remove this method if the plugin does not provide any steps.
func (p *TEMPLATEPlugin) StepTypes() []string {
	return []string{
		// "step.example_action",
	}
}

// CreateStep creates a step instance of the given type.
// Remove this method if the plugin does not provide any steps.
func (p *TEMPLATEPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	// case "step.example_action":
	//     return newExampleStep(name, config), nil
	default:
		return nil, fmt.Errorf("TEMPLATE: unknown step type %q", typeName)
	}
}
