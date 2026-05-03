package internal_test

import (
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestNewPlugin_ImplementsPluginProvider(t *testing.T) {
	var _ sdk.PluginProvider = internal.NewPlugin()
}

func TestManifest_HasRequiredFields(t *testing.T) {
	m := internal.NewPlugin().Manifest()
	if m.Name == "" {
		t.Error("manifest Name is empty")
	}
	if m.Name != "workflow-plugin-audit-chain" {
		t.Errorf("manifest Name = %q, want %q", m.Name, "workflow-plugin-audit-chain")
	}
	if m.Version == "" {
		t.Error("manifest Version is empty — build-time ldflags injection missing")
	}
	if m.Description == "" {
		t.Error("manifest Description is empty")
	}
}

func TestModuleTypes_Declared(t *testing.T) {
	p := internal.NewPlugin()
	mp, ok := p.(sdk.ModuleProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.ModuleProvider")
	}
	types := mp.ModuleTypes()
	want := []string{
		"audit.ledger",
		"audit.anchor_provider.opentimestamps",
		"audit.anchor_provider.git",
		"audit.anchor_provider.sigstore",
		"audit.anchor_provider.ethereum",
		"audit.anchor_provider.aws_qldb",
	}
	typeSet := make(map[string]bool, len(types))
	for _, t := range types {
		typeSet[t] = true
	}
	for _, w := range want {
		if !typeSet[w] {
			t.Errorf("ModuleTypes() missing %q", w)
		}
	}
}

func TestStepTypes_Declared(t *testing.T) {
	p := internal.NewPlugin()
	sp, ok := p.(sdk.StepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.StepProvider")
	}
	types := sp.StepTypes()
	want := []string{
		"step.audit.append",
		"step.audit.verify",
		"step.audit.merkle_root",
		"step.audit.anchor",
		"step.audit.poll_anchor_confirmation",
		"step.audit.proof",
		"step.audit.public_receipt",
	}
	typeSet := make(map[string]bool, len(types))
	for _, t := range types {
		typeSet[t] = true
	}
	for _, w := range want {
		if !typeSet[w] {
			t.Errorf("StepTypes() missing %q", w)
		}
	}
}

func TestTriggerTypes_Declared(t *testing.T) {
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TriggerProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TriggerProvider")
	}
	types := tp.TriggerTypes()
	found := false
	for _, tt := range types {
		if tt == "trigger.audit.entry_appended" {
			found = true
			break
		}
	}
	if !found {
		t.Error("TriggerTypes() missing trigger.audit.entry_appended")
	}
}

func TestCreateTrigger_UnknownType_ReturnsError(t *testing.T) {
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TriggerProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TriggerProvider")
	}
	_, err := tp.CreateTrigger("unknown.trigger", nil, nil)
	if err == nil {
		t.Error("CreateTrigger with unknown type should return error")
	}
	if !strings.Contains(err.Error(), "unknown trigger type") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateModule_UnknownType_ReturnsError(t *testing.T) {
	p := internal.NewPlugin()
	mp, ok := p.(sdk.ModuleProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.ModuleProvider")
	}
	_, err := mp.CreateModule("unknown.type", "test", nil)
	if err == nil {
		t.Error("CreateModule with unknown type should return error")
	}
	if !strings.Contains(err.Error(), "unknown module type") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateStep_UnknownType_ReturnsError(t *testing.T) {
	p := internal.NewPlugin()
	sp, ok := p.(sdk.StepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.StepProvider")
	}
	_, err := sp.CreateStep("unknown.type", "test", nil)
	if err == nil {
		t.Error("CreateStep with unknown type should return error")
	}
	if !strings.Contains(err.Error(), "unknown step type") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateModule_KnownType_ReturnsNotImplemented(t *testing.T) {
	p := internal.NewPlugin()
	mp, ok := p.(sdk.ModuleProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.ModuleProvider")
	}
	_, err := mp.CreateModule("audit.ledger", "test", nil)
	if err == nil {
		t.Error("CreateModule for audit.ledger should return not-implemented error")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestCreateStep_KnownType_ReturnsNotImplemented(t *testing.T) {
	p := internal.NewPlugin()
	sp, ok := p.(sdk.StepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.StepProvider")
	}
	_, err := sp.CreateStep("step.audit.append", "test", nil)
	if err == nil {
		t.Error("CreateStep for step.audit.append should return not-implemented error")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("unexpected error message: %v", err)
	}
}
