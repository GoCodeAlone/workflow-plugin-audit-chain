package internal_test

import (
	"strings"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
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
	for _, typ := range types {
		typeSet[typ] = true
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
	for _, typ := range types {
		typeSet[typ] = true
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

func TestCreateTrigger_KnownType_ReturnsNotImplemented(t *testing.T) {
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TriggerProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TriggerProvider")
	}
	_, err := tp.CreateTrigger("trigger.audit.entry_appended", nil, nil)
	if err == nil {
		t.Error("CreateTrigger for trigger.audit.entry_appended should return not-implemented error")
	}
	if !strings.Contains(err.Error(), "not yet implemented") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// ── TypedStepProvider tests (primary gRPC path) ──────────────────────────────

func typedStepProvider(t *testing.T) sdk.TypedStepProvider {
	t.Helper()
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TypedStepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TypedStepProvider")
	}
	return tp
}

// TestTypedStepTypes_Declared verifies all 7 step types are returned.
func TestTypedStepTypes_Declared(t *testing.T) {
	tp := typedStepProvider(t)
	types := tp.TypedStepTypes()
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
	for _, typ := range types {
		typeSet[typ] = true
	}
	for _, w := range want {
		if !typeSet[w] {
			t.Errorf("TypedStepTypes() missing %q", w)
		}
	}
}

// TestCreateTypedStep_UnknownType_ReturnsError verifies that an unknown type
// returns an "unknown step type" error.
func TestCreateTypedStep_UnknownType_ReturnsError(t *testing.T) {
	tp := typedStepProvider(t)
	_, err := tp.CreateTypedStep("unknown.step.type", "x", nil)
	if err == nil {
		t.Fatal("expected error for unknown type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown step type") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestCreateTypedStep_KnownType_ReturnsInstance verifies that known step types
// produce a non-nil StepInstance (nil config is valid — no step-level config).
func TestCreateTypedStep_KnownType_ReturnsInstance(t *testing.T) {
	tp := typedStepProvider(t)
	for _, typeName := range []string{
		"step.audit.append",
		"step.audit.verify",
		"step.audit.merkle_root",
		"step.audit.anchor",
		"step.audit.poll_anchor_confirmation",
		"step.audit.proof",
		"step.audit.public_receipt",
	} {
		inst, err := tp.CreateTypedStep(typeName, "test-"+typeName, nil)
		if err != nil {
			t.Errorf("%s: unexpected error: %v", typeName, err)
			continue
		}
		if inst == nil {
			t.Errorf("%s: expected non-nil StepInstance, got nil", typeName)
		}
	}
}

// ── CreateTypedModule tests (primary gRPC path) ───────────────────────────────

func typedModuleProvider(t *testing.T) sdk.TypedModuleProvider {
	t.Helper()
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TypedModuleProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TypedModuleProvider")
	}
	return tp
}

// TestCreateTypedModule_LedgerConfig_ValidConfig verifies that a properly
// packed LedgerConfig returns a non-nil module.
func TestCreateTypedModule_LedgerConfig_ValidConfig(t *testing.T) {
	tp := typedModuleProvider(t)

	cfg := &auditv1.LedgerConfig{
		Name: "bmw-financial",
		Dsn:  "postgres://u:p@localhost/db?sslmode=disable",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}

	m, err := tp.CreateTypedModule("audit.ledger", "my-ledger", packed)
	if err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil module")
	}
}

// TestCreateTypedModule_LedgerConfig_NilConfig surfaces validation errors
// (empty name + empty dsn) rather than panicking on a nil config.
func TestCreateTypedModule_LedgerConfig_NilConfig(t *testing.T) {
	tp := typedModuleProvider(t)

	_, err := tp.CreateTypedModule("audit.ledger", "my-ledger", nil)
	if err == nil {
		t.Fatal("expected error for nil config, got nil")
	}
}

// TestCreateTypedModule_MismatchedAnypbType verifies that passing a config
// packed as the wrong proto type returns an unmarshal error, not a panic.
func TestCreateTypedModule_MismatchedAnypbType(t *testing.T) {
	tp := typedModuleProvider(t)

	// Pack an OpenTimestampsProviderConfig but claim it is for audit.ledger.
	wrongType := &auditv1.OpenTimestampsProviderConfig{
		CalendarServers: []string{"https://alice.btc.calendar.opentimestamps.org"},
	}
	packed, err := anypb.New(wrongType)
	if err != nil {
		t.Fatalf("anypb.New: %v", err)
	}

	_, err = tp.CreateTypedModule("audit.ledger", "my-ledger", packed)
	if err == nil {
		t.Fatal("expected unmarshal error for mismatched anypb type, got nil")
	}
}

// TestCreateTypedModule_DeferredProvider verifies ethereum and aws_qldb return
// a "not yet implemented" error rather than panicking or silently succeeding.
func TestCreateTypedModule_DeferredProvider(t *testing.T) {
	tp := typedModuleProvider(t)

	for _, typeName := range []string{
		"audit.anchor_provider.ethereum",
		"audit.anchor_provider.aws_qldb",
	} {
		_, err := tp.CreateTypedModule(typeName, "deferred", nil)
		if err == nil {
			t.Errorf("%s: expected error, got nil", typeName)
			continue
		}
		if !strings.Contains(err.Error(), "not yet implemented") {
			t.Errorf("%s: unexpected error message: %v", typeName, err)
		}
	}
}

// TestCreateTypedModule_UnknownType verifies that a completely unknown module
// type returns an "unknown module type" error.
func TestCreateTypedModule_UnknownType(t *testing.T) {
	tp := typedModuleProvider(t)

	_, err := tp.CreateTypedModule("unknown.module.type", "x", nil)
	if err == nil {
		t.Fatal("expected error for unknown type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown module type") {
		t.Errorf("unexpected error message: %v", err)
	}
}
