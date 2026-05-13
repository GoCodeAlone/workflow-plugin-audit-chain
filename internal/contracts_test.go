package internal_test

import (
	"slices"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// TestPluginImplementsContractProvider verifies the plugin satisfies the
// sdk.ContractProvider interface. Without this the engine cannot decode
// typed config from YAML into the right proto message before calling
// CreateTypedModule / CreateTypedStep (Bug 3).
func TestPluginImplementsContractProvider(t *testing.T) {
	p := internal.NewPlugin()
	if _, ok := p.(sdk.ContractProvider); !ok {
		t.Fatalf("plugin %T does not implement sdk.ContractProvider", p)
	}
}

// TestContractRegistry_NonNil sanity-checks that the registry has a
// descriptor set and at least one contract.
func TestContractRegistry_NonNil(t *testing.T) {
	reg := contractRegistry(t)
	if reg == nil {
		t.Fatal("ContractRegistry() returned nil")
	}
	if reg.FileDescriptorSet == nil {
		t.Fatal("ContractRegistry().FileDescriptorSet is nil")
	}
	if len(reg.FileDescriptorSet.File) == 0 {
		t.Fatal("ContractRegistry().FileDescriptorSet.File is empty")
	}
	if len(reg.Contracts) == 0 {
		t.Fatal("ContractRegistry().Contracts is empty")
	}
}

// TestContractRegistry_CoversEveryModuleType asserts that every typed module
// type advertised by the plugin has a MODULE-kind contract descriptor, except
// the deferred ethereum/aws_qldb providers which are intentionally absent
// (CreateTypedModule returns "not yet implemented" for them).
func TestContractRegistry_CoversEveryModuleType(t *testing.T) {
	reg := contractRegistry(t)
	moduleContracts := map[string]*pb.ContractDescriptor{}
	for _, c := range reg.Contracts {
		if c.Kind == pb.ContractKind_CONTRACT_KIND_MODULE {
			moduleContracts[c.ModuleType] = c
		}
	}

	implemented := []string{
		"audit.ledger",
		"audit.anchor_provider.opentimestamps",
		"audit.anchor_provider.git",
		"audit.anchor_provider.sigstore",
	}
	for _, mt := range implemented {
		c, ok := moduleContracts[mt]
		if !ok {
			t.Errorf("module type %q has no MODULE contract descriptor", mt)
			continue
		}
		if c.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Errorf("module %q: mode = %v, want STRICT_PROTO", mt, c.Mode)
		}
		if c.ConfigMessage == "" {
			t.Errorf("module %q: ConfigMessage is empty", mt)
		}
	}

	// Deferred providers must NOT have descriptors (no proto config yet).
	deferred := []string{
		"audit.anchor_provider.ethereum",
		"audit.anchor_provider.aws_qldb",
	}
	for _, mt := range deferred {
		if _, ok := moduleContracts[mt]; ok {
			t.Errorf("deferred module type %q must not have a contract descriptor", mt)
		}
	}
}

// TestContractRegistry_CoversEveryStepType asserts that every typed step type
// advertised by the plugin has a STEP-kind contract descriptor with non-empty
// Input/Output messages and STRICT_PROTO mode.
func TestContractRegistry_CoversEveryStepType(t *testing.T) {
	reg := contractRegistry(t)
	stepContracts := map[string]*pb.ContractDescriptor{}
	for _, c := range reg.Contracts {
		if c.Kind == pb.ContractKind_CONTRACT_KIND_STEP {
			stepContracts[c.StepType] = c
		}
	}

	wantStepTypes := []string{
		"step.audit.append",
		"step.audit.verify",
		"step.audit.merkle_root",
		"step.audit.anchor",
		"step.audit.poll_anchor_confirmation",
		"step.audit.proof",
		"step.audit.public_receipt",
	}
	for _, st := range wantStepTypes {
		c, ok := stepContracts[st]
		if !ok {
			t.Errorf("step type %q has no STEP contract descriptor", st)
			continue
		}
		if c.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Errorf("step %q: mode = %v, want STRICT_PROTO", st, c.Mode)
		}
		if c.InputMessage == "" {
			t.Errorf("step %q: InputMessage is empty", st)
		}
		if c.OutputMessage == "" {
			t.Errorf("step %q: OutputMessage is empty", st)
		}
		if c.ConfigMessage == "" {
			t.Errorf("step %q: ConfigMessage is empty (must reference google.protobuf.Empty for stateless steps)", st)
		}
	}

	// No surprise step entries.
	for got := range stepContracts {
		if !slices.Contains(wantStepTypes, got) {
			t.Errorf("ContractRegistry has STEP descriptor for unknown type %q", got)
		}
	}
}

// TestContractRegistry_TypedConfigSteps asserts that the two step types BMW
// drives via the YAML `config:` block (poll_anchor_confirmation and
// public_receipt) advertise a fully-qualified non-Empty ConfigMessage so the
// engine routes the typed config through STRICT_PROTO dispatch without
// rejecting BMW keys. v0.2.2 strict-proto-config-fields fix.
func TestContractRegistry_TypedConfigSteps(t *testing.T) {
	reg := contractRegistry(t)
	wantConfig := map[string]string{
		"step.audit.poll_anchor_confirmation": "workflow.plugin.audit.v1.PollAnchorConfirmationConfig",
		"step.audit.public_receipt":           "workflow.plugin.audit.v1.PublicReceiptConfig",
	}
	got := map[string]*pb.ContractDescriptor{}
	for _, c := range reg.Contracts {
		if c.Kind == pb.ContractKind_CONTRACT_KIND_STEP {
			got[c.StepType] = c
		}
	}
	for stepType, wantMsg := range wantConfig {
		c, ok := got[stepType]
		if !ok {
			t.Errorf("step %q: missing contract descriptor", stepType)
			continue
		}
		if c.ConfigMessage != wantMsg {
			t.Errorf("step %q: ConfigMessage = %q, want %q (must NOT be google.protobuf.Empty so BMW YAML config keys pass STRICT_PROTO)", stepType, c.ConfigMessage, wantMsg)
		}
	}
}

// TestContractRegistry_PluginContractsMatchTypedStepFactories asserts that the
// declared STEP contract types exactly match the set of typed step types the
// plugin actually serves (TypedStepTypes). Drift between contracts and
// factories is exactly the Bug 3 failure mode this registry guards against.
func TestContractRegistry_PluginContractsMatchTypedStepFactories(t *testing.T) {
	p, ok := internal.NewPlugin().(*internal.AuditChainPlugin)
	if !ok {
		t.Fatalf("NewPlugin() returned %T, want *internal.AuditChainPlugin", internal.NewPlugin())
	}
	reg := p.ContractRegistry()
	declared := map[string]struct{}{}
	for _, c := range reg.Contracts {
		if c.Kind == pb.ContractKind_CONTRACT_KIND_STEP {
			declared[c.StepType] = struct{}{}
		}
	}
	for _, st := range p.TypedStepTypes() {
		if _, ok := declared[st]; !ok {
			t.Errorf("typed step %q has no contract descriptor; engine cannot decode its input proto", st)
		}
	}
}

// contractRegistry is a test helper that returns the plugin's contract
// registry, failing the test if the plugin does not implement the interface.
func contractRegistry(t *testing.T) *pb.ContractRegistry {
	t.Helper()
	p := internal.NewPlugin()
	cp, ok := p.(sdk.ContractProvider)
	if !ok {
		t.Fatalf("plugin %T does not implement sdk.ContractProvider", p)
	}
	return cp.ContractRegistry()
}
