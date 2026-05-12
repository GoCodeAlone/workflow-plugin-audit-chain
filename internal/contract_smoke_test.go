package internal_test

// contract_smoke_test.go verifies the plugin factory and the
// trigger.audit.entry_appended factory specifically, because this trigger type
// was the failure surface in BMW PR #277 (trigger not registered under the
// strict-contracts SDK path).

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// TestAuditChainPlugin_FactoryNonNil verifies that NewPlugin() returns a
// non-nil PluginProvider. A nil return causes sdk.Serve to panic at startup.
func TestAuditChainPlugin_FactoryNonNil(t *testing.T) {
	p := internal.NewPlugin()
	if p == nil {
		t.Fatal("NewPlugin() returned nil; factory must return a non-nil PluginProvider")
	}
}

// TestAuditChainPlugin_TriggerEntryAppended_Registered verifies that
// trigger.audit.entry_appended is registered in TriggerTypes(). This was the
// BMW PR #277 failure surface: the trigger was declared in plugin.json but not
// returned by TriggerTypes(), causing the engine to reject the plugin at load.
func TestAuditChainPlugin_TriggerEntryAppended_Registered(t *testing.T) {
	p := internal.NewPlugin()
	if p == nil {
		t.Fatal("NewPlugin() returned nil")
	}

	tp, ok := p.(sdk.TriggerProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TriggerProvider")
	}

	const target = "trigger.audit.entry_appended"
	for _, tt := range tp.TriggerTypes() {
		if tt == target {
			return // found
		}
	}
	t.Errorf("TriggerTypes() does not include %q; got: %v", target, tp.TriggerTypes())
}

// TestAuditChainPlugin_TriggerEntryAppended_CreateReturnsError verifies that
// calling CreateTrigger for trigger.audit.entry_appended returns a non-nil
// error (not-yet-implemented), rather than returning (nil, nil) which would
// silently accept an unregistered trigger and stall the engine at runtime.
func TestAuditChainPlugin_TriggerEntryAppended_CreateReturnsError(t *testing.T) {
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TriggerProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TriggerProvider")
	}

	_, err := tp.CreateTrigger("trigger.audit.entry_appended", nil, nil)
	if err == nil {
		t.Fatal("CreateTrigger(trigger.audit.entry_appended) returned nil error; expected 'not yet implemented'")
	}
}
