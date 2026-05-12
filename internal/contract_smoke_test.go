package internal_test

// contract_smoke_test.go verifies the plugin factory returns a non-nil,
// non-typed-nil PluginProvider — the SDK v0.51.2 contract required by the
// strict-contracts CI gate.
//
// Trigger-type registration and error-path assertions for
// trigger.audit.entry_appended live in plugin_test.go
// (TestTriggerTypes_Declared + TestCreateTrigger_KnownType_ReturnsNotImplemented),
// which is the canonical coverage for those cases.

import (
	"reflect"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
)

// TestAuditChainPlugin_FactoryNonNil verifies that NewPlugin() returns a
// non-nil PluginProvider. A nil return causes sdk.Serve to panic at startup.
func TestAuditChainPlugin_FactoryNonNil(t *testing.T) {
	p := internal.NewPlugin()
	if p == nil {
		t.Fatal("NewPlugin() returned nil; factory must return a non-nil PluginProvider")
	}
	// Guard against typed-nil (interface non-nil but underlying pointer is nil),
	// which would panic at sdk.Serve call time.
	v := reflect.ValueOf(p)
	if v.Kind() == reflect.Ptr && v.IsNil() {
		t.Fatal("NewPlugin() returned a typed-nil interface value")
	}
	// Type-assert to concrete type to confirm factory wiring.
	if _, ok := p.(*internal.AuditChainPlugin); !ok {
		t.Fatalf("NewPlugin() returned unexpected type %T", p)
	}
}
