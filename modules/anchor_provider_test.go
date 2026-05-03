package modules_test

import (
	"context"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
)

// TestNewAnchorProviderModule_OTS verifies the OpenTimestamps module factory
// creates a valid module from a typed OpenTimestampsProviderConfig.
func TestNewAnchorProviderModule_OTS(t *testing.T) {
	cfg := &auditv1.OpenTimestampsProviderConfig{
		CalendarServers: []string{"https://alice.btc.calendar.opentimestamps.org"},
	}
	m, err := modules.NewOpenTimestampsProviderModule("my-ots", cfg)
	if err != nil {
		t.Fatalf("NewOpenTimestampsProviderModule: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil module")
	}
}

// TestNewAnchorProviderModule_OTS_RejectsEmptyCalendars verifies that
// OpenTimestamps module creation fails when no calendar servers are specified.
func TestNewAnchorProviderModule_OTS_RejectsEmptyCalendars(t *testing.T) {
	cfg := &auditv1.OpenTimestampsProviderConfig{
		CalendarServers: nil,
	}
	_, err := modules.NewOpenTimestampsProviderModule("my-ots", cfg)
	if err == nil {
		t.Fatal("expected error for empty calendar servers, got nil")
	}
}

// TestNewAnchorProviderModule_Git verifies the git module factory creates a
// valid module from a typed GitAnchorProviderConfig.
func TestNewAnchorProviderModule_Git(t *testing.T) {
	cfg := &auditv1.GitAnchorProviderConfig{
		Remote: "file:///tmp/test-repo",
	}
	m, err := modules.NewGitAnchorProviderModule("my-git", cfg)
	if err != nil {
		t.Fatalf("NewGitAnchorProviderModule: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil module")
	}
}

// TestNewAnchorProviderModule_Git_RejectsEmptyRemote verifies that the git
// module creation fails when no remote is configured.
func TestNewAnchorProviderModule_Git_RejectsEmptyRemote(t *testing.T) {
	cfg := &auditv1.GitAnchorProviderConfig{
		Remote: "",
	}
	_, err := modules.NewGitAnchorProviderModule("my-git", cfg)
	if err == nil {
		t.Fatal("expected error for empty remote, got nil")
	}
}

// TestNewAnchorProviderModule_Sigstore verifies the Sigstore module factory
// creates a valid module from a typed SigstoreProviderConfig.
func TestNewAnchorProviderModule_Sigstore(t *testing.T) {
	cfg := &auditv1.SigstoreProviderConfig{
		RekorUrl: "https://rekor.sigstore.dev",
	}
	m, err := modules.NewSigstoreProviderModule("my-sigstore", cfg)
	if err != nil {
		t.Fatalf("NewSigstoreProviderModule: %v", err)
	}
	if m == nil {
		t.Fatal("expected non-nil module")
	}
}

// TestAnchorProviderModule_InitRegistersProvider verifies that Init registers
// the anchor provider in the global registry.
func TestAnchorProviderModule_OTS_InitRegistersProvider(t *testing.T) {
	const name = "ots-test-instance"
	modules.UnregisterAnchorProvider(name)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(name) })

	cfg := &auditv1.OpenTimestampsProviderConfig{
		CalendarServers: []string{"https://alice.btc.calendar.opentimestamps.org"},
	}
	m, err := modules.NewOpenTimestampsProviderModule(name, cfg)
	if err != nil {
		t.Fatalf("NewOpenTimestampsProviderModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	p, ok := modules.GetAnchorProvider(name)
	if !ok {
		t.Fatal("GetAnchorProvider returned false after Init")
	}
	if p == nil {
		t.Fatal("GetAnchorProvider returned nil provider")
	}
	if p.Name() != "opentimestamps" {
		t.Errorf("provider.Name() = %q, want %q", p.Name(), "opentimestamps")
	}
}

// TestAnchorProviderModule_Git_InitRegistersProvider verifies the git provider
// is registered after Init. A file:// remote is used to avoid SSH agent checks
// at construction time (no actual push occurs).
func TestAnchorProviderModule_Git_InitRegistersProvider(t *testing.T) {
	const name = "git-test-instance"
	modules.UnregisterAnchorProvider(name)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(name) })

	cfg := &auditv1.GitAnchorProviderConfig{
		Remote: "file:///tmp/test-anchor-repo",
	}
	m, err := modules.NewGitAnchorProviderModule(name, cfg)
	if err != nil {
		t.Fatalf("NewGitAnchorProviderModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	p, ok := modules.GetAnchorProvider(name)
	if !ok {
		t.Fatal("GetAnchorProvider returned false after Init")
	}
	if p.Name() != "git" {
		t.Errorf("provider.Name() = %q, want %q", p.Name(), "git")
	}
}

// TestAnchorProviderModule_Sigstore_InitRegistersProvider verifies the Sigstore
// provider is registered after Init.
func TestAnchorProviderModule_Sigstore_InitRegistersProvider(t *testing.T) {
	const name = "sigstore-test-instance"
	modules.UnregisterAnchorProvider(name)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(name) })

	cfg := &auditv1.SigstoreProviderConfig{}
	m, err := modules.NewSigstoreProviderModule(name, cfg)
	if err != nil {
		t.Fatalf("NewSigstoreProviderModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	p, ok := modules.GetAnchorProvider(name)
	if !ok {
		t.Fatal("GetAnchorProvider returned false after Init")
	}
	if p.Name() != "sigstore" {
		t.Errorf("provider.Name() = %q, want %q", p.Name(), "sigstore")
	}
}

// TestAnchorProviderModule_StopUnregisters verifies that Stop removes the
// provider from the registry.
func TestAnchorProviderModule_StopUnregisters(t *testing.T) {
	const name = "stop-ots-instance"
	modules.UnregisterAnchorProvider(name)

	cfg := &auditv1.OpenTimestampsProviderConfig{
		CalendarServers: []string{"https://alice.btc.calendar.opentimestamps.org"},
	}
	m, err := modules.NewOpenTimestampsProviderModule(name, cfg)
	if err != nil {
		t.Fatalf("NewOpenTimestampsProviderModule: %v", err)
	}
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	_, ok := modules.GetAnchorProvider(name)
	if ok {
		t.Fatal("GetAnchorProvider returned true after Stop; should be unregistered")
	}
}
