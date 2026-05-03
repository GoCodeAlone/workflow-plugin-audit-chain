package internal_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	auditv1 "github.com/GoCodeAlone/workflow-plugin-audit-chain/gen"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/modules"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/types/known/anypb"
)

// ── Binary build ──────────────────────────────────────────────────────────────

// TestIntegration_BinaryBuilds verifies that the cmd/workflow-plugin-audit-chain
// entrypoint compiles and links cleanly. The main.go is trivial (sdk.Serve),
// so this primarily catches import-cycle regressions, missing ldflags, or a
// broken transitive dependency after refactors.
//
// Skipped in short mode (go test -short) since it shells out to the Go toolchain.
func TestIntegration_BinaryBuilds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary build test in short mode")
	}

	// Derive the project root from the location of this source file so the
	// test is robust regardless of the working directory.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Skip("runtime.Caller unavailable; cannot locate project root")
	}
	// thisFile = .../internal/integration_test.go → parent dir = internal/ →
	// parent-of-parent = project root.
	projectRoot := filepath.Dir(filepath.Dir(thisFile))

	out := filepath.Join(t.TempDir(), "workflow-plugin-audit-chain")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/workflow-plugin-audit-chain/")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "GOWORK=off")

	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("binary build failed:\n%s\nerror: %v", output, err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("binary not found after build: %v", err)
	}
}

// ── Typed step dispatch ───────────────────────────────────────────────────────

// TestIntegration_AllStepsAreTyped verifies that every step type declared by
// the plugin produces a TypedStepInstance, not a legacy StepInstance. The
// signal is that calling the legacy Execute() method returns
// "typed step requires typed_input payload" — the SDK's sentinel for steps
// that must be dispatched through the typed gRPC path.
//
// If any step factory accidentally returns a legacy step (e.g. due to a wiring
// bug), Execute() would not return that error and this test would fail.
func TestIntegration_AllStepsAreTyped(t *testing.T) {
	p := internal.NewPlugin()
	tp, ok := p.(sdk.TypedStepProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TypedStepProvider")
	}

	for _, typeName := range tp.TypedStepTypes() {
		typeName := typeName
		t.Run(typeName, func(t *testing.T) {
			inst, err := tp.CreateTypedStep(typeName, "integ-"+typeName, nil)
			if err != nil {
				t.Fatalf("CreateTypedStep: %v", err)
			}

			// A TypedStepInstance returns this exact error on the legacy path.
			_, err = inst.Execute(context.Background(), nil, nil, nil, nil, nil)
			if err == nil {
				t.Fatal("Execute returned nil error — expected typed-step dispatch error")
			}
			if !strings.Contains(err.Error(), "typed") {
				t.Fatalf("Execute error does not mention 'typed': %v", err)
			}
		})
	}
}

// ── Module lifecycle ──────────────────────────────────────────────────────────

// TestIntegration_LedgerModuleLifecycle verifies the full Init → Start → Stop
// lifecycle of the audit.ledger module created through the plugin's typed module
// factory. Key invariants under test:
//
//   - Init opens the connection pool (lazy — no network call for pgx) and
//     registers the appender + DB in the global registries.
//   - Start is a no-op (returns nil).
//   - Stop unregisters both entries and closes the pool.
//   - A second Init call returns an error instead of leaking a pool.
func TestIntegration_LedgerModuleLifecycle(t *testing.T) {
	const partitionName = "integ-ledger-lifecycle"

	// Ensure the registry is clean before and after.
	modules.UnregisterLedger(partitionName)
	modules.UnregisterDB(partitionName)
	t.Cleanup(func() {
		modules.UnregisterLedger(partitionName)
		modules.UnregisterDB(partitionName)
	})

	p := internal.NewPlugin()
	tp, ok := p.(sdk.TypedModuleProvider)
	if !ok {
		t.Fatal("plugin does not implement sdk.TypedModuleProvider")
	}

	cfg := &auditv1.LedgerConfig{
		Name: partitionName,
		// A valid DSN string — pgx's sql.Open is lazy, so no connection is
		// attempted at Init time and this test runs without a real Postgres.
		Dsn: "postgres://u:p@localhost:5432/db?sslmode=disable",
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack LedgerConfig: %v", err)
	}

	m, err := tp.CreateTypedModule("audit.ledger", "integ-ledger", packed)
	if err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}

	// Before Init: ledger must not be registered.
	if _, found := modules.GetLedger(partitionName); found {
		t.Error("ledger registered before Init")
	}
	if _, found := modules.GetDB(partitionName); found {
		t.Error("DB registered before Init")
	}

	// Init: opens connection pool + registers appender and DB.
	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop(context.Background()) })

	if _, found := modules.GetLedger(partitionName); !found {
		t.Error("ledger not registered after Init")
	}
	if _, found := modules.GetDB(partitionName); !found {
		t.Error("DB not registered after Init")
	}

	// Second Init must fail (double-init guard).
	if err := m.Init(); err == nil {
		t.Error("second Init should return error, got nil")
	}

	// Start is a no-op.
	if err := m.Start(context.Background()); err != nil {
		t.Errorf("Start: %v", err)
	}

	// Stop: unregisters and closes.
	if err := m.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	if _, found := modules.GetLedger(partitionName); found {
		t.Error("ledger still registered after Stop")
	}
	if _, found := modules.GetDB(partitionName); found {
		t.Error("DB still registered after Stop")
	}
}

// TestIntegration_AnchorProviderModule_OpenTimestamps verifies that the
// audit.anchor_provider.opentimestamps module can be created and its lifecycle
// run (Init/Start/Stop) without error. The provider makes no network calls on
// Init so no live service is required.
func TestIntegration_AnchorProviderModule_OpenTimestamps(t *testing.T) {
	const providerName = "integ-ots-provider"
	modules.UnregisterAnchorProvider(providerName)
	t.Cleanup(func() { modules.UnregisterAnchorProvider(providerName) })

	p := internal.NewPlugin()
	tp := p.(sdk.TypedModuleProvider)

	cfg := &auditv1.OpenTimestampsProviderConfig{
		CalendarServers: []string{"https://alice.btc.calendar.opentimestamps.org"},
	}
	packed, err := anypb.New(cfg)
	if err != nil {
		t.Fatalf("pack config: %v", err)
	}

	m, err := tp.CreateTypedModule("audit.anchor_provider.opentimestamps", providerName, packed)
	if err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}

	if err := m.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := m.Start(context.Background()); err != nil {
		t.Errorf("Start: %v", err)
	}
	if err := m.Stop(context.Background()); err != nil {
		t.Errorf("Stop: %v", err)
	}

	// After Stop, the provider should be unregistered.
	if _, found := modules.GetAnchorProvider(providerName); found {
		t.Error("anchor provider still registered after Stop")
	}
}
