package internal_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-TEMPLATE/internal"
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
	if m.Version == "" {
		t.Error("manifest Version is empty — build-time ldflags injection missing")
	}
	if m.Description == "" {
		t.Error("manifest Description is empty")
	}
}
