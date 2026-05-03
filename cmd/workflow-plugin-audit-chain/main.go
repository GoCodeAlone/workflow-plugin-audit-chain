// Command workflow-plugin-audit-chain is a workflow engine external plugin
// providing tamper-evident hash-chained audit logging with periodic Merkle root
// anchoring to external providers (OpenTimestamps/Bitcoin, git, Sigstore, etc.).
// It runs as a subprocess and communicates with the host workflow engine via
// the go-plugin gRPC protocol.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-audit-chain/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewPlugin())
}
