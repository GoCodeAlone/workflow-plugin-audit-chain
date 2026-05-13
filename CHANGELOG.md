# Changelog

All notable changes to `workflow-plugin-audit-chain` are documented in this
file. The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.3] - 2026-05-13

### Fixed

- **strict-proto type drift** in two `step.audit.*` Config messages, surfaced
  by BMW local smoke against `workflow-server v0.51.5` after v0.2.2 introduced
  the typed Config messages. BMW pipelines populate these fields via Go
  templates (`"{{ .item.proof_data }}"`, `"{{ .item.audit_sequence }}"`) that
  render as raw strings; strict-proto's `bytes` and `int64` field kinds reject
  those values:
  - `PollAnchorConfirmationConfig.proof_data`: `bytes` → `string`. proto3 JSON
    encoding requires `bytes` to be base64-encoded; BMW does not base64-encode.
    Handler merge converts string → []byte by raw byte copy; providers treat
    `ProofData` as an opaque pass-through so no decoding is applied.
  - `PublicReceiptConfig.sequence`: `int64` → `string`. The strict-proto
    decoder rejects string → int64 coercion at the typed-config boundary even
    with engine-side scalar-coerce. Handler merge parses the string with
    `strconv.ParseInt` and returns a typed error on a non-numeric value.
- `testdata/compat-strict-proto-config.yaml` updated to mirror the BMW
  templated-string shape (`sequence: "1"`, `proof_data: "raw-proof-bytes"`)
  so the compat-gate continues to lock the v0.2.3 contract.

### Notes

- `PollAnchorConfirmationRequest.proof_data` and `PublicReceiptRequest.sequence`
  (the gRPC Input messages) are unchanged. Only the Config messages are
  affected; direct-gRPC dispatch (integration_test.go, third-party callers)
  continues to use `bytes` and `int64` as before.

## [0.2.2] - 2026-05-13

### Fixed

- **strict-proto config fields** for `step.audit.poll_anchor_confirmation` and
  `step.audit.public_receipt`. Both step types previously declared their
  ConfigMessage as `google.protobuf.Empty`, which caused workflow engine
  v0.51.x to reject every key in the YAML `config:` block under STRICT_PROTO
  (`DiscardUnknown: false`). Surfaced by BMW local smoke against workflow
  v0.51.5.
  - Added `PollAnchorConfirmationConfig { anchor_id, provider, external_id, proof_data, ledger }`.
  - Added `PublicReceiptConfig { ledger, sequence, redact_fields }`.
  - Updated `internal/contracts.go` and `plugin.contracts.json` to point each
    step's `config` at the new typed message.
  - Updated handlers to merge typed `req.Config` over typed `req.Input` (Config
    wins on field collisions, matching the BMW pattern where `config:` is
    authoritative; Input remains the fallback for direct gRPC dispatch).
  - Bumped SDK pin to `workflow v0.51.5` and `minEngineVersion` to `0.51.5`.

### Added

- `.github/workflows/workflow-compat.yml` — compat gate that builds the plugin
  and runs `wfctl validate --plugin-dir ./build testdata/compat-strict-proto-config.yaml`
  against the latest wfctl release. Locks in the v0.2.2 typed-config contract
  so a future refactor cannot silently revert ConfigMessage back to Empty.
- Tests covering the Config-path precedence (`Config` wins over `Input` on
  field collisions) for both handlers.

## [0.2.1] - 2026-04-26

- Implemented `sdk.ContractProvider` so the engine receives a `ContractRegistry`
  and can decode typed config from YAML into the right proto message before
  dispatching `CreateTypedModule` / `CreateTypedStep` (Bug 3 fix).

## [0.2.0] - 2026-04-26

- Cutover to strict typed contracts; SDK pinned to `workflow v0.51.2`.

## [0.1.0] - 2026-04-22

- Initial release. Audit ledger module, three anchor-provider modules
  (OpenTimestamps, git, Sigstore Rekor), seven typed step types, one trigger,
  end-to-end integration test.
