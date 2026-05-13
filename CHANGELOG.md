# Changelog

All notable changes to `workflow-plugin-audit-chain` are documented in this
file. The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
