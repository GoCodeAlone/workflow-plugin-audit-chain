# workflow-plugin-audit-chain

A [GoCodeAlone/workflow](https://github.com/GoCodeAlone/workflow) external plugin providing **tamper-evident hash-chained audit logging** with periodic Merkle root anchoring to external trust providers (OpenTimestamps/Bitcoin, git, Sigstore, Ethereum, AWS QLDB).

Each audit log entry is hash-chained to the previous one. Any post-hoc tampering breaks the chain and is detectable via `step.audit.verify`. Daily Merkle roots are anchored externally so integrity guarantees survive even a compromised database.

**Design spec:** `docs/plans/2026-05-02-prereq-workflow-plugin-audit-chain-design.md` in the BMW E2E fulfillment plan repo.

## Step types

| Step | Purpose |
|---|---|
| `step.audit.append` | Append a hash-chained entry to a ledger (serialised via FOR UPDATE). |
| `step.audit.verify` | Verify chain integrity over a sequence range — O(n). |
| `step.audit.merkle_root` | Build a Merkle tree over a range and return the root. |
| `step.audit.anchor` | Anchor a Merkle root to one or more configured providers. |
| `step.audit.poll_anchor_confirmation` | Poll a pending anchor for confirmation state advancement. |
| `step.audit.proof` | Return a Merkle inclusion proof + anchor records for a sequence. |
| `step.audit.public_receipt` | Generate a verifiable public receipt JSON with optional field redaction. |

## Module types

| Module | Purpose |
|---|---|
| `audit.ledger` | Declares a ledger partition (name, anchor providers, schedule). |
| `audit.anchor_provider.opentimestamps` | Anchors to Bitcoin via OpenTimestamps calendar servers (default; free). |
| `audit.anchor_provider.git` | Commits Merkle root to a git remote (fast redundancy). |
| `audit.anchor_provider.sigstore` | Anchors to Sigstore Rekor transparent log. |
| `audit.anchor_provider.ethereum` | Anchors to Ethereum L1 or L2. |
| `audit.anchor_provider.aws_qldb` | Anchors to AWS Quantum Ledger Database. |

## Trigger types

| Trigger | Purpose |
|---|---|
| `trigger.audit.entry_appended` | Fires a pipeline on each new entry appended to a ledger. |

## Quick start

```yaml
modules:
  - name: my-audit-ledger
    type: audit.ledger
    config:
      name: my-ledger
      description: "Financial event audit log"
      anchor_providers: [opentimestamps, git]
      anchor_schedule: "0 1 * * *"
      anchor_min_entries: 1

  - name: my-ots
    type: audit.anchor_provider.opentimestamps
    config:
      calendar_servers:
        - "https://alice.btc.calendar.opentimestamps.org"
        - "https://bob.btc.calendar.opentimestamps.org"
```

```yaml
steps:
  - name: record_event
    type: step.audit.append
    config:
      ledger: my-ledger
      event_type: payment.captured
      payload: '{"amount_cents":2000,"item_id":"abc123"}'
      actor: stripe-webhook
```

## Build & test

```sh
GOWORK=off go build ./...
GOWORK=off go test ./... -v -race -count=1
make proto-gen   # regenerate gen/audit.pb.go from proto/audit.proto
```

## License

MIT — see [LICENSE](LICENSE).
