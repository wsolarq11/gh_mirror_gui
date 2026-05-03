# gh_mirror_gui Roadmap

## Route statement

Current reality:

> **Windows-first Trusted GitHub Release Downloader**

Medium-term product:

> **Windows-first Artifact Trust Broker**

Long-term north star:

> **Windows Local Software Trust Root**

The user should still see one Windows UI. Internally, the system should evolve into a testable trust backend that UI, CLI, auto-update, and future enterprise policy all call through stable contracts.

## Non-goals

- Not a mirror-list aggregator.
- Not a generic download manager.
- Not a UI-only trust dashboard.
- Not a second release pipeline beside `tools\release-verify.ps1`.

Download speed matters, but the durable moat is trusted acquisition: source discovery, artifact download, source authenticity, hash/provenance verification, policy verdict, evidence, update, rollback, and audit.

## Phase 0: Baseline already achieved

- GitHub Release URL/repo discovery.
- Asset picker.
- Direct GitHub release asset download.
- Adaptive/resumable downloader.
- Checksum/provenance hash verification.
- Evidence/history JSON.
- User trust policy for `UNKNOWN` and `MISMATCH`.
- Signed verification source MVP on `main`.
- `tools\release-verify.ps1` as the single delivery front door.

## Phase 1: Signed source true end-to-end release

Goal: make source authenticity real in a public release, not only implemented on `main`.

Deliverables:

- Configure `RELEASE_ED25519_PRIVATE_KEY_HEX` for release automation.
- Next version release uploads `SHA256SUMS.txt.sig` and `release-provenance.json.sig`.
- README explains how users pin/import the matching publisher public key.
- Release verification receipt proves signed-source behavior without changing `v0.1.2`.

Stop condition: a fresh release can be downloaded by the app, hash verified, source-signature verified, and recorded in evidence.

## Phase 2: Trust Center UI

Goal: make trust state obvious without moving trust decisions into UI.

Deliverables:

- A single Trust Center panel showing:
  - hash status: `VERIFIED` / `MISMATCH` / `UNKNOWN`
  - source authenticity: `TRUSTED_SIGNATURE` / `UNSIGNED` / `MISSING_SIGNATURE` / `BAD_SIGNATURE` / `NO_TRUSTED_KEY`
  - publisher key fingerprint
  - policy verdict
  - evidence path
  - final file disposition
- UI only displays backend/core verdicts.
- Existing tests and release-verify gate cover the decision points.

## Phase 3: Auto-update MVP

Goal: use the same trusted acquisition path to update this application.

Deliverables:

- UI checks `wsolarq11/gh_mirror_gui` releases.
- Update candidate must satisfy hash + provenance + source authenticity + pinned publisher policy.
- Installer/update step is staged and reversible.
- Evidence records the update decision.

Stop condition: update is refused when signature/publisher/policy fails.

## Phase 4: Core crate and backend contract

Goal: make UI a shell over a stable core/backend contract.

Deliverables:

- Extract trust-critical logic into a core crate or clean module boundary.
- Define request/response DTOs for:
  - resolve release
  - choose asset
  - download
  - verify source/artifact
  - apply policy
  - record evidence
- UI stops making final trust decisions.
- CLI/headless tests exercise the same contract.

## Phase 5: Artifact Trust Broker

Goal: make GitHub Release the first source adapter, not the hardcoded product boundary.

Deliverables:

- Source adapter interface.
- Verifier adapter interface.
- Policy contract for user and enterprise modes.
- Evidence ledger stable schema.
- Future adapters can include GitLab Release, raw URL, internal registry, or S3-like storage without rewriting trust logic.

## Phase 6: Windows Local Software Trust Root

Goal: graduate from trusted download to software lifecycle trust.

Possible scope:

- install/update/rollback orchestration
- revocation/blocklist
- publisher identity lifecycle
- enterprise policy import/lock
- audit export
- optional runtime allow/deny integration

This is the north star, not the next implementation target. Do not expand scope here until the GitHub Release trust path and Artifact Trust Broker contracts are stable.

## Prioritization rule

When choosing the next small loop, prefer work that strengthens the main chain:

```text
release discovery
  -> asset picker
  -> verification-aware adaptive/resumable downloader
  -> evidence/history
  -> provenance/checksum
  -> trust policy
  -> signed trust root
  -> auto-update / enterprise policy
```

Avoid work that creates a second long-term path, hides trust decisions in UI, or cannot be proven by tests plus `tools\release-verify.ps1`.

