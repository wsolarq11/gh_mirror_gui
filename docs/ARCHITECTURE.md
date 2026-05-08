# gh_mirror_gui Architecture

## Architecture statement

The product should look like one Windows UI to the user, but internally it should behave like a trusted local acquisition backend with a thin UI shell.

One-line contract:

```text
Source + Intent + Policy -> Evidence + Verdict + ActionPlan
```

All current and future phases should collapse to this artifact-decision
pipeline: resolve a source, interpret the intent, apply policy, record
evidence, emit a verdict, and expose only a safe action plan.
Phases are milestone labels; mechanism belongs to the one-line artifact
decision contract and the `ArtifactDecision` backend surface.

```text
UI Shell
  -> Core / backend contract
     -> Source adapter
     -> Download engine
     -> Verification engine
     -> Source trust engine
     -> Policy engine
     -> Evidence ledger
     -> Release verification front door
```

## Current module map

- `src/releases.rs`: GitHub Release discovery and asset selection helpers.
- `src/artifact_decision.rs`: first-class decision DTOs and formula:
  `Source + Intent + Policy -> Evidence + Verdict + ActionPlan`.
- `src/source_adapter.rs`: artifact source adapter seam; today it wraps GitHub Release resolution.
- `src/download.rs`: direct, resumable, and segmented download primitives.
- `src/bench.rs`: headless benchmark and adaptive strategy evaluation.
- `src/verification.rs`: checksum/provenance parsing, source selection, hash verification, and source-trust attachment.
- `src/verifier_adapter.rs`: verification adapter seam; today it wraps GitHub Release checksum/provenance verification.
- `src/core_runtime.rs`: internal composition point that wires adapters behind a stable `backend_contract` front door.
- `src/source_trust.rs`: Ed25519 detached signature verification/signing, publisher key pinning, and `source_trust` evidence.
- `src/trust_policy.rs`: trust policy, file disposition, quarantine/delete/open-location decisions.
- `src/trust_center.rs`: UI-framework-free Trust Center snapshot contract built from backend/core verification reports, policy snapshots, and evidence paths.
- `src/update_candidate.rs`: no-mutation self-update candidate contract; it accepts only newer trusted signed releases and refuses same-version, unsigned, bad-signature, or missing-key candidates.
- `src/update_apply_plan.rs`: pure staged apply/install/rollback plan DTO; it describes a reversible no-mutation plan for a staged candidate and is previewable by the UI through `backend_contract`.
- `src/evidence_ledger.rs`: evidence ledger seam; today it writes JSON/JSONL evidence to the filesystem.
- `src/history.rs`: benchmark history and verification evidence JSON.
- `src/gui_app.rs`: egui application state and UI orchestration. This layer should stay thin over `backend_contract` and only render backend/core DTO verdicts (Trust Center snapshot, update candidate status, evidence paths, etc.).
- `src/main.rs`: thin Windows entrypoint that wires CLI dispatch + GUI startup and delegates UI behavior to the UI modules.
- `tools\release-verify.ps1`: single delivery front door and receipt producer.
- `tools\release-signing-bootstrap.ps1`: no-publish helper for signing-secret status/bootstrap and next-tag preflight; it delegates delivery proof back to `tools\release-verify.ps1`.

## Boundary rules

### UI Shell

The UI may:

- collect input
- call core/backend operations
- display verdicts
- import/normalize publisher key pins
- open evidence or folders selected by policy
- render the Trust Center from backend/core verification reports, source-trust
  evidence, policy snapshots, and file-disposition results

The UI must not:

- invent final trust verdicts
- silently override policy decisions
- write evidence schemas independently of core/backend records
- decide quarantine/delete outside the policy engine

### Core / backend contract

The core/backend is responsible for:

- release resolution
- asset metadata normalization
- download strategy
- hash/provenance verification
- source authenticity verification
- policy verdict
- file disposition
- evidence/history writes

The future backend may be a Rust crate first, then a local process/daemon later. Do not daemonize before the core contract is clean.

### Network egress policy (GitHub official artifact domains only)

Default policy:

- All outbound HTTP(S) requests must be **https://** and must target **GitHub official artifact hosts only**.
- Redirect targets must be validated under the same policy (no open redirects to arbitrary hosts).

Implementation:

- Canonical allowlist lives in `src/url_policy.rs` (used across download, release resolve, verification, source trust, and update-candidate paths).

Selftest-only exception:

- `tools\release-verify.ps1` runs `--staged-release-download-selftest`, which spins up a **loopback** static HTTP server for deterministic staging checks.
- Loopback URLs are allowed **only inside this selftest harness** (guarded by `url_policy::enable_loopback_for_selftests()` and limited to loopback hosts).

### Verification engine

Hash match and source authenticity are separate facts:

- hash status: `VERIFIED`, `MISMATCH`, `UNKNOWN`
- source authenticity: `TRUSTED_SIGNATURE`, `UNSIGNED`, `MISSING_SIGNATURE`, `BAD_SIGNATURE`, `NO_TRUSTED_KEY`, `NOT_APPLICABLE`
- effective trust decision: `TRUSTED`, `BLOCK`, or `RISK`

A hash-verified file can still be blocked if the verification source is not authentic under policy.

### Source trust engine

Current MVP:

- Ed25519 detached signature over the exact source bytes.
- Signature assets:
  - `SHA256SUMS.txt.sig`
  - `release-provenance.json.sig`
- Publisher key pin is an Ed25519 public key.
- Release public key export is `publisher-key.ed25519.pub`; users pin/import
  that public key, never the private signing seed.
- Release signing readiness is checked by a local doctor that reads
  `RELEASE_ED25519_PRIVATE_KEY_HEX`, derives the publisher public key, signs a
  fixture source asset, verifies the detached signature, and records the public
  key fingerprint.
- Evidence stores key SHA256 fingerprint, not raw public/private key material.

Future adapters may support minisign, cosign, GitHub attestation, SLSA provenance, or enterprise CA chains through the same `source_trust` concept.

### Policy engine

Policy decides:

- whether `UNKNOWN` downloads are kept or deleted
- whether `UNKNOWN` may expose open-folder UI
- whether `MISMATCH` is quarantined or deleted
- whether signed source is required
- whether a publisher key is pinned and valid

Enterprise policy should become a stricter layer above user policy later.

### Evidence ledger

Evidence must remain reviewable and machine-readable:

- history JSONL stores summary fields for strategy and trust decisions
- evidence JSON stores the exact trust facts and file disposition
- `Open Evidence` must use the exact evidence path recorded for the completed download
- schema changes must be covered by tests and release-verify receipt gates

## Release verification front door

`tools\release-verify.ps1` is the delivery judge. It must keep recording:

- git provenance
- clean-workspace gate (`checks.git_workspace_clean`) so a `PASS` receipt cannot
  be claimed while repo files are modified, staged, or untracked
- toolchain provenance
- key source files and guardrail document hashes
- fmt/test/clippy/build command results
- trust-policy/source-trust gate coverage
- release signing readiness, including public key export and next-release
  `.sig` asset contract
- release signing bootstrap contract: repo secret presence, protected `v0.1.2`
  immutability, planned next-tag readiness, no release/tag mutation by default,
  and no private seed material in receipts or logs
- release workflow artifact contract checks that fail fast if the tag workflow
  stops refusing unsigned releases, stops staging signed assets, or stops
  uploading the required binary, checksum, provenance, publisher key, and
  `.sig` assets
- target volume governance via `tools\target-gc.ps1`, which keeps only the
  most recent delivery runs by default and can optionally prune incremental
  caches; the receipt must capture its before/after report so retention changes
  stay auditable
- signed release staging dry-run, including `release-provenance.json` schema
  checks, detached signature verification for both signed source assets, and a
  headless app download selftest that re-downloads the staged binary, verifies
  checksum/provenance signatures against the exported publisher key, and
  records evidence
- origin release verification for the existing release, including public
  `SHA256SUMS.txt.sig`, `release-provenance.json.sig`, and
  `publisher-key.ed25519.pub` signature verification against the downloaded
  public release assets
- update candidate contract selftest that proves the next self-update layer is
  no-mutation and refuses untrusted candidates before any install/replace step
- update apply plan contract selftest that produces a pure reversible
  `UpdateApplyPlan` DTO for a staged candidate, describing backup/replace/
  rollback steps without mutating the filesystem yet
- production Rust panic-pattern guard (`checks.production_rust_panic_guard`)
  that rejects direct `unwrap` / `expect` / `panic` style failure paths before
  `#[cfg(test)] mod tests` sections, with CLI fail-closed tests covering the
  signature public-key source contract
- UI apply-plan preview that renders the backend contract DTO through
  `backend_contract` without creating a second execution path
- UI shell thinness gate (`checks.ui_shell_thinness`) that fails fast if GUI
  modules start depending directly on core pipeline layers instead of routing
  through `backend_contract`
- Self-update Stage 1 latest-release check and Trust Center display: backend
  reports only `candidate`, `no-update`, or `refused`, records evidence, and
  never installs, replaces the executable, writes system persistence, mutates
  tags, publishes releases, or touches secrets
- Self-update Stage 2 candidate staging: backend stages a verified candidate to
  a local folder and records stage evidence. It still does not install,
  replace the executable, write system persistence, mutate tags, publish
  releases, or touch secrets.
- CI front-door contract (`checks.ci_frontdoor_contract`) that keeps GitHub
  Actions on the same fmt/test/clippy/build sequence and ends with
  `tools\release-verify.ps1`, rather than a parallel delivery judge
- network smoke
- benchmark
- degradation summary (`checks.release_verify_degraded`) when an external
  network/benchmark probe falls back to a deterministic local proof path
- GUI launch smoke

Passing CI is useful but not a replacement for the local receipt when a task requires full delivery evidence.

## Future local agent

The likely end-state is:

```text
gh_mirror_gui.exe
  starts UI
  embeds or launches local trusted backend
  communicates through JSON-RPC / named pipe / localhost API
```

User experience remains one UI. Engineering gains stable contracts shared by GUI, CLI, self-updater, enterprise policy tooling, and future source adapters.
