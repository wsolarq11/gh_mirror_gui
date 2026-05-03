# gh_mirror_gui repo guardrails

本文件作用于整个仓库。后续 agent / 人类改动本仓库时，必须优先保持这里定义的路线与边界。

## Product route

一句话路线：

> 当前现实目标是 **Windows-first Trusted GitHub Release Downloader**；中期产品目标是 **Windows-first Artifact Trust Broker**；长期北极星是 **Windows Local Software Trust Root**。

用户侧始终收敛成一个 Windows UI；工程侧保持 `core/backend/API/evidence/policy` 分层；交付裁判继续只走 `tools\release-verify.ps1 + receipt.json`。

路线分层：

1. **Now**: trusted GitHub Release discovery / asset picker / adaptive resumable download / checksum-provenance-source-trust verification / evidence / policy.
2. **Next**: signed source becomes real end-to-end in the next release, with publisher key pinning and `.sig` assets.
3. **Then**: Trust Center UI, auto-update MVP, and a cleaner core/backend contract.
4. **Later**: source/verifier/policy adapters make GitHub Release only the first adapter in an Artifact Trust Broker.
5. **North star**: Windows Local Software Trust Root: acquisition, verification, policy, update, rollback, revocation, and audit.

## Hard boundaries

- Do **not** redefine this project as a mirror-list aggregator.
- Do **not** prioritize piling up fixed mirrors or shallow UI polish over trust/evidence/policy/backend-contract work.
- Do **not** let the UI make final trust verdicts. UI may request actions and display verdicts; backend/core decides.
- Do **not** let README or conversation notes replace executable verification. `tools\release-verify.ps1` receipt is the delivery judge.
- Do **not** mutate, retag, or republish `v0.1.2` unless the user explicitly starts a release-repair task. Existing `v0.1.2` must deref to `7482e7bdfa12c5ccb31e6365e8251e68006366c6`.
- Do **not** keep long-term dual tracks. Experiments must converge back into the single main chain or be removed.

## Required design shape

Every non-trivial feature should map to at least one of these stable surfaces:

- source adapter
- download engine
- verification engine
- source trust
- policy engine
- evidence/history
- UI shell
- release verification gate

Trust-critical logic belongs in testable Rust modules first. UI code should stay thin, low-friction, and verdict-display oriented.

## Verification contract

Before claiming delivery, run the relevant subset; for release/readiness changes run the full front door:

```powershell
cargo fmt --check
cargo test --all-targets --locked
cargo clippy --all-targets --locked -- -D warnings
cargo build --release --locked
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

Route guardrails are first-class artifacts. Keep `AGENTS.md`, `docs\ROADMAP.md`, and `docs\ARCHITECTURE.md` in sync with major direction changes, and keep them covered by the release verification receipt.

