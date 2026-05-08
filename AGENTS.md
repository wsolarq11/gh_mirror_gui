# gh_mirror_gui repo guardrails

本文件作用于整个仓库。后续 agent / 人类改动本仓库时，必须优先保持这里定义的路线与边界。

## Product route

一句话路线：

> 当前现实目标是 **Windows-first Trusted GitHub Release Downloader**；中期产品目标是 **Windows-first Artifact Trust Broker**；长期北极星是 **Windows Local Software Trust Root**。

一句话统一判定式：`Source + Intent + Policy -> Evidence + Verdict + ActionPlan`。
Phase 只作为里程碑标签；机制统一归入上述 artifact-decision contract 与 `ArtifactDecision` backend surface。

用户侧始终收敛成一个 Windows UI；工程侧保持 `core/backend/API/evidence/policy` 分层；交付裁判继续只走 `tools\release-verify.ps1 + receipt.json`。
自动化/长程推进先读取 `docs\GOAL-ANCHOR.json` 作为机器可读锚点；该锚点只枚举路线文档、门禁、执行 gate 与产物边界，不替代设计文档或 release receipt。

路线分层：

1. **Now**: trusted GitHub Release discovery / asset picker / adaptive resumable download / checksum-provenance-source-trust verification / evidence / policy.
2. **Completed in `v0.1.3`**: signed source is real in a public release, with publisher key pinning and `.sig` assets.
3. **Completed in `v0.1.6`**: public signed release consumption gate + no-mutation self-update candidate contract (Stage 1 check + Stage 2 staging, no install/replace), all proven by `tools\\release-verify.ps1` receipts.
4. **Next**: auto-update MVP (still trust-first, staged, reversible) and a cleaner core/backend contract convergence.
5. **Later**: source/verifier/policy adapters make GitHub Release only the first adapter in an Artifact Trust Broker.
6. **North star**: Windows Local Software Trust Root: acquisition, verification, policy, update, rollback, revocation, and audit.

## Hard boundaries

- Do **not** redefine this project as a mirror-list aggregator.
- Do **not** prioritize piling up fixed mirrors or shallow UI polish over trust/evidence/policy/backend-contract work.
- Do **not** let the UI make final trust verdicts. UI may request actions and display verdicts; backend/core decides.
- Do **not** let README or conversation notes replace executable verification. `tools\release-verify.ps1` receipt is the delivery judge.
- Do **not** mutate, retag, or republish `v0.1.2` unless the user explicitly starts a release-repair task. Existing `v0.1.2` must deref to `7482e7bdfa12c5ccb31e6365e8251e68006366c6`.
- Do **not** keep long-term dual tracks. Experiments must converge back into the single main chain or be removed.
- `docs\GOAL-ANCHOR.json` is the single machine-readable goal anchor. Design/end-state route docs are anchored only in `AGENTS.md`, `README.md`, `docs\ROADMAP.md`, and `docs\ARCHITECTURE.md`; run/audit evidence belongs in `target\delivery\<run_id>\` receipts or `.run\<namespace>\{logs,data,cache,tmp}`.

## MCP 优化约定

- Machine anchor: `MCP-first optimization = get_architecture / search_graph / trace_path / detect_changes`; stale or missing index must be refreshed before long-running optimization.
- 对本仓库做持续优化、结构梳理、变更影响分析、跨层重构、回归排查时，默认先用 MCP 的 `get_architecture` / `search_graph` / `trace_path` / `detect_changes`。
- 如果 MCP 索引过期或缺失，先 refresh/index，再继续；不要只靠记忆或纯文本 grep 作为长期优化主路径。

## Required design shape

Every non-trivial feature should map to at least one of these stable surfaces:

- source adapter
- download engine
- verification engine
- source trust
- policy engine
- update candidate contract
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

Route guardrails are first-class artifacts. Keep `docs\GOAL-ANCHOR.json`, `AGENTS.md`, `README.md`, `docs\ROADMAP.md`, and `docs\ARCHITECTURE.md` in sync with major direction changes, and keep the doc inventory covered by the release verification receipt.
