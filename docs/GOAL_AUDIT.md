# Goal completion audit checklist (living)

This document is a **living** checklist for auditing progress toward the north-star objective
defined by `AGENTS.md` + `docs/ROADMAP.md` + `docs/ARCHITECTURE.md`.

It does **not** replace executable verification. The single delivery judge remains:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

---

## Objective restatement (concrete criteria)

The system should:

1) **Restrict network egress** to **GitHub official artifact domains only** (https-only; redirect targets validated).
2) Expose **one stable Windows UI** that stays thin and **does not make final trust verdicts**.
3) Collapse the engineering surface into a **single `backend_contract` front door** with a small set of stable DTOs + use-cases.
4) Provide the full trusted acquisition pipeline:
   - release discovery / asset selection
   - adaptive + resumable download
   - SHA256 verification (VERIFIED / MISMATCH / UNKNOWN)
   - signed source authenticity with publisher key pinning (Ed25519 detached signatures today)
   - policy verdict + file disposition
   - evidence / audit history
   - no-mutation self-update candidate evaluation + Stage 2 staging (no install / no exe replacement)
5) Keep GitHub Release as **the first adapter**, while steadily evolving toward an **Artifact Trust Broker**
   through stable internal seams (source / verifier / evidence ledger).
6) Treat `tools\release-verify.ps1 + receipt.json` as the **only delivery judge**.

---

## Prompt-to-artifact checklist (what to inspect)

### A. Route guardrails / product route
- [ ] Route statement is consistent and not redefined as a mirror-list aggregator.
  - Evidence: `AGENTS.md`, `docs/ROADMAP.md`, `docs/ARCHITECTURE.md`, receipt `checks.route_guardrails`.
- [ ] `v0.1.2` immutability guardrail is still enforced.
  - Evidence: receipt `checks.route_guardrails` (must remain green).

### B. Network egress policy (GitHub official artifacts only)
- [ ] All outbound HTTP(S) is **https-only** and **host allowlisted**; redirects are re-validated.
  - Evidence: `src/url_policy.rs`, receipt `checks.download_engine_contract`, tests `url_policy::*`.
- [ ] Selftest-only exception allows **loopback http** only inside staged-release harness.
  - Evidence: `src/url_policy.rs` + `src/staged_release.rs`, tests `url_policy::validate_allows_local_http_in_tests`.

### C. Backend contract is the single front door
- [ ] UI calls core through `gh_mirror_gui::backend_contract` and consumes stable DTOs.
  - Evidence: `src/backend_contract.rs`, `src/gui_app.rs` (UI shell) + `src/main.rs` (entrypoint), receipt `checks.trust_center_backend_contract`.
- [ ] UI shell stays thin (no direct dependency on core pipeline modules; rendering-only modules depend on `backend_contract` DTOs).
  - Evidence: `src/gui_app.rs`, `src/gui_trust_center.rs`, `src/gui_update_candidate.rs`, receipt `checks.ui_shell_thinness`.
- [ ] Core seams exist for Phase 5 evolution (Artifact Trust Broker shape).
  - Evidence: `src/source_adapter.rs`, `src/verifier_adapter.rs`, `src/evidence_ledger.rs`,
    `docs/ARCHITECTURE.md`.

### D. Trusted acquisition pipeline
- [ ] Release discovery + asset selection works through the contract.
  - Evidence: `src/releases.rs`, `src/backend_contract.rs`, receipt `checks.origin_latest_release`,
    `checks.target_latest_release`, `checks.github_url_intent_router_contract`.
- [ ] Adaptive/resumable download + range probe is exercised.
  - Evidence: `src/download.rs`, receipt `checks.network_range_smoke`, `checks.download_benchmark`.
- [ ] Verification engine produces correct hash status and trust decision.
  - Evidence: `src/verification.rs`, receipt `checks.trust_policy_contract`, tests `verification::*`.
- [ ] Signed source trust is enforced (publisher key pin + detached signatures).
  - Evidence: `src/source_trust.rs`, receipt `checks.signed_release_staging`,
    `checks.origin_release_verification`, tests `source_trust::*`.
- [ ] Policy + file disposition is applied by core (not UI).
  - Evidence: `src/trust_policy.rs`, receipt `checks.trust_policy_contract`,
    Trust Center snapshot fields in `src/trust_center.rs`.
- [ ] Evidence/history is written and reviewable.
  - Evidence: `src/history.rs`, `src/evidence_ledger.rs`, receipt `checks.download_benchmark`,
    `checks.trust_policy_contract`, `checks.update_candidate_latest_selftest`.

### E. Self-update candidate contract (no mutation / no install)
- [ ] Candidate rules are enforced: newer-only, exe-only, VERIFIED + TRUSTED_SIGNATURE + pinned publisher fingerprint, policy trusted.
  - Evidence: `src/update_candidate.rs`, receipt `checks.update_candidate_contract`,
    tests `update_candidate::*`.
- [ ] Stage 2 is exercised end-to-end against public releases (staging only; no install).
  - Evidence: receipt `checks.post_publish_self_update_stage2` (must be ok=true).

---

## Completion protocol

The goal should be considered **not achieved** unless:

- All checklist items above have concrete evidence **and**
- A fresh `tools\release-verify.ps1` run produces `PASS` with a receipt that covers the
  relevant checks for the claimed progress.
