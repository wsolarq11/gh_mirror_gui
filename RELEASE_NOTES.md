# gh_mirror_gui v0.1.4 Release Notes

## Highlights

- Adds a public signed release consumption gate to the single delivery judge: `tools\release-verify.ps1 + receipt.json`.
- Adds **Self-update Stage 1**: a no-mutation latest-release check that only reports `candidate`, `no-update`, or `refused` and records evidence (no install, no exe replacement, no persistence).
- Strengthens the no-mutation UpdateCandidate contract: newer-only, `gh_mirror_gui.exe` only, hash `VERIFIED`, signed source `TRUSTED_SIGNATURE`, pinned publisher key required.
- Preserves `v0.1.2` unchanged and keeps all trust-critical decisions in backend/core contracts; the UI only displays verdicts.

## Verification

Release verification command used before tagging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

No-publish signing preflight:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-signing-bootstrap.ps1 -Action Preflight -TargetTag v0.1.4
```

The release assets include:

- `gh_mirror_gui.exe`
- `SHA256SUMS.txt`
- `SHA256SUMS.txt.sig`
- `release-provenance.json`
- `release-provenance.json.sig`
- `publisher-key.ed25519.pub`

Verify the executable hash with:

```powershell
Get-FileHash .\gh_mirror_gui.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

## Notes

This release extends the signed-source contract with a **public consumption gate** and a **no-mutation update-candidate check**, so self-update behavior can only be built on top of a proven signed public release contract (and remains install-free in this stage).
