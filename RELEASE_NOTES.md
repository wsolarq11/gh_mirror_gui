# gh_mirror_gui v0.1.5 Release Notes

## Highlights

- Ships **Self-update Stage 2 (staging)**: stage a verified update candidate into a local folder and record reviewable stage evidence (still no install, no exe replacement, no persistence).
- Adds a Stage 2 runtime selftest wired into the single delivery judge: `tools\release-verify.ps1 + receipt.json` now proves Stage 2 behavior end-to-end.
- Improves private-repo compatibility for release asset fetches by preferring the GitHub API asset URL (with token) when available.
- Preserves `v0.1.2` unchanged and keeps all trust-critical decisions in backend/core contracts; the UI only displays verdicts.

## Verification

Release verification command used before tagging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

No-publish signing preflight:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-signing-bootstrap.ps1 -Action Preflight -TargetTag v0.1.5
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

This release continues the trust-first self-update route: Stage 2 only stages a verified candidate and writes evidence. Installation/replacement remains out of scope until the same contract can prove rollback and no silent mutation.
