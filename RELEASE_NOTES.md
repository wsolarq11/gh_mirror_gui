# gh_mirror_gui v0.1.6 Release Notes

## Highlights

- Minimal validation release to exercise **Self-update Stage 2 (staging)** against a newer public signed release.
- Extends `--update-candidate-stage-selftest` with:
  - `--current-version` override (simulate an older running version)
  - `--trusted-publisher-key-file` (simulate a pinned publisher key)
- Preserves `v0.1.2` unchanged and keeps all trust-critical decisions in backend/core contracts; the UI only displays verdicts.

## Verification

Release verification command used before tagging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

No-publish signing preflight:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-signing-bootstrap.ps1 -Action Preflight -TargetTag v0.1.6
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

This release keeps the trust-first self-update route: Stage 2 only stages a verified candidate and writes evidence. Installation/replacement remains out of scope until the same contract can prove rollback and no silent mutation.
