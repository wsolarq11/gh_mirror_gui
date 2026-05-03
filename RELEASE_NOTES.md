# gh_mirror_gui v0.1.2 Release Notes

## Highlights

- Made release verification results actionable in the GUI: `VERIFIED` is trusted, `MISMATCH` is blocking, and `UNKNOWN` is a yellow risk state.
- Added clear retry / open-evidence decision points for mismatched downloads instead of treating checksum failures as ordinary completed downloads.
- Persisted reviewable verification evidence JSON with the local download history for `VERIFIED`, `MISMATCH`, and `UNKNOWN` release download reports.
- Kept GitHub release discovery, asset picking, adaptive/resumable downloads, and safe TLS defaults on the same Windows-first main path.
- Locked the trust-state contract into the reproducible release verifier receipt through `checks.trust_policy_contract`.

## Verification

Release verification command used before tagging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

The release assets include:

- `gh_mirror_gui.exe`
- `SHA256SUMS.txt`
- `release-provenance.json`

Verify the executable hash with:

```powershell
Get-FileHash .\gh_mirror_gui.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

## Notes

This release turns verification from a passive label into a user-actionable trust policy while preserving the v0.1.1 release discovery and asset selection flow.
