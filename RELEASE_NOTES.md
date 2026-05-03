# gh_mirror_gui v0.1.1 Release Notes

## Highlights

- Added GitHub release discovery in the GUI: paste `owner/repo`, a GitHub repository URL, `/releases`, `/releases/latest`, or `/releases/tag/<tag>` to resolve release assets.
- Added an asset picker so users can choose a release asset before handing it to the existing adaptive downloader.
- Preserved direct release asset URL downloads for the original low-friction path.
- Kept the downloader internals split into testable modules for download strategy, benchmark mode, and history-backed selection.
- Kept safe TLS defaults: invalid certificates remain rejected unless explicitly enabled for controlled debugging.

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

This release is the first user-facing vertical slice after v0.1.0: GitHub Release discovery and asset selection now sit in front of the existing Windows-first downloader.
