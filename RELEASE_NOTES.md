# gh_mirror_gui v0.1.0 Release Notes

## Highlights

- Fixed fresh download creation for `.part` files by opening with write access.
- Added an adaptive segmented downloader for large GitHub release assets.
- Added safe resume metadata for segmented downloads.
- Added a headless benchmark mode for reproducible speed verification.
- Added a one-command release verification front door at `tools\release-verify.ps1`.
- Restored safe TLS defaults with OS-native certificate trust: invalid certificates are rejected unless explicitly enabled for controlled debugging.

## Verification

Release verification command:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

The release assets include:

- `gh_mirror_gui.exe`
- `SHA256SUMS.txt`
- `receipt.json`

Verify the executable hash with:

```powershell
Get-FileHash .\gh_mirror_gui.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

## Notes

The unsafe TLS compatibility option is intentionally opt-in and should only be used with trusted debugging proxies or controlled environments.
