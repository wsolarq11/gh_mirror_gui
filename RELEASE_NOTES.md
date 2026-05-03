# gh_mirror_gui v0.1.3 Release Notes

## Highlights

- Adds a no-publish release signing bootstrap/preflight front door for the next trusted release.
- Requires `RELEASE_ED25519_PRIVATE_KEY_HEX` before the tag workflow can publish, so unsigned releases fail closed.
- Keeps signed-source proof in the single delivery judge: `tools\release-verify.ps1 + receipt.json`.
- Preserves `v0.1.2` unchanged while preparing the first public release with `.sig` assets and `publisher-key.ed25519.pub`.
- Keeps Trust Center / policy / evidence decisions in backend contracts; the UI only displays verdicts.

## Verification

Release verification command used before tagging:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

No-publish signing preflight:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-signing-bootstrap.ps1 -Action Preflight -TargetTag v0.1.3
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

This release promotes source authenticity from staged proof to the public release contract: users can pin/import `publisher-key.ed25519.pub`, require signed checksum/provenance sources, and review evidence for the final backend policy verdict.
