# gh_mirror_gui

A small Windows desktop GUI for downloading GitHub release assets with progress, pause/resume/cancel, proxy support, and an adaptive segmented downloader.

## Features

- GitHub release discovery: paste `owner/repo`, a GitHub repo URL, `/releases`,
  `/releases/latest`, or `/releases/tag/<tag>` and choose an asset in the GUI.
- Verification-aware release downloads: when a selected release also ships
  `SHA256SUMS.txt`, checksum, or `release-provenance.json` assets, the GUI
  computes the downloaded file SHA256 and reports `VERIFIED`, `MISMATCH`, or
  `UNKNOWN`.
- Signed verification source trust: when checksum/provenance assets also ship
  detached Ed25519 hex signatures such as `SHA256SUMS.txt.sig` or
  `release-provenance.json.sig`, the GUI can verify the verification source
  against a pinned publisher public key and record hash verification separately
  from source authenticity.
- Public signed release consumption: the release verification front door proves
  the latest `wsolarq11/gh_mirror_gui` release signatures and publisher key
  before self-update installation behavior is allowed.
- Direct GitHub release asset downloads still work.
- Adaptive strategy selection: single stream or concurrent HTTP `Range` segments based on live sampling and local history.
- Safe resume via `.part` files and metadata validation for URL, total size, `ETag`, and `Last-Modified`.
- Progress, speed, elapsed time, cancellation, and pause/resume controls.
- Optional proxy URL support.
- Safe TLS defaults: TLS uses the OS-native trust store and rejects invalid certificates unless the explicit unsafe compatibility switch is enabled.

## Route and architecture

The project route is intentionally trust-first:

```text
Windows-first Trusted GitHub Release Downloader
  -> Windows-first Artifact Trust Broker
  -> Windows Local Software Trust Root
```

User-side experience should stay one Windows UI. Internally, trust-critical
logic should stay in testable core/backend surfaces and be proven by
`tools\release-verify.ps1 + receipt.json`.

See:

- `AGENTS.md` for repo guardrails.
- `docs\ROADMAP.md` for the phased route.
- `docs\ARCHITECTURE.md` for layer boundaries.

## Download and verify

Download `gh_mirror_gui.exe` and `SHA256SUMS.txt` from the latest GitHub Release, then verify:

```powershell
Get-FileHash .\gh_mirror_gui.exe -Algorithm SHA256
Get-Content .\SHA256SUMS.txt
```

The hash from `Get-FileHash` should match the `gh_mirror_gui.exe` line in `SHA256SUMS.txt`.

## Run

```powershell
.\gh_mirror_gui.exe
```

Paste a GitHub repository or release URL, then click **Find release assets** (or
use **Paste** to resolve automatically when the clipboard contains a supported
GitHub release URL). Choose an asset from the picker, click **Use selected
asset**, choose a save directory, optionally set a proxy, then click
**Download**.

If the same release contains checksum/provenance assets, the picker shows the
detected verification sources and the final status includes the downloaded file
SHA256 verification result.

If those checksum/provenance sources also have detached signature assets, the
same picker marks them as signed. Signatures use the source file bytes as the
message, an Ed25519 public key pin entered/imported in the GUI, and a detached
signature file containing 128 hex characters.

Verification status is operational:

- `VERIFIED` is trusted and shows the matched checksum/provenance source.
- `MISMATCH` is blocking: retry the download or open the evidence before
  trusting the file.
- `UNKNOWN` is a yellow risk state: the file was saved, but no matching
  checksum/provenance could verify it.
- Source authenticity is separate from hash matching. A file can have
  `VERIFIED` hash bytes but still be blocked if the matched verification source
  has a bad signature, or if **Require signed checksum/provenance source** is
  enabled and the source is unsigned or no publisher key is pinned.

Each verified release download writes a reviewable JSON evidence record next to
the local download history, and the GUI exposes **Open Evidence** after the
download finishes.

The **Trust policy** panel makes post-verification handling explicit and
persists it with the rest of the GUI settings:

- `VERIFIED` is kept and trusted.
- `MISMATCH` is blocking and is either quarantined under
  `.gh_mirror_gui-quarantine\` next to the selected save path or deleted,
  depending on the selected policy.
- `UNKNOWN` is risky; the user chooses whether to keep the file and whether the
  GUI may expose **Open Folder** for that saved file.
- Signed source policy is optional by default for compatibility. Pin/import an
  Ed25519 publisher public key and enable **Require signed checksum/provenance
  source** to quarantine/delete hash-verified downloads whose checksum or
  provenance source is unsigned, missing a trusted key, or has a bad signature.
- The history/evidence path can be left blank for the default app data location
  or set to a specific `bench-history.jsonl`; **Open Evidence** uses the exact
  JSON evidence path recorded for the completed download.

History JSONL and evidence JSON include both:

- `verification_status` / `status`: hash result (`VERIFIED`, `MISMATCH`,
  `UNKNOWN`).
- `verification_source_trust` / `source_trust`: source authenticity
  (`TRUSTED_SIGNATURE`, `UNSIGNED`, `MISSING_SIGNATURE`, `BAD_SIGNATURE`,
  `NO_TRUSTED_KEY`, or `NOT_APPLICABLE`) plus the signature asset and pinned key
  fingerprint when available.

Supported discovery inputs:

```text
owner/repo
https://github.com/owner/repo
https://github.com/owner/repo/releases
https://github.com/owner/repo/releases/latest
https://github.com/owner/repo/releases/tag/v1.2.3
```

## Proxy and TLS

Proxy examples:

```text
http://127.0.0.1:7890
socks5://127.0.0.1:7890
```

By default the app validates TLS certificates through the OS-native trust store. The checkbox **Allow invalid TLS certificates (unsafe)** is only for trusted debugging proxies or controlled environments.

## Headless benchmark mode

The release binary can also run an automated real-download benchmark:

```powershell
.\gh_mirror_gui.exe --bench-download `
  --url https://github.com/owner/repo/releases/download/tag/file.zip `
  --out .\file.zip `
  --json .\bench.json `
  --history .\bench-history.jsonl `
  --mode adaptive
```

Compatibility flag for controlled debugging only:

```powershell
.\gh_mirror_gui.exe --bench-download --allow-invalid-certs --url <URL> --out <PATH>
```

## Reproduce release verification

From the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
```

Full matrix benchmark:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1
```

Evidence is written under `target\delivery\<run_id>\`.
The receipt records build provenance including the git commit, Rust toolchain,
`Cargo.lock` hash, release binary hash, verification command logs, and
`checks.trust_policy_contract` for the `VERIFIED` / `MISMATCH` / `UNKNOWN`
decision rules and signed verification source trust gates. It also records
`checks.signed_release_staging`, a no-publish dry run that stages
`gh_mirror_gui.exe`, `SHA256SUMS.txt`, `release-provenance.json`, detached
`.sig` assets, and `publisher-key.ed25519.pub`, verifies the two signed source
assets against that exported public key, and then re-downloads the staged
binary through the app itself to prove hash + source-signature + evidence end
to end.

For public releases, the receipt also records
`checks.origin_release_verification.source_signature_verification`: it downloads
the latest public signed-source assets (`SHA256SUMS.txt`,
`SHA256SUMS.txt.sig`, `release-provenance.json`, `release-provenance.json.sig`,
and `publisher-key.ed25519.pub`), verifies both detached source signatures
against the public key, and checks the publisher fingerprint matches
`release-provenance.json`. When GitHub provides an asset digest for
`gh_mirror_gui.exe`, the receipt also cross-checks that digest against the
expected `SHA256SUMS.txt` value.

The real-world *binary download + hash verification* for public releases is
covered by `checks.post_publish_self_update_stage2`: it stages the latest
verified `gh_mirror_gui.exe` into a local folder (no install / no exe
replacement) and proves the staged SHA256 matches the expected signed checksum.

`checks.update_candidate_contract` is a no-mutation self-update gate. It proves
that candidate evaluation can accept only a newer trusted signed
`gh_mirror_gui.exe` release and can refuse same-version, bad-signature,
missing-key, or unsigned-required candidates without installing or replacing
anything.

The GUI now exposes that contract as **Self-update Stage 1**: it checks the
public latest `wsolarq11/gh_mirror_gui` release and displays only the backend
verdict (`candidate`, `no-update`, or `refused`), `refusal_reason`, publisher
fingerprint, and evidence path. This stage does not install, replace the exe,
write system persistence, create tags, or publish releases.

**Self-update Stage 2** stages a verified candidate to a local folder and
records stage evidence. It still performs no install, exe replacement, or
system persistence; the UI only displays backend/core verdicts.

## Release automation

`v0.1.3` is the first public signed release with `.sig` assets and
`publisher-key.ed25519.pub`. Future trusted releases are created by pushing a
version tag. The tag must match the package version in `Cargo.toml`. Do not run
the tag commands until the no-publish bootstrap/preflight helper below reports
no blockers:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1 -SkipBenchmarkMatrix
git tag -a <next-tag> -m "Release <next-tag>"
git push origin main
git push origin <next-tag>
```

The `Release` GitHub Actions workflow rebuilds the Windows release binary with
the pinned Rust toolchain, reruns `fmt` / `test` / `clippy`, generates
`SHA256SUMS.txt` and `release-provenance.json`, signs both verification source
assets, and creates the GitHub Release.

`RELEASE_ED25519_PRIVATE_KEY_HEX` is required for the next trusted release. It
must be configured as a GitHub repository secret before pushing the next tag.
The value is a 32-byte Ed25519 seed encoded as 64 hex characters. The release
workflow refuses to create an unsigned release when that secret is missing or
invalid.

The safe bootstrap/preflight helper is no-publish by default: it never creates a
tag or Release, records only secret presence metadata plus public key
fingerprints, and delegates signed staging proof to `tools\release-verify.ps1`.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-signing-bootstrap.ps1 `
  -Action Preflight `
  -TargetTag <next-tag>
```

If the signing root has been generated and stored by the owner, set the current
process environment variable and explicitly opt in to the GitHub secret
mutation. Do not pass the seed on the command line, and remove the process
environment variable after the helper exits:

```powershell
$env:RELEASE_ED25519_PRIVATE_KEY_HEX = "<64-hex Ed25519 seed>"
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-signing-bootstrap.ps1 `
  -Action Bootstrap `
  -SetGitHubSecret
Remove-Item Env:RELEASE_ED25519_PRIVATE_KEY_HEX
```

Bootstrap receipts are written under
`target\release-signing-bootstrap\<run_id>\receipt.json`. The receipt records
`private_key_material = "not_recorded"`.

The workflow exports the matching public key as `publisher-key.ed25519.pub` and
uploads detached source signatures as `SHA256SUMS.txt.sig` and
`release-provenance.json.sig`. Users can download `publisher-key.ed25519.pub`,
compare its SHA256 fingerprint against the release provenance or an owner
channel, then paste/import the 64-hex public key into the GUI and enable
**Require signed checksum/provenance source**. When a resolved release contains
`publisher-key.ed25519.pub`, the release asset panel can also fetch that asset
and pin the normalized Ed25519 public key directly; backend verification and
policy still decide the final trust verdict after download. The GUI stores only
the public key pin/fingerprint, never the private signing seed.

Local signing readiness can be checked without publishing a release:

```powershell
$env:RELEASE_ED25519_PRIVATE_KEY_HEX = "<64-hex Ed25519 seed>"
.\target\release\gh_mirror_gui.exe --release-signing-doctor `
  --fixture-dir .\target\release-signing-fixture `
  --json .\target\release-signing-readiness.json `
  --public-key-out .\target\publisher-key.ed25519.pub
```

## License

This project is licensed under the MIT License. See `LICENSE` for details.
