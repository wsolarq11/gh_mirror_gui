# gh_mirror_gui

A small Windows desktop GUI for downloading GitHub release assets with progress, pause/resume/cancel, proxy support, and an adaptive segmented downloader.

## Features

- Direct GitHub release asset downloads.
- Adaptive strategy selection: single stream or concurrent HTTP `Range` segments based on live sampling and local history.
- Safe resume via `.part` files and metadata validation for URL, total size, `ETag`, and `Last-Modified`.
- Progress, speed, elapsed time, cancellation, and pause/resume controls.
- Optional proxy URL support.
- Safe TLS defaults: TLS uses the OS-native trust store and rejects invalid certificates unless the explicit unsafe compatibility switch is enabled.

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

Paste a GitHub release asset URL, choose a save directory, optionally set a proxy, then click **Download**.

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

## License

This project is licensed under the MIT License. See `LICENSE` for details.
