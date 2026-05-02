# gh_mirror_gui Release Verification — 2026-05-02

## Outcome

PASS. The workspace now has a rebuilt release binary, an automated verification front door, unit coverage for the download failure path, network smoke coverage against the latest upstream asset, and GUI launch smoke coverage.

Final receipt:

```text
target/delivery/20260503-005353/receipt.json
```

Speed matrix receipt:

```text
target/delivery/20260502-193931/receipt.json
target/delivery/20260502-193931/bench-matrix.json
```

Reproduce with:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\tools\release-verify.ps1
```

## Release discovery matrix

| Surface | Source | Result |
| --- | --- | --- |
| This app repo | `https://github.com/wsolarq11/gh_mirror_gui/releases` + GitHub REST latest-release endpoint | No published GitHub Release. GitHub UI says there are not any releases; REST `releases/latest` returned `404`. |
| Local repo baseline | `git log --oneline --decorate -10`; `git tag` | `main...origin/main`, latest commit `ed1432d Stop tracking dst-admin-go.1.6.1.tar.gz`, no tags. |
| Target downloadable upstream | `https://github.com/carrot-hu23/dst-admin-go/releases/tag/1.6.1` + GitHub REST latest-release endpoint | Latest release is `1.6.1`, published `2026-02-16T10:36:08Z`; assets include `dst-admin-go.1.6.1.tar.gz` size `32353113` and `dst-admin-go.1.6.1-window.zip` size `32966643`. |
| Existing local downloaded asset | `dst-admin-go.1.6.1.tar.gz`; `target\release\dst-admin-go.1.6.1.tar.gz` | Both files are size `32353113`, matching the latest upstream `.tar.gz` asset size; SHA256 `BE8AADC431C88F370235AB8F29793647BD7638AE172696B350907D7FD993DE0E`. |

Latest `dst-admin-go` release notes captured from GitHub:

- 优化亮色和暗黑主题
- 增加自定义主题色（系统设置/主题设置）
- 增加自定义指令（默认支持棱镜）
- 优化世界列表
- 调整模组订阅界面

## Code/change matrix

| Area | File | Change | Verification |
| --- | --- | --- | --- |
| Download failure root cause | `src/main.rs` | Added `.write(true)` to the fresh `.part` file creation branch using `OpenOptions::create(true).truncate(true)` | `download_single_creates_new_temp_file_with_write_access` passed |
| Speed ceiling | `src/main.rs` | Added Range probing and segmented concurrent download path for large assets; matrix-selected default profile uses 4 MiB segments and up to 4 workers, with single-thread fallback when Range is not available | `probe_download_detects_range_support_and_metadata` and `download_segmented_writes_all_ranges_and_removes_resume_meta` passed |
| Resume safety | `src/main.rs` | Existing `.part` resume now restarts cleanly when a server ignores `Range` and returns `200 OK`, preventing duplicated/corrupt append | `download_single_restarts_when_resume_range_is_ignored` passed |
| Progress/UI pressure | `src/main.rs` | Increased download buffer to 256 KiB and throttled progress events to a 200 ms cadence | `cargo test --all-targets` and GUI launch smoke passed |
| Resume/range behavior | `src/main.rs` tests | Added local HTTP server test for existing `.part` resume with `Range` request | `download_single_resumes_existing_part_file_with_range_request` passed |
| URL/mirror helpers | `src/main.rs` tests | Added direct URL/mirror URL and filename extraction assertions | `url_helpers_cover_direct_and_mirror_cases` passed |
| Speed display | `src/main.rs` tests | Added bytes/KB/MB formatting assertions | `speed_formatting_covers_bytes_kb_and_mb` passed |
| Proxy validation | `src/main.rs` tests | Added invalid proxy URL rejection assertion | `client_builder_rejects_invalid_proxy_url` passed |
| Clippy hygiene | `src/main.rs` | Collapsed nested Open Folder `if` blocks | `cargo clippy --all-targets -- -D warnings` passed |
| Evidence/release gate | `tools/release-verify.ps1` | Added one-command verification: git status, fmt, tests, clippy, release build, latest release lookup, network range smoke, GUI launch smoke, JSON receipt | Final receipt `status=PASS` |
| Headless benchmark gate | `src/main.rs`; `tools/release-verify.ps1` | Added `--bench-download --url <URL> --out <PATH> --json <PATH> --history <PATH> --mode auto|single|segmented|adaptive --segment-size <bytes> --concurrency <n>` for full real-asset benchmark without GUI/file dialogs; release verification now records benchmark JSON/matrix and verifies size/hash | `target/delivery/20260503-005353/bench-download.json` |
| GUI adaptive mainline | `src/main.rs` | GUI downloads now choose a history-backed strategy before full download, using matching history when available and falling back to the static matrix winner; successful GUI downloads append full-download history | `history_backed_strategy_*` tests passed; GUI launch smoke passed |
| Ignore hygiene | `.gitignore` | Removed duplicate target-specific tar.gz rules; kept generic `*.tar.gz` and `download_error.log` | `git status` confirms only intended tracked changes/untracked `tools/` |

## Requirement/function verification matrix

| Requirement | Verification method | Evidence |
| --- | --- | --- |
| App compiles as release binary | `cargo build --release` | `target/release/gh_mirror_gui.exe`, size `8388608`, SHA256 `2D6C783E2510B5B6D59DBC65A070E22455DA7C054D491D07D8DF69249BFFCD9F` |
| Automated test suite green | `cargo test --all-targets` | `10 passed; 0 failed` in `target/delivery/20260503-005353/cargo-test-all-targets.log` |
| Formatting green | `cargo fmt --check` | exit `0` in receipt |
| Lint green | `cargo clippy --all-targets -- -D warnings` | exit `0` in receipt |
| URL parsing and direct/mirror URL construction | Unit test | `url_helpers_cover_direct_and_mirror_cases` |
| Save file creation on fresh download | Unit test with local HTTP server | `download_single_creates_new_temp_file_with_write_access` |
| Resume existing partial download | Unit test with local HTTP server and `Range` header | `download_single_resumes_existing_part_file_with_range_request` |
| Server ignores resume `Range` | Unit test with local HTTP server returning `200 OK` despite an existing `.part` file | `download_single_restarts_when_resume_range_is_ignored` |
| Large-file speed path via concurrent segments | Unit test with local HTTP server serving byte ranges | `download_segmented_writes_all_ranges_and_removes_resume_meta` |
| Range capability detection | Unit test with `HEAD` and `GET Range: bytes=0-0` | `probe_download_detects_range_support_and_metadata` |
| Progress channel emits useful download progress | Unit test asserts progress event with downloaded bytes and expected total | `download_single_creates_new_temp_file_with_write_access` |
| Speed text formatting | Unit test | `speed_formatting_covers_bytes_kb_and_mb` |
| Invalid proxy is rejected before download | Unit test | `client_builder_rejects_invalid_proxy_url` |
| Latest upstream GitHub asset reachable | `curl --range 0-65535` via `tools/release-verify.ps1` | `65536` bytes downloaded; SHA256 `9EEF6F54DC65E105A089C093AAF4FEB4BA0810BA109A3C55CA8D2D48F2B813BD` |
| GUI binary can launch on this machine | `Start-Process target\release\gh_mirror_gui.exe`, observe 3s, then terminate | `gui_launch_smoke.ok=true` |
| Full latest asset benchmark, final default | `target\release\gh_mirror_gui.exe --bench-download ...` | `mode=adaptive`, `selected_variant=seg-c16-s2m`, `history_matches=7`, `concurrency=16`, `segment_size=2097152`, `segments=16`, `total_bytes=32353113`, `download_ms=140602`, `avg_mib_s=0.2194`, SHA256 `BE8AADC431C88F370235AB8F29793647BD7638AE172696B350907D7FD993DE0E` |
| Benchmark matrix winner | `tools\release-verify.ps1` full matrix | Winner from same-window matrix: `seg-c4-s4m`, `concurrency=4`, `segment_size=4194304`, `download_ms=163986`, `avg_mib_s=0.1882`; faster than `single` (`0.0540 MiB/s`) and `curl` (`0.0352 MiB/s`) in that run |
| Adaptive benchmark, final gate | `target\release\gh_mirror_gui.exe --bench-download --mode adaptive ...` | Fair 4 MiB sampling selected `seg-c16-s2m`; sample rates: `single=0.0298`, `seg-c4-s4m=0.0378`, `seg-c8-s4m=0.0234`, `seg-c16-s2m=0.0508` MiB/s; full download PASS with SHA256 `BE8AADC431C88F370235AB8F29793647BD7638AE172696B350907D7FD993DE0E` |
| History-backed adaptive, final gate | `target\release\gh_mirror_gui.exe --bench-download --mode adaptive --history target\bench-history.jsonl ...` | Loaded `6` matching history entries; sample-only winner was `seg-c16-s2m`, but score with historical full-download results selected `seg-c4-s4m`; full download PASS with SHA256 `BE8AADC431C88F370235AB8F29793647BD7638AE172696B350907D7FD993DE0E` |
| GUI-backed adaptive integration, final gate | `target\release\gh_mirror_gui.exe --bench-download --mode adaptive --history target\bench-history.jsonl ...`; GUI smoke | Loaded `7` matching history entries; adaptive selected `seg-c16-s2m` in the latest network window; GUI launch smoke passed with the same binary |

## Failure root cause

Observed runtime error:

```text
download_file error: Open temp file error: creating or truncating a file requires write or append access
```

Root cause:

```rust
fs::OpenOptions::new()
    .create(true)
    .truncate(true)
    .open(&tmp_path)
```

The fresh-download branch requested `create(true)` and `truncate(true)` without write/append access. Rust `OpenOptions` requires write access for truncation, and file creation requires either write or append access. The fixed branch now includes `.write(true)`.

## External/source evidence

- GitHub latest-release endpoint semantics: <https://docs.github.com/rest/releases/releases?apiVersion=2022-11-28#get-the-latest-release>
- This app repo releases page: <https://github.com/wsolarq11/gh_mirror_gui/releases>
- `dst-admin-go` latest release page: <https://github.com/carrot-hu23/dst-admin-go/releases/tag/1.6.1>
- Rust `OpenOptions` docs: <https://doc.rust-lang.org/std/fs/struct.OpenOptions.html>
- Reqwest `ClientBuilder` TLS warning context for future hardening: <https://docs.rs/reqwest/latest/reqwest/blocking/struct.ClientBuilder.html#method.danger_accept_invalid_certs>

## Noted follow-up risk

`build_client` currently uses `danger_accept_invalid_certs(true)`. That was not changed in this pass to avoid altering the existing network behavior while fixing the decisive download failure. Reqwest documents this as a last-resort setting because it trusts invalid certificates. Recommended follow-up: replace it with a user-visible advanced option or proper custom root certificate handling.




