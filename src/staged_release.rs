use crate::download::{
    build_client, download_with_strategy, probe_download, sha256_file, DownloadControl,
    SelectedDownloadStrategy,
};
use crate::history::{append_download_history, VerificationHistoryContext};
use crate::releases::{ReleaseAsset, ResolvedRelease};
use crate::source_trust::{
    normalize_public_key_pin, trusted_key_fingerprint, SourceAuthenticityStatus,
};
use crate::trust_policy::{
    apply_file_disposition, plan_file_disposition_for_report, TrustPolicyConfig,
};
use crate::verification::{
    verification_plan_for_selected_asset, verify_downloaded_file, DownloadVerificationPlan,
    VerificationReport, VerificationTrustDecision,
};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Arc,
};
use std::thread;
use std::time::{Duration, Instant};

const RELEASE_BINARY_ASSET: &str = "gh_mirror_gui.exe";
const SHA256SUMS_ASSET: &str = "SHA256SUMS.txt";
const SHA256SUMS_SIGNATURE_ASSET: &str = "SHA256SUMS.txt.sig";
const PROVENANCE_ASSET: &str = "release-provenance.json";
const PROVENANCE_SIGNATURE_ASSET: &str = "release-provenance.json.sig";
const PUBLISHER_KEY_ASSET: &str = "publisher-key.ed25519.pub";

struct StagedReleaseSelfTestConfig {
    release_dir: PathBuf,
    out_dir: PathBuf,
    history_path: PathBuf,
    json_path: Option<PathBuf>,
}

struct StaticServer {
    base_url: String,
    stop: Arc<AtomicBool>,
    handle: thread::JoinHandle<Result<Vec<String>, String>>,
}

impl StaticServer {
    fn stop(self) -> Result<Vec<String>, String> {
        self.stop.store(true, Ordering::Relaxed);
        self.handle
            .join()
            .map_err(|_| "staged release static server panicked".to_string())?
    }
}

pub fn run_staged_release_download_selftest(args: &[String]) -> Result<(), String> {
    // This command spins up a local static HTTP server for deterministic, offline-ish selftests.
    // Keep production network policy strict (GitHub official domains only), but allow loopback
    // URLs inside this selftest harness.
    crate::url_policy::enable_loopback_for_selftests();
    let config = parse_staged_release_selftest_config(args)?;
    let report = run_staged_release_selftest(&config)?;
    let pretty_report = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialize staged release download selftest JSON: {e}"))?;
    if let Some(json_path) = &config.json_path {
        write_text_file(json_path, &format!("{pretty_report}\n"))?;
    }
    println!("{pretty_report}");
    Ok(())
}

fn parse_staged_release_selftest_config(
    args: &[String],
) -> Result<StagedReleaseSelfTestConfig, String> {
    let mut release_dir = None;
    let mut out_dir = None;
    let mut history_path = None;
    let mut json_path = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--release-dir" => {
                i += 1;
                release_dir = args.get(i).map(PathBuf::from);
            }
            "--out-dir" => {
                i += 1;
                out_dir = args.get(i).map(PathBuf::from);
            }
            "--history" => {
                i += 1;
                history_path = args.get(i).map(PathBuf::from);
            }
            "--json" => {
                i += 1;
                json_path = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --staged-release-download-selftest option: {other}"
                ))
            }
        }
        i += 1;
    }

    let release_dir = release_dir.ok_or_else(|| "--release-dir is required".to_string())?;
    let out_dir = out_dir.unwrap_or_else(|| release_dir.join("download-selftest"));
    let history_path = history_path.unwrap_or_else(|| out_dir.join("bench-history.jsonl"));
    Ok(StagedReleaseSelfTestConfig {
        release_dir,
        out_dir,
        history_path,
        json_path,
    })
}

fn run_staged_release_selftest(
    config: &StagedReleaseSelfTestConfig,
) -> Result<serde_json::Value, String> {
    validate_required_assets(&config.release_dir)?;
    fs::create_dir_all(&config.out_dir)
        .map_err(|e| format!("Create staged release download selftest dir error: {e}"))?;
    if let Some(parent) = config.history_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Create staged release history dir error: {e}"))?;
    }

    let output = config.out_dir.join(RELEASE_BINARY_ASSET);
    let _ = fs::remove_file(&output);
    let _ = fs::remove_file(format!("{}.part", output.to_string_lossy()));
    let _ = fs::remove_file(format!("{}.part.json", output.to_string_lossy()));
    let _ = fs::remove_file(&config.history_path);

    let public_key_path = config.release_dir.join(PUBLISHER_KEY_ASSET);
    let public_key_text = fs::read_to_string(&public_key_path)
        .map_err(|e| format!("Read staged publisher public key error: {e}"))?;
    let pinned_public_key = normalize_public_key_pin(&public_key_text)?;
    let public_key_fingerprint = trusted_key_fingerprint(&pinned_public_key)
        .ok_or_else(|| "staged publisher public key fingerprint failed".to_string())?;

    let server = start_static_server(config.release_dir.clone())?;
    let release = staged_release_metadata(&config.release_dir, &server.base_url)?;
    let full_plan = verification_plan_for_selected_asset(&release, 0)
        .ok_or_else(|| "staged release asset verification plan was not created".to_string())?;
    assert_complete_staged_plan(&full_plan)?;

    let client = build_client("", 30, false)?;
    let download_url = release.assets[0].browser_download_url.clone();
    let probe = probe_download_with_retry(&client, &download_url)?;
    let strategy = SelectedDownloadStrategy {
        variant: "staged-signed-release-single".to_string(),
        config: None,
        history_matches: 0,
    };
    let (progress_tx, progress_rx) = mpsc::channel();
    let ctrl = DownloadControl::new();
    let download_start = Instant::now();
    download_with_strategy(
        &client,
        &download_url,
        &output.to_string_lossy(),
        &probe,
        &strategy,
        &ctrl,
        &progress_tx,
    )?;
    let download_elapsed = download_start.elapsed();
    let progress_events = progress_rx.try_iter().count();

    let mut policy = TrustPolicyConfig::default();
    policy.source_trust.require_trusted_source = true;
    policy.source_trust.trusted_publisher_key = pinned_public_key.clone();

    let checksum_plan = DownloadVerificationPlan {
        asset_name: full_plan.asset_name.clone(),
        checksum_asset: full_plan.checksum_asset.clone(),
        checksum_signature_asset: full_plan.checksum_signature_asset.clone(),
        provenance_asset: None,
        provenance_signature_asset: None,
    };
    let provenance_plan = DownloadVerificationPlan {
        asset_name: full_plan.asset_name.clone(),
        checksum_asset: None,
        checksum_signature_asset: None,
        provenance_asset: full_plan.provenance_asset.clone(),
        provenance_signature_asset: full_plan.provenance_signature_asset.clone(),
    };

    let checksum_verification = verify_source_chain_and_record_evidence(
        "sha256sums",
        SHA256SUMS_ASSET,
        &client,
        &output,
        &download_url,
        &probe,
        &strategy,
        download_elapsed,
        &checksum_plan,
        &policy,
        &config.history_path,
    )?;
    let provenance_verification = verify_source_chain_and_record_evidence(
        "provenance",
        PROVENANCE_ASSET,
        &client,
        &output,
        &download_url,
        &probe,
        &strategy,
        download_elapsed,
        &provenance_plan,
        &policy,
        &config.history_path,
    )?;

    let server_requests = server.stop()?;
    assert_server_requests_cover_chain(&server_requests)?;

    let downloaded_size = fs::metadata(&output)
        .map_err(|e| format!("Stat staged downloaded binary error: {e}"))?
        .len();
    let downloaded_sha256 = sha256_file(&output)?;
    Ok(json!({
        "schema_version": 1,
        "ok": true,
        "release_dir": config.release_dir,
        "download": {
            "url": download_url,
            "output": output,
            "size": downloaded_size,
            "sha256": downloaded_sha256,
            "probe": {
                "total": probe.total,
                "range_supported": probe.range_supported,
                "etag": probe.etag,
                "last_modified": probe.last_modified,
            },
            "strategy": {
                "variant": strategy.variant,
                "mode": "single",
            },
            "progress_events": progress_events,
        },
        "publisher_key": {
            "path": public_key_path,
            "fingerprint_sha256": public_key_fingerprint,
            "imported_from_asset": PUBLISHER_KEY_ASSET,
        },
        "policy": policy.snapshot(),
        "history_path": config.history_path,
        "verifications": {
            "sha256sums": checksum_verification,
            "provenance": provenance_verification,
        },
        "server_requests": server_requests,
    }))
}

fn probe_download_with_retry(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<crate::download::DownloadProbe, String> {
    let mut last_error = None;
    // The staged-release selftest spins up a loopback server in a background thread.
    // On some Windows setups we occasionally observe a transient connect/send failure
    // right after the listener is bound. Retrying keeps the receipt gate stable
    // without weakening production network policy.
    for attempt in 0..6 {
        match probe_download(client, url) {
            Ok(probe) => return Ok(probe),
            Err(e) => {
                last_error = Some(e);
                if attempt < 5 {
                    thread::sleep(Duration::from_millis(25));
                }
            }
        }
    }
    Err(format!(
        "Range probe request failed after retries: {}",
        last_error.unwrap_or_else(|| "unknown probe failure".to_string())
    ))
}

#[allow(clippy::too_many_arguments)]
fn verify_source_chain_and_record_evidence(
    label: &str,
    expected_source_name: &str,
    client: &reqwest::blocking::Client,
    output: &PathBuf,
    download_url: &str,
    probe: &crate::download::DownloadProbe,
    strategy: &SelectedDownloadStrategy,
    download_elapsed: Duration,
    plan: &DownloadVerificationPlan,
    policy: &TrustPolicyConfig,
    history_path: &Path,
) -> Result<serde_json::Value, String> {
    let report = verify_downloaded_file(
        client,
        output,
        RELEASE_BINARY_ASSET,
        Some(plan),
        &policy.source_trust,
    )?;
    assert_trusted_staged_report(label, expected_source_name, &report)?;
    let disposition = plan_file_disposition_for_report(output, &report, policy);
    let applied = apply_file_disposition(&disposition)?;
    let evidence_path = append_download_history(
        &Some(history_path.to_path_buf()),
        download_url,
        output,
        probe,
        strategy,
        download_elapsed,
        Some(VerificationHistoryContext {
            report: &report,
            policy,
            file_disposition: &disposition,
        }),
    )?
    .ok_or_else(|| format!("{label} verification evidence path was not written"))?;
    assert_evidence_matches_trusted_source(label, expected_source_name, &evidence_path)?;

    Ok(json!({
        "ok": true,
        "status": report.status.as_str(),
        "trust_decision": report.effective_trust_decision().as_str(),
        "asset_name": report.asset_name,
        "file_sha256": report.file_sha256,
        "expected_sha256": report.expected_sha256,
        "source": report.source,
        "source_trust": report.source_trust,
        "detail": report.detail,
        "file_disposition": {
            "action": applied.action.as_str(),
            "original_path": applied.original_path,
            "final_path": applied.final_path,
        },
        "evidence_path": evidence_path,
    }))
}

fn validate_required_assets(release_dir: &Path) -> Result<(), String> {
    for name in [
        RELEASE_BINARY_ASSET,
        SHA256SUMS_ASSET,
        SHA256SUMS_SIGNATURE_ASSET,
        PROVENANCE_ASSET,
        PROVENANCE_SIGNATURE_ASSET,
        PUBLISHER_KEY_ASSET,
    ] {
        let path = release_dir.join(name);
        if !path.is_file() {
            return Err(format!("staged release required asset missing: {name}"));
        }
    }
    Ok(())
}

fn staged_release_metadata(release_dir: &Path, base_url: &str) -> Result<ResolvedRelease, String> {
    let asset_names = [
        RELEASE_BINARY_ASSET,
        SHA256SUMS_ASSET,
        SHA256SUMS_SIGNATURE_ASSET,
        PROVENANCE_ASSET,
        PROVENANCE_SIGNATURE_ASSET,
        PUBLISHER_KEY_ASSET,
    ];
    let assets = asset_names
        .into_iter()
        .map(|name| {
            let path = release_dir.join(name);
            let size = fs::metadata(&path)
                .map_err(|e| format!("Stat staged release asset {name} error: {e}"))?
                .len();
            Ok(ReleaseAsset {
                name: name.to_string(),
                size,
                browser_download_url: format!("{base_url}/{name}"),
                content_type: None,
                api_url: None,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(ResolvedRelease {
        owner: "local".to_string(),
        repo: "gh_mirror_gui-staged".to_string(),
        tag_name: "signed-staging".to_string(),
        name: Some("signed-staging".to_string()),
        html_url: base_url.to_string(),
        assets,
    })
}

fn assert_complete_staged_plan(plan: &DownloadVerificationPlan) -> Result<(), String> {
    if plan.asset_name != RELEASE_BINARY_ASSET {
        return Err(format!(
            "staged verification plan asset mismatch: {}",
            plan.asset_name
        ));
    }
    if plan
        .checksum_asset
        .as_ref()
        .map(|asset| asset.name.as_str())
        != Some(SHA256SUMS_ASSET)
    {
        return Err("staged verification plan did not select SHA256SUMS.txt".to_string());
    }
    if plan
        .checksum_signature_asset
        .as_ref()
        .map(|asset| asset.name.as_str())
        != Some(SHA256SUMS_SIGNATURE_ASSET)
    {
        return Err("staged verification plan did not select SHA256SUMS.txt.sig".to_string());
    }
    if plan
        .provenance_asset
        .as_ref()
        .map(|asset| asset.name.as_str())
        != Some(PROVENANCE_ASSET)
    {
        return Err("staged verification plan did not select release-provenance.json".to_string());
    }
    if plan
        .provenance_signature_asset
        .as_ref()
        .map(|asset| asset.name.as_str())
        != Some(PROVENANCE_SIGNATURE_ASSET)
    {
        return Err(
            "staged verification plan did not select release-provenance.json.sig".to_string(),
        );
    }
    Ok(())
}

fn assert_trusted_staged_report(
    label: &str,
    expected_source_name: &str,
    report: &VerificationReport,
) -> Result<(), String> {
    if report.status.as_str() != "VERIFIED" {
        return Err(format!(
            "{label} staged download verification status was {}",
            report.status.as_str()
        ));
    }
    if report.effective_trust_decision() != VerificationTrustDecision::Trusted {
        return Err(format!(
            "{label} staged download trust decision was {}",
            report.effective_trust_decision().as_str()
        ));
    }
    if report.source.as_deref() != Some(expected_source_name) {
        return Err(format!(
            "{label} staged download source mismatch: {:?}",
            report.source
        ));
    }
    let Some(source_trust) = &report.source_trust else {
        return Err(format!("{label} staged download source trust was missing"));
    };
    if source_trust.status != SourceAuthenticityStatus::TrustedSignature {
        return Err(format!(
            "{label} staged source authenticity was {}",
            source_trust.status.as_str()
        ));
    }
    if source_trust.signature_asset_name.as_deref() != Some(&format!("{expected_source_name}.sig"))
    {
        return Err(format!(
            "{label} staged signature asset mismatch: {:?}",
            source_trust.signature_asset_name
        ));
    }
    if source_trust
        .trusted_publisher_key_fingerprint_sha256
        .as_deref()
        .is_none()
    {
        return Err(format!(
            "{label} staged source trust did not record key fingerprint"
        ));
    }
    Ok(())
}

fn assert_evidence_matches_trusted_source(
    label: &str,
    expected_source_name: &str,
    evidence_path: &Path,
) -> Result<(), String> {
    let text = fs::read_to_string(evidence_path)
        .map_err(|e| format!("Read {label} staged evidence error: {e}"))?;
    let evidence = serde_json::from_str::<serde_json::Value>(&text)
        .map_err(|e| format!("Parse {label} staged evidence JSON error: {e}"))?;
    if evidence["status"] != "VERIFIED" {
        return Err(format!("{label} staged evidence did not record VERIFIED"));
    }
    if evidence["trust_decision"] != "TRUSTED" {
        return Err(format!("{label} staged evidence did not record TRUSTED"));
    }
    if evidence["source"] != expected_source_name {
        return Err(format!(
            "{label} staged evidence source mismatch: {}",
            evidence["source"]
        ));
    }
    if evidence["source_trust"]["status"] != "TRUSTED_SIGNATURE" {
        return Err(format!(
            "{label} staged evidence source_trust status mismatch: {}",
            evidence["source_trust"]["status"]
        ));
    }
    if evidence["source_trust"]["trusted_publisher_key_fingerprint_sha256"]
        .as_str()
        .is_none()
    {
        return Err(format!("{label} staged evidence missing key fingerprint"));
    }
    if evidence["policy"]["source_trust"]["require_trusted_source"] != true {
        return Err(format!(
            "{label} staged evidence did not record required signed source policy"
        ));
    }
    if evidence["file_disposition"]["action"] != "KEEP" {
        return Err(format!(
            "{label} staged evidence file disposition was not KEEP"
        ));
    }
    Ok(())
}

fn assert_server_requests_cover_chain(requests: &[String]) -> Result<(), String> {
    let required = [
        format!("GET /{RELEASE_BINARY_ASSET}"),
        format!("GET /{SHA256SUMS_ASSET}"),
        format!("GET /{SHA256SUMS_SIGNATURE_ASSET}"),
        format!("GET /{PROVENANCE_ASSET}"),
        format!("GET /{PROVENANCE_SIGNATURE_ASSET}"),
    ];
    let missing = required
        .iter()
        .filter(|needle| !requests.iter().any(|request| request.starts_with(*needle)))
        .cloned()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return Err(format!(
            "staged release static server did not observe requests: {}",
            missing.join(", ")
        ));
    }
    let binary_get = format!("GET /{RELEASE_BINARY_ASSET}");
    let binary_range_probe = format!("GET /{RELEASE_BINARY_ASSET} Range: bytes=0-0");
    if !requests
        .iter()
        .any(|request| request == &binary_range_probe)
    {
        return Err(
            "staged release download did not exercise the deterministic range probe GET"
                .to_string(),
        );
    }
    let binary_full_gets = requests
        .iter()
        .filter(|request| *request == &binary_get)
        .count();
    if binary_full_gets < 1 {
        return Err("staged release download did not exercise a full binary GET".to_string());
    }
    Ok(())
}

fn start_static_server(root: PathBuf) -> Result<StaticServer, String> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("Bind staged release static server error: {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("Configure staged release static server error: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("Read staged release static server addr error: {e}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        let mut requests = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match listener.accept() {
                Ok((stream, _)) => match handle_static_request(stream, &root) {
                    Ok(summary) => requests.push(summary),
                    Err(e) => requests.push(format!("ERROR {e}")),
                },
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if thread_stop.load(Ordering::Relaxed) {
                        break;
                    }
                    if Instant::now() > deadline {
                        return Err("staged release static server timed out".to_string());
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(e) => return Err(format!("staged release static server accept error: {e}")),
            }
        }
        Ok(requests)
    });

    Ok(StaticServer {
        base_url: format!("http://{addr}"),
        stop,
        handle,
    })
}

fn handle_static_request(mut stream: TcpStream, root: &Path) -> Result<String, String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| format!("Configure staged server read timeout error: {e}"))?;
    let mut request = Vec::new();
    let mut buf = [0_u8; 1024];
    loop {
        let n = stream
            .read(&mut buf)
            .map_err(|e| format!("Read staged server request error: {e}"))?;
        if n == 0 {
            break;
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") || request.len() > 16 * 1024 {
            break;
        }
    }
    let request_text = String::from_utf8_lossy(&request);
    let mut lines = request_text.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| "staged server request line missing".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "staged server request method missing".to_string())?;
    let raw_path = parts
        .next()
        .ok_or_else(|| "staged server request path missing".to_string())?;
    let range_header = request_text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("range") {
            Some(value.trim().to_string())
        } else {
            None
        }
    });
    let summary = format!(
        "{method} {raw_path}{}",
        range_header
            .as_ref()
            .map(|range| format!(" Range: {range}"))
            .unwrap_or_default()
    );
    let response = build_static_response(root, method, raw_path, range_header.as_deref())?;
    stream
        .write_all(&response)
        .map_err(|e| format!("Write staged server response error: {e}"))?;
    Ok(summary)
}

fn build_static_response(
    root: &Path,
    method: &str,
    raw_path: &str,
    range_header: Option<&str>,
) -> Result<Vec<u8>, String> {
    let Some(path) = request_path(root, raw_path) else {
        return Ok(http_response(404, "Not Found", &[], false, None));
    };
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(http_response(404, "Not Found", &[], false, None)),
    };
    if method == "HEAD" {
        return Ok(http_response(200, "OK", &bytes, true, None));
    }
    if method != "GET" {
        return Ok(http_response(405, "Method Not Allowed", &[], false, None));
    }

    if let Some((start, end)) = range_header.and_then(|range| parse_byte_range(range, bytes.len()))
    {
        let body = &bytes[start..=end];
        return Ok(http_response(
            206,
            "Partial Content",
            body,
            false,
            Some(format!("bytes {start}-{end}/{}", bytes.len())),
        ));
    }

    Ok(http_response(200, "OK", &bytes, false, None))
}

fn request_path(root: &Path, raw_path: &str) -> Option<PathBuf> {
    let clean = raw_path
        .split('?')
        .next()
        .unwrap_or(raw_path)
        .trim_start_matches('/');
    if clean.is_empty() || clean.contains("..") || clean.contains('\\') || clean.contains('/') {
        return None;
    }
    Some(root.join(clean.replace("%20", " ")))
}

fn parse_byte_range(range: &str, len: usize) -> Option<(usize, usize)> {
    if len == 0 {
        return None;
    }
    let spec = range.trim().strip_prefix("bytes=")?;
    let (start, end) = spec.split_once('-')?;
    let start = start.parse::<usize>().ok()?;
    let end = if end.trim().is_empty() {
        len - 1
    } else {
        end.parse::<usize>().ok()?.min(len - 1)
    };
    if start > end || start >= len {
        None
    } else {
        Some((start, end))
    }
}

fn http_response(
    status: u16,
    reason: &str,
    body: &[u8],
    head_only: bool,
    content_range: Option<String>,
) -> Vec<u8> {
    let mut headers = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
        body.len()
    );
    if let Some(content_range) = content_range {
        headers.push_str(&format!("Content-Range: {content_range}\r\n"));
    }
    headers.push_str("\r\n");
    let mut response = headers.into_bytes();
    if !head_only {
        response.extend_from_slice(body);
    }
    response
}

fn write_text_file(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Create dir error: {e}"))?;
    }
    fs::write(path, text).map_err(|e| format!("Write {} error: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_trust::{public_key_from_private_seed, sign_ed25519_detached};

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_staged_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    #[test]
    fn staged_request_contract_allows_missing_best_effort_head_probe() {
        let requests = vec![
            format!("GET /{RELEASE_BINARY_ASSET} Range: bytes=0-0"),
            format!("GET /{RELEASE_BINARY_ASSET}"),
            format!("GET /{SHA256SUMS_ASSET}"),
            format!("GET /{SHA256SUMS_SIGNATURE_ASSET}"),
            format!("GET /{PROVENANCE_ASSET}"),
            format!("GET /{PROVENANCE_SIGNATURE_ASSET}"),
        ];

        assert_server_requests_cover_chain(&requests).unwrap();
    }

    #[test]
    fn staged_request_contract_requires_deterministic_range_probe() {
        let requests = vec![
            format!("GET /{RELEASE_BINARY_ASSET}"),
            format!("GET /{SHA256SUMS_ASSET}"),
            format!("GET /{SHA256SUMS_SIGNATURE_ASSET}"),
            format!("GET /{PROVENANCE_ASSET}"),
            format!("GET /{PROVENANCE_SIGNATURE_ASSET}"),
        ];

        let err = assert_server_requests_cover_chain(&requests).unwrap_err();

        assert!(err.contains("deterministic range probe GET"));
    }

    #[test]
    fn staged_release_download_selftest_downloads_verifies_and_writes_evidence() {
        let release_dir = unique_test_path("release");
        let out_dir = unique_test_path("out");
        fs::create_dir_all(&release_dir).unwrap();
        let binary = release_dir.join(RELEASE_BINARY_ASSET);
        fs::write(&binary, b"staged release binary").unwrap();
        let binary_hash = sha256_file(&binary).unwrap();
        let sha256sums = format!("{binary_hash}  {RELEASE_BINARY_ASSET}\n");
        let provenance = json!({
            "schema_version": 1,
            "dry_run": true,
            "artifacts": {
                "release_binary": {
                    "path": RELEASE_BINARY_ASSET,
                    "sha256": binary_hash,
                },
            },
        })
        .to_string();
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = public_key_from_private_seed(private_key).unwrap();
        let sha256sums_signature =
            sign_ed25519_detached(sha256sums.as_bytes(), private_key).unwrap();
        let provenance_signature =
            sign_ed25519_detached(provenance.as_bytes(), private_key).unwrap();
        fs::write(release_dir.join(SHA256SUMS_ASSET), sha256sums).unwrap();
        fs::write(
            release_dir.join(SHA256SUMS_SIGNATURE_ASSET),
            format!("{sha256sums_signature}\n"),
        )
        .unwrap();
        fs::write(release_dir.join(PROVENANCE_ASSET), &provenance).unwrap();
        fs::write(
            release_dir.join(PROVENANCE_SIGNATURE_ASSET),
            format!("{provenance_signature}\n"),
        )
        .unwrap();
        fs::write(
            release_dir.join(PUBLISHER_KEY_ASSET),
            format!("{public_key}\n"),
        )
        .unwrap();

        let json_path = out_dir.join("selftest.json");
        run_staged_release_download_selftest(&[
            "--release-dir".to_string(),
            release_dir.display().to_string(),
            "--out-dir".to_string(),
            out_dir.display().to_string(),
            "--json".to_string(),
            json_path.display().to_string(),
        ])
        .unwrap();

        let report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["download"]["sha256"], binary_hash);
        assert_eq!(report["verifications"]["sha256sums"]["status"], "VERIFIED");
        assert_eq!(
            report["verifications"]["sha256sums"]["trust_decision"],
            "TRUSTED"
        );
        assert_eq!(report["verifications"]["provenance"]["status"], "VERIFIED");
        assert_eq!(
            report["verifications"]["provenance"]["trust_decision"],
            "TRUSTED"
        );
        assert!(report["verifications"]["sha256sums"]["evidence_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).is_file()));
        assert!(report["verifications"]["provenance"]["evidence_path"]
            .as_str()
            .is_some_and(|path| Path::new(path).is_file()));

        let _ = fs::remove_dir_all(release_dir);
        let _ = fs::remove_dir_all(out_dir);
    }
}
