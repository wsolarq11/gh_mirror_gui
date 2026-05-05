use crate::download::sha256_file;
use crate::releases::{ReleaseAsset, ResolvedRelease};
use crate::source_trust::{
    evaluate_source_trust, not_applicable_source_trust, SourceTrustEvidence,
    SourceTrustPolicyConfig,
};
use reqwest::blocking::Client;
use std::path::PathBuf;

const MAX_VERIFICATION_ASSET_BYTES: usize = 5 * 1024 * 1024;
const VERIFICATION_ASSET_MAX_RETRIES: u32 = 2;
const VERIFICATION_ASSET_RETRY_DELAY_MS: u64 = 100;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerificationAsset {
    pub name: String,
    pub browser_download_url: String,
    pub api_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DownloadVerificationPlan {
    pub asset_name: String,
    pub checksum_asset: Option<VerificationAsset>,
    pub checksum_signature_asset: Option<VerificationAsset>,
    pub provenance_asset: Option<VerificationAsset>,
    pub provenance_signature_asset: Option<VerificationAsset>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum VerificationStatus {
    Verified,
    Mismatch,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum VerificationTrustDecision {
    Trusted,
    Block,
    Risk,
}

impl VerificationStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Verified => "VERIFIED",
            Self::Mismatch => "MISMATCH",
            Self::Unknown => "UNKNOWN",
        }
    }

    #[cfg(test)]
    pub(crate) fn trust_decision(&self) -> VerificationTrustDecision {
        match self {
            Self::Verified => VerificationTrustDecision::Trusted,
            Self::Mismatch => VerificationTrustDecision::Block,
            Self::Unknown => VerificationTrustDecision::Risk,
        }
    }
}

impl VerificationTrustDecision {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::Block => "BLOCK",
            Self::Risk => "RISK",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct VerificationReport {
    pub status: VerificationStatus,
    pub asset_name: String,
    pub file_sha256: String,
    pub expected_sha256: Option<String>,
    pub source: Option<String>,
    pub source_trust: Option<SourceTrustEvidence>,
    pub detail: String,
}

impl VerificationReport {
    pub(crate) fn effective_trust_decision(&self) -> VerificationTrustDecision {
        match self.status {
            VerificationStatus::Mismatch => VerificationTrustDecision::Block,
            VerificationStatus::Unknown => VerificationTrustDecision::Risk,
            VerificationStatus::Verified => {
                if self
                    .source_trust
                    .as_ref()
                    .is_some_and(SourceTrustEvidence::is_blocking)
                {
                    VerificationTrustDecision::Block
                } else {
                    VerificationTrustDecision::Trusted
                }
            }
        }
    }
}

pub(crate) fn verification_plan_for_selected_asset(
    release: &ResolvedRelease,
    asset_index: usize,
) -> Option<DownloadVerificationPlan> {
    let selected = release.assets.get(asset_index)?;
    let checksum_asset = best_checksum_asset(&release.assets, &selected.name);
    let provenance_asset = best_provenance_asset(&release.assets, &selected.name);
    Some(DownloadVerificationPlan {
        asset_name: selected.name.clone(),
        checksum_signature_asset: checksum_asset
            .as_ref()
            .and_then(|asset| best_signature_asset(&release.assets, &asset.name)),
        provenance_signature_asset: provenance_asset
            .as_ref()
            .and_then(|asset| best_signature_asset(&release.assets, &asset.name)),
        checksum_asset,
        provenance_asset,
    })
}

pub(crate) fn verification_source_summary(plan: &DownloadVerificationPlan) -> String {
    let mut sources = Vec::new();
    if let Some(asset) = &plan.checksum_asset {
        let signed = plan
            .checksum_signature_asset
            .as_ref()
            .map(|sig| format!(" signed by {}", sig.name))
            .unwrap_or_else(|| " unsigned".to_string());
        sources.push(format!("{} ({})", asset.name, signed.trim()));
    }
    if let Some(asset) = &plan.provenance_asset {
        let signed = plan
            .provenance_signature_asset
            .as_ref()
            .map(|sig| format!(" signed by {}", sig.name))
            .unwrap_or_else(|| " unsigned".to_string());
        sources.push(format!("{} ({})", asset.name, signed.trim()));
    }

    if sources.is_empty() {
        "No checksum/provenance assets detected; result will be UNKNOWN".to_string()
    } else {
        format!("Verification assets: {}", sources.join(" + "))
    }
}

pub(crate) fn verify_downloaded_file(
    client: &Client,
    path: &PathBuf,
    asset_name: &str,
    plan: Option<&DownloadVerificationPlan>,
    source_trust_policy: &SourceTrustPolicyConfig,
) -> Result<VerificationReport, String> {
    let file_sha256 = normalize_sha256(&sha256_file(path)?)
        .ok_or_else(|| "Downloaded file SHA256 was not a valid SHA256 digest".to_string())?;
    let Some(plan) = plan else {
        return Ok(unknown_report(
            asset_name,
            file_sha256,
            "No release asset context was available for checksum/provenance discovery".to_string(),
            source_trust_policy,
        ));
    };

    let mut notes = Vec::new();
    let mut verified_but_untrusted_source = None;
    if let Some(checksum_asset) = &plan.checksum_asset {
        match fetch_text_asset(client, checksum_asset) {
            Ok((text, bytes)) => {
                if let Some(expected) = expected_sha256_from_checksum_asset(
                    &text,
                    &plan.asset_name,
                    &checksum_asset.name,
                ) {
                    let signature_text = fetch_signature_text(
                        client,
                        plan.checksum_signature_asset.as_ref(),
                        &mut notes,
                    );
                    let source_trust = evaluate_source_trust(
                        &bytes,
                        &checksum_asset.name,
                        plan.checksum_signature_asset
                            .as_ref()
                            .map(|asset| asset.name.as_str()),
                        signature_text.as_deref(),
                        source_trust_policy,
                    );
                    let report = report_from_expected(
                        &plan.asset_name,
                        file_sha256.clone(),
                        expected,
                        checksum_asset.name.clone(),
                        Some(source_trust),
                    );
                    if report.status == VerificationStatus::Mismatch {
                        return Ok(report);
                    }
                    if source_trust_policy.require_trusted_source
                        && report
                            .source_trust
                            .as_ref()
                            .is_some_and(SourceTrustEvidence::is_blocking)
                    {
                        verified_but_untrusted_source.get_or_insert(report);
                    } else {
                        return Ok(report);
                    }
                } else {
                    notes.push(format!(
                        "{} did not contain a SHA256 entry for {}",
                        checksum_asset.name, plan.asset_name
                    ));
                }
            }
            Err(e) => notes.push(format!("{} could not be read: {e}", checksum_asset.name)),
        }
    }

    if let Some(provenance_asset) = &plan.provenance_asset {
        match fetch_text_asset(client, provenance_asset) {
            Ok((text, bytes)) => {
                if let Some(expected) = expected_sha256_from_provenance(&text, &plan.asset_name) {
                    let signature_text = fetch_signature_text(
                        client,
                        plan.provenance_signature_asset.as_ref(),
                        &mut notes,
                    );
                    let source_trust = evaluate_source_trust(
                        &bytes,
                        &provenance_asset.name,
                        plan.provenance_signature_asset
                            .as_ref()
                            .map(|asset| asset.name.as_str()),
                        signature_text.as_deref(),
                        source_trust_policy,
                    );
                    let report = report_from_expected(
                        &plan.asset_name,
                        file_sha256.clone(),
                        expected,
                        provenance_asset.name.clone(),
                        Some(source_trust),
                    );
                    if report.status == VerificationStatus::Mismatch {
                        return Ok(report);
                    }
                    if source_trust_policy.require_trusted_source
                        && report
                            .source_trust
                            .as_ref()
                            .is_some_and(SourceTrustEvidence::is_blocking)
                    {
                        verified_but_untrusted_source.get_or_insert(report);
                    } else {
                        return Ok(report);
                    }
                } else {
                    notes.push(format!(
                        "{} did not contain a SHA256 entry for {}",
                        provenance_asset.name, plan.asset_name
                    ));
                }
            }
            Err(e) => notes.push(format!("{} could not be read: {e}", provenance_asset.name)),
        }
    }

    if notes.is_empty() {
        notes.push(
            "No checksum/provenance assets were detected for the selected release asset".into(),
        );
    }

    if let Some(report) = verified_but_untrusted_source {
        return Ok(report);
    }

    Ok(unknown_report(
        &plan.asset_name,
        file_sha256,
        notes.join("; "),
        source_trust_policy,
    ))
}

fn best_checksum_asset(assets: &[ReleaseAsset], target_name: &str) -> Option<VerificationAsset> {
    assets
        .iter()
        .filter(|asset| !filename_matches(&asset.name, target_name))
        .filter(|asset| !is_signature_asset_name(&asset.name))
        .filter_map(|asset| {
            checksum_asset_sort_key(&asset.name, target_name).map(|key| (key, asset))
        })
        .min_by_key(|(key, _)| *key)
        .map(|(_, asset)| asset)
        .map(to_verification_asset)
}

fn best_provenance_asset(assets: &[ReleaseAsset], target_name: &str) -> Option<VerificationAsset> {
    assets
        .iter()
        .filter(|asset| !filename_matches(&asset.name, target_name))
        .filter(|asset| !is_signature_asset_name(&asset.name))
        .filter(|asset| provenance_asset_rank(&asset.name).is_some())
        .min_by_key(|asset| provenance_asset_rank(&asset.name).unwrap_or(u8::MAX))
        .map(to_verification_asset)
}

fn best_signature_asset(assets: &[ReleaseAsset], source_name: &str) -> Option<VerificationAsset> {
    let lower_source = source_name.to_ascii_lowercase();
    let candidates = [
        format!("{lower_source}.sig"),
        format!("{lower_source}.ed25519"),
        format!("{lower_source}.ed25519.sig"),
    ];
    assets
        .iter()
        .filter(|asset| !filename_matches(&asset.name, source_name))
        .filter(|asset| {
            let lower = asset.name.to_ascii_lowercase();
            candidates.contains(&lower)
        })
        .min_by_key(|asset| signature_asset_rank(&asset.name, source_name).unwrap_or(u8::MAX))
        .map(to_verification_asset)
}

fn signature_asset_rank(name: &str, source_name: &str) -> Option<u8> {
    let lower = name.to_ascii_lowercase();
    let source = source_name.to_ascii_lowercase();
    if lower == format!("{source}.sig") {
        Some(0)
    } else if lower == format!("{source}.ed25519") {
        Some(1)
    } else if lower == format!("{source}.ed25519.sig") {
        Some(2)
    } else {
        None
    }
}

fn is_signature_asset_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".sig") || lower.ends_with(".ed25519")
}

fn to_verification_asset(asset: &ReleaseAsset) -> VerificationAsset {
    VerificationAsset {
        name: asset.name.clone(),
        browser_download_url: asset.browser_download_url.clone(),
        api_url: asset.api_url.clone(),
    }
}

fn checksum_asset_rank(name: &str) -> Option<u8> {
    let lower = name.to_ascii_lowercase();
    if lower == "sha256sums.txt" || lower == "sha256sum.txt" {
        Some(0)
    } else if lower.ends_with(".sha256") || lower.ends_with(".sha256sum") {
        Some(1)
    } else if lower.contains("sha256") {
        Some(2)
    } else if lower.contains("checksum") || lower.contains("checksums") {
        Some(3)
    } else {
        None
    }
}

fn checksum_asset_sort_key(name: &str, target_name: &str) -> Option<(u8, u8)> {
    let rank = checksum_asset_rank(name)?;
    let target_penalty = if checksum_filename_targets_asset(name, target_name) {
        0
    } else {
        1
    };
    Some((target_penalty, rank))
}

fn checksum_filename_targets_asset(name: &str, asset_name: &str) -> bool {
    let normalized = normalize_filename(name);
    let lower = normalized.to_ascii_lowercase();
    for suffix in [
        ".sha256",
        ".sha256sum",
        ".sha256.txt",
        ".checksum",
        ".checksums",
        ".checksum.txt",
    ] {
        if let Some(stem) = lower.strip_suffix(suffix) {
            return filename_matches(stem, asset_name);
        }
    }
    false
}

fn provenance_asset_rank(name: &str) -> Option<u8> {
    let lower = name.to_ascii_lowercase();
    if lower == "release-provenance.json" {
        Some(0)
    } else if lower.ends_with(".json") && lower.contains("provenance") {
        Some(1)
    } else {
        None
    }
}

fn github_token() -> Option<String> {
    std::env::var("GITHUB_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn is_github_host(url: &str) -> bool {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return false;
    };
    matches!(
        parsed.host_str(),
        Some("github.com") | Some("api.github.com")
    )
}

fn fetch_text_asset(
    client: &Client,
    asset: &VerificationAsset,
) -> Result<(String, Vec<u8>), String> {
    let mut last_retryable_error = None;
    let token = github_token();
    let (url, accept_octet_stream) = match (token.is_some(), asset.api_url.as_deref()) {
        (true, Some(api_url)) => (api_url, true),
        _ => (asset.browser_download_url.as_str(), false),
    };
    let url = crate::url_policy::parse_and_validate_https_github_official_url(
        url,
        "verification asset url",
    )?;

    for attempt in 0..=VERIFICATION_ASSET_MAX_RETRIES {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_millis(
                VERIFICATION_ASSET_RETRY_DELAY_MS,
            ));
        }

        let mut request = client
            .get(url.clone())
            .header("User-Agent", "gh_mirror_gui-verifier");
        if accept_octet_stream {
            request = request.header("Accept", "application/octet-stream");
        }
        if let Some(token) = token.as_deref() {
            if accept_octet_stream || is_github_host(url.as_str()) {
                request = request.bearer_auth(token);
            }
        }

        let response = match request.send() {
            Ok(response) => response,
            Err(e) => {
                last_retryable_error = Some(format!("verification asset request failed: {e}"));
                continue;
            }
        };

        let status = response.status();
        if !status.is_success() {
            let error = format!("HTTP {}", status.as_u16());
            if is_retryable_verification_asset_status(status) {
                last_retryable_error = Some(error);
                continue;
            }
            return Err(error);
        }

        let bytes = match response.bytes() {
            Ok(bytes) => bytes,
            Err(e) => {
                last_retryable_error = Some(format!("verification asset body read failed: {e}"));
                continue;
            }
        };
        if bytes.len() > MAX_VERIFICATION_ASSET_BYTES {
            return Err(format!(
                "verification asset is too large: {} bytes",
                bytes.len()
            ));
        }
        let bytes = bytes.to_vec();
        let text = String::from_utf8(bytes.clone())
            .map_err(|e| format!("verification asset was not UTF-8: {e}"))?;
        return Ok((text, bytes));
    }

    Err(format!(
        "verification asset fetch failed after {} attempts: {}",
        VERIFICATION_ASSET_MAX_RETRIES + 1,
        last_retryable_error.unwrap_or_else(|| "unknown transient error".to_string())
    ))
}

fn is_retryable_verification_asset_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status.as_u16() == 429
}

fn fetch_signature_text(
    client: &Client,
    signature_asset: Option<&VerificationAsset>,
    notes: &mut Vec<String>,
) -> Option<String> {
    let signature_asset = signature_asset?;
    match fetch_text_asset(client, signature_asset) {
        Ok((text, _)) => Some(text),
        Err(e) => {
            notes.push(format!("{} could not be read: {e}", signature_asset.name));
            None
        }
    }
}

#[cfg(test)]
fn expected_sha256_from_checksums(text: &str, asset_name: &str) -> Option<String> {
    expected_sha256_from_checksums_inner(text, asset_name, false)
}

fn expected_sha256_from_checksum_asset(
    text: &str,
    asset_name: &str,
    checksum_asset_name: &str,
) -> Option<String> {
    expected_sha256_from_checksums_inner(
        text,
        asset_name,
        checksum_filename_targets_asset(checksum_asset_name, asset_name),
    )
}

fn expected_sha256_from_checksums_inner(
    text: &str,
    asset_name: &str,
    allow_hash_only: bool,
) -> Option<String> {
    let mut hash_only = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some((filename, hash)) = parse_bsd_sha256_line(trimmed) {
            if filename_matches(filename, asset_name) {
                return normalize_sha256(hash);
            }
        }

        let mut parts = trimmed.split_whitespace();
        let Some(hash) = parts.next() else {
            continue;
        };
        let Some(normalized_hash) = normalize_sha256(hash) else {
            continue;
        };
        let filename = parts.collect::<Vec<_>>().join(" ");
        if filename.is_empty() {
            hash_only.push(normalized_hash);
            continue;
        }
        if filename_matches(&filename, asset_name) {
            return Some(normalized_hash);
        }
    }
    if allow_hash_only && hash_only.len() == 1 {
        return hash_only.into_iter().next();
    }
    None
}

pub(crate) fn expected_sha256_from_provenance(text: &str, asset_name: &str) -> Option<String> {
    let value =
        serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}')).ok()?;
    find_asset_hash_in_json(&value, asset_name)
}

fn parse_bsd_sha256_line(line: &str) -> Option<(&str, &str)> {
    let rest = line.strip_prefix("SHA256 (")?;
    let (filename, rest) = rest.split_once(") = ")?;
    Some((filename, rest.trim()))
}

fn find_asset_hash_in_json(value: &serde_json::Value, asset_name: &str) -> Option<String> {
    match value {
        serde_json::Value::Object(map) => {
            let path = map
                .get("path")
                .or_else(|| map.get("name"))
                .and_then(|v| v.as_str());
            let hash = map
                .get("sha256")
                .or_else(|| map.get("digest"))
                .and_then(|v| v.as_str());
            if let (Some(path), Some(hash)) = (path, hash) {
                if filename_matches(path, asset_name) {
                    return normalize_sha256(hash);
                }
            }

            for (key, child) in map {
                if filename_matches(key, asset_name) {
                    if let Some(hash) = child
                        .get("sha256")
                        .or_else(|| child.get("digest"))
                        .and_then(|v| v.as_str())
                    {
                        if let Some(hash) = normalize_sha256(hash) {
                            return Some(hash);
                        }
                    }
                }
                if let Some(found) = find_asset_hash_in_json(child, asset_name) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(values) => values
            .iter()
            .find_map(|value| find_asset_hash_in_json(value, asset_name)),
        _ => None,
    }
}

fn report_from_expected(
    asset_name: &str,
    file_sha256: String,
    expected_sha256: String,
    source: String,
    source_trust: Option<SourceTrustEvidence>,
) -> VerificationReport {
    let status = if file_sha256 == expected_sha256 {
        VerificationStatus::Verified
    } else {
        VerificationStatus::Mismatch
    };
    let detail = if status == VerificationStatus::Verified {
        format!("SHA256 matched {source}")
    } else {
        format!("SHA256 mismatch against {source}")
    };
    VerificationReport {
        status,
        asset_name: asset_name.to_string(),
        file_sha256,
        expected_sha256: Some(expected_sha256),
        source: Some(source),
        source_trust,
        detail,
    }
}

fn unknown_report(
    asset_name: &str,
    file_sha256: String,
    detail: String,
    source_trust_policy: &SourceTrustPolicyConfig,
) -> VerificationReport {
    VerificationReport {
        status: VerificationStatus::Unknown,
        asset_name: asset_name.to_string(),
        file_sha256,
        expected_sha256: None,
        source: None,
        source_trust: Some(not_applicable_source_trust(source_trust_policy, &detail)),
        detail,
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let trimmed = trimmed
        .strip_prefix("sha256:")
        .or_else(|| trimmed.strip_prefix("SHA256:"))
        .unwrap_or(trimmed);
    if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_uppercase())
    } else {
        None
    }
}

fn filename_matches(candidate: &str, asset_name: &str) -> bool {
    let candidate = normalize_filename(candidate);
    let asset_name = normalize_filename(asset_name);
    candidate.eq_ignore_ascii_case(&asset_name)
        || candidate
            .rsplit('/')
            .next()
            .is_some_and(|name| name.eq_ignore_ascii_case(&asset_name))
}

fn normalize_filename(value: &str) -> String {
    value
        .trim()
        .trim_start_matches('*')
        .trim_start_matches("./")
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_trust::{hex_encode_for_test, SourceAuthenticityStatus, SourceTrustDecision};
    use ed25519_dalek::{Signer, SigningKey};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn asset(name: &str) -> ReleaseAsset {
        ReleaseAsset {
            name: name.to_string(),
            size: 1,
            browser_download_url: format!("https://example.test/{name}"),
            content_type: None,
            api_url: None,
        }
    }

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_verify_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    fn serve_text_once(body: String) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
            request
        });

        (format!("http://{addr}/SHA256SUMS.txt"), handle)
    }

    fn serve_transient_status_then_text(
        transient_status: &'static str,
        body: String,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                requests.push(String::from_utf8_lossy(&buf[..n]).to_string());

                if attempt == 0 {
                    let response = format!(
                        "HTTP/1.1 {transient_status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    stream.write_all(response.as_bytes()).unwrap();
                } else {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).unwrap();
                    stream.write_all(body.as_bytes()).unwrap();
                }
            }
            requests
        });

        (format!("http://{addr}/SHA256SUMS.txt"), handle)
    }

    fn serve_text_assets(
        bodies: Vec<(&'static str, String)>,
    ) -> (String, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..bodies.len() {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .trim_start_matches('/')
                    .to_string();
                requests.push(request);
                let body = bodies
                    .iter()
                    .find_map(|(name, body)| (*name == path).then_some(body.as_str()))
                    .unwrap_or("");
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
            requests
        });

        (format!("http://{addr}"), handle)
    }

    fn signed_source(source_text: &str) -> (String, String) {
        let signing_key = SigningKey::from_bytes(&[7u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let signature = signing_key.sign(source_text.as_bytes());
        (
            hex_encode_for_test(&verifying_key.to_bytes()),
            hex_encode_for_test(&signature.to_bytes()),
        )
    }

    #[test]
    fn detects_checksum_and_provenance_assets_for_selected_release_asset() {
        let release = ResolvedRelease {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            tag_name: "v1.0.0".to_string(),
            name: None,
            html_url: "https://github.com/owner/repo/releases/tag/v1.0.0".to_string(),
            assets: vec![
                asset("app.exe"),
                asset("SHA256SUMS.txt"),
                asset("SHA256SUMS.txt.sig"),
                asset("release-provenance.json"),
                asset("release-provenance.json.sig"),
            ],
        };

        let plan = verification_plan_for_selected_asset(&release, 0).unwrap();

        assert_eq!(plan.asset_name, "app.exe");
        assert_eq!(plan.checksum_asset.as_ref().unwrap().name, "SHA256SUMS.txt");
        assert_eq!(
            plan.checksum_signature_asset.as_ref().unwrap().name,
            "SHA256SUMS.txt.sig"
        );
        assert_eq!(
            plan.provenance_asset.as_ref().unwrap().name,
            "release-provenance.json"
        );
        assert_eq!(
            plan.provenance_signature_asset.as_ref().unwrap().name,
            "release-provenance.json.sig"
        );
        assert!(verification_source_summary(&plan).contains("SHA256SUMS.txt"));
        assert!(verification_source_summary(&plan).contains("signed by SHA256SUMS.txt.sig"));
    }

    #[test]
    fn parses_sha256sums_common_formats() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        assert_eq!(
            expected_sha256_from_checksums(&format!("{hash}  app.exe"), "app.exe"),
            Some(hash.to_string())
        );
        assert_eq!(
            expected_sha256_from_checksums(&format!("{hash} *./dist/app.exe"), "app.exe"),
            Some(hash.to_string())
        );
        assert_eq!(
            expected_sha256_from_checksums(&format!("SHA256 (app.exe) = {hash}"), "app.exe"),
            Some(hash.to_string())
        );
        assert_eq!(
            expected_sha256_from_checksum_asset(hash, "app.exe", "app.exe.sha256"),
            Some(hash.to_string())
        );
        assert_eq!(
            expected_sha256_from_checksum_asset(
                &format!("sha256:{hash}"),
                "app.exe",
                "app.exe.sha256"
            ),
            Some(hash.to_string())
        );
        assert_eq!(
            expected_sha256_from_checksum_asset(hash, "app.exe", "SHA256SUMS.txt"),
            None
        );
    }

    #[test]
    fn parses_release_provenance_artifact_hash() {
        let provenance = r#"{
          "artifacts": {
            "release_binary": {
              "path": "gh_mirror_gui.exe",
              "size": 7121408,
              "sha256": "a9bdb5ae91b153ed8e04513ca9322b4445a91d3be8dd2695a8f1c206c9937ccc"
            }
          }
        }"#;

        assert_eq!(
            expected_sha256_from_provenance(provenance, "gh_mirror_gui.exe"),
            Some("A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string())
        );

        let digest_provenance = r#"{
          "artifacts": {
            "release_binary": {
              "path": "gh_mirror_gui.exe",
              "digest": "sha256:a9bdb5ae91b153ed8e04513ca9322b4445a91d3be8dd2695a8f1c206c9937ccc"
            }
          }
        }"#;
        assert_eq!(
            expected_sha256_from_provenance(digest_provenance, "gh_mirror_gui.exe"),
            Some("A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string())
        );
    }

    #[test]
    fn parses_release_provenance_with_utf8_bom() {
        let provenance = concat!(
            "\u{feff}",
            r#"{
              "artifacts": {
                "release_binary": {
                  "path": "gh_mirror_gui.exe",
                  "sha256": "a9bdb5ae91b153ed8e04513ca9322b4445a91d3be8dd2695a8f1c206c9937ccc"
                }
              }
            }"#
        );

        assert_eq!(
            expected_sha256_from_provenance(provenance, "gh_mirror_gui.exe"),
            Some("A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string())
        );
    }

    #[test]
    fn prefers_target_specific_checksum_assets() {
        let release = ResolvedRelease {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            tag_name: "v1.0.0".to_string(),
            name: None,
            html_url: "https://github.com/owner/repo/releases/tag/v1.0.0".to_string(),
            assets: vec![
                asset("app.exe"),
                asset("SHA256SUMS.txt"),
                asset("other.exe.sha256"),
                asset("app.exe.sha256"),
            ],
        };

        let plan = verification_plan_for_selected_asset(&release, 0).unwrap();

        assert_eq!(plan.checksum_asset.as_ref().unwrap().name, "app.exe.sha256");
    }

    #[test]
    fn reports_verified_mismatch_and_unknown_states() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let verified = report_from_expected(
            "app.exe",
            hash.to_string(),
            hash.to_string(),
            "SHA256SUMS.txt".to_string(),
            None,
        );
        assert_eq!(verified.status, VerificationStatus::Verified);
        assert_eq!(verified.status.as_str(), "VERIFIED");
        assert_eq!(
            verified.status.trust_decision(),
            VerificationTrustDecision::Trusted
        );

        let mismatch = report_from_expected(
            "app.exe",
            hash.to_string(),
            "B9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string(),
            "SHA256SUMS.txt".to_string(),
            None,
        );
        assert_eq!(mismatch.status, VerificationStatus::Mismatch);
        assert_eq!(
            mismatch.status.trust_decision(),
            VerificationTrustDecision::Block
        );

        let unknown = unknown_report(
            "app.exe",
            hash.to_string(),
            "no source".to_string(),
            &SourceTrustPolicyConfig::default(),
        );
        assert_eq!(unknown.status, VerificationStatus::Unknown);
        assert_eq!(
            unknown.status.trust_decision(),
            VerificationTrustDecision::Risk
        );
    }

    #[test]
    fn verifies_downloaded_file_against_checksum_asset() {
        let path = unique_test_path("app.exe");
        fs::write(&path, b"verified payload").unwrap();
        let expected = sha256_file(&path).unwrap();
        let (checksum_url, server) = serve_text_once(format!("{expected}  app.exe\n"));
        let plan = DownloadVerificationPlan {
            asset_name: "app.exe".to_string(),
            checksum_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt".to_string(),
                browser_download_url: checksum_url,
                api_url: None,
            }),
            checksum_signature_asset: None,
            provenance_asset: None,
            provenance_signature_asset: None,
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let report = verify_downloaded_file(
            &client,
            &path,
            "app.exe",
            Some(&plan),
            &SourceTrustPolicyConfig::default(),
        )
        .unwrap();
        let request = server.join().unwrap();

        assert!(request.starts_with("GET /SHA256SUMS.txt HTTP/1.1"));
        assert_eq!(report.status, VerificationStatus::Verified);
        assert_eq!(report.expected_sha256, Some(expected));
        assert_eq!(report.source, Some("SHA256SUMS.txt".to_string()));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verification_asset_fetch_retries_transient_server_failure() {
        let path = unique_test_path("retry-verification-source.exe");
        fs::write(&path, b"verified after retry").unwrap();
        let expected = sha256_file(&path).unwrap();
        let (checksum_url, server) =
            serve_transient_status_then_text("502 Bad Gateway", format!("{expected}  app.exe\n"));
        let plan = DownloadVerificationPlan {
            asset_name: "app.exe".to_string(),
            checksum_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt".to_string(),
                browser_download_url: checksum_url,
                api_url: None,
            }),
            checksum_signature_asset: None,
            provenance_asset: None,
            provenance_signature_asset: None,
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let report = verify_downloaded_file(
            &client,
            &path,
            "app.exe",
            Some(&plan),
            &SourceTrustPolicyConfig::default(),
        )
        .unwrap();
        let requests = server.join().unwrap();

        assert_eq!(requests.len(), 2);
        assert!(requests
            .iter()
            .all(|request| request.starts_with("GET /SHA256SUMS.txt HTTP/1.1")));
        assert_eq!(report.status, VerificationStatus::Verified);
        assert_eq!(report.expected_sha256, Some(expected));
        assert_eq!(report.source, Some("SHA256SUMS.txt".to_string()));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn verifies_downloaded_file_with_good_signed_checksum_source() {
        let path = unique_test_path("signed-app.exe");
        fs::write(&path, b"signed payload").unwrap();
        let expected = sha256_file(&path).unwrap();
        let checksum_text = format!("{expected}  app.exe\n");
        let (public_key, signature_text) = signed_source(&checksum_text);
        let (base_url, server) = serve_text_assets(vec![
            ("SHA256SUMS.txt", checksum_text),
            ("SHA256SUMS.txt.sig", signature_text),
        ]);
        let plan = DownloadVerificationPlan {
            asset_name: "app.exe".to_string(),
            checksum_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt".to_string(),
                browser_download_url: format!("{base_url}/SHA256SUMS.txt"),
                api_url: None,
            }),
            checksum_signature_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt.sig".to_string(),
                browser_download_url: format!("{base_url}/SHA256SUMS.txt.sig"),
                api_url: None,
            }),
            provenance_asset: None,
            provenance_signature_asset: None,
        };
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: true,
            trusted_publisher_key: public_key,
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let report =
            verify_downloaded_file(&client, &path, "app.exe", Some(&plan), &policy).unwrap();
        let requests = server.join().unwrap();

        assert_eq!(requests.len(), 2);
        assert_eq!(report.status, VerificationStatus::Verified);
        assert_eq!(
            report.source_trust.as_ref().map(|trust| trust.status),
            Some(SourceAuthenticityStatus::TrustedSignature)
        );
        assert_eq!(
            report.source_trust.as_ref().map(|trust| trust.decision),
            Some(SourceTrustDecision::Trusted)
        );
        assert_eq!(
            report.effective_trust_decision(),
            VerificationTrustDecision::Trusted
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn blocks_bad_signature_even_when_hash_matches() {
        let path = unique_test_path("bad-signature-app.exe");
        fs::write(&path, b"signed payload").unwrap();
        let expected = sha256_file(&path).unwrap();
        let checksum_text = format!("{expected}  app.exe\n");
        let (public_key, mut signature_text) = signed_source(&checksum_text);
        signature_text.replace_range(0..2, "00");
        let (base_url, server) = serve_text_assets(vec![
            ("SHA256SUMS.txt", checksum_text),
            ("SHA256SUMS.txt.sig", signature_text),
        ]);
        let plan = DownloadVerificationPlan {
            asset_name: "app.exe".to_string(),
            checksum_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt".to_string(),
                browser_download_url: format!("{base_url}/SHA256SUMS.txt"),
                api_url: None,
            }),
            checksum_signature_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt.sig".to_string(),
                browser_download_url: format!("{base_url}/SHA256SUMS.txt.sig"),
                api_url: None,
            }),
            provenance_asset: None,
            provenance_signature_asset: None,
        };
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: false,
            trusted_publisher_key: public_key,
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let report =
            verify_downloaded_file(&client, &path, "app.exe", Some(&plan), &policy).unwrap();
        server.join().unwrap();

        assert_eq!(report.status, VerificationStatus::Verified);
        assert_eq!(
            report.source_trust.as_ref().map(|trust| trust.status),
            Some(SourceAuthenticityStatus::BadSignature)
        );
        assert_eq!(
            report.effective_trust_decision(),
            VerificationTrustDecision::Block
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn required_source_trust_blocks_missing_signature() {
        let path = unique_test_path("missing-signature-app.exe");
        fs::write(&path, b"signed payload").unwrap();
        let expected = sha256_file(&path).unwrap();
        let checksum_text = format!("{expected}  app.exe\n");
        let (public_key, _) = signed_source(&checksum_text);
        let (checksum_url, server) = serve_text_once(checksum_text);
        let plan = DownloadVerificationPlan {
            asset_name: "app.exe".to_string(),
            checksum_asset: Some(VerificationAsset {
                name: "SHA256SUMS.txt".to_string(),
                browser_download_url: checksum_url,
                api_url: None,
            }),
            checksum_signature_asset: None,
            provenance_asset: None,
            provenance_signature_asset: None,
        };
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: true,
            trusted_publisher_key: public_key,
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let report =
            verify_downloaded_file(&client, &path, "app.exe", Some(&plan), &policy).unwrap();
        server.join().unwrap();

        assert_eq!(report.status, VerificationStatus::Verified);
        assert_eq!(
            report.source_trust.as_ref().map(|trust| trust.status),
            Some(SourceAuthenticityStatus::MissingSignature)
        );
        assert_eq!(
            report.effective_trust_decision(),
            VerificationTrustDecision::Block
        );
        let _ = fs::remove_file(path);
    }
}
