use crate::bench::choose_history_backed_strategy;
use crate::download::{build_client, download_with_strategy, probe_download, DownloadProbe};
use crate::github_intent::{parse_github_intent, ParsedGithubIntent};
use crate::history::{append_download_history, load_bench_history, VerificationHistoryContext};
use crate::source_adapter::{GitHubReleaseAdapter, SourceAdapter};
use crate::source_trust::import_publisher_key_pin_from_release_asset;
use crate::trust_policy::{apply_file_disposition, plan_file_disposition_for_report};
use crate::update_candidate::{
    check_latest_update_candidate, refused_update_candidate_check_report,
    refused_update_candidate_stage_report, stage_latest_update_candidate,
};
use crate::verifier_adapter::{GitHubReleaseVerifierAdapter, VerifierAdapter};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Instant;

// ---------------------------------------------------------------------------
// Public backend contract surface (the single runtime "door")
// ---------------------------------------------------------------------------

pub use crate::bench::run_bench_download;
pub use crate::download::DownloadControl;
pub use crate::history::default_history_path;
pub use crate::releases::{ReleaseAsset, ReleaseQuery, ReleaseQueryKind, ResolvedRelease};
pub use crate::source_trust::public_key_from_private_seed;
pub use crate::source_trust::sign_ed25519_detached;
pub use crate::source_trust::verify_ed25519_detached;
pub use crate::source_trust::ImportedPublisherKeyPin;
pub use crate::source_trust::SourceTrustPolicyConfig;
pub use crate::source_trust::{normalize_public_key_pin, trusted_key_fingerprint};
pub use crate::staged_release::run_staged_release_download_selftest;
pub use crate::trust_center::publisher_key_source_label_for_policy;
pub use crate::trust_policy::file_disposition_summary;
pub use crate::trust_policy::open_location_button_label_for_facts;
pub use crate::trust_policy::{AppliedFileDisposition, FileDispositionAction};
pub use crate::trust_policy::{MismatchFilePolicy, TrustPolicyConfig};
pub use crate::update_candidate::run_update_candidate_contract_selftest;
pub use crate::update_candidate::run_update_candidate_latest_selftest;
pub use crate::update_candidate::run_update_candidate_stage_selftest;
pub use crate::update_candidate::{UpdateCandidateCheckReport, UpdateCandidateStageReport};

pub type DownloadProgressMessage = (u64, u64, f64, f64);

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DownloadSpec {
    pub url: String,
    pub filename: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IntentDTO {
    DirectDownload {
        spec: DownloadSpec,
        human_readable_label: String,
    },
    NeedsAssetPick {
        query: ReleaseQuery,
        picker_hint: Option<String>,
    },
    Unsupported {
        reason: String,
        suggested_examples: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustCenterSnapshot {
    pub downloaded_asset: String,
    pub hash_status: String,
    pub file_sha256: String,
    pub expected_sha256: String,
    pub source_authenticity: String,
    pub source_trust_detail: String,
    pub source_asset: String,
    pub signature_asset: String,
    pub publisher_key_fingerprint: String,
    pub publisher_key_source: String,
    pub policy_verdict: String,
    pub policy_at_decision: String,
    pub evidence_path: String,
    pub evidence_access: String,
    pub file_disposition: String,
    pub final_path: String,
}

fn trust_center_snapshot(
    report: &crate::verification::VerificationReport,
    evidence_path: Option<&Path>,
    disposition: &AppliedFileDisposition,
    policy_snapshot: &crate::trust_policy::TrustPolicySnapshot,
    publisher_key_source: Option<&str>,
) -> TrustCenterSnapshot {
    let snapshot = crate::trust_center::trust_center_snapshot(
        report,
        evidence_path,
        disposition,
        policy_snapshot,
        publisher_key_source,
    );

    TrustCenterSnapshot {
        downloaded_asset: snapshot.downloaded_asset,
        hash_status: snapshot.hash_status,
        file_sha256: snapshot.file_sha256,
        expected_sha256: snapshot.expected_sha256,
        source_authenticity: snapshot.source_authenticity,
        source_trust_detail: snapshot.source_trust_detail,
        source_asset: snapshot.source_asset,
        signature_asset: snapshot.signature_asset,
        publisher_key_fingerprint: snapshot.publisher_key_fingerprint,
        publisher_key_source: snapshot.publisher_key_source,
        policy_verdict: snapshot.policy_verdict,
        policy_at_decision: snapshot.policy_at_decision,
        evidence_path: snapshot.evidence_path,
        evidence_access: snapshot.evidence_access,
        file_disposition: snapshot.file_disposition,
        final_path: snapshot.final_path,
    }
}

pub fn resolve_download_intent(input: &str) -> IntentDTO {
    match parse_github_intent(input) {
        ParsedGithubIntent::DirectDownload {
            url,
            filename,
            label,
        } => IntentDTO::DirectDownload {
            spec: DownloadSpec { url, filename },
            human_readable_label: label,
        },
        ParsedGithubIntent::ReleaseQuery { query, picker_hint } => {
            IntentDTO::NeedsAssetPick { query, picker_hint }
        }
        ParsedGithubIntent::Unsupported {
            reason,
            suggested_examples,
        } => IntentDTO::Unsupported {
            reason,
            suggested_examples,
        },
    }
}

pub fn official_github_artifact_hosts() -> &'static [&'static str] {
    crate::url_policy::official_github_artifact_hosts()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_download_intent_rejects_non_github_hosts() {
        let intent = resolve_download_intent("https://example.com/file.zip");
        assert!(
            matches!(intent, IntentDTO::Unsupported { .. }),
            "expected Unsupported, got: {intent:?}"
        );
    }

    #[test]
    fn official_github_artifact_hosts_contains_core_hosts() {
        let hosts = official_github_artifact_hosts();
        assert!(hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case("github.com")));
        assert!(hosts
            .iter()
            .any(|host| host.eq_ignore_ascii_case("api.github.com")));
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DownloadCompletion {
    pub original_path: PathBuf,
    pub trust_center: TrustCenterSnapshot,
    pub evidence_path: Option<PathBuf>,
    pub file_disposition: AppliedFileDisposition,
}

pub struct DownloadContractInput {
    pub effective_url: String,
    pub save_path: PathBuf,
    pub asset_name: String,
    /// Optional GitHub release context that enables checksum/provenance discovery for verification.
    /// When absent, verification will be UNKNOWN.
    pub verification_release: Option<ResolvedRelease>,
    pub verification_asset_index: Option<usize>,
    pub trust_policy: TrustPolicyConfig,
    pub publisher_key_source_at_decision: String,
    pub history_path: PathBuf,
}

pub fn verification_source_summary_for_release_asset(
    release: &ResolvedRelease,
    asset_index: usize,
) -> String {
    GitHubReleaseVerifierAdapter
        .verification_plan_for_selected_asset(release, asset_index)
        .map(|plan| crate::verification::verification_source_summary(&plan))
        .unwrap_or_else(|| {
            "No checksum/provenance assets detected; result will be UNKNOWN".to_string()
        })
}

fn log_error(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("download_error.log")
    {
        use std::io::Write;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}

pub struct BackendClientSettings {
    proxy: String,
    allow_invalid_certs: bool,
}

impl BackendClientSettings {
    pub fn new(proxy: String, allow_invalid_certs: bool) -> Self {
        Self {
            proxy,
            allow_invalid_certs,
        }
    }

    fn client(&self, timeout_secs: u64) -> Result<reqwest::blocking::Client, String> {
        build_client(&self.proxy, timeout_secs, self.allow_invalid_certs)
    }
}

pub fn resolve_release_assets_for_query(
    settings: &BackendClientSettings,
    query: &ReleaseQuery,
) -> Result<ResolvedRelease, String> {
    let client = settings
        .client(30)
        .map_err(|e| format!("Release resolver client error: {e}"))?;
    GitHubReleaseAdapter.resolve_release_assets(&client, None, query)
}

pub fn import_publisher_key_from_release_asset(
    settings: &BackendClientSettings,
    asset: &ReleaseAsset,
) -> Result<ImportedPublisherKeyPin, String> {
    let client = settings
        .client(30)
        .map_err(|e| format!("Publisher key import client error: {e}"))?;
    import_publisher_key_pin_from_release_asset(&client, asset)
}

pub fn run_update_candidate_check(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
) -> UpdateCandidateCheckReport {
    match settings.client(60) {
        Ok(client) => check_latest_update_candidate(
            &client,
            crate::update_candidate::UpdateCandidateCheckConfig {
                current_version,
                source_trust_policy,
                evidence_dir,
                api_base: None,
            },
        ),
        Err(e) => refused_update_candidate_check_report(
            current_version,
            format!("self-update client build failed: {e}"),
            evidence_dir,
        ),
    }
}

pub fn run_update_candidate_stage(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
    stage_root: &Path,
) -> UpdateCandidateStageReport {
    match settings.client(60) {
        Ok(client) => stage_latest_update_candidate(
            &client,
            crate::update_candidate::UpdateCandidateStageConfig {
                current_version,
                source_trust_policy,
                evidence_dir,
                stage_root,
                api_base: None,
            },
        ),
        Err(e) => refused_update_candidate_stage_report(
            current_version,
            format!("self-update client build failed: {e}"),
            evidence_dir,
        ),
    }
}

pub fn run_download_contract(
    settings: &BackendClientSettings,
    input: DownloadContractInput,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<DownloadProgressMessage>,
) -> Result<DownloadCompletion, String> {
    let effective_url = input.effective_url.as_str();
    let save_path = input.save_path;
    let asset_name = input.asset_name;
    let verification_release = input.verification_release;
    let verification_asset_index = input.verification_asset_index;
    let trust_policy = input.trust_policy;
    let publisher_key_source_at_decision = input.publisher_key_source_at_decision;
    let history_path = input.history_path;

    crate::url_policy::parse_and_validate_https_github_official_url(effective_url, "download url")?;

    let client = match settings.client(3600) {
        Ok(c) => c,
        Err(e) => {
            log_error(&format!("build_client error: {e}"));
            let _ = progress_tx.send((0, 0, 0.0, 0.0));
            return Err(format!("Client build error: {e}"));
        }
    };

    let probe = match probe_download(&client, effective_url) {
        Ok(probe) => probe,
        Err(e) => {
            log_error(&format!("probe_download error: {e}"));
            DownloadProbe {
                total: 0,
                range_supported: false,
                etag: None,
                last_modified: None,
            }
        }
    };

    let history = load_bench_history(&Some(history_path.clone()), effective_url, &probe);
    let strategy = choose_history_backed_strategy(&probe, &history);
    let save_path_str = save_path.to_string_lossy().to_string();
    let download_start = Instant::now();

    let verification_plan = match (verification_release.as_ref(), verification_asset_index) {
        (None, None) => None,
        (Some(release), Some(idx)) => {
            if release.assets.get(idx).is_none() {
                return Err(format!(
                    "Download verification context is invalid: asset index {idx} is out of range (assets={})",
                    release.assets.len()
                ));
            }
            GitHubReleaseVerifierAdapter.verification_plan_for_selected_asset(release, idx)
        }
        _ => {
            return Err(
                "Download verification context is inconsistent (release + asset index must be both set or both absent)"
                    .to_string(),
            );
        }
    };

    if let Err(e) = download_with_strategy(
        &client,
        effective_url,
        &save_path_str,
        &probe,
        &strategy,
        ctrl,
        progress_tx,
    ) {
        log_error(&format!("download_file error: {e}"));
        let _ = progress_tx.send((0, 0, 0.0, 0.0));
        return Err(e);
    }

    // Ensure the UI sees a non-error completion progress event even when the probe could
    // not determine a total size (probe.total == 0). Otherwise the (0,0) sentinel would
    // be indistinguishable from failure.
    let downloaded_bytes = fs::metadata(&save_path).map(|meta| meta.len()).unwrap_or(0);
    let done_total = if downloaded_bytes > 0 {
        downloaded_bytes
    } else if probe.total > 0 {
        probe.total
    } else {
        1
    };
    let _ = progress_tx.send((done_total, done_total, 0.0, 0.0));

    let verification = match GitHubReleaseVerifierAdapter.verify_downloaded_file(
        &client,
        &save_path,
        &asset_name,
        verification_plan.as_ref(),
        &trust_policy.source_trust,
    ) {
        Ok(report) => report,
        Err(e) => {
            log_error(&format!("verify_downloaded_file error: {e}"));
            return Err(format!(
                "Download completed but SHA256 verification failed: {e}"
            ));
        }
    };

    let disposition_plan =
        plan_file_disposition_for_report(&save_path, &verification, &trust_policy);
    let evidence_path = match append_download_history(
        &Some(history_path.clone()),
        effective_url,
        &save_path,
        &probe,
        &strategy,
        download_start.elapsed(),
        Some(VerificationHistoryContext {
            report: &verification,
            policy: &trust_policy,
            file_disposition: &disposition_plan,
        }),
    ) {
        Ok(evidence_path) => evidence_path,
        Err(e) => {
            log_error(&format!("append_download_history error: {e}"));
            None
        }
    };

    let file_disposition = match apply_file_disposition(&disposition_plan) {
        Ok(disposition) => disposition,
        Err(e) => {
            log_error(&format!("apply_file_disposition error: {e}"));
            return Err(format!(
                "Download completed but trust policy file disposition failed: {e}"
            ));
        }
    };

    let policy_snapshot = trust_policy.snapshot();
    let publisher_key_source = if publisher_key_source_at_decision.trim().is_empty() {
        None
    } else {
        Some(publisher_key_source_at_decision.as_str())
    };
    let trust_center = trust_center_snapshot(
        &verification,
        evidence_path.as_deref(),
        &file_disposition,
        &policy_snapshot,
        publisher_key_source,
    );

    Ok(DownloadCompletion {
        original_path: save_path,
        trust_center,
        evidence_path,
        file_disposition,
    })
}
