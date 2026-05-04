use crate::bench::choose_history_backed_strategy;
use crate::download::{
    build_client, download_with_strategy, probe_download, DownloadControl, DownloadProbe,
};
use crate::history::{append_download_history, load_bench_history, VerificationHistoryContext};
use crate::releases::ReleaseAsset;
use crate::releases::{resolve_release_assets, ReleaseQuery, ResolvedRelease};
use crate::source_trust::SourceTrustPolicyConfig;
use crate::source_trust::{import_publisher_key_pin_from_release_asset, ImportedPublisherKeyPin};
use crate::trust_policy::{
    apply_file_disposition, plan_file_disposition_for_report, AppliedFileDisposition,
    TrustPolicyConfig, TrustPolicySnapshot,
};
use crate::update_candidate::{
    check_latest_update_candidate, refused_update_candidate_check_report,
    refused_update_candidate_stage_report, stage_latest_update_candidate,
};
use crate::update_candidate::{UpdateCandidateCheckReport, UpdateCandidateStageReport};
use crate::verification::{verify_downloaded_file, DownloadVerificationPlan, VerificationReport};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::time::Instant;

pub(crate) type DownloadProgressMessage = (u64, u64, f64, f64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DownloadCompletion {
    pub(crate) original_path: PathBuf,
    pub(crate) verification: VerificationReport,
    pub(crate) evidence_path: Option<PathBuf>,
    pub(crate) policy_snapshot: TrustPolicySnapshot,
    pub(crate) publisher_key_source_at_decision: String,
    pub(crate) file_disposition: AppliedFileDisposition,
}

pub(crate) struct DownloadContractInput {
    pub(crate) effective_url: String,
    pub(crate) save_path: PathBuf,
    pub(crate) asset_name: String,
    pub(crate) verification_plan: Option<DownloadVerificationPlan>,
    pub(crate) trust_policy: TrustPolicyConfig,
    pub(crate) publisher_key_source_at_decision: String,
    pub(crate) history_path: PathBuf,
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

pub(crate) struct BackendClientSettings {
    pub(crate) proxy: String,
    pub(crate) allow_invalid_certs: bool,
}

impl BackendClientSettings {
    pub(crate) fn new(proxy: String, allow_invalid_certs: bool) -> Self {
        Self {
            proxy,
            allow_invalid_certs,
        }
    }

    fn client(&self, timeout_secs: u64) -> Result<reqwest::blocking::Client, String> {
        build_client(&self.proxy, timeout_secs, self.allow_invalid_certs)
    }
}

pub(crate) fn resolve_release_assets_for_query(
    settings: &BackendClientSettings,
    query: &ReleaseQuery,
) -> Result<ResolvedRelease, String> {
    let client = settings
        .client(30)
        .map_err(|e| format!("Release resolver client error: {e}"))?;
    resolve_release_assets(&client, query)
}

pub(crate) fn import_publisher_key_from_release_asset(
    settings: &BackendClientSettings,
    asset: &ReleaseAsset,
) -> Result<ImportedPublisherKeyPin, String> {
    let client = settings
        .client(30)
        .map_err(|e| format!("Publisher key import client error: {e}"))?;
    import_publisher_key_pin_from_release_asset(&client, asset)
}

pub(crate) fn run_update_candidate_check(
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

pub(crate) fn run_update_candidate_stage(
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

pub(crate) fn run_download_contract(
    settings: &BackendClientSettings,
    input: DownloadContractInput,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<DownloadProgressMessage>,
) -> Result<DownloadCompletion, String> {
    let effective_url = input.effective_url.as_str();
    let save_path = input.save_path;
    let asset_name = input.asset_name;
    let verification_plan = input.verification_plan;
    let trust_policy = input.trust_policy;
    let publisher_key_source_at_decision = input.publisher_key_source_at_decision;
    let history_path = input.history_path;

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

    let verification = match verify_downloaded_file(
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

    Ok(DownloadCompletion {
        original_path: save_path,
        verification,
        evidence_path,
        policy_snapshot: trust_policy.snapshot(),
        publisher_key_source_at_decision,
        file_disposition,
    })
}
