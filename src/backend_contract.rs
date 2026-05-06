use crate::core_runtime::{
    CoreClientSettings, CoreDownloadIntent, CoreRuntime, RunDownloadContractInput,
};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

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
pub use crate::update_apply_plan::run_update_apply_plan_contract_selftest;
pub use crate::update_apply_plan::{
    UpdateApplyPlan, UpdateApplyPlanEvidenceRecord, UpdateApplyPlanStatus, UpdateApplyStep,
};
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

impl From<crate::trust_center::TrustCenterSnapshot> for TrustCenterSnapshot {
    fn from(snapshot: crate::trust_center::TrustCenterSnapshot) -> Self {
        Self {
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
}

pub fn resolve_download_intent(input: &str) -> IntentDTO {
    match CoreRuntime::default().resolve_download_intent(input) {
        CoreDownloadIntent::DirectDownload {
            spec,
            human_readable_label,
        } => IntentDTO::DirectDownload {
            spec: DownloadSpec {
                url: spec.url,
                filename: spec.filename,
            },
            human_readable_label,
        },
        CoreDownloadIntent::NeedsAssetPick { query, picker_hint } => {
            IntentDTO::NeedsAssetPick { query, picker_hint }
        }
        CoreDownloadIntent::Unsupported {
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
    CoreRuntime::default().verification_source_summary_for_selected_asset(release, asset_index)
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

    fn core_settings(&self) -> CoreClientSettings {
        CoreClientSettings::new(self.proxy.clone(), self.allow_invalid_certs)
    }
}

pub fn resolve_release_assets_for_query(
    settings: &BackendClientSettings,
    query: &ReleaseQuery,
) -> Result<ResolvedRelease, String> {
    let runtime = CoreRuntime::default();
    let client = runtime
        .build_client(&settings.core_settings(), 30)
        .map_err(|e| format!("Release resolver client error: {e}"))?;
    runtime.resolve_release_assets(&client, None, query)
}

pub fn import_publisher_key_from_release_asset(
    settings: &BackendClientSettings,
    asset: &ReleaseAsset,
) -> Result<ImportedPublisherKeyPin, String> {
    let runtime = CoreRuntime::default();
    let client = runtime
        .build_client(&settings.core_settings(), 30)
        .map_err(|e| format!("Publisher key import client error: {e}"))?;
    runtime.import_publisher_key_from_release_asset(&client, asset)
}

pub fn run_update_candidate_check(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
) -> UpdateCandidateCheckReport {
    let runtime = CoreRuntime::default();
    match runtime.build_client(&settings.core_settings(), 60) {
        Ok(client) => runtime.check_latest_update_candidate(
            &client,
            current_version,
            source_trust_policy,
            evidence_dir,
            None,
        ),
        Err(e) => runtime.refused_update_candidate_check_report(
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
    let runtime = CoreRuntime::default();
    match runtime.build_client(&settings.core_settings(), 60) {
        Ok(client) => runtime.stage_latest_update_candidate(
            &client,
            current_version,
            source_trust_policy,
            evidence_dir,
            stage_root,
            None,
        ),
        Err(e) => runtime.refused_update_candidate_stage_report(
            current_version,
            format!("self-update client build failed: {e}"),
            evidence_dir,
        ),
    }
}

pub fn build_update_apply_plan_for_stage2(
    stage_report: &UpdateCandidateStageReport,
    target_exe_path: &Path,
) -> UpdateApplyPlan {
    CoreRuntime::default().build_update_apply_plan_for_stage2(stage_report, target_exe_path)
}

pub fn record_update_apply_plan_evidence_for_stage2(
    stage_report: &UpdateCandidateStageReport,
    target_exe_path: &Path,
) -> UpdateApplyPlanEvidenceRecord {
    CoreRuntime::default()
        .record_update_apply_plan_evidence_for_stage2(stage_report, target_exe_path)
}

pub fn run_download_contract(
    settings: &BackendClientSettings,
    input: DownloadContractInput,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<DownloadProgressMessage>,
) -> Result<DownloadCompletion, String> {
    let DownloadContractInput {
        effective_url,
        save_path,
        asset_name,
        verification_release,
        verification_asset_index,
        trust_policy,
        publisher_key_source_at_decision,
        history_path,
    } = input;

    let runtime = CoreRuntime::default();
    let client = match runtime.build_client(&settings.core_settings(), 3600) {
        Ok(c) => c,
        Err(e) => {
            let _ = progress_tx.send((0, 0, 0.0, 0.0));
            return Err(format!("Client build error: {e}"));
        }
    };
    let completion = runtime.run_download_contract(RunDownloadContractInput {
        client: &client,
        effective_url: effective_url.as_str(),
        save_path,
        asset_name,
        verification_release,
        verification_asset_index,
        trust_policy,
        publisher_key_source_at_decision,
        history_path,
        ctrl,
        progress_tx,
    })?;

    Ok(DownloadCompletion {
        original_path: completion.original_path,
        trust_center: completion.trust_center.into(),
        evidence_path: completion.evidence_path,
        file_disposition: completion.file_disposition,
    })
}
