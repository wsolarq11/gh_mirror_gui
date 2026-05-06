use crate::core_runtime::{
    CoreClientSettings, CoreDownloadIntent, CoreRuntime, CoreTrustCenterSnapshot,
    RunDownloadContractInput,
};
use std::path::Path;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};

// ---------------------------------------------------------------------------
// Public backend contract surface (the single runtime "door")
// ---------------------------------------------------------------------------

pub use crate::download::DownloadControl;
pub use crate::releases::{ReleaseAsset, ReleaseQuery, ReleaseQueryKind, ResolvedRelease};
pub use crate::source_trust::ImportedPublisherKeyPin;
pub use crate::source_trust::SourceTrustPolicyConfig;
pub use crate::trust_policy::{AppliedFileDisposition, FileDispositionAction};
pub use crate::trust_policy::{MismatchFilePolicy, TrustPolicyConfig};
pub use crate::update_apply_plan::{
    UpdateApplyPlan, UpdateApplyPlanEvidenceRecord, UpdateApplyPlanStatus, UpdateApplyStep,
};
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

impl From<CoreTrustCenterSnapshot> for TrustCenterSnapshot {
    fn from(snapshot: CoreTrustCenterSnapshot) -> Self {
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

pub fn default_history_path() -> PathBuf {
    CoreRuntime::default().default_history_path()
}

pub fn publisher_key_source_label_for_policy(
    trust_policy: &TrustPolicyConfig,
    publisher_key_source: &str,
) -> String {
    CoreRuntime::default().publisher_key_source_label_for_policy(trust_policy, publisher_key_source)
}

pub fn open_location_button_label_for_facts(
    hash_status: &str,
    policy_verdict: &str,
    disposition: &AppliedFileDisposition,
    policy: &TrustPolicyConfig,
) -> Option<&'static str> {
    CoreRuntime::default().open_location_button_label_for_facts(
        hash_status,
        policy_verdict,
        disposition,
        policy,
    )
}

pub fn file_disposition_summary(disposition: &AppliedFileDisposition) -> String {
    CoreRuntime::default().file_disposition_summary(disposition)
}

pub fn public_key_from_private_seed(private_key_text: &str) -> Result<String, String> {
    CoreRuntime::default().public_key_from_private_seed(private_key_text)
}

pub fn sign_ed25519_detached(message: &[u8], private_key_text: &str) -> Result<String, String> {
    CoreRuntime::default().sign_ed25519_detached(message, private_key_text)
}

pub fn verify_ed25519_detached(
    message: &[u8],
    signature_text: &str,
    public_key_text: &str,
) -> Result<(), String> {
    CoreRuntime::default().verify_ed25519_detached(message, signature_text, public_key_text)
}

pub fn normalize_public_key_pin(public_key_text: &str) -> Result<String, String> {
    CoreRuntime::default().normalize_public_key_pin(public_key_text)
}

pub fn trusted_key_fingerprint(public_key_text: &str) -> Option<String> {
    CoreRuntime::default().trusted_key_fingerprint(public_key_text)
}

pub fn run_bench_download(args: &[String]) -> Result<(), String> {
    CoreRuntime::default().run_bench_download(args)
}

pub fn run_staged_release_download_selftest(args: &[String]) -> Result<(), String> {
    CoreRuntime::default().run_staged_release_download_selftest(args)
}

pub fn run_update_candidate_contract_selftest(args: &[String]) -> Result<(), String> {
    CoreRuntime::default().run_update_candidate_contract_selftest(args)
}

pub fn run_update_candidate_latest_selftest(args: &[String]) -> Result<(), String> {
    CoreRuntime::default().run_update_candidate_latest_selftest(args)
}

pub fn run_update_candidate_stage_selftest(args: &[String]) -> Result<(), String> {
    CoreRuntime::default().run_update_candidate_stage_selftest(args)
}

pub fn run_update_apply_plan_contract_selftest(args: &[String]) -> Result<(), String> {
    CoreRuntime::default().run_update_apply_plan_contract_selftest(args)
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
    CoreRuntime::default().resolve_release_assets_for_query(&settings.core_settings(), query)
}

pub fn import_publisher_key_from_release_asset(
    settings: &BackendClientSettings,
    asset: &ReleaseAsset,
) -> Result<ImportedPublisherKeyPin, String> {
    CoreRuntime::default()
        .import_publisher_key_from_release_asset_for_settings(&settings.core_settings(), asset)
}

pub fn run_update_candidate_check(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
) -> UpdateCandidateCheckReport {
    CoreRuntime::default().run_update_candidate_check(
        &settings.core_settings(),
        current_version,
        source_trust_policy,
        evidence_dir,
    )
}

pub fn run_update_candidate_stage(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
    stage_root: &Path,
) -> UpdateCandidateStageReport {
    CoreRuntime::default().run_update_candidate_stage(
        &settings.core_settings(),
        current_version,
        source_trust_policy,
        evidence_dir,
        stage_root,
    )
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

    let core_settings = settings.core_settings();
    let completion = CoreRuntime::default().run_download_contract(RunDownloadContractInput {
        settings: &core_settings,
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
