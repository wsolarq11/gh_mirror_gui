use crate::core_runtime::{
    CoreClientSettings, CoreDisplayRow, CoreDownloadIntent, CorePathAction, CorePathActionKind,
    CoreRuntime, CoreStatusNotice, CoreStatusNoticeLevel, CoreTrustCenterSnapshot,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendDisplayRow {
    pub label: &'static str,
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendPathActionKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendPathAction {
    pub label: &'static str,
    pub path: String,
    pub missing_message: String,
    pub kind: BackendPathActionKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendStatusNoticeLevel {
    Good,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackendStatusNotice {
    pub level: BackendStatusNoticeLevel,
    pub message: &'static str,
    pub retry_label: Option<&'static str>,
}

fn backend_display_row_from_core(row: CoreDisplayRow) -> BackendDisplayRow {
    BackendDisplayRow {
        label: row.label,
        value: row.value,
    }
}

fn backend_status_notice_from_core(notice: CoreStatusNotice) -> BackendStatusNotice {
    BackendStatusNotice {
        level: match notice.level {
            CoreStatusNoticeLevel::Good => BackendStatusNoticeLevel::Good,
            CoreStatusNoticeLevel::Warning => BackendStatusNoticeLevel::Warning,
            CoreStatusNoticeLevel::Error => BackendStatusNoticeLevel::Error,
        },
        message: notice.message,
        retry_label: notice.retry_label,
    }
}

fn backend_path_action_from_core(action: CorePathAction) -> BackendPathAction {
    BackendPathAction {
        label: action.label,
        path: action.path,
        missing_message: action.missing_message,
        kind: match action.kind {
            CorePathActionKind::File => BackendPathActionKind::File,
            CorePathActionKind::Directory => BackendPathActionKind::Directory,
        },
    }
}

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

fn core_trust_center_snapshot_from_backend(
    snapshot: &TrustCenterSnapshot,
) -> CoreTrustCenterSnapshot {
    CoreTrustCenterSnapshot {
        downloaded_asset: snapshot.downloaded_asset.clone(),
        hash_status: snapshot.hash_status.clone(),
        file_sha256: snapshot.file_sha256.clone(),
        expected_sha256: snapshot.expected_sha256.clone(),
        source_authenticity: snapshot.source_authenticity.clone(),
        source_trust_detail: snapshot.source_trust_detail.clone(),
        source_asset: snapshot.source_asset.clone(),
        signature_asset: snapshot.signature_asset.clone(),
        publisher_key_fingerprint: snapshot.publisher_key_fingerprint.clone(),
        publisher_key_source: snapshot.publisher_key_source.clone(),
        policy_verdict: snapshot.policy_verdict.clone(),
        policy_at_decision: snapshot.policy_at_decision.clone(),
        evidence_path: snapshot.evidence_path.clone(),
        evidence_access: snapshot.evidence_access.clone(),
        file_disposition: snapshot.file_disposition.clone(),
        final_path: snapshot.final_path.clone(),
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
    CoreRuntime::default().official_github_artifact_hosts()
}

pub fn default_history_path() -> PathBuf {
    CoreRuntime::default().default_history_path()
}

pub fn release_query_selector_label(query: &ReleaseQuery) -> String {
    CoreRuntime::default().release_query_selector_label(query)
}

pub fn release_asset_picker_label(asset: &ReleaseAsset) -> String {
    CoreRuntime::default().release_asset_picker_label(asset)
}

pub fn trust_policy_from_settings(
    unknown_keep_file: bool,
    unknown_allow_open: bool,
    mismatch_file_policy: MismatchFilePolicy,
    require_trusted_source: bool,
    trusted_publisher_key: String,
) -> TrustPolicyConfig {
    CoreRuntime::default().trust_policy_from_settings(
        unknown_keep_file,
        unknown_allow_open,
        mismatch_file_policy,
        require_trusted_source,
        trusted_publisher_key,
    )
}

pub fn apply_imported_publisher_key_pin(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
    imported: ImportedPublisherKeyPin,
    source_label: impl Into<String>,
) -> String {
    CoreRuntime::default().apply_imported_publisher_key_pin(
        trust_policy,
        publisher_key_source,
        imported,
        source_label.into(),
    )
}

pub fn source_trust_policy_config(trust_policy: &TrustPolicyConfig) -> SourceTrustPolicyConfig {
    CoreRuntime::default().source_trust_policy_config(trust_policy)
}

pub fn source_trust_requires_signed(trust_policy: &TrustPolicyConfig) -> bool {
    CoreRuntime::default().source_trust_requires_signed(trust_policy)
}

pub fn set_source_trust_requires_signed(
    trust_policy: &mut TrustPolicyConfig,
    require_trusted_source: bool,
) {
    CoreRuntime::default().set_source_trust_requires_signed(trust_policy, require_trusted_source);
}

pub fn trusted_publisher_key_text(trust_policy: &TrustPolicyConfig) -> String {
    CoreRuntime::default().trusted_publisher_key_text(trust_policy)
}

pub fn set_trusted_publisher_key_from_manual_input(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
    trusted_publisher_key: String,
) {
    CoreRuntime::default().set_trusted_publisher_key_from_manual_input(
        trust_policy,
        publisher_key_source,
        trusted_publisher_key,
    );
}

pub fn set_trusted_publisher_key_pin(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
    trusted_publisher_key: String,
    source_label: impl Into<String>,
) -> String {
    CoreRuntime::default().set_trusted_publisher_key_pin(
        trust_policy,
        publisher_key_source,
        trusted_publisher_key,
        source_label.into(),
    )
}

pub fn normalize_trusted_publisher_key(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
) -> Result<String, String> {
    CoreRuntime::default().normalize_trusted_publisher_key(trust_policy, publisher_key_source)
}

pub fn clear_trusted_publisher_key(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
) {
    CoreRuntime::default().clear_trusted_publisher_key(trust_policy, publisher_key_source);
}

pub fn trusted_publisher_key_fingerprint(trust_policy: &TrustPolicyConfig) -> Option<String> {
    CoreRuntime::default().trusted_publisher_key_fingerprint(trust_policy)
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

pub fn source_trust_status_summary(snapshot: &TrustCenterSnapshot) -> String {
    CoreRuntime::default()
        .source_trust_status_summary(&core_trust_center_snapshot_from_backend(snapshot))
}

pub fn download_completion_status(
    snapshot: &TrustCenterSnapshot,
    disposition: &AppliedFileDisposition,
) -> String {
    CoreRuntime::default().download_completion_status(
        &core_trust_center_snapshot_from_backend(snapshot),
        disposition,
    )
}

pub fn download_notification_status(snapshot: &TrustCenterSnapshot) -> String {
    CoreRuntime::default()
        .download_notification_status(&core_trust_center_snapshot_from_backend(snapshot))
}

pub fn last_download_status_notice(snapshot: &TrustCenterSnapshot) -> Option<BackendStatusNotice> {
    CoreRuntime::default()
        .last_download_status_notice(&snapshot.hash_status, &snapshot.policy_verdict)
        .map(backend_status_notice_from_core)
}

pub fn last_download_evidence_action(evidence_path: Option<&Path>) -> Option<BackendPathAction> {
    CoreRuntime::default()
        .last_download_evidence_action(evidence_path)
        .map(backend_path_action_from_core)
}

pub fn last_download_open_location_action(
    snapshot: &TrustCenterSnapshot,
    disposition: &AppliedFileDisposition,
    trust_policy: &TrustPolicyConfig,
    download_path: &Path,
    save_dir: &Path,
) -> Option<BackendPathAction> {
    CoreRuntime::default()
        .last_download_open_location_action(
            &snapshot.hash_status,
            &snapshot.policy_verdict,
            disposition,
            trust_policy,
            download_path,
            save_dir,
        )
        .map(backend_path_action_from_core)
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

pub fn update_candidate_check_status_summary(report: &UpdateCandidateCheckReport) -> String {
    CoreRuntime::default().update_candidate_check_status_summary(report)
}

pub fn update_candidate_check_rows(report: &UpdateCandidateCheckReport) -> Vec<BackendDisplayRow> {
    CoreRuntime::default()
        .update_candidate_check_rows(report)
        .into_iter()
        .map(backend_display_row_from_core)
        .collect()
}

pub fn update_candidate_check_evidence_warning(
    report: &UpdateCandidateCheckReport,
) -> Option<String> {
    CoreRuntime::default().update_candidate_check_evidence_warning(report)
}

pub fn update_candidate_check_evidence_action(
    report: &UpdateCandidateCheckReport,
) -> Option<BackendPathAction> {
    CoreRuntime::default()
        .update_candidate_check_evidence_action(report)
        .map(backend_path_action_from_core)
}

pub fn update_candidate_stage_status_summary(report: &UpdateCandidateStageReport) -> String {
    CoreRuntime::default().update_candidate_stage_status_summary(report)
}

pub fn update_candidate_stage_rows(report: &UpdateCandidateStageReport) -> Vec<BackendDisplayRow> {
    CoreRuntime::default()
        .update_candidate_stage_rows(report)
        .into_iter()
        .map(backend_display_row_from_core)
        .collect()
}

pub fn update_candidate_stage_evidence_warning(
    report: &UpdateCandidateStageReport,
) -> Option<String> {
    CoreRuntime::default().update_candidate_stage_evidence_warning(report)
}

pub fn update_candidate_stage_folder_action(
    report: &UpdateCandidateStageReport,
) -> Option<BackendPathAction> {
    CoreRuntime::default()
        .update_candidate_stage_folder_action(report)
        .map(backend_path_action_from_core)
}

pub fn update_candidate_stage_evidence_action(
    report: &UpdateCandidateStageReport,
) -> Option<BackendPathAction> {
    CoreRuntime::default()
        .update_candidate_stage_evidence_action(report)
        .map(backend_path_action_from_core)
}

pub fn describe_update_apply_step(step: &UpdateApplyStep) -> String {
    CoreRuntime::default().describe_update_apply_step(step)
}

pub fn update_apply_plan_summary_rows(
    plan: &UpdateApplyPlan,
    evidence: Option<&UpdateApplyPlanEvidenceRecord>,
) -> Vec<BackendDisplayRow> {
    CoreRuntime::default()
        .update_apply_plan_summary_rows(plan, evidence)
        .into_iter()
        .map(backend_display_row_from_core)
        .collect()
}

pub fn update_apply_plan_step_rows(plan: &UpdateApplyPlan) -> Vec<String> {
    CoreRuntime::default().update_apply_plan_step_rows(plan)
}

pub fn update_apply_plan_evidence_warning(
    evidence: Option<&UpdateApplyPlanEvidenceRecord>,
) -> Option<String> {
    CoreRuntime::default().update_apply_plan_evidence_warning(evidence)
}

pub fn update_apply_plan_evidence_action(
    evidence: Option<&UpdateApplyPlanEvidenceRecord>,
) -> Option<BackendPathAction> {
    CoreRuntime::default()
        .update_apply_plan_evidence_action(evidence)
        .map(backend_path_action_from_core)
}

pub fn update_apply_plan_missing_evidence_message(
    evidence: Option<&UpdateApplyPlanEvidenceRecord>,
) -> Option<&'static str> {
    CoreRuntime::default().update_apply_plan_missing_evidence_message(evidence)
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

    #[test]
    fn release_display_helpers_keep_ui_out_of_release_variant_formatting() {
        let latest = ReleaseQuery {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            kind: ReleaseQueryKind::Latest,
        };
        let tagged = ReleaseQuery {
            owner: "owner".to_string(),
            repo: "repo".to_string(),
            kind: ReleaseQueryKind::Tag("v1.2.3".to_string()),
        };
        let asset = ReleaseAsset {
            name: "app.zip".to_string(),
            size: 2 * 1024 * 1024,
            browser_download_url: "https://github.com/owner/repo/releases/download/v1/app.zip"
                .to_string(),
            content_type: Some("application/zip".to_string()),
            api_url: None,
        };

        assert_eq!(release_query_selector_label(&latest), "latest");
        assert_eq!(release_query_selector_label(&tagged), "tag v1.2.3");
        assert_eq!(release_asset_picker_label(&asset), "app.zip (2.0 MiB)");
    }

    #[test]
    fn trust_policy_from_settings_keeps_ui_out_of_source_trust_substructure() {
        let policy = trust_policy_from_settings(
            false,
            true,
            MismatchFilePolicy::Delete,
            true,
            "publisher-key".to_string(),
        );

        assert!(!policy.unknown_keep_file);
        assert!(policy.unknown_allow_open);
        assert_eq!(policy.mismatch_file_policy, MismatchFilePolicy::Delete);
        assert!(policy.source_trust.require_trusted_source);
        assert_eq!(policy.source_trust.trusted_publisher_key, "publisher-key");
    }

    #[test]
    fn imported_publisher_key_application_keeps_gui_out_of_pin_result_fields() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = public_key_from_private_seed(private_key).unwrap();
        let fingerprint = trusted_key_fingerprint(&public_key).unwrap();
        let imported = ImportedPublisherKeyPin {
            public_key: public_key.clone(),
            fingerprint_sha256: fingerprint.clone(),
            asset_name: "publisher-key.ed25519.pub".to_string(),
        };
        let mut policy = TrustPolicyConfig::default();
        let mut publisher_key_source = String::new();

        let status = apply_imported_publisher_key_pin(
            &mut policy,
            &mut publisher_key_source,
            imported,
            "GitHub Release owner/repo@v1 asset publisher-key.ed25519.pub",
        );

        assert_eq!(policy.source_trust.trusted_publisher_key, public_key);
        assert_eq!(
            publisher_key_source,
            "GitHub Release owner/repo@v1 asset publisher-key.ed25519.pub"
        );
        assert!(status.contains("publisher-key.ed25519.pub"));
        assert!(status.contains(&fingerprint[..12]));
    }

    #[test]
    fn source_trust_key_helpers_keep_gui_out_of_nested_policy_mutation() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = public_key_from_private_seed(private_key).unwrap();
        let prefixed_key = format!("ed25519:{public_key}");
        let mut policy = TrustPolicyConfig::default();
        let mut source = String::new();

        assert!(!source_trust_requires_signed(&policy));
        set_source_trust_requires_signed(&mut policy, true);
        assert!(source_trust_requires_signed(&policy));

        set_trusted_publisher_key_from_manual_input(&mut policy, &mut source, prefixed_key.clone());
        assert_eq!(source, "manual/pasted key in Trust policy UI");
        assert_eq!(trusted_publisher_key_text(&policy), prefixed_key);

        let status = normalize_trusted_publisher_key(&mut policy, &mut source).unwrap();
        assert_eq!(status, "Normalized Ed25519 publisher key");
        assert_eq!(trusted_publisher_key_text(&policy), public_key);
        assert!(trusted_publisher_key_fingerprint(&policy).is_some());
        assert!(source_trust_policy_config(&policy).require_trusted_source);

        let status = set_trusted_publisher_key_pin(
            &mut policy,
            &mut source,
            public_key,
            "local file C:\\key.pub",
        );
        assert!(status.contains("local file C:\\key.pub"));

        clear_trusted_publisher_key(&mut policy, &mut source);
        assert!(trusted_publisher_key_text(&policy).is_empty());
        assert!(source.is_empty());
    }

    #[test]
    fn update_status_and_apply_step_display_helpers_keep_ui_thin() {
        let check = UpdateCandidateCheckReport {
            schema_version: 1,
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            release_url: "https://github.com/owner/repo/releases/tag/v1.2.3".to_string(),
            asset_name: "gh_mirror_gui.exe".to_string(),
            release_publisher_key_fingerprint_sha256: None,
            evaluation: crate::update_candidate::UpdateCandidateEvaluation {
                schema_version: 1,
                status: crate::update_candidate::UpdateCandidateStatus::Candidate,
                current_version: "0.1.0".to_string(),
                candidate_version: "1.2.3".to_string(),
                release_tag: "v1.2.3".to_string(),
                asset_name: "gh_mirror_gui.exe".to_string(),
                reason: "candidate is newer".to_string(),
                verification_status: "VERIFIED".to_string(),
                file_sha256: None,
                expected_sha256: None,
                verification_source: None,
                source_authenticity_status: None,
                source_trust_decision: None,
                publisher_key_fingerprint_sha256: None,
                evidence_path: Some("check-evidence.json".to_string()),
                no_mutation: true,
            },
            evidence_write_error: Some("check write failed".to_string()),
        };
        let stage = UpdateCandidateStageReport {
            schema_version: 1,
            status: crate::update_candidate::UpdateCandidateStageStatus::Staged,
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            release_url: "https://github.com/owner/repo/releases/tag/v1.2.3".to_string(),
            stage_dir: Some("stage".to_string()),
            staged_asset_path: Some("stage/gh_mirror_gui.exe".to_string()),
            staged_sha256: Some("abc".to_string()),
            expected_sha256: Some("abc".to_string()),
            publisher_key_fingerprint_sha256: None,
            reason: "candidate staged".to_string(),
            no_install: true,
            check_report: check.clone(),
            evidence_path: Some("stage-evidence.json".to_string()),
            evidence_write_error: Some("stage write failed".to_string()),
        };
        let step = UpdateApplyStep::BackupCurrentExecutable {
            from: "current.exe".to_string(),
            to: "current.exe.bak".to_string(),
        };
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: UpdateApplyPlanStatus::Planned,
            reason: "planned staged update apply (no mutation)".to_string(),
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: Some("stage".to_string()),
            staged_asset_path: Some("stage/gh_mirror_gui.exe".to_string()),
            expected_sha256: Some("abc".to_string()),
            target_exe_path: Some("current.exe".to_string()),
            backup_exe_path: Some("current.exe.bak".to_string()),
            reversible: true,
            no_mutation: true,
            steps: vec![step.clone()],
        };
        let evidence = UpdateApplyPlanEvidenceRecord {
            schema_version: 1,
            ok: true,
            no_mutation: true,
            stage_dir: Some("stage".to_string()),
            evidence_path: Some("apply-plan.json".to_string()),
            write_error: Some("apply write failed".to_string()),
            plan: plan.clone(),
        };

        assert_eq!(
            update_candidate_check_status_summary(&check),
            "Self-update check: candidate (candidate is newer)"
        );
        assert_eq!(
            update_candidate_stage_status_summary(&stage),
            "Self-update stage: staged (candidate staged)"
        );
        let check_rows = update_candidate_check_rows(&check);
        assert!(check_rows.contains(&BackendDisplayRow {
            label: "Release",
            value: "owner/repo @ v1.2.3".to_string()
        }));
        assert!(check_rows.contains(&BackendDisplayRow {
            label: "Reason",
            value: "candidate is newer".to_string()
        }));
        assert!(check_rows.contains(&BackendDisplayRow {
            label: "No mutation",
            value: "true".to_string()
        }));
        assert_eq!(
            update_candidate_check_evidence_warning(&check),
            Some("Evidence write warning: check write failed".to_string())
        );
        assert_eq!(
            update_candidate_check_evidence_action(&check),
            Some(BackendPathAction {
                label: "📄 Open Update Evidence",
                path: "check-evidence.json".to_string(),
                missing_message: "Update evidence path is recorded but not present on disk."
                    .to_string(),
                kind: BackendPathActionKind::File
            })
        );

        let stage_rows = update_candidate_stage_rows(&stage);
        assert!(stage_rows.contains(&BackendDisplayRow {
            label: "Stage dir",
            value: "stage".to_string()
        }));
        assert!(stage_rows.contains(&BackendDisplayRow {
            label: "Staged asset",
            value: "stage/gh_mirror_gui.exe".to_string()
        }));
        assert_eq!(
            update_candidate_stage_evidence_warning(&stage),
            Some("Evidence write warning: stage write failed".to_string())
        );
        assert_eq!(
            update_candidate_stage_folder_action(&stage),
            Some(BackendPathAction {
                label: "📁 Open stage folder",
                path: "stage".to_string(),
                missing_message: "Stage folder path is recorded but not present on disk."
                    .to_string(),
                kind: BackendPathActionKind::Directory
            })
        );
        assert_eq!(
            update_candidate_stage_evidence_action(&stage),
            Some(BackendPathAction {
                label: "📄 Open stage evidence",
                path: "stage-evidence.json".to_string(),
                missing_message: "Stage evidence path is recorded but not present on disk."
                    .to_string(),
                kind: BackendPathActionKind::File
            })
        );
        assert_eq!(
            describe_update_apply_step(&step),
            "Backup current executable current.exe -> current.exe.bak"
        );

        let plan_rows = update_apply_plan_summary_rows(&plan, Some(&evidence));
        assert!(plan_rows.contains(&BackendDisplayRow {
            label: "Status",
            value: "planned".to_string()
        }));
        assert!(plan_rows.contains(&BackendDisplayRow {
            label: "Evidence path",
            value: "apply-plan.json".to_string()
        }));
        assert!(plan_rows.contains(&BackendDisplayRow {
            label: "Steps",
            value: "1".to_string()
        }));
        assert_eq!(
            update_apply_plan_step_rows(&plan),
            vec!["1: Backup current executable current.exe -> current.exe.bak".to_string()]
        );
        assert_eq!(
            update_apply_plan_evidence_warning(Some(&evidence)),
            Some("Evidence write warning: apply write failed".to_string())
        );
        assert_eq!(
            update_apply_plan_evidence_action(Some(&evidence)),
            Some(BackendPathAction {
                label: "📄 Open apply plan evidence",
                path: "apply-plan.json".to_string(),
                missing_message: "Apply plan evidence path is recorded but not present on disk."
                    .to_string(),
                kind: BackendPathActionKind::File
            })
        );
        assert_eq!(
            update_apply_plan_missing_evidence_message(None),
            Some("Apply plan evidence is not recorded for this preview.")
        );
    }

    #[test]
    fn last_download_display_helpers_keep_gui_out_of_trust_decision_formatting() {
        let mut snapshot = TrustCenterSnapshot {
            downloaded_asset: "app.exe".to_string(),
            hash_status: "VERIFIED".to_string(),
            file_sha256: "abc".to_string(),
            expected_sha256: "abc".to_string(),
            source_authenticity: "trusted".to_string(),
            source_trust_detail: "trusted source".to_string(),
            source_asset: "SHA256SUMS.txt".to_string(),
            signature_asset: "SHA256SUMS.txt.sig".to_string(),
            publisher_key_fingerprint: "fingerprint".to_string(),
            publisher_key_source: "pinned".to_string(),
            policy_verdict: "TRUSTED".to_string(),
            policy_at_decision: "policy".to_string(),
            evidence_path: "evidence.json".to_string(),
            evidence_access: "openable".to_string(),
            file_disposition: "file kept".to_string(),
            final_path: "C:\\downloads\\app.exe".to_string(),
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("C:\\downloads\\app.exe"),
            final_path: Some(PathBuf::from("C:\\downloads\\app.exe")),
        };

        assert_eq!(
            last_download_status_notice(&snapshot),
            Some(BackendStatusNotice {
                level: BackendStatusNoticeLevel::Good,
                message: "Trusted: checksum/provenance hash and source policy passed.",
                retry_label: None
            })
        );
        assert_eq!(
            source_trust_status_summary(&snapshot),
            "trusted decision=TRUSTED via SHA256SUMS.txt.sig key=fingerprint"
        );
        assert!(download_completion_status(&snapshot, &disposition).contains("Download complete"));
        assert_eq!(
            download_notification_status(&snapshot),
            "Download complete (VERIFIED)"
        );
        assert_eq!(
            last_download_evidence_action(Some(Path::new("evidence.json"))),
            Some(BackendPathAction {
                label: "📄 Open Evidence",
                path: "evidence.json".to_string(),
                missing_message: "Evidence path recorded but file is missing: evidence.json"
                    .to_string(),
                kind: BackendPathActionKind::File
            })
        );
        assert_eq!(
            last_download_open_location_action(
                &snapshot,
                &disposition,
                &TrustPolicyConfig::default(),
                Path::new("C:\\downloads\\app.exe"),
                Path::new("C:\\downloads"),
            ),
            Some(BackendPathAction {
                label: "📂 Open Folder",
                path: "C:\\downloads".to_string(),
                missing_message:
                    "Download folder is recorded but not present on disk: C:\\downloads".to_string(),
                kind: BackendPathActionKind::Directory
            })
        );

        snapshot.policy_verdict = "BLOCK".to_string();
        assert_eq!(
            last_download_status_notice(&snapshot),
            Some(BackendStatusNotice {
                level: BackendStatusNoticeLevel::Error,
                message:
                    "Blocked: checksum matched, but verification source signature is not trusted.",
                retry_label: Some("🔁 Retry Download")
            })
        );
        assert!(
            download_completion_status(&snapshot, &disposition).contains("Verification BLOCKED")
        );
        assert_eq!(
            download_notification_status(&snapshot),
            "Download blocked (UNTRUSTED SOURCE)"
        );
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
