use crate::update_apply_plan::{UpdateApplyPlan, UpdateApplyPlanStatus, UpdateApplyStep};
use crate::update_candidate::{UpdateCandidateStageReport, UpdateCandidateStageStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const UPDATE_APPLY_READINESS_MODULE_OWNER: &str = "src/update_apply_readiness.rs";
const UPDATE_APPLY_READINESS_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateApplyReadinessStatus {
    Refused,
    ReadyForManualApply,
    Blocked,
    Unknown,
    StaleStage,
    ApprovalRequired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ManualApprovalState {
    NotRequested,
    Required,
    Granted,
    Expired,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyReadinessRecord {
    pub schema_version: u32,
    pub ok: bool,
    pub module_owner: String,
    pub no_live_mutation: bool,
    pub apply_performed: bool,
    pub install_performed: bool,
    pub status: UpdateApplyReadinessStatus,
    pub reason: String,
    pub repo: String,
    pub release_tag: String,
    pub stage_dir: Option<String>,
    pub stage_evidence_path: Option<String>,
    pub stage_status: String,
    pub staged_asset_path: Option<String>,
    pub expected_sha256: Option<String>,
    pub staged_sha256: Option<String>,
    pub verification_status: Option<String>,
    pub source_authenticity_status: Option<String>,
    pub source_trust_decision: Option<String>,
    pub publisher_key_fingerprint_sha256: Option<String>,
    pub target_current_exe_path: Option<String>,
    pub target_canonical_path: Option<String>,
    pub staged_asset_canonical_path: Option<String>,
    pub backup_destination_path: Option<String>,
    pub backup_boundary_path: Option<String>,
    pub rollback_plan: Vec<String>,
    pub manual_approval_state: ManualApprovalState,
    pub refusal_reasons: Vec<String>,
    pub evidence_path: Option<String>,
    pub write_error: Option<String>,
    pub plan: UpdateApplyPlan,
}

pub(crate) fn readiness_status_label(status: UpdateApplyReadinessStatus) -> &'static str {
    match status {
        UpdateApplyReadinessStatus::Refused => "refused",
        UpdateApplyReadinessStatus::ReadyForManualApply => "ready-for-manual-apply",
        UpdateApplyReadinessStatus::Blocked => "blocked",
        UpdateApplyReadinessStatus::Unknown => "unknown",
        UpdateApplyReadinessStatus::StaleStage => "stale-stage",
        UpdateApplyReadinessStatus::ApprovalRequired => "approval-required",
    }
}

fn unique_update_apply_readiness_selftest_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gh_mirror_gui_update_apply_readiness_selftest_{}_{}",
        std::process::id(),
        nonce
    ))
}

fn sha256_file_upper(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("Read {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:X}", hasher.finalize()))
}

fn paths_equal_if_available(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

fn path_is_within_if_available(child: &Path, parent: &Path) -> bool {
    match (child.canonicalize(), parent.canonicalize()) {
        (Ok(child), Ok(parent)) => child.starts_with(parent),
        _ => child.starts_with(parent),
    }
}

fn canonical_display(path: &Path) -> Option<String> {
    path.canonicalize()
        .ok()
        .map(|path| path.display().to_string())
}

fn backup_path_for_target_in_dir(
    target_current_exe_path: &Path,
    backup_boundary_dir: &Path,
) -> Result<PathBuf, String> {
    let file_name = target_current_exe_path
        .file_name()
        .ok_or_else(|| "target exe path has no file name".to_string())?
        .to_string_lossy()
        .to_string();
    Ok(backup_boundary_dir.join(format!("{file_name}.bak-readiness")))
}

fn empty_plan(
    stage_report: &UpdateCandidateStageReport,
    target_current_exe_path: &Path,
) -> UpdateApplyPlan {
    UpdateApplyPlan {
        schema_version: 1,
        status: UpdateApplyPlanStatus::Refused,
        reason: "live apply readiness not proven".to_string(),
        repo: stage_report.repo.clone(),
        release_tag: stage_report.release_tag.clone(),
        stage_dir: stage_report.stage_dir.clone(),
        staged_asset_path: stage_report.staged_asset_path.clone(),
        expected_sha256: stage_report.expected_sha256.clone(),
        target_exe_path: Some(target_current_exe_path.display().to_string()),
        backup_exe_path: None,
        reversible: false,
        no_mutation: true,
        steps: Vec::new(),
    }
}

fn base_record(
    stage_report: &UpdateCandidateStageReport,
    target_current_exe_path: &Path,
    manual_approval_state: ManualApprovalState,
) -> UpdateApplyReadinessRecord {
    UpdateApplyReadinessRecord {
        schema_version: UPDATE_APPLY_READINESS_SCHEMA_VERSION,
        ok: false,
        module_owner: UPDATE_APPLY_READINESS_MODULE_OWNER.to_string(),
        no_live_mutation: true,
        apply_performed: false,
        install_performed: false,
        status: UpdateApplyReadinessStatus::Refused,
        reason: "live apply readiness not proven".to_string(),
        repo: stage_report.repo.clone(),
        release_tag: stage_report.release_tag.clone(),
        stage_dir: stage_report.stage_dir.clone(),
        stage_evidence_path: stage_report.evidence_path.clone(),
        stage_status: format!("{:?}", stage_report.status),
        staged_asset_path: stage_report.staged_asset_path.clone(),
        expected_sha256: stage_report.expected_sha256.clone(),
        staged_sha256: stage_report.staged_sha256.clone(),
        verification_status: Some(
            stage_report
                .check_report
                .evaluation
                .verification_status
                .clone(),
        ),
        source_authenticity_status: stage_report
            .check_report
            .evaluation
            .source_authenticity_status
            .clone(),
        source_trust_decision: stage_report
            .check_report
            .evaluation
            .source_trust_decision
            .clone(),
        publisher_key_fingerprint_sha256: stage_report.publisher_key_fingerprint_sha256.clone(),
        target_current_exe_path: Some(target_current_exe_path.display().to_string()),
        target_canonical_path: canonical_display(target_current_exe_path),
        staged_asset_canonical_path: stage_report
            .staged_asset_path
            .as_deref()
            .and_then(|path| canonical_display(Path::new(path))),
        backup_destination_path: None,
        backup_boundary_path: None,
        rollback_plan: Vec::new(),
        manual_approval_state,
        refusal_reasons: Vec::new(),
        evidence_path: None,
        write_error: None,
        plan: empty_plan(stage_report, target_current_exe_path),
    }
}

fn finish_not_ready(
    mut record: UpdateApplyReadinessRecord,
    status: UpdateApplyReadinessStatus,
    reason: impl Into<String>,
) -> UpdateApplyReadinessRecord {
    let reason = reason.into();
    record.status = status;
    record.reason = reason.clone();
    record.refusal_reasons.push(reason.clone());
    record.plan.status = UpdateApplyPlanStatus::Refused;
    record.plan.reason = reason;
    record.plan.no_mutation = true;
    record.no_live_mutation = true;
    record.apply_performed = false;
    record.install_performed = false;
    record.ok = false;
    record
}

fn build_readiness_plan(
    stage_report: &UpdateCandidateStageReport,
    target_current_exe_path: &Path,
    backup_destination_path: &Path,
    expected_sha256: &str,
    staged_asset_path: &str,
    status: UpdateApplyReadinessStatus,
) -> UpdateApplyPlan {
    UpdateApplyPlan {
        schema_version: 1,
        status: UpdateApplyPlanStatus::Planned,
        reason: format!(
            "live apply readiness {} (no live mutation; manual gate required before execution)",
            readiness_status_label(status)
        ),
        repo: stage_report.repo.clone(),
        release_tag: stage_report.release_tag.clone(),
        stage_dir: stage_report.stage_dir.clone(),
        staged_asset_path: Some(staged_asset_path.to_string()),
        expected_sha256: Some(expected_sha256.to_string()),
        target_exe_path: Some(target_current_exe_path.display().to_string()),
        backup_exe_path: Some(backup_destination_path.display().to_string()),
        reversible: true,
        no_mutation: true,
        steps: vec![
            UpdateApplyStep::VerifyStagedCandidateSha256 {
                path: staged_asset_path.to_string(),
                expected_sha256: expected_sha256.to_string(),
            },
            UpdateApplyStep::BackupCurrentExecutable {
                from: target_current_exe_path.display().to_string(),
                to: backup_destination_path.display().to_string(),
            },
            UpdateApplyStep::ReplaceExecutableFromStage {
                from: staged_asset_path.to_string(),
                to: target_current_exe_path.display().to_string(),
            },
            UpdateApplyStep::VerifyInstalledExecutableSha256 {
                path: target_current_exe_path.display().to_string(),
                expected_sha256: expected_sha256.to_string(),
            },
            UpdateApplyStep::RollbackByRestoringBackup {
                from_backup: backup_destination_path.display().to_string(),
                to_target: target_current_exe_path.display().to_string(),
            },
        ],
    }
}

pub(crate) fn build_update_apply_readiness(
    stage_report: &UpdateCandidateStageReport,
    target_current_exe_path: &Path,
    backup_boundary_dir: Option<&Path>,
    manual_approval_state: ManualApprovalState,
) -> UpdateApplyReadinessRecord {
    let mut record = base_record(stage_report, target_current_exe_path, manual_approval_state);

    if stage_report.status != UpdateCandidateStageStatus::Staged {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            format!(
                "live apply readiness requires STAGED report, got {:?}",
                stage_report.status
            ),
        );
    }
    if stage_report.check_report.evaluation.status
        != crate::update_candidate::UpdateCandidateStatus::Candidate
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            format!(
                "live apply readiness requires upstream candidate status CANDIDATE, got {:?}",
                stage_report.check_report.evaluation.status
            ),
        );
    }
    if !stage_report
        .check_report
        .evaluation
        .verification_status
        .eq_ignore_ascii_case("VERIFIED")
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            format!(
                "live apply readiness requires VERIFIED hash status, got {}",
                stage_report.check_report.evaluation.verification_status
            ),
        );
    }
    if stage_report
        .check_report
        .evaluation
        .source_trust_decision
        .as_deref()
        .filter(|decision| decision.eq_ignore_ascii_case("TRUSTED"))
        .is_none()
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            "live apply readiness requires trusted source policy decision",
        );
    }
    if stage_report
        .check_report
        .evaluation
        .source_authenticity_status
        .as_deref()
        .filter(|status| status.eq_ignore_ascii_case("TRUSTED_SIGNATURE"))
        .is_none()
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            "live apply readiness requires trusted signed source authenticity",
        );
    }
    if stage_report
        .publisher_key_fingerprint_sha256
        .as_deref()
        .or(stage_report.check_report.publisher_key_fingerprint_sha256())
        .map(str::trim)
        .filter(|fingerprint| !fingerprint.is_empty())
        .is_none()
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            "live apply readiness requires publisher key fingerprint evidence",
        );
    }
    if stage_report.evidence_write_error.is_some()
        || stage_report.check_report.evidence_write_error.is_some()
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            "live apply readiness requires prior stage/check evidence without write errors",
        );
    }

    let stage_dir = match stage_report.stage_dir.as_deref() {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => {
            return finish_not_ready(
                record,
                UpdateApplyReadinessStatus::Refused,
                "live apply readiness requires stage_dir",
            )
        }
    };
    if !stage_dir.is_dir() {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Blocked,
            format!(
                "live apply readiness stage_dir is not a directory: {}",
                stage_dir.display()
            ),
        );
    }

    let stage_evidence_path = match stage_report.evidence_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_not_ready(
                record,
                UpdateApplyReadinessStatus::Refused,
                "live apply readiness requires stage evidence path",
            )
        }
    };
    if !stage_evidence_path.is_file() {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Blocked,
            format!(
                "live apply readiness stage evidence is missing: {}",
                stage_evidence_path.display()
            ),
        );
    }
    if !path_is_within_if_available(&stage_evidence_path, &stage_dir) {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Blocked,
            "live apply readiness stage evidence must stay within stage_dir",
        );
    }

    let staged_asset_path = match stage_report.staged_asset_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_not_ready(
                record,
                UpdateApplyReadinessStatus::Refused,
                "live apply readiness requires staged_asset_path",
            )
        }
    };
    if !staged_asset_path.is_file() {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Blocked,
            format!(
                "live apply readiness staged asset is missing: {}",
                staged_asset_path.display()
            ),
        );
    }
    if !path_is_within_if_available(&staged_asset_path, &stage_dir) {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Blocked,
            "live apply readiness staged asset must stay within stage_dir",
        );
    }

    let expected_sha256 = match stage_report.expected_sha256.as_deref() {
        Some(sha) if !sha.trim().is_empty() => sha,
        _ => {
            return finish_not_ready(
                record,
                UpdateApplyReadinessStatus::Refused,
                "live apply readiness requires expected_sha256",
            )
        }
    };
    if stage_report
        .staged_sha256
        .as_deref()
        .map(|sha| !sha.eq_ignore_ascii_case(expected_sha256))
        .unwrap_or(true)
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::StaleStage,
            "live apply readiness refuses stale staged_sha256",
        );
    }
    let actual_staged_sha256 = match sha256_file_upper(&staged_asset_path) {
        Ok(sha) => sha,
        Err(e) => {
            return finish_not_ready(
                record,
                UpdateApplyReadinessStatus::Blocked,
                format!("live apply readiness could not hash staged asset: {e}"),
            )
        }
    };
    record.staged_sha256 = Some(actual_staged_sha256.clone());
    if !actual_staged_sha256.eq_ignore_ascii_case(expected_sha256) {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::StaleStage,
            "live apply readiness refuses staged asset hash mismatch",
        );
    }

    if !target_current_exe_path.is_file() {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Blocked,
            format!(
                "live apply readiness target current exe is not a file: {}",
                target_current_exe_path.display()
            ),
        );
    }
    if paths_equal_if_available(target_current_exe_path, &staged_asset_path) {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            "live apply readiness refuses target equal to staged asset",
        );
    }

    let backup_boundary = backup_boundary_dir.unwrap_or(stage_dir.as_path());
    record.backup_boundary_path = Some(backup_boundary.display().to_string());
    if !backup_boundary.is_dir() {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Unknown,
            format!(
                "live apply readiness backup boundary is not a directory: {}",
                backup_boundary.display()
            ),
        );
    }
    if !path_is_within_if_available(backup_boundary, &stage_dir) {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Unknown,
            "live apply readiness backup boundary cannot be proven side-effect-free within stage_dir",
        );
    }

    let backup_destination =
        match backup_path_for_target_in_dir(target_current_exe_path, backup_boundary) {
            Ok(path) => path,
            Err(e) => {
                return finish_not_ready(
                    record,
                    UpdateApplyReadinessStatus::Blocked,
                    format!("live apply readiness could not build backup destination: {e}"),
                )
            }
        };
    if paths_equal_if_available(target_current_exe_path, &backup_destination)
        || paths_equal_if_available(&staged_asset_path, &backup_destination)
    {
        return finish_not_ready(
            record,
            UpdateApplyReadinessStatus::Refused,
            "live apply readiness refuses unsafe backup destination collision",
        );
    }
    record.backup_destination_path = Some(backup_destination.display().to_string());

    let status = match manual_approval_state {
        ManualApprovalState::Granted => UpdateApplyReadinessStatus::ReadyForManualApply,
        ManualApprovalState::Required | ManualApprovalState::NotRequested => {
            UpdateApplyReadinessStatus::ApprovalRequired
        }
        ManualApprovalState::Expired | ManualApprovalState::Refused => {
            return finish_not_ready(
                record,
                UpdateApplyReadinessStatus::Refused,
                "live apply readiness manual approval is not granted",
            )
        }
    };

    let staged_asset_display = staged_asset_path.display().to_string();
    let mut plan = build_readiness_plan(
        stage_report,
        target_current_exe_path,
        &backup_destination,
        expected_sha256,
        &staged_asset_display,
        status,
    );
    if status == UpdateApplyReadinessStatus::ApprovalRequired {
        plan.reason = "live apply readiness proven but manual approval is required before execution (no live mutation)".to_string();
    }
    record.status = status;
    record.reason = plan.reason.clone();
    record.plan = plan;
    record.rollback_plan = record
        .plan
        .steps
        .iter()
        .filter_map(|step| match step {
            UpdateApplyStep::RollbackByRestoringBackup {
                from_backup,
                to_target,
            } => Some(format!("restore {from_backup} to {to_target}")),
            _ => None,
        })
        .collect();
    record.ok = true;
    record.no_live_mutation = true;
    record.apply_performed = false;
    record.install_performed = false;
    record
}

pub(crate) fn write_update_apply_readiness_evidence_for_stage2(
    stage_report: &UpdateCandidateStageReport,
    target_current_exe_path: &Path,
    backup_boundary_dir: Option<&Path>,
    manual_approval_state: ManualApprovalState,
) -> UpdateApplyReadinessRecord {
    let mut record = build_update_apply_readiness(
        stage_report,
        target_current_exe_path,
        backup_boundary_dir,
        manual_approval_state,
    );

    let stage_dir = match stage_report.stage_dir.as_deref() {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => {
            record.write_error =
                Some("live apply readiness evidence requires stage_dir".to_string());
            record.ok = false;
            return record;
        }
    };
    let evidence_path = stage_dir.join("update-apply-readiness.json");
    record.evidence_path = Some(evidence_path.display().to_string());
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let payload = serde_json::json!({
        "schema_version": UPDATE_APPLY_READINESS_SCHEMA_VERSION,
        "generated_at_unix_ms": generated_at_unix_ms,
        "no_live_mutation": record.no_live_mutation,
        "apply_performed": record.apply_performed,
        "install_performed": record.install_performed,
        "record": &record,
    });
    match crate::evidence_ledger::write_json_pretty(&evidence_path, &payload) {
        Ok(()) => {}
        Err(e) => {
            record.write_error = Some(format!("write update apply readiness evidence failed: {e}"));
            record.ok = false;
        }
    }
    record
}

fn write_selftest_json(json_out: Option<PathBuf>, pretty_report: &str) -> Result<(), String> {
    if let Some(json_path) = json_out {
        if let Some(parent) = json_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("Create selftest JSON dir: {e}"))?;
        }
        fs::write(&json_path, format!("{pretty_report}\n"))
            .map_err(|e| format!("Write update apply readiness selftest JSON: {e}"))?;
    }
    Ok(())
}

fn parse_selftest_json_arg(args: &[String], flag_name: &str) -> Result<Option<PathBuf>, String> {
    let mut json_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                i += 1;
                json_out = args.get(i).map(PathBuf::from);
            }
            other => return Err(format!("unknown {flag_name} option: {other}")),
        }
        i += 1;
    }
    Ok(json_out)
}

fn selftest_stage_report(
    root: &Path,
    stage_dir: &Path,
    staged_asset_path: &Path,
    stage_evidence_path: &Path,
    expected_sha256: &str,
) -> UpdateCandidateStageReport {
    UpdateCandidateStageReport {
        schema_version: 1,
        status: UpdateCandidateStageStatus::Staged,
        repo: "wsolarq11/gh_mirror_gui".to_string(),
        release_tag: "v9.9.9".to_string(),
        release_url: "https://example.invalid/releases/tag/v9.9.9".to_string(),
        stage_dir: Some(stage_dir.display().to_string()),
        staged_asset_path: Some(staged_asset_path.display().to_string()),
        staged_sha256: Some(expected_sha256.to_string()),
        expected_sha256: Some(expected_sha256.to_string()),
        publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
        reason: "staged verified candidate (no install)".to_string(),
        no_install: true,
        check_report: crate::update_candidate::UpdateCandidateCheckReport {
            schema_version: 1,
            repo: "wsolarq11/gh_mirror_gui".to_string(),
            release_tag: "v9.9.9".to_string(),
            release_url: "https://example.invalid/releases/tag/v9.9.9".to_string(),
            asset_name: "gh_mirror_gui.exe".to_string(),
            release_publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            evaluation: crate::update_candidate::UpdateCandidateEvaluation {
                schema_version: 1,
                status: crate::update_candidate::UpdateCandidateStatus::Candidate,
                current_version: "v9.9.8".to_string(),
                candidate_version: "9.9.9".to_string(),
                release_tag: "v9.9.9".to_string(),
                asset_name: "gh_mirror_gui.exe".to_string(),
                reason: "fixture".to_string(),
                verification_status: "VERIFIED".to_string(),
                file_sha256: Some(expected_sha256.to_string()),
                expected_sha256: Some(expected_sha256.to_string()),
                verification_source: Some("SHA256SUMS.txt".to_string()),
                source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
                source_trust_decision: Some("TRUSTED".to_string()),
                publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
                evidence_path: Some(
                    root.join("update-candidate-check.json")
                        .display()
                        .to_string(),
                ),
                no_mutation: true,
            },
            evidence_write_error: None,
        },
        evidence_path: Some(stage_evidence_path.display().to_string()),
        evidence_write_error: None,
    }
}

pub(crate) fn run_update_apply_readiness_contract_selftest(args: &[String]) -> Result<(), String> {
    let json_out = parse_selftest_json_arg(args, "--update-apply-readiness-contract-selftest")?;

    let root = unique_update_apply_readiness_selftest_root();
    let stage_dir = root.join("stage");
    fs::create_dir_all(&stage_dir)
        .map_err(|e| format!("Create apply-readiness selftest dir: {e}"))?;
    let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
    fs::write(&staged_asset_path, b"staged readiness candidate bytes")
        .map_err(|e| format!("Write staged readiness asset fixture: {e}"))?;
    let expected_sha256 = sha256_file_upper(&staged_asset_path)?;
    let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
    fs::write(&stage_evidence_path, b"{}")
        .map_err(|e| format!("Write stage readiness evidence fixture: {e}"))?;
    let stage_report = selftest_stage_report(
        &root,
        &stage_dir,
        &staged_asset_path,
        &stage_evidence_path,
        &expected_sha256,
    );
    let current_exe_path =
        std::env::current_exe().map_err(|e| format!("current executable path unavailable: {e}"))?;
    let current_exe_before_sha256 = sha256_file_upper(&current_exe_path)?;
    let readiness = write_update_apply_readiness_evidence_for_stage2(
        &stage_report,
        &current_exe_path,
        Some(&stage_dir),
        ManualApprovalState::Required,
    );
    let current_exe_after_sha256 = sha256_file_upper(&current_exe_path)?;
    let current_exe_unchanged =
        current_exe_before_sha256.eq_ignore_ascii_case(&current_exe_after_sha256);
    let artifact_decision =
        crate::artifact_decision::ArtifactDecision::from_update_apply_readiness(&readiness);
    let evidence_ready = readiness
        .evidence_path
        .as_deref()
        .map(|path| Path::new(path).is_file())
        .unwrap_or(false);
    let target_is_current_exe = readiness
        .target_current_exe_path
        .as_deref()
        .map(|path| paths_equal_if_available(Path::new(path), &current_exe_path))
        .unwrap_or(false);
    let approval_required = readiness.status == UpdateApplyReadinessStatus::ApprovalRequired
        && readiness.manual_approval_state == ManualApprovalState::Required;
    let ok = readiness.ok
        && readiness.no_live_mutation
        && !readiness.apply_performed
        && !readiness.install_performed
        && readiness.plan.no_mutation
        && readiness.plan.reversible
        && approval_required
        && evidence_ready
        && current_exe_unchanged
        && target_is_current_exe
        && artifact_decision.action_plan.no_mutation;

    let report = serde_json::json!({
        "schema_version": UPDATE_APPLY_READINESS_SCHEMA_VERSION,
        "ok": ok,
        "module_owner": UPDATE_APPLY_READINESS_MODULE_OWNER,
        "status": readiness.status,
        "status_label": readiness_status_label(readiness.status),
        "approval_required": approval_required,
        "no_mutation": readiness.plan.no_mutation,
        "no_live_mutation": readiness.no_live_mutation,
        "apply_performed": readiness.apply_performed,
        "install_performed": readiness.install_performed,
        "reversible": readiness.plan.reversible,
        "target_is_current_exe": target_is_current_exe,
        "current_exe": {
            "path": current_exe_path.display().to_string(),
            "before_sha256": current_exe_before_sha256,
            "after_sha256": current_exe_after_sha256,
            "unchanged": current_exe_unchanged,
        },
        "plan": readiness.plan,
        "readiness": readiness,
        "artifact_decision": artifact_decision,
        "evidence": {
            "ready": evidence_ready,
        },
        "fixture": {
            "root": root.display().to_string(),
            "stage_dir": stage_dir.display().to_string(),
            "stage_evidence_path": stage_evidence_path.display().to_string(),
            "staged_asset_path": staged_asset_path.display().to_string(),
            "expected_sha256": expected_sha256,
        }
    });
    let pretty_report = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialize readiness selftest JSON: {e}"))?;
    write_selftest_json(json_out, &pretty_report)?;
    println!("{pretty_report}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct ReadinessFixture {
        root: PathBuf,
        stage_dir: PathBuf,
        target_exe_path: PathBuf,
        stage_report: UpdateCandidateStageReport,
    }

    impl ReadinessFixture {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "gh_mirror_gui_readiness_test_{}_{}_{}",
                name,
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos()
            ));
            let stage_dir = root.join("stage");
            fs::create_dir_all(&stage_dir).expect("create readiness fixture stage dir");
            let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
            fs::write(&stage_evidence_path, b"{}").expect("write stage evidence fixture");
            let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
            fs::write(&staged_asset_path, b"staged candidate").expect("write staged fixture");
            let expected_sha256 =
                sha256_file_upper(&staged_asset_path).expect("hash staged fixture");
            let target_exe_path = root.join("current").join("gh_mirror_gui.exe");
            fs::create_dir_all(target_exe_path.parent().unwrap())
                .expect("create target fixture dir");
            fs::write(&target_exe_path, b"current exe").expect("write target fixture");
            let stage_report = selftest_stage_report(
                &root,
                &stage_dir,
                &staged_asset_path,
                &stage_evidence_path,
                &expected_sha256,
            );
            Self {
                root,
                stage_dir,
                target_exe_path,
                stage_report,
            }
        }
    }

    impl Drop for ReadinessFixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn update_apply_readiness_refuses_non_staged_report() {
        let mut fixture = ReadinessFixture::new("non_staged");
        fixture.stage_report.status = UpdateCandidateStageStatus::Refused;

        let record = build_update_apply_readiness(
            &fixture.stage_report,
            &fixture.target_exe_path,
            Some(&fixture.stage_dir),
            ManualApprovalState::Required,
        );

        assert_eq!(record.status, UpdateApplyReadinessStatus::Refused);
        assert!(!record.ok);
        assert!(record.no_live_mutation);
        assert!(!record.apply_performed);
        assert!(!record.install_performed);
    }

    #[test]
    fn update_apply_readiness_builds_reversible_preflight_without_mutation() {
        let fixture = ReadinessFixture::new("reversible");
        let target_before = sha256_file_upper(&fixture.target_exe_path).expect("hash target");

        let record = write_update_apply_readiness_evidence_for_stage2(
            &fixture.stage_report,
            &fixture.target_exe_path,
            Some(&fixture.stage_dir),
            ManualApprovalState::Required,
        );
        let target_after = sha256_file_upper(&fixture.target_exe_path).expect("hash target");

        assert!(record.ok);
        assert_eq!(record.status, UpdateApplyReadinessStatus::ApprovalRequired);
        assert_eq!(record.manual_approval_state, ManualApprovalState::Required);
        assert!(record.plan.reversible);
        assert!(record.plan.no_mutation);
        assert!(record.no_live_mutation);
        assert!(!record.apply_performed);
        assert!(!record.install_performed);
        assert_eq!(target_before, target_after);
        assert!(record
            .evidence_path
            .as_deref()
            .map(|path| Path::new(path).is_file())
            .unwrap_or(false));
        assert_eq!(
            record.backup_boundary_path.as_deref(),
            Some(fixture.stage_dir.display().to_string().as_str())
        );
    }

    #[test]
    fn update_apply_readiness_refuses_untrusted_source_before_live_boundary() {
        let mut fixture = ReadinessFixture::new("untrusted");
        fixture
            .stage_report
            .check_report
            .evaluation
            .source_trust_decision = Some("BLOCK".to_string());

        let record = build_update_apply_readiness(
            &fixture.stage_report,
            &fixture.target_exe_path,
            Some(&fixture.stage_dir),
            ManualApprovalState::Required,
        );

        assert_eq!(record.status, UpdateApplyReadinessStatus::Refused);
        assert!(!record.ok);
        assert!(record
            .refusal_reasons
            .iter()
            .any(|reason| { reason.contains("trusted source policy decision") }));
    }

    #[test]
    fn update_apply_readiness_reports_unknown_when_backup_boundary_cannot_be_proven_side_effect_free(
    ) {
        let fixture = ReadinessFixture::new("unknown_boundary");
        let outside_boundary = fixture.root.join("outside");
        fs::create_dir_all(&outside_boundary).expect("create outside boundary");

        let record = build_update_apply_readiness(
            &fixture.stage_report,
            &fixture.target_exe_path,
            Some(&outside_boundary),
            ManualApprovalState::Required,
        );

        assert_eq!(record.status, UpdateApplyReadinessStatus::Unknown);
        assert!(!record.ok);
        assert!(record.plan.no_mutation);
        assert!(record.no_live_mutation);
    }

    #[test]
    fn update_apply_readiness_refuses_stale_staged_sha_before_live_boundary() {
        let mut fixture = ReadinessFixture::new("stale");
        fixture.stage_report.staged_sha256 = Some("BAD".to_string());

        let record = build_update_apply_readiness(
            &fixture.stage_report,
            &fixture.target_exe_path,
            Some(&fixture.stage_dir),
            ManualApprovalState::Required,
        );

        assert_eq!(record.status, UpdateApplyReadinessStatus::StaleStage);
        assert!(!record.ok);
        assert!(record.no_live_mutation);
    }

    #[test]
    fn update_apply_readiness_requires_manual_approval_before_live_apply() {
        let fixture = ReadinessFixture::new("approval");

        let record = build_update_apply_readiness(
            &fixture.stage_report,
            &fixture.target_exe_path,
            Some(&fixture.stage_dir),
            ManualApprovalState::Required,
        );

        assert_eq!(record.status, UpdateApplyReadinessStatus::ApprovalRequired);
        assert_eq!(record.manual_approval_state, ManualApprovalState::Required);
        assert!(record.ok);
        assert!(record.reason.contains("manual approval"));
        assert!(!record.apply_performed);
        assert!(!record.install_performed);
    }

    #[test]
    fn update_apply_readiness_selftest_preserves_current_exe_without_apply() {
        let json_path = std::env::temp_dir().join(format!(
            "gh_mirror_gui_readiness_selftest_{}_{}.json",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let args = vec!["--json".to_string(), json_path.display().to_string()];

        run_update_apply_readiness_contract_selftest(&args).expect("readiness selftest");
        let value: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(&json_path).expect("read readiness selftest json"),
        )
        .expect("parse readiness selftest json");

        assert_eq!(value["ok"], true);
        assert_eq!(value["no_live_mutation"], true);
        assert_eq!(value["apply_performed"], false);
        assert_eq!(value["install_performed"], false);
        assert_eq!(value["current_exe"]["unchanged"], true);
        assert_eq!(value["target_is_current_exe"], true);
        let _ = fs::remove_file(json_path);
    }
}
