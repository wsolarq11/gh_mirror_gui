use crate::update_candidate::{UpdateCandidateStageReport, UpdateCandidateStageStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const UPDATE_APPLY_PLAN_SCHEMA_VERSION: u32 = 1;
const UPDATE_APPLY_PLAN_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const UPDATE_APPLY_FIXTURE_EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateApplyPlanStatus {
    Planned,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum UpdateApplyStep {
    VerifyStagedCandidateSha256 {
        path: String,
        expected_sha256: String,
    },
    BackupCurrentExecutable {
        from: String,
        to: String,
    },
    ReplaceExecutableFromStage {
        from: String,
        to: String,
    },
    VerifyInstalledExecutableSha256 {
        path: String,
        expected_sha256: String,
    },
    RollbackByRestoringBackup {
        from_backup: String,
        to_target: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyPlan {
    pub schema_version: u32,
    pub status: UpdateApplyPlanStatus,
    pub reason: String,
    pub repo: String,
    pub release_tag: String,
    pub stage_dir: Option<String>,
    pub staged_asset_path: Option<String>,
    pub expected_sha256: Option<String>,
    pub target_exe_path: Option<String>,
    pub backup_exe_path: Option<String>,
    pub reversible: bool,
    pub no_mutation: bool,
    pub steps: Vec<UpdateApplyStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyPlanEvidenceRecord {
    pub schema_version: u32,
    pub ok: bool,
    pub no_mutation: bool,
    pub stage_dir: Option<String>,
    pub evidence_path: Option<String>,
    pub write_error: Option<String>,
    pub plan: UpdateApplyPlan,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateApplyFixtureStatus {
    Refused,
    AppliedAndRolledBack,
    RollbackFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyFixtureEvidenceRecord {
    pub schema_version: u32,
    pub ok: bool,
    pub fixture_only: bool,
    pub no_live_mutation: bool,
    pub rollback_ok: bool,
    pub status: UpdateApplyFixtureStatus,
    pub reason: String,
    pub stage_dir: Option<String>,
    pub stage_evidence_path: Option<String>,
    pub staged_asset_path: Option<String>,
    pub verification_status: Option<String>,
    pub source_authenticity_status: Option<String>,
    pub source_trust_decision: Option<String>,
    pub publisher_key_fingerprint_sha256: Option<String>,
    pub target_fixture_path: Option<String>,
    pub backup_path: Option<String>,
    pub expected_sha256: Option<String>,
    pub staged_sha256: Option<String>,
    pub installed_sha256: Option<String>,
    pub rollback_sha256: Option<String>,
    pub evidence_path: Option<String>,
    pub write_error: Option<String>,
    pub plan: UpdateApplyPlan,
}

fn backup_path_for_target(target_exe_path: &Path, suffix: &str) -> Result<PathBuf, String> {
    let file_name = target_exe_path
        .file_name()
        .ok_or_else(|| "target exe path has no file name".to_string())?
        .to_string_lossy()
        .to_string();
    let backup_name = format!("{file_name}.bak-{suffix}");
    Ok(target_exe_path.with_file_name(backup_name))
}

fn unique_update_apply_plan_selftest_root() -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gh_mirror_gui_update_apply_plan_selftest_{}_{}",
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

fn fixture_evidence_dir(
    stage_report: &UpdateCandidateStageReport,
    target_fixture_path: &Path,
) -> Option<PathBuf> {
    stage_report
        .stage_dir
        .as_deref()
        .filter(|dir| !dir.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| target_fixture_path.parent().map(Path::to_path_buf))
}

fn write_update_apply_fixture_evidence(
    mut record: UpdateApplyFixtureEvidenceRecord,
    evidence_dir: Option<PathBuf>,
) -> UpdateApplyFixtureEvidenceRecord {
    let Some(evidence_dir) = evidence_dir else {
        record.write_error =
            Some("fixture apply evidence requires stage_dir or target parent".to_string());
        return record;
    };

    let evidence_path = evidence_dir.join("update-apply-fixture.json");
    record.evidence_path = Some(evidence_path.display().to_string());
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let payload = serde_json::json!({
        "schema_version": UPDATE_APPLY_FIXTURE_EVIDENCE_SCHEMA_VERSION,
        "generated_at_unix_ms": generated_at_unix_ms,
        "record": &record,
    });
    match crate::evidence_ledger::write_json_pretty(&evidence_path, &payload) {
        Ok(()) => record,
        Err(e) => {
            record.write_error = Some(format!("write update apply fixture evidence failed: {e}"));
            record
        }
    }
}

fn refused_fixture_record(
    stage_report: &UpdateCandidateStageReport,
    target_fixture_path: &Path,
    reason: String,
) -> UpdateApplyFixtureEvidenceRecord {
    let plan = build_update_apply_plan(stage_report, target_fixture_path, "fixture");
    UpdateApplyFixtureEvidenceRecord {
        schema_version: UPDATE_APPLY_FIXTURE_EVIDENCE_SCHEMA_VERSION,
        ok: false,
        fixture_only: true,
        no_live_mutation: true,
        rollback_ok: false,
        status: UpdateApplyFixtureStatus::Refused,
        reason,
        stage_dir: stage_report.stage_dir.clone(),
        stage_evidence_path: stage_report.evidence_path.clone(),
        staged_asset_path: stage_report.staged_asset_path.clone(),
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
        target_fixture_path: Some(target_fixture_path.display().to_string()),
        backup_path: plan.backup_exe_path.clone(),
        expected_sha256: stage_report.expected_sha256.clone(),
        staged_sha256: stage_report.staged_sha256.clone(),
        installed_sha256: None,
        rollback_sha256: None,
        evidence_path: None,
        write_error: None,
        plan,
    }
}

fn path_is_within_if_available(child: &Path, parent: &Path) -> bool {
    match (child.canonicalize(), parent.canonicalize()) {
        (Ok(child), Ok(parent)) => child.starts_with(parent),
        _ => child.starts_with(parent),
    }
}

fn fixture_root_from_stage_dir(stage_dir: &Path) -> &Path {
    stage_dir
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(stage_dir)
}

fn fixture_refusal(
    stage_report: &UpdateCandidateStageReport,
    target_fixture_path: &Path,
    evidence_dir: Option<PathBuf>,
    reason: impl Into<String>,
) -> UpdateApplyFixtureEvidenceRecord {
    write_update_apply_fixture_evidence(
        refused_fixture_record(stage_report, target_fixture_path, reason.into()),
        evidence_dir,
    )
}

struct FixtureRecordOutcome {
    status: UpdateApplyFixtureStatus,
    ok: bool,
    rollback_ok: bool,
    reason: String,
    installed_sha256: Option<String>,
    rollback_sha256: Option<String>,
}

impl FixtureRecordOutcome {
    fn new(
        status: UpdateApplyFixtureStatus,
        ok: bool,
        rollback_ok: bool,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            status,
            ok,
            rollback_ok,
            reason: reason.into(),
            installed_sha256: None,
            rollback_sha256: None,
        }
    }

    fn installed_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.installed_sha256 = Some(sha256.into());
        self
    }

    fn rollback_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.rollback_sha256 = Some(sha256.into());
        self
    }
}

fn fixture_record_from_plan(
    stage_report: &UpdateCandidateStageReport,
    plan: UpdateApplyPlan,
    target_fixture_path: &Path,
    outcome: FixtureRecordOutcome,
) -> UpdateApplyFixtureEvidenceRecord {
    UpdateApplyFixtureEvidenceRecord {
        schema_version: UPDATE_APPLY_FIXTURE_EVIDENCE_SCHEMA_VERSION,
        ok: outcome.ok,
        fixture_only: true,
        no_live_mutation: true,
        rollback_ok: outcome.rollback_ok,
        status: outcome.status,
        reason: outcome.reason,
        stage_dir: stage_report.stage_dir.clone(),
        stage_evidence_path: stage_report.evidence_path.clone(),
        staged_asset_path: stage_report.staged_asset_path.clone(),
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
        target_fixture_path: Some(target_fixture_path.display().to_string()),
        backup_path: plan.backup_exe_path.clone(),
        expected_sha256: stage_report.expected_sha256.clone(),
        staged_sha256: stage_report.staged_sha256.clone(),
        installed_sha256: outcome.installed_sha256,
        rollback_sha256: outcome.rollback_sha256,
        evidence_path: None,
        write_error: None,
        plan,
    }
}

fn rollback_fixture_target(
    backup_path: &Path,
    target_fixture_path: &Path,
) -> Result<String, String> {
    fs::copy(backup_path, target_fixture_path).map_err(|e| {
        format!(
            "rollback fixture target {} from backup {} failed: {e}",
            target_fixture_path.display(),
            backup_path.display()
        )
    })?;
    sha256_file_upper(target_fixture_path)
}

pub(crate) fn apply_update_fixture_for_stage2(
    stage_report: &UpdateCandidateStageReport,
    target_fixture_path: &Path,
) -> UpdateApplyFixtureEvidenceRecord {
    let evidence_dir = fixture_evidence_dir(stage_report, target_fixture_path);

    if stage_report.status != UpdateCandidateStageStatus::Staged {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!(
                "fixture apply requires STAGED report, got {:?}",
                stage_report.status
            ),
        );
    }
    if stage_report.check_report.evaluation.status
        != crate::update_candidate::UpdateCandidateStatus::Candidate
    {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!(
                "fixture apply requires upstream candidate status CANDIDATE, got {:?}",
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
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!(
                "fixture apply requires VERIFIED hash status, got {}",
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
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply requires trusted source policy decision",
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
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply requires trusted signed source authenticity",
        );
    }
    let stage_publisher_fingerprint = match stage_report
        .publisher_key_fingerprint_sha256
        .as_deref()
        .map(str::trim)
        .filter(|fingerprint| !fingerprint.is_empty())
    {
        Some(fingerprint) => fingerprint,
        None => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                "fixture apply requires publisher key fingerprint",
            );
        }
    };
    if stage_report
        .check_report
        .evaluation
        .publisher_key_fingerprint_sha256
        .as_deref()
        .map(str::trim)
        .filter(|fingerprint| fingerprint.eq_ignore_ascii_case(stage_publisher_fingerprint))
        .is_none()
    {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply requires matching publisher key fingerprint in check evidence",
        );
    }
    if let Some(error) = stage_report.check_report.evidence_write_error.as_deref() {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!("fixture apply requires successful check evidence write: {error}"),
        );
    }
    if let Some(error) = stage_report.evidence_write_error.as_deref() {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!("fixture apply requires successful stage evidence write: {error}"),
        );
    }

    let stage_evidence_path = match stage_report.evidence_path.as_deref() {
        Some(path) if !path.trim().is_empty() && Path::new(path).is_file() => Path::new(path),
        Some(path) if !path.trim().is_empty() => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                format!("fixture apply requires existing stage evidence: {path}"),
            )
        }
        _ => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                "fixture apply requires stage evidence path",
            )
        }
    };

    let stage_dir = match stage_report.stage_dir.as_deref() {
        Some(dir) if !dir.trim().is_empty() && Path::new(dir).is_dir() => Path::new(dir),
        Some(dir) if !dir.trim().is_empty() => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                format!("fixture apply requires existing stage_dir: {dir}"),
            )
        }
        _ => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                "fixture apply requires stage_dir",
            )
        }
    };
    if !path_is_within_if_available(stage_evidence_path, stage_dir) {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply requires stage evidence inside stage_dir",
        );
    }

    let staged_asset_path = match stage_report.staged_asset_path.as_deref() {
        Some(path) if !path.trim().is_empty() && Path::new(path).is_file() => Path::new(path),
        Some(path) if !path.trim().is_empty() => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                format!("fixture apply requires existing staged asset: {path}"),
            )
        }
        _ => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                "fixture apply requires staged_asset_path",
            )
        }
    };
    if !path_is_within_if_available(staged_asset_path, stage_dir) {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply requires staged asset inside stage_dir",
        );
    }

    let expected_sha256 = match stage_report.expected_sha256.as_deref() {
        Some(sha) if !sha.trim().is_empty() => sha.trim().to_ascii_uppercase(),
        _ => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                "fixture apply requires expected_sha256",
            )
        }
    };

    if !target_fixture_path.is_file() {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!(
                "fixture apply requires existing target fixture file: {}",
                target_fixture_path.display()
            ),
        );
    }
    if std::env::current_exe()
        .ok()
        .as_deref()
        .map(|current| paths_equal_if_available(target_fixture_path, current))
        .unwrap_or(false)
    {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply refuses the live current executable path",
        );
    }
    if paths_equal_if_available(target_fixture_path, staged_asset_path) {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            "fixture apply target must differ from staged asset",
        );
    }
    let fixture_root = fixture_root_from_stage_dir(stage_dir);
    if !path_is_within_if_available(target_fixture_path, fixture_root) {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!(
                "fixture apply target must stay inside fixture root: {}",
                fixture_root.display()
            ),
        );
    }

    let staged_sha256 = match sha256_file_upper(staged_asset_path) {
        Ok(sha) => sha,
        Err(e) => return fixture_refusal(stage_report, target_fixture_path, evidence_dir, e),
    };
    if staged_sha256 != expected_sha256 {
        return fixture_refusal(
            stage_report,
            target_fixture_path,
            evidence_dir,
            format!(
                "staged asset sha256 mismatch: observed {staged_sha256}, expected {expected_sha256}"
            ),
        );
    }
    if let Some(recorded_sha) = stage_report
        .staged_sha256
        .as_deref()
        .filter(|sha| !sha.trim().is_empty())
    {
        if !recorded_sha.eq_ignore_ascii_case(&staged_sha256) {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                format!(
                    "stage report sha256 mismatch: recorded {recorded_sha}, observed {staged_sha256}"
                ),
            );
        }
    }

    let mut plan = build_update_apply_plan(stage_report, target_fixture_path, "fixture");
    if plan.status != UpdateApplyPlanStatus::Planned {
        return fixture_refusal(stage_report, target_fixture_path, evidence_dir, plan.reason);
    }
    plan.no_mutation = false;
    plan.reason = "fixture apply plan executes only inside fixture and rolls back".to_string();

    let backup_path = match plan.backup_exe_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return fixture_refusal(
                stage_report,
                target_fixture_path,
                evidence_dir,
                "fixture apply could not determine backup path",
            )
        }
    };
    let original_sha256 = match sha256_file_upper(target_fixture_path) {
        Ok(sha) => sha,
        Err(e) => return fixture_refusal(stage_report, target_fixture_path, evidence_dir, e),
    };

    if let Err(e) = fs::copy(target_fixture_path, &backup_path) {
        let record = fixture_record_from_plan(
            stage_report,
            plan,
            target_fixture_path,
            FixtureRecordOutcome::new(
                UpdateApplyFixtureStatus::Refused,
                false,
                false,
                format!("fixture backup failed before replace: {e}"),
            ),
        );
        return write_update_apply_fixture_evidence(record, evidence_dir);
    }

    if let Err(e) = fs::copy(staged_asset_path, target_fixture_path) {
        let rollback_result = rollback_fixture_target(&backup_path, target_fixture_path);
        let (status, rollback_ok, reason, rollback_sha256) = match rollback_result {
            Ok(sha) if sha == original_sha256 => (
                UpdateApplyFixtureStatus::Refused,
                true,
                format!("fixture replace failed; rollback restored target: {e}"),
                Some(sha),
            ),
            Ok(sha) => (
                UpdateApplyFixtureStatus::RollbackFailed,
                false,
                format!(
                    "fixture replace failed and rollback hash mismatch: {e}; rollback sha {sha} expected {original_sha256}"
                ),
                Some(sha),
            ),
            Err(rollback_error) => (
                UpdateApplyFixtureStatus::RollbackFailed,
                false,
                format!("fixture replace failed and rollback failed: {e}; {rollback_error}"),
                None,
            ),
        };
        let mut outcome = FixtureRecordOutcome::new(status, false, rollback_ok, reason);
        if let Some(sha) = rollback_sha256 {
            outcome = outcome.rollback_sha256(sha);
        }
        let record = fixture_record_from_plan(stage_report, plan, target_fixture_path, outcome);
        return write_update_apply_fixture_evidence(record, evidence_dir);
    }

    let installed_sha256 = match sha256_file_upper(target_fixture_path) {
        Ok(sha) => sha,
        Err(e) => {
            let rollback_result = rollback_fixture_target(&backup_path, target_fixture_path);
            let (status, rollback_ok, reason, rollback_sha256) = match rollback_result {
                Ok(sha) if sha == original_sha256 => (
                    UpdateApplyFixtureStatus::Refused,
                    true,
                    format!("fixture installed hash read failed; rollback restored target: {e}"),
                    Some(sha),
                ),
                Ok(sha) => (
                    UpdateApplyFixtureStatus::RollbackFailed,
                    false,
                    format!(
                        "fixture installed hash read failed and rollback hash mismatch: {e}; rollback sha {sha} expected {original_sha256}"
                    ),
                    Some(sha),
                ),
                Err(rollback_error) => (
                    UpdateApplyFixtureStatus::RollbackFailed,
                    false,
                    format!("fixture installed hash read failed and rollback failed: {e}; {rollback_error}"),
                    None,
                ),
            };
            let mut outcome = FixtureRecordOutcome::new(status, false, rollback_ok, reason);
            if let Some(sha) = rollback_sha256 {
                outcome = outcome.rollback_sha256(sha);
            }
            let record = fixture_record_from_plan(stage_report, plan, target_fixture_path, outcome);
            return write_update_apply_fixture_evidence(record, evidence_dir);
        }
    };

    if installed_sha256 != expected_sha256 {
        let rollback_result = rollback_fixture_target(&backup_path, target_fixture_path);
        let (status, rollback_ok, reason, rollback_sha256) = match rollback_result {
            Ok(sha) if sha == original_sha256 => (
                UpdateApplyFixtureStatus::Refused,
                true,
                format!(
                    "fixture installed sha256 mismatch; rollback restored target: observed {installed_sha256}, expected {expected_sha256}"
                ),
                Some(sha),
            ),
            Ok(sha) => (
                UpdateApplyFixtureStatus::RollbackFailed,
                false,
                format!(
                    "fixture installed sha256 mismatch and rollback hash mismatch: observed {installed_sha256}, expected {expected_sha256}; rollback sha {sha} expected {original_sha256}"
                ),
                Some(sha),
            ),
            Err(rollback_error) => (
                UpdateApplyFixtureStatus::RollbackFailed,
                false,
                format!(
                    "fixture installed sha256 mismatch and rollback failed: observed {installed_sha256}, expected {expected_sha256}; {rollback_error}"
                ),
                None,
            ),
        };
        let mut outcome = FixtureRecordOutcome::new(status, false, rollback_ok, reason)
            .installed_sha256(installed_sha256);
        if let Some(sha) = rollback_sha256 {
            outcome = outcome.rollback_sha256(sha);
        }
        let record = fixture_record_from_plan(stage_report, plan, target_fixture_path, outcome);
        return write_update_apply_fixture_evidence(record, evidence_dir);
    }

    let rollback_result = rollback_fixture_target(&backup_path, target_fixture_path);
    let (status, ok, rollback_ok, reason, rollback_sha256) = match rollback_result {
        Ok(sha) if sha == original_sha256 => (
            UpdateApplyFixtureStatus::AppliedAndRolledBack,
            true,
            true,
            "fixture apply backed up, replaced, verified, and rolled back".to_string(),
            Some(sha),
        ),
        Ok(sha) => (
            UpdateApplyFixtureStatus::RollbackFailed,
            false,
            false,
            format!(
                "fixture apply verified but rollback hash mismatch: rollback sha {sha} expected {original_sha256}"
            ),
            Some(sha),
        ),
        Err(e) => (
            UpdateApplyFixtureStatus::RollbackFailed,
            false,
            false,
            format!("fixture apply verified but rollback failed: {e}"),
            None,
        ),
    };
    let mut outcome = FixtureRecordOutcome::new(status, ok, rollback_ok, reason)
        .installed_sha256(installed_sha256);
    if let Some(sha) = rollback_sha256 {
        outcome = outcome.rollback_sha256(sha);
    }
    let record = fixture_record_from_plan(stage_report, plan, target_fixture_path, outcome);
    write_update_apply_fixture_evidence(record, evidence_dir)
}

/// Build a pure, no-mutation update apply/install/rollback plan.
///
/// This plan does **not** perform any filesystem mutations; it only describes
/// what an installer helper would do.
pub(crate) fn build_update_apply_plan(
    stage_report: &UpdateCandidateStageReport,
    target_exe_path: &Path,
    backup_suffix: &str,
) -> UpdateApplyPlan {
    let mut base = UpdateApplyPlan {
        schema_version: UPDATE_APPLY_PLAN_SCHEMA_VERSION,
        status: UpdateApplyPlanStatus::Refused,
        reason: "not planned".to_string(),
        repo: stage_report.repo.clone(),
        release_tag: stage_report.release_tag.clone(),
        stage_dir: stage_report.stage_dir.clone(),
        staged_asset_path: stage_report.staged_asset_path.clone(),
        expected_sha256: stage_report.expected_sha256.clone(),
        target_exe_path: Some(target_exe_path.display().to_string()),
        backup_exe_path: None,
        reversible: false,
        no_mutation: true,
        steps: vec![],
    };

    if stage_report.status != UpdateCandidateStageStatus::Staged {
        base.reason = format!(
            "apply plan requires STAGED report, got {:?}",
            stage_report.status
        );
        return base;
    }

    let stage_dir = match stage_report.stage_dir.as_deref() {
        Some(dir) if !dir.trim().is_empty() => dir,
        _ => {
            base.reason = "apply plan requires stage_dir".to_string();
            return base;
        }
    };
    let staged_asset = match stage_report.staged_asset_path.as_deref() {
        Some(path) if !path.trim().is_empty() => path,
        _ => {
            base.reason = "apply plan requires staged_asset_path".to_string();
            return base;
        }
    };
    let expected_sha = match stage_report.expected_sha256.as_deref() {
        Some(sha) if !sha.trim().is_empty() => sha,
        _ => {
            base.reason = "apply plan requires expected_sha256".to_string();
            return base;
        }
    };

    let backup = match backup_path_for_target(target_exe_path, backup_suffix) {
        Ok(path) => path,
        Err(e) => {
            base.reason = format!("apply plan could not build backup path: {e}");
            return base;
        }
    };

    base.status = UpdateApplyPlanStatus::Planned;
    base.reason = "planned staged update apply (no mutation)".to_string();
    base.backup_exe_path = Some(backup.display().to_string());
    base.reversible = true;
    base.steps = vec![
        UpdateApplyStep::VerifyStagedCandidateSha256 {
            path: staged_asset.to_string(),
            expected_sha256: expected_sha.to_string(),
        },
        UpdateApplyStep::BackupCurrentExecutable {
            from: target_exe_path.display().to_string(),
            to: backup.display().to_string(),
        },
        UpdateApplyStep::ReplaceExecutableFromStage {
            from: staged_asset.to_string(),
            to: target_exe_path.display().to_string(),
        },
        UpdateApplyStep::VerifyInstalledExecutableSha256 {
            path: target_exe_path.display().to_string(),
            expected_sha256: expected_sha.to_string(),
        },
        UpdateApplyStep::RollbackByRestoringBackup {
            from_backup: backup.display().to_string(),
            to_target: target_exe_path.display().to_string(),
        },
    ];

    // Make sure the plan is at least self-consistent even before any mutation exists.
    if !Path::new(stage_dir).is_dir() {
        // Still planned: the plan is pure. Surface the observation as a reason suffix.
        base.reason.push_str(" (stage_dir_missing)");
    }
    if !Path::new(staged_asset).is_file() {
        base.reason.push_str(" (staged_asset_missing)");
    }

    base
}

pub(crate) fn write_update_apply_plan_evidence_for_stage2(
    stage_report: &UpdateCandidateStageReport,
    target_exe_path: &Path,
) -> UpdateApplyPlanEvidenceRecord {
    let plan = build_update_apply_plan(stage_report, target_exe_path, "evidence");
    let mut record = UpdateApplyPlanEvidenceRecord {
        schema_version: UPDATE_APPLY_PLAN_EVIDENCE_SCHEMA_VERSION,
        ok: false,
        no_mutation: plan.no_mutation,
        stage_dir: stage_report.stage_dir.clone(),
        evidence_path: None,
        write_error: None,
        plan: plan.clone(),
    };

    if stage_report.status != UpdateCandidateStageStatus::Staged {
        record.write_error = Some(format!(
            "apply plan evidence requires STAGED report, got {:?}",
            stage_report.status
        ));
        return record;
    }

    let stage_dir = match stage_report.stage_dir.as_deref() {
        Some(dir) if !dir.trim().is_empty() => Path::new(dir),
        _ => {
            record.write_error = Some("apply plan evidence requires stage_dir".to_string());
            return record;
        }
    };

    let evidence_path = stage_dir.join("update-apply-plan.json");
    let generated_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let payload = serde_json::json!({
        "schema_version": UPDATE_APPLY_PLAN_EVIDENCE_SCHEMA_VERSION,
        "generated_at_unix_ms": generated_at_unix_ms,
        "no_mutation": plan.no_mutation,
        "plan": plan,
    });
    record.evidence_path = Some(evidence_path.display().to_string());
    match crate::evidence_ledger::write_json_pretty(&evidence_path, &payload) {
        Ok(()) => {
            record.ok = true;
        }
        Err(e) => {
            record.write_error = Some(format!("write update apply plan evidence failed: {e}"));
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
            .map_err(|e| format!("Write update apply selftest JSON: {e}"))?;
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

pub(crate) fn run_update_apply_plan_contract_selftest(args: &[String]) -> Result<(), String> {
    let json_out = parse_selftest_json_arg(args, "--update-apply-plan-contract-selftest")?;

    let root = unique_update_apply_plan_selftest_root();
    let stage_dir = root.join("stage");
    fs::create_dir_all(&stage_dir).map_err(|e| format!("Create apply-plan selftest dir: {e}"))?;
    let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
    fs::write(&staged_asset_path, b"staged apply candidate bytes")
        .map_err(|e| format!("Write staged asset fixture: {e}"))?;
    let expected_sha256 = sha256_file_upper(&staged_asset_path)?;
    let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
    fs::write(&stage_evidence_path, b"{}")
        .map_err(|e| format!("Write stage evidence fixture: {e}"))?;
    let target_exe_path = root.join("gh_mirror_gui.exe");
    let stage_report = selftest_stage_report(
        &root,
        &stage_dir,
        &staged_asset_path,
        &stage_evidence_path,
        &expected_sha256,
    );
    let plan = build_update_apply_plan(&stage_report, &target_exe_path, "selftest");
    let ok = matches!(plan.status, UpdateApplyPlanStatus::Planned)
        && plan.no_mutation
        && plan.reversible
        && plan.steps.len() >= 5;
    let evidence_record =
        write_update_apply_plan_evidence_for_stage2(&stage_report, &target_exe_path);
    let evidence_ready = evidence_record.ok
        && evidence_record
            .evidence_path
            .as_deref()
            .map(|path| Path::new(path).is_file())
            .unwrap_or(false);
    let ok = ok && evidence_ready;
    let report = serde_json::json!({
        "schema_version": UPDATE_APPLY_PLAN_SCHEMA_VERSION,
        "ok": ok,
        "no_mutation": plan.no_mutation,
        "reversible": plan.reversible,
        "status": plan.status,
        "reason": plan.reason,
        "plan": plan,
        "evidence": {
            "ready": evidence_ready,
            "record": evidence_record,
        },
        "fixture": {
            "root": root,
            "stage_dir": stage_dir,
            "stage_evidence_path": stage_evidence_path,
            "staged_asset_path": staged_asset_path,
            "target_exe_path": target_exe_path,
            "expected_sha256": expected_sha256,
        }
    });
    let pretty_report = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialize selftest JSON: {e}"))?;
    write_selftest_json(json_out, &pretty_report)?;
    println!("{pretty_report}");
    if !ok {
        return Err("update apply plan contract selftest did not produce a planned reversible no-mutation plan".to_string());
    }
    Ok(())
}

pub(crate) fn run_update_apply_fixture_contract_selftest(args: &[String]) -> Result<(), String> {
    let json_out = parse_selftest_json_arg(args, "--update-apply-fixture-contract-selftest")?;

    let root = unique_update_apply_plan_selftest_root();
    let stage_dir = root.join("stage");
    fs::create_dir_all(&stage_dir)
        .map_err(|e| format!("Create apply fixture selftest dir: {e}"))?;
    let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
    fs::write(&staged_asset_path, b"trusted staged update bytes")
        .map_err(|e| format!("Write staged fixture asset: {e}"))?;
    let expected_sha256 = sha256_file_upper(&staged_asset_path)?;
    let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
    fs::write(&stage_evidence_path, b"{}")
        .map_err(|e| format!("Write stage evidence fixture: {e}"))?;
    let target_fixture_path = root.join("gh_mirror_gui.exe");
    fs::write(&target_fixture_path, b"original trusted app bytes")
        .map_err(|e| format!("Write target fixture asset: {e}"))?;
    let original_sha256 = sha256_file_upper(&target_fixture_path)?;
    let stage_report = selftest_stage_report(
        &root,
        &stage_dir,
        &staged_asset_path,
        &stage_evidence_path,
        &expected_sha256,
    );

    let fixture_apply = apply_update_fixture_for_stage2(&stage_report, &target_fixture_path);
    let target_after_sha256 = sha256_file_upper(&target_fixture_path)?;
    let evidence_ready = fixture_apply
        .evidence_path
        .as_deref()
        .map(|path| Path::new(path).is_file())
        .unwrap_or(false);
    let decision = crate::artifact_decision::ArtifactDecision::from_update_apply_fixture_evidence(
        &fixture_apply,
    );
    let ok = fixture_apply.ok
        && fixture_apply.fixture_only
        && fixture_apply.no_live_mutation
        && fixture_apply.rollback_ok
        && matches!(
            fixture_apply.status,
            UpdateApplyFixtureStatus::AppliedAndRolledBack
        )
        && evidence_ready
        && target_after_sha256 == original_sha256;
    let report = serde_json::json!({
        "schema_version": UPDATE_APPLY_FIXTURE_EVIDENCE_SCHEMA_VERSION,
        "ok": ok,
        "fixture_only": fixture_apply.fixture_only,
        "no_live_mutation": fixture_apply.no_live_mutation,
        "rollback_ok": fixture_apply.rollback_ok,
        "status": fixture_apply.status,
        "fixture_apply": fixture_apply,
        "artifact_decision": decision,
        "evidence": {
            "ready": evidence_ready,
        },
        "fixture": {
            "root": root,
            "stage_dir": stage_dir,
            "stage_evidence_path": stage_evidence_path,
            "staged_asset_path": staged_asset_path,
            "target_fixture_path": target_fixture_path,
            "expected_sha256": expected_sha256,
            "original_sha256": original_sha256,
            "target_after_sha256": target_after_sha256,
        }
    });
    let pretty_report = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialize fixture selftest JSON: {e}"))?;
    write_selftest_json(json_out, &pretty_report)?;
    println!("{pretty_report}");
    if !ok {
        return Err("update apply fixture contract selftest did not back up, replace, verify, and roll back inside fixture".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_candidate::{
        UpdateCandidateCheckReport, UpdateCandidateEvaluation, UpdateCandidateStatus,
    };

    fn staged_report_fixture() -> UpdateCandidateStageReport {
        UpdateCandidateStageReport {
            schema_version: 1,
            status: UpdateCandidateStageStatus::Staged,
            repo: "wsolarq11/gh_mirror_gui".to_string(),
            release_tag: "v9.9.9".to_string(),
            release_url: "https://example.invalid/releases/tag/v9.9.9".to_string(),
            stage_dir: Some("target/stage".to_string()),
            staged_asset_path: Some("target/stage/gh_mirror_gui.exe".to_string()),
            staged_sha256: Some("ABCDEF".to_string()),
            expected_sha256: Some("ABCDEF".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            reason: "staged verified candidate (no install)".to_string(),
            no_install: true,
            check_report: UpdateCandidateCheckReport {
                schema_version: 1,
                repo: "wsolarq11/gh_mirror_gui".to_string(),
                release_tag: "v9.9.9".to_string(),
                release_url: "https://example.invalid/releases/tag/v9.9.9".to_string(),
                asset_name: "gh_mirror_gui.exe".to_string(),
                release_publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
                evaluation: UpdateCandidateEvaluation {
                    schema_version: 1,
                    status: UpdateCandidateStatus::Candidate,
                    current_version: "v9.9.8".to_string(),
                    candidate_version: "9.9.9".to_string(),
                    release_tag: "v9.9.9".to_string(),
                    asset_name: "gh_mirror_gui.exe".to_string(),
                    reason: "fixture".to_string(),
                    verification_status: "VERIFIED".to_string(),
                    file_sha256: Some("ABCDEF".to_string()),
                    expected_sha256: Some("ABCDEF".to_string()),
                    verification_source: Some("SHA256SUMS.txt".to_string()),
                    source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
                    source_trust_decision: Some("TRUSTED".to_string()),
                    publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
                    evidence_path: None,
                    no_mutation: true,
                },
                evidence_write_error: None,
            },
            evidence_path: Some("target/stage/update-candidate-stage.json".to_string()),
            evidence_write_error: None,
        }
    }

    struct ApplyFixture {
        root: PathBuf,
        report: UpdateCandidateStageReport,
        target_path: PathBuf,
        backup_path: PathBuf,
        staged_sha256: String,
        original_sha256: String,
        original_bytes: Vec<u8>,
    }

    fn apply_fixture_on_disk() -> ApplyFixture {
        let root = unique_update_apply_plan_selftest_root();
        let stage_dir = root.join("stage");
        fs::create_dir_all(&stage_dir).expect("fixture stage dir should be creatable");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged bytes")
            .expect("staged asset should be writable");
        let staged_sha256 = sha256_file_upper(&staged_asset_path).unwrap();
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("stage evidence should be writable");
        let target_path = root.join("gh_mirror_gui.exe");
        let original_bytes = b"original target bytes".to_vec();
        fs::write(&target_path, &original_bytes).expect("target fixture should be writable");
        let original_sha256 = sha256_file_upper(&target_path).unwrap();
        let report = selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &staged_sha256,
        );
        let backup_path = backup_path_for_target(&target_path, "fixture").unwrap();
        ApplyFixture {
            root,
            report,
            target_path,
            backup_path,
            staged_sha256,
            original_sha256,
            original_bytes,
        }
    }

    #[test]
    fn update_apply_plan_refuses_non_staged_report() {
        let mut report = staged_report_fixture();
        report.status = UpdateCandidateStageStatus::NoUpdate;
        let plan = build_update_apply_plan(&report, Path::new("C:\\tmp\\gh_mirror_gui.exe"), "x");
        assert_eq!(plan.status, UpdateApplyPlanStatus::Refused);
        assert!(plan.no_mutation);
        assert!(plan.steps.is_empty());
    }

    #[test]
    fn update_apply_plan_builds_reversible_steps_without_mutation() {
        let report = staged_report_fixture();
        let plan =
            build_update_apply_plan(&report, Path::new("C:\\tmp\\gh_mirror_gui.exe"), "test");
        assert_eq!(plan.status, UpdateApplyPlanStatus::Planned);
        assert!(plan.no_mutation);
        assert!(plan.reversible);
        assert!(plan.steps.len() >= 5);
        assert!(plan
            .backup_exe_path
            .as_deref()
            .unwrap_or("")
            .contains("gh_mirror_gui.exe.bak-test"));
    }

    #[test]
    fn fixture_apply_refuses_unstaged_report() {
        let mut fixture = apply_fixture_on_disk();
        fixture.report.status = UpdateCandidateStageStatus::NoUpdate;
        let record = apply_update_fixture_for_stage2(&fixture.report, &fixture.target_path);

        assert_eq!(record.status, UpdateApplyFixtureStatus::Refused);
        assert!(!record.ok);
        assert_eq!(
            fs::read(&fixture.target_path).unwrap(),
            fixture.original_bytes
        );
        assert!(!fixture.backup_path.exists());
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn fixture_apply_refuses_missing_stage_asset() {
        let fixture = apply_fixture_on_disk();
        fs::remove_file(
            fixture
                .report
                .staged_asset_path
                .as_deref()
                .map(Path::new)
                .unwrap(),
        )
        .unwrap();

        let record = apply_update_fixture_for_stage2(&fixture.report, &fixture.target_path);

        assert_eq!(record.status, UpdateApplyFixtureStatus::Refused);
        assert!(record.reason.contains("staged asset"));
        assert_eq!(
            fs::read(&fixture.target_path).unwrap(),
            fixture.original_bytes
        );
        assert!(!fixture.backup_path.exists());
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn fixture_apply_refuses_missing_expected_sha256() {
        let mut fixture = apply_fixture_on_disk();
        fixture.report.expected_sha256 = None;

        let record = apply_update_fixture_for_stage2(&fixture.report, &fixture.target_path);

        assert_eq!(record.status, UpdateApplyFixtureStatus::Refused);
        assert!(record.reason.contains("expected_sha256"));
        assert_eq!(
            fs::read(&fixture.target_path).unwrap(),
            fixture.original_bytes
        );
        assert!(!fixture.backup_path.exists());
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn fixture_apply_refuses_untrusted_source_before_mutation() {
        let mut fixture = apply_fixture_on_disk();
        fixture.report.check_report.evaluation.source_trust_decision = Some("BLOCK".to_string());

        let record = apply_update_fixture_for_stage2(&fixture.report, &fixture.target_path);

        assert_eq!(record.status, UpdateApplyFixtureStatus::Refused);
        assert!(record.reason.contains("trusted source policy"));
        assert_eq!(
            fs::read(&fixture.target_path).unwrap(),
            fixture.original_bytes
        );
        assert!(!fixture.backup_path.exists());
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn fixture_apply_refuses_mismatched_staged_sha_before_mutation() {
        let mut fixture = apply_fixture_on_disk();
        fixture.report.expected_sha256 = Some("00".repeat(32));

        let record = apply_update_fixture_for_stage2(&fixture.report, &fixture.target_path);

        assert_eq!(record.status, UpdateApplyFixtureStatus::Refused);
        assert!(record.reason.contains("sha256 mismatch"));
        assert_eq!(
            fs::read(&fixture.target_path).unwrap(),
            fixture.original_bytes
        );
        assert!(!fixture.backup_path.exists());
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn fixture_apply_backs_up_replaces_verifies_and_rolls_back() {
        let fixture = apply_fixture_on_disk();

        let record = apply_update_fixture_for_stage2(&fixture.report, &fixture.target_path);

        assert_eq!(
            record.status,
            UpdateApplyFixtureStatus::AppliedAndRolledBack
        );
        assert!(record.ok);
        assert!(record.fixture_only);
        assert!(record.no_live_mutation);
        assert!(record.rollback_ok);
        assert_eq!(
            record.installed_sha256.as_deref(),
            Some(fixture.staged_sha256.as_str())
        );
        assert_eq!(
            record.rollback_sha256.as_deref(),
            Some(fixture.original_sha256.as_str())
        );
        assert_eq!(
            fs::read(&fixture.target_path).unwrap(),
            fixture.original_bytes
        );
        assert!(fixture.backup_path.exists());
        assert!(record
            .evidence_path
            .as_deref()
            .map(|path| Path::new(path).is_file())
            .unwrap_or(false));
        assert!(!record.plan.no_mutation);
        let _ = fs::remove_dir_all(&fixture.root);
    }

    #[test]
    fn fixture_apply_never_accepts_live_current_exe_path_by_default() {
        let fixture = apply_fixture_on_disk();
        let current_exe = std::env::current_exe().expect("test current exe should be known");

        let record = apply_update_fixture_for_stage2(&fixture.report, &current_exe);

        assert_eq!(record.status, UpdateApplyFixtureStatus::Refused);
        assert!(record.reason.contains("live current executable"));
        assert!(!record.ok);
        let _ = fs::remove_dir_all(&fixture.root);
    }
}
