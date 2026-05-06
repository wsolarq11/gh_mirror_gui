use crate::update_candidate::{UpdateCandidateStageReport, UpdateCandidateStageStatus};
use std::path::{Path, PathBuf};

const UPDATE_APPLY_PLAN_SCHEMA_VERSION: u32 = 1;

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

fn backup_path_for_target(target_exe_path: &Path, suffix: &str) -> Result<PathBuf, String> {
    let file_name = target_exe_path
        .file_name()
        .ok_or_else(|| "target exe path has no file name".to_string())?
        .to_string_lossy()
        .to_string();
    let backup_name = format!("{file_name}.bak-{suffix}");
    Ok(target_exe_path.with_file_name(backup_name))
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
}
