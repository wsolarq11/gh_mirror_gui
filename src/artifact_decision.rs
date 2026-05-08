use crate::update_apply_plan::{UpdateApplyPlan, UpdateApplyPlanStatus, UpdateApplyStep};
use crate::update_candidate::{
    UpdateCandidateCheckReport, UpdateCandidateStageReport, UpdateCandidateStageStatus,
    UpdateCandidateStatus,
};
use std::path::Path;

const ARTIFACT_DECISION_SCHEMA_VERSION: u32 = 1;
const ARTIFACT_DECISION_FORMULA: &str =
    "Source + Intent + Policy -> Evidence + Verdict + ActionPlan";

/// Runtime intent names the core action, not a roadmap phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactIntent {
    Download,
    CheckUpdate,
    StageUpdate,
    PlanApply,
    AuditOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ArtifactVerdict {
    Trusted,
    Risk,
    Block,
    Candidate,
    Staged,
    NoUpdate,
    Planned,
    Refused,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactActionKind {
    None,
    Keep,
    Quarantine,
    Delete,
    Download,
    Stage,
    PlanApply,
    AuditOnly,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactActionPathKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactCandidate {
    pub source: String,
    pub artifact_name: String,
    pub version_or_tag: Option<String>,
    pub uri: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactEvidenceSummary {
    pub evidence_path: Option<String>,
    pub hash_status: Option<String>,
    pub source_authenticity: Option<String>,
    pub publisher_key_fingerprint_sha256: Option<String>,
    pub policy_verdict: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactActionPath {
    pub label: String,
    pub path: String,
    pub missing_message: String,
    pub kind: ArtifactActionPathKind,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactActionPlan {
    pub kind: ArtifactActionKind,
    pub status: String,
    pub summary: String,
    pub reversible: bool,
    pub no_mutation: bool,
    pub path_action: Option<ArtifactActionPath>,
    pub steps: Vec<String>,
}

/// Single runtime decision DTO. Numbered phases stay in roadmap milestones only.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ArtifactDecision {
    pub schema_version: u32,
    pub contract: String,
    pub intent: ArtifactIntent,
    pub candidate: ArtifactCandidate,
    pub evidence: ArtifactEvidenceSummary,
    pub verdict: ArtifactVerdict,
    pub action_plan: ArtifactActionPlan,
}

impl ArtifactDecision {
    pub fn new(
        intent: ArtifactIntent,
        candidate: ArtifactCandidate,
        evidence: ArtifactEvidenceSummary,
        verdict: ArtifactVerdict,
        action_plan: ArtifactActionPlan,
    ) -> Self {
        Self {
            schema_version: ARTIFACT_DECISION_SCHEMA_VERSION,
            contract: ARTIFACT_DECISION_FORMULA.to_string(),
            intent,
            candidate,
            evidence,
            verdict,
            action_plan,
        }
    }

    pub fn from_update_candidate_check(report: &UpdateCandidateCheckReport) -> Self {
        let verdict = match report.evaluation.status {
            UpdateCandidateStatus::Candidate => ArtifactVerdict::Candidate,
            UpdateCandidateStatus::NoUpdate => ArtifactVerdict::NoUpdate,
            UpdateCandidateStatus::Refused => ArtifactVerdict::Refused,
        };
        let action_kind = match report.evaluation.status {
            UpdateCandidateStatus::Candidate => ArtifactActionKind::Stage,
            UpdateCandidateStatus::NoUpdate | UpdateCandidateStatus::Refused => {
                ArtifactActionKind::None
            }
        };

        Self::new(
            ArtifactIntent::CheckUpdate,
            ArtifactCandidate {
                source: report.repo.clone(),
                artifact_name: report.asset_name.clone(),
                version_or_tag: Some(report.release_tag.clone()),
                uri: Some(report.release_url.clone()),
            },
            ArtifactEvidenceSummary {
                evidence_path: report.evaluation.evidence_path.clone(),
                hash_status: Some(report.evaluation.verification_status.clone()),
                source_authenticity: report.evaluation.source_authenticity_status.clone(),
                publisher_key_fingerprint_sha256: report
                    .publisher_key_fingerprint_sha256()
                    .map(str::to_string),
                policy_verdict: report.evaluation.source_trust_decision.clone(),
            },
            verdict,
            ArtifactActionPlan {
                kind: action_kind,
                status: report.status_display().to_string(),
                summary: report.evaluation.reason.clone(),
                reversible: true,
                no_mutation: report.evaluation.no_mutation,
                path_action: None,
                steps: Vec::new(),
            },
        )
    }

    pub fn from_update_candidate_stage(report: &UpdateCandidateStageReport) -> Self {
        let verdict = match report.status {
            UpdateCandidateStageStatus::Staged => ArtifactVerdict::Staged,
            UpdateCandidateStageStatus::NoUpdate => ArtifactVerdict::NoUpdate,
            UpdateCandidateStageStatus::Refused => ArtifactVerdict::Refused,
        };
        let action_kind = match report.status {
            UpdateCandidateStageStatus::Staged => ArtifactActionKind::PlanApply,
            UpdateCandidateStageStatus::NoUpdate | UpdateCandidateStageStatus::Refused => {
                ArtifactActionKind::None
            }
        };

        Self::new(
            ArtifactIntent::StageUpdate,
            ArtifactCandidate {
                source: report.repo.clone(),
                artifact_name: report.check_report.asset_name.clone(),
                version_or_tag: Some(report.release_tag.clone()),
                uri: Some(report.release_url.clone()),
            },
            ArtifactEvidenceSummary {
                evidence_path: report.evidence_path.clone(),
                hash_status: Some(report.check_report.evaluation.verification_status.clone()),
                source_authenticity: report
                    .check_report
                    .evaluation
                    .source_authenticity_status
                    .clone(),
                publisher_key_fingerprint_sha256: report.publisher_key_fingerprint_sha256.clone(),
                policy_verdict: report.check_report.evaluation.source_trust_decision.clone(),
            },
            verdict,
            ArtifactActionPlan {
                kind: action_kind,
                status: stage_status_label(report.status).to_string(),
                summary: report.reason.clone(),
                reversible: true,
                no_mutation: report.no_install,
                path_action: report.stage_dir.as_ref().map(|path| ArtifactActionPath {
                    label: "📁 Open stage folder".to_string(),
                    path: path.clone(),
                    missing_message: "Stage folder path is recorded but not present on disk."
                        .to_string(),
                    kind: ArtifactActionPathKind::Directory,
                }),
                steps: report
                    .staged_asset_path
                    .iter()
                    .map(|path| format!("stage verified candidate: {path}"))
                    .collect(),
            },
        )
    }

    pub fn from_update_apply_plan(plan: &UpdateApplyPlan, evidence_path: Option<&str>) -> Self {
        let verdict = match plan.status {
            UpdateApplyPlanStatus::Planned => ArtifactVerdict::Planned,
            UpdateApplyPlanStatus::Refused => ArtifactVerdict::Refused,
        };
        let action_kind = match plan.status {
            UpdateApplyPlanStatus::Planned => ArtifactActionKind::PlanApply,
            UpdateApplyPlanStatus::Refused => ArtifactActionKind::None,
        };

        Self::new(
            ArtifactIntent::PlanApply,
            ArtifactCandidate {
                source: plan.repo.clone(),
                artifact_name: plan
                    .staged_asset_path
                    .as_deref()
                    .and_then(|path| Path::new(path).file_name())
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                version_or_tag: Some(plan.release_tag.clone()),
                uri: plan.staged_asset_path.clone(),
            },
            ArtifactEvidenceSummary {
                evidence_path: evidence_path.map(str::to_string),
                hash_status: plan
                    .expected_sha256
                    .as_ref()
                    .map(|_| "VERIFIED".to_string()),
                source_authenticity: None,
                publisher_key_fingerprint_sha256: None,
                policy_verdict: Some(report_status_label(plan.status)),
            },
            verdict,
            ArtifactActionPlan {
                kind: action_kind,
                status: report_status_label(plan.status),
                summary: plan.reason.clone(),
                reversible: plan.reversible,
                no_mutation: plan.no_mutation,
                path_action: None,
                steps: plan.steps.iter().map(describe_update_apply_step).collect(),
            },
        )
    }
}

fn report_status_label(status: UpdateApplyPlanStatus) -> String {
    match status {
        UpdateApplyPlanStatus::Planned => "planned".to_string(),
        UpdateApplyPlanStatus::Refused => "refused".to_string(),
    }
}

fn stage_status_label(status: UpdateCandidateStageStatus) -> &'static str {
    match status {
        UpdateCandidateStageStatus::Staged => "staged",
        UpdateCandidateStageStatus::NoUpdate => "no-update",
        UpdateCandidateStageStatus::Refused => "refused",
    }
}

fn describe_update_apply_step(step: &UpdateApplyStep) -> String {
    match step {
        UpdateApplyStep::VerifyStagedCandidateSha256 { path, .. } => {
            format!("verify staged candidate sha256: {path}")
        }
        UpdateApplyStep::BackupCurrentExecutable { from, to } => {
            format!("backup current executable: {from} -> {to}")
        }
        UpdateApplyStep::ReplaceExecutableFromStage { from, to } => {
            format!("replace executable from stage: {from} -> {to}")
        }
        UpdateApplyStep::VerifyInstalledExecutableSha256 { path, .. } => {
            format!("verify installed executable sha256: {path}")
        }
        UpdateApplyStep::RollbackByRestoringBackup {
            from_backup,
            to_target,
        } => {
            format!("rollback by restoring backup: {from_backup} -> {to_target}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update_apply_plan::{UpdateApplyPlan, UpdateApplyPlanStatus, UpdateApplyStep};
    use crate::update_candidate::{
        UpdateCandidateCheckReport, UpdateCandidateEvaluation, UpdateCandidateStageReport,
        UpdateCandidateStageStatus, UpdateCandidateStatus,
    };

    fn check_report_fixture() -> UpdateCandidateCheckReport {
        UpdateCandidateCheckReport {
            schema_version: 1,
            repo: "wsolarq11/gh_mirror_gui".to_string(),
            release_tag: "v0.1.7".to_string(),
            release_url: "https://github.com/wsolarq11/gh_mirror_gui/releases/tag/v0.1.7"
                .to_string(),
            asset_name: "gh_mirror_gui.exe".to_string(),
            release_publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            evaluation: UpdateCandidateEvaluation {
                schema_version: 1,
                status: UpdateCandidateStatus::Candidate,
                current_version: "0.1.6".to_string(),
                candidate_version: "0.1.7".to_string(),
                release_tag: "v0.1.7".to_string(),
                asset_name: "gh_mirror_gui.exe".to_string(),
                reason: "newer trusted signed candidate".to_string(),
                verification_status: "VERIFIED".to_string(),
                file_sha256: Some("FILESHA".to_string()),
                expected_sha256: Some("FILESHA".to_string()),
                verification_source: Some("SHA256SUMS.txt".to_string()),
                source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
                source_trust_decision: Some("TRUSTED".to_string()),
                publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
                evidence_path: Some("evidence.json".to_string()),
                no_mutation: true,
            },
            evidence_write_error: None,
        }
    }

    #[test]
    fn artifact_decision_contract_formula_is_single_pipeline() {
        assert_eq!(
            ARTIFACT_DECISION_FORMULA,
            "Source + Intent + Policy -> Evidence + Verdict + ActionPlan"
        );
    }

    #[test]
    fn artifact_decision_serialization_keeps_phase_labels_out_of_runtime_contract() {
        let decision = ArtifactDecision::from_update_candidate_check(&check_report_fixture());
        let value = serde_json::to_value(&decision)
            .expect("artifact decision should serialize in unit tests");
        let serialized = serde_json::to_string(&value)
            .expect("artifact decision JSON should serialize in unit tests");

        assert!(
            !serialized.to_ascii_lowercase().contains("phase"),
            "runtime decision JSON must not carry roadmap phase labels: {serialized}"
        );
        assert!(value.get("intent").is_some());
        assert!(value.get("verdict").is_some());
        assert!(value.get("action_plan").is_some());
    }

    #[test]
    fn artifact_decision_wraps_update_candidate_as_evidence_verdict_action_plan() {
        let report = check_report_fixture();
        let decision = ArtifactDecision::from_update_candidate_check(&report);

        assert_eq!(decision.intent, ArtifactIntent::CheckUpdate);
        assert_eq!(decision.verdict, ArtifactVerdict::Candidate);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::Stage);
        assert_eq!(decision.action_plan.path_action, None);
        assert_eq!(
            decision.evidence.source_authenticity.as_deref(),
            Some("TRUSTED_SIGNATURE")
        );
        assert!(decision.action_plan.no_mutation);
    }

    #[test]
    fn artifact_decision_wraps_update_stage_as_next_apply_plan_intent() {
        let check_report = check_report_fixture();
        let stage = UpdateCandidateStageReport {
            schema_version: 1,
            status: UpdateCandidateStageStatus::Staged,
            repo: check_report.repo.clone(),
            release_tag: check_report.release_tag.clone(),
            release_url: check_report.release_url.clone(),
            stage_dir: Some("target/stage".to_string()),
            staged_asset_path: Some("target/stage/gh_mirror_gui.exe".to_string()),
            staged_sha256: Some("FILESHA".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            reason: "staged verified candidate".to_string(),
            no_install: true,
            check_report,
            evidence_path: Some("stage-evidence.json".to_string()),
            evidence_write_error: None,
        };

        let decision = ArtifactDecision::from_update_candidate_stage(&stage);

        assert_eq!(decision.intent, ArtifactIntent::StageUpdate);
        assert_eq!(decision.verdict, ArtifactVerdict::Staged);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::PlanApply);
        assert_eq!(
            decision.action_plan.path_action,
            Some(ArtifactActionPath {
                label: "📁 Open stage folder".to_string(),
                path: "target/stage".to_string(),
                missing_message: "Stage folder path is recorded but not present on disk."
                    .to_string(),
                kind: ArtifactActionPathKind::Directory,
            })
        );
        assert!(decision.action_plan.reversible);
        assert!(decision.action_plan.no_mutation);
        assert_eq!(
            decision.action_plan.steps,
            vec!["stage verified candidate: target/stage/gh_mirror_gui.exe".to_string()]
        );
    }

    #[test]
    fn artifact_decision_wraps_update_apply_plan_as_action_plan_surface() {
        let report = check_report_fixture();
        let stage = UpdateCandidateStageReport {
            schema_version: 1,
            status: UpdateCandidateStageStatus::Staged,
            repo: report.repo.clone(),
            release_tag: report.release_tag.clone(),
            release_url: report.release_url.clone(),
            stage_dir: Some("target/stage".to_string()),
            staged_asset_path: Some("target/stage/gh_mirror_gui.exe".to_string()),
            staged_sha256: Some("FILESHA".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            reason: "staged verified candidate".to_string(),
            no_install: true,
            check_report: report,
            evidence_path: Some("stage-evidence.json".to_string()),
            evidence_write_error: None,
        };
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: UpdateApplyPlanStatus::Planned,
            reason: "planned staged update apply (no mutation)".to_string(),
            repo: stage.repo.clone(),
            release_tag: stage.release_tag.clone(),
            stage_dir: stage.stage_dir.clone(),
            staged_asset_path: stage.staged_asset_path.clone(),
            expected_sha256: stage.expected_sha256.clone(),
            target_exe_path: Some("target\\release\\gh_mirror_gui.exe".to_string()),
            backup_exe_path: Some("target\\release\\gh_mirror_gui.exe.bak-test".to_string()),
            reversible: true,
            no_mutation: true,
            steps: vec![UpdateApplyStep::VerifyStagedCandidateSha256 {
                path: "target/stage/gh_mirror_gui.exe".to_string(),
                expected_sha256: "FILESHA".to_string(),
            }],
        };

        let decision = ArtifactDecision::from_update_apply_plan(&plan, Some("plan-evidence.json"));

        assert_eq!(decision.intent, ArtifactIntent::PlanApply);
        assert_eq!(decision.verdict, ArtifactVerdict::Planned);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::PlanApply);
        assert_eq!(
            decision.evidence.evidence_path.as_deref(),
            Some("plan-evidence.json")
        );
        assert!(decision.action_plan.steps[0].contains("verify staged candidate sha256"));
    }
}
