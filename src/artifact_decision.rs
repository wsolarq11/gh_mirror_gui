use crate::update_apply_plan::{
    UpdateApplyFixtureEvidenceRecord, UpdateApplyFixtureStatus, UpdateApplyPlan,
    UpdateApplyPlanStatus, UpdateApplyStep,
};
use crate::update_apply_readiness::{UpdateApplyReadinessRecord, UpdateApplyReadinessStatus};
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
    ApplyReadiness,
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
    Ready,
    ApprovalRequired,
    Unknown,
    Blocked,
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
    ApplyReadiness,
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

    pub fn from_update_apply_fixture_evidence(record: &UpdateApplyFixtureEvidenceRecord) -> Self {
        let trusted_fixture = fixture_apply_trusted(record);
        let verdict = match record.status {
            UpdateApplyFixtureStatus::AppliedAndRolledBack if trusted_fixture => {
                ArtifactVerdict::Trusted
            }
            UpdateApplyFixtureStatus::RollbackFailed => ArtifactVerdict::Risk,
            UpdateApplyFixtureStatus::AppliedAndRolledBack | UpdateApplyFixtureStatus::Refused => {
                ArtifactVerdict::Refused
            }
        };
        let action_kind = match record.status {
            UpdateApplyFixtureStatus::AppliedAndRolledBack if trusted_fixture => {
                ArtifactActionKind::AuditOnly
            }
            UpdateApplyFixtureStatus::RollbackFailed => ArtifactActionKind::AuditOnly,
            UpdateApplyFixtureStatus::AppliedAndRolledBack | UpdateApplyFixtureStatus::Refused => {
                ArtifactActionKind::None
            }
        };
        let mut steps: Vec<String> = record
            .plan
            .steps
            .iter()
            .map(describe_update_apply_step)
            .collect();
        steps.push(format!(
            "fixture apply result: {} (fixture_only={}, rollback_ok={}, no_live_mutation={})",
            record.reason, record.fixture_only, record.rollback_ok, record.no_live_mutation
        ));

        Self::new(
            ArtifactIntent::PlanApply,
            ArtifactCandidate {
                source: record.plan.repo.clone(),
                artifact_name: record
                    .staged_asset_path
                    .as_deref()
                    .and_then(|path| Path::new(path).file_name())
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                version_or_tag: Some(record.plan.release_tag.clone()),
                uri: record.staged_asset_path.clone(),
            },
            ArtifactEvidenceSummary {
                evidence_path: record.evidence_path.clone(),
                hash_status: record.verification_status.clone().or_else(|| {
                    record
                        .installed_sha256
                        .as_ref()
                        .filter(|_| trusted_fixture)
                        .map(|_| "VERIFIED".to_string())
                }),
                source_authenticity: record.source_authenticity_status.clone(),
                publisher_key_fingerprint_sha256: record.publisher_key_fingerprint_sha256.clone(),
                policy_verdict: record
                    .source_trust_decision
                    .clone()
                    .or_else(|| Some(fixture_status_label(record.status).to_string())),
            },
            verdict,
            ArtifactActionPlan {
                kind: action_kind,
                status: fixture_status_label(record.status).to_string(),
                summary: record.reason.clone(),
                reversible: record.rollback_ok || record.plan.reversible,
                no_mutation: record.plan.no_mutation,
                path_action: None,
                steps,
            },
        )
    }

    pub fn from_update_apply_readiness(record: &UpdateApplyReadinessRecord) -> Self {
        let trusted_readiness = update_apply_readiness_trusted(record);
        let verdict = match record.status {
            UpdateApplyReadinessStatus::ReadyForManualApply if trusted_readiness => {
                ArtifactVerdict::Ready
            }
            UpdateApplyReadinessStatus::ApprovalRequired if trusted_readiness => {
                ArtifactVerdict::ApprovalRequired
            }
            UpdateApplyReadinessStatus::Unknown => ArtifactVerdict::Unknown,
            UpdateApplyReadinessStatus::Blocked => ArtifactVerdict::Blocked,
            UpdateApplyReadinessStatus::Refused
            | UpdateApplyReadinessStatus::StaleStage
            | UpdateApplyReadinessStatus::ReadyForManualApply
            | UpdateApplyReadinessStatus::ApprovalRequired => ArtifactVerdict::Refused,
        };
        let action_kind = match verdict {
            ArtifactVerdict::Ready | ArtifactVerdict::ApprovalRequired => {
                ArtifactActionKind::ApplyReadiness
            }
            ArtifactVerdict::Unknown | ArtifactVerdict::Blocked => ArtifactActionKind::AuditOnly,
            _ => ArtifactActionKind::None,
        };
        let mut steps: Vec<String> = record
            .plan
            .steps
            .iter()
            .map(describe_update_apply_step)
            .collect();
        steps.push(format!(
            "live apply readiness result: {} (no_live_mutation={}, apply_performed={}, install_performed={})",
            record.reason, record.no_live_mutation, record.apply_performed, record.install_performed
        ));

        Self::new(
            ArtifactIntent::ApplyReadiness,
            ArtifactCandidate {
                source: record.repo.clone(),
                artifact_name: record
                    .staged_asset_path
                    .as_deref()
                    .and_then(|path| Path::new(path).file_name())
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                version_or_tag: Some(record.release_tag.clone()),
                uri: record.staged_asset_path.clone(),
            },
            ArtifactEvidenceSummary {
                evidence_path: record.evidence_path.clone(),
                hash_status: record.verification_status.clone(),
                source_authenticity: record.source_authenticity_status.clone(),
                publisher_key_fingerprint_sha256: record.publisher_key_fingerprint_sha256.clone(),
                policy_verdict: record
                    .source_trust_decision
                    .clone()
                    .or_else(|| Some(readiness_status_label(record.status).to_string())),
            },
            verdict,
            ArtifactActionPlan {
                kind: action_kind,
                status: readiness_status_label(record.status).to_string(),
                summary: record.reason.clone(),
                reversible: record.plan.reversible,
                no_mutation: record.plan.no_mutation
                    && record.no_live_mutation
                    && !record.apply_performed
                    && !record.install_performed,
                path_action: None,
                steps,
            },
        )
    }
}

fn update_apply_readiness_trusted(record: &UpdateApplyReadinessRecord) -> bool {
    record.ok
        && record.no_live_mutation
        && !record.apply_performed
        && !record.install_performed
        && record.plan.no_mutation
        && record.plan.reversible
        && record
            .verification_status
            .as_deref()
            .map(|status| status.eq_ignore_ascii_case("VERIFIED"))
            .unwrap_or(false)
        && record
            .source_authenticity_status
            .as_deref()
            .map(|status| status.eq_ignore_ascii_case("TRUSTED_SIGNATURE"))
            .unwrap_or(false)
        && record
            .source_trust_decision
            .as_deref()
            .map(|decision| decision.eq_ignore_ascii_case("TRUSTED"))
            .unwrap_or(false)
        && record
            .publisher_key_fingerprint_sha256
            .as_deref()
            .map(str::trim)
            .map(|fingerprint| !fingerprint.is_empty())
            .unwrap_or(false)
}

fn fixture_apply_trusted(record: &UpdateApplyFixtureEvidenceRecord) -> bool {
    record.ok
        && record.fixture_only
        && record.no_live_mutation
        && record.rollback_ok
        && record
            .installed_sha256
            .as_deref()
            .zip(record.expected_sha256.as_deref())
            .map(|(installed, expected)| installed.eq_ignore_ascii_case(expected))
            .unwrap_or(false)
        && record
            .source_authenticity_status
            .as_deref()
            .map(|status| status.eq_ignore_ascii_case("TRUSTED_SIGNATURE"))
            .unwrap_or(false)
        && record
            .source_trust_decision
            .as_deref()
            .map(|decision| decision.eq_ignore_ascii_case("TRUSTED"))
            .unwrap_or(false)
        && record
            .publisher_key_fingerprint_sha256
            .as_deref()
            .map(str::trim)
            .map(|fingerprint| !fingerprint.is_empty())
            .unwrap_or(false)
}

fn report_status_label(status: UpdateApplyPlanStatus) -> String {
    match status {
        UpdateApplyPlanStatus::Planned => "planned".to_string(),
        UpdateApplyPlanStatus::Refused => "refused".to_string(),
    }
}

fn fixture_status_label(status: UpdateApplyFixtureStatus) -> &'static str {
    match status {
        UpdateApplyFixtureStatus::Refused => "refused",
        UpdateApplyFixtureStatus::AppliedAndRolledBack => "applied-and-rolled-back",
        UpdateApplyFixtureStatus::RollbackFailed => "rollback-failed",
    }
}

fn readiness_status_label(status: UpdateApplyReadinessStatus) -> &'static str {
    match status {
        UpdateApplyReadinessStatus::Refused => "refused",
        UpdateApplyReadinessStatus::ReadyForManualApply => "ready-for-manual-apply",
        UpdateApplyReadinessStatus::Blocked => "blocked",
        UpdateApplyReadinessStatus::Unknown => "unknown",
        UpdateApplyReadinessStatus::StaleStage => "stale-stage",
        UpdateApplyReadinessStatus::ApprovalRequired => "approval-required",
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
    use crate::update_apply_plan::{
        UpdateApplyFixtureEvidenceRecord, UpdateApplyFixtureStatus, UpdateApplyPlan,
        UpdateApplyPlanStatus, UpdateApplyStep,
    };
    use crate::update_apply_readiness::{
        ManualApprovalState, UpdateApplyReadinessRecord, UpdateApplyReadinessStatus,
        UPDATE_APPLY_READINESS_MODULE_OWNER,
    };
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

    fn readiness_record_fixture(status: UpdateApplyReadinessStatus) -> UpdateApplyReadinessRecord {
        let plan_status = match status {
            UpdateApplyReadinessStatus::ReadyForManualApply
            | UpdateApplyReadinessStatus::ApprovalRequired => UpdateApplyPlanStatus::Planned,
            _ => UpdateApplyPlanStatus::Refused,
        };
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: plan_status,
            reason: "live apply readiness proven but manual approval is required before execution (no live mutation)".to_string(),
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: Some("stage".to_string()),
            staged_asset_path: Some("stage/gh_mirror_gui.exe".to_string()),
            expected_sha256: Some("abc".to_string()),
            target_exe_path: Some("current/gh_mirror_gui.exe".to_string()),
            backup_exe_path: Some("stage/gh_mirror_gui.exe.bak-readiness".to_string()),
            reversible: matches!(
                status,
                UpdateApplyReadinessStatus::ReadyForManualApply
                    | UpdateApplyReadinessStatus::ApprovalRequired
            ),
            no_mutation: true,
            steps: vec![UpdateApplyStep::BackupCurrentExecutable {
                from: "current/gh_mirror_gui.exe".to_string(),
                to: "stage/gh_mirror_gui.exe.bak-readiness".to_string(),
            }],
        };

        UpdateApplyReadinessRecord {
            schema_version: 1,
            ok: matches!(
                status,
                UpdateApplyReadinessStatus::ReadyForManualApply
                    | UpdateApplyReadinessStatus::ApprovalRequired
            ),
            module_owner: UPDATE_APPLY_READINESS_MODULE_OWNER.to_string(),
            no_live_mutation: true,
            apply_performed: false,
            install_performed: false,
            status,
            reason: match status {
                UpdateApplyReadinessStatus::Unknown => {
                    "backup readiness cannot be proven side-effect-free".to_string()
                }
                UpdateApplyReadinessStatus::Refused | UpdateApplyReadinessStatus::StaleStage => {
                    "live apply readiness refused before mutation".to_string()
                }
                _ => "live apply readiness proven but manual approval is required before execution (no live mutation)".to_string(),
            },
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: Some("stage".to_string()),
            stage_evidence_path: Some("stage/update-candidate-stage.json".to_string()),
            stage_status: "Staged".to_string(),
            staged_asset_path: Some("stage/gh_mirror_gui.exe".to_string()),
            expected_sha256: Some("abc".to_string()),
            staged_sha256: Some("abc".to_string()),
            verification_status: Some("VERIFIED".to_string()),
            source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
            source_trust_decision: Some("TRUSTED".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            target_current_exe_path: Some("current/gh_mirror_gui.exe".to_string()),
            target_canonical_path: Some("current/gh_mirror_gui.exe".to_string()),
            staged_asset_canonical_path: Some("stage/gh_mirror_gui.exe".to_string()),
            backup_destination_path: Some("stage/gh_mirror_gui.exe.bak-readiness".to_string()),
            backup_boundary_path: Some("stage".to_string()),
            rollback_plan: vec![
                "restore stage/gh_mirror_gui.exe.bak-readiness to current/gh_mirror_gui.exe"
                    .to_string(),
            ],
            manual_approval_state: match status {
                UpdateApplyReadinessStatus::ReadyForManualApply => ManualApprovalState::Granted,
                _ => ManualApprovalState::Required,
            },
            refusal_reasons: Vec::new(),
            evidence_path: Some("stage/update-apply-readiness.json".to_string()),
            write_error: None,
            plan,
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

    #[test]
    fn artifact_decision_wraps_apply_readiness_as_not_installed() {
        let record = readiness_record_fixture(UpdateApplyReadinessStatus::ApprovalRequired);
        let decision = ArtifactDecision::from_update_apply_readiness(&record);

        assert_eq!(decision.intent, ArtifactIntent::ApplyReadiness);
        assert_eq!(decision.verdict, ArtifactVerdict::ApprovalRequired);
        assert_eq!(
            decision.action_plan.kind,
            ArtifactActionKind::ApplyReadiness
        );
        assert!(decision.action_plan.no_mutation);
        assert_eq!(
            decision.evidence.source_authenticity.as_deref(),
            Some("TRUSTED_SIGNATURE")
        );
        assert_eq!(decision.evidence.policy_verdict.as_deref(), Some("TRUSTED"));
        assert!(
            !decision
                .action_plan
                .summary
                .to_ascii_lowercase()
                .contains("installed"),
            "readiness summary must not imply installation"
        );
        assert!(
            !decision
                .action_plan
                .summary
                .to_ascii_lowercase()
                .contains("applied"),
            "readiness summary must not imply apply already happened"
        );
    }

    #[test]
    fn artifact_decision_refuses_untrusted_readiness() {
        let mut record = readiness_record_fixture(UpdateApplyReadinessStatus::ApprovalRequired);
        record.source_trust_decision = Some("BLOCK".to_string());
        let decision = ArtifactDecision::from_update_apply_readiness(&record);

        assert_eq!(decision.intent, ArtifactIntent::ApplyReadiness);
        assert_eq!(decision.verdict, ArtifactVerdict::Refused);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::None);
        assert!(decision.action_plan.no_mutation);
    }

    #[test]
    fn artifact_decision_requires_approval_for_ready_live_apply() {
        let record = readiness_record_fixture(UpdateApplyReadinessStatus::ApprovalRequired);
        let decision = ArtifactDecision::from_update_apply_readiness(&record);

        assert_eq!(decision.verdict, ArtifactVerdict::ApprovalRequired);
        assert_eq!(decision.action_plan.status, "approval-required");
        assert_eq!(
            decision.action_plan.kind,
            ArtifactActionKind::ApplyReadiness
        );
        assert!(decision.action_plan.reversible);
        assert!(decision.action_plan.no_mutation);
    }

    #[test]
    fn artifact_decision_reports_unknown_readiness_without_trust_escalation() {
        let record = readiness_record_fixture(UpdateApplyReadinessStatus::Unknown);
        let decision = ArtifactDecision::from_update_apply_readiness(&record);

        assert_eq!(decision.intent, ArtifactIntent::ApplyReadiness);
        assert_eq!(decision.verdict, ArtifactVerdict::Unknown);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::AuditOnly);
        assert!(decision.action_plan.no_mutation);
        assert!(!decision.action_plan.reversible);
    }

    #[test]
    fn artifact_decision_wraps_update_apply_fixture_as_evidence_verdict_action_plan() {
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: UpdateApplyPlanStatus::Planned,
            reason: "fixture apply plan executes only inside fixture and rolls back".to_string(),
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: Some("fixture/stage".to_string()),
            staged_asset_path: Some("fixture/stage/gh_mirror_gui.exe".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            target_exe_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_exe_path: Some("fixture/gh_mirror_gui.exe.bak-fixture".to_string()),
            reversible: true,
            no_mutation: false,
            steps: vec![UpdateApplyStep::RollbackByRestoringBackup {
                from_backup: "fixture/gh_mirror_gui.exe.bak-fixture".to_string(),
                to_target: "fixture/gh_mirror_gui.exe".to_string(),
            }],
        };
        let record = UpdateApplyFixtureEvidenceRecord {
            schema_version: 1,
            ok: true,
            fixture_only: true,
            no_live_mutation: true,
            rollback_ok: true,
            status: UpdateApplyFixtureStatus::AppliedAndRolledBack,
            reason: "fixture apply backed up, replaced, verified, and rolled back".to_string(),
            stage_dir: Some("fixture/stage".to_string()),
            stage_evidence_path: Some("fixture/stage/update-candidate-stage.json".to_string()),
            staged_asset_path: Some("fixture/stage/gh_mirror_gui.exe".to_string()),
            verification_status: Some("VERIFIED".to_string()),
            source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
            source_trust_decision: Some("TRUSTED".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            target_fixture_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_path: Some("fixture/gh_mirror_gui.exe.bak-fixture".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            staged_sha256: Some("FILESHA".to_string()),
            installed_sha256: Some("FILESHA".to_string()),
            rollback_sha256: Some("ORIGINALSHA".to_string()),
            evidence_path: Some("fixture/update-apply-fixture.json".to_string()),
            write_error: None,
            plan,
        };

        let decision = ArtifactDecision::from_update_apply_fixture_evidence(&record);

        assert_eq!(decision.intent, ArtifactIntent::PlanApply);
        assert_eq!(decision.verdict, ArtifactVerdict::Trusted);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::AuditOnly);
        assert!(!decision.action_plan.no_mutation);
        assert!(decision.action_plan.reversible);
        assert_eq!(
            decision.evidence.source_authenticity.as_deref(),
            Some("TRUSTED_SIGNATURE")
        );
        assert_eq!(
            decision
                .evidence
                .publisher_key_fingerprint_sha256
                .as_deref(),
            Some("FINGERPRINT")
        );
        assert_eq!(
            decision.evidence.evidence_path.as_deref(),
            Some("fixture/update-apply-fixture.json")
        );
        assert!(decision
            .action_plan
            .steps
            .iter()
            .any(|step| step.contains("rollback_ok=true")));
    }

    #[test]
    fn artifact_decision_wraps_update_apply_fixture_refusal_without_action_path() {
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: UpdateApplyPlanStatus::Refused,
            reason: "fixture apply requires expected_sha256".to_string(),
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: None,
            staged_asset_path: None,
            expected_sha256: None,
            target_exe_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_exe_path: None,
            reversible: false,
            no_mutation: true,
            steps: vec![],
        };
        let record = UpdateApplyFixtureEvidenceRecord {
            schema_version: 1,
            ok: false,
            fixture_only: true,
            no_live_mutation: true,
            rollback_ok: false,
            status: UpdateApplyFixtureStatus::Refused,
            reason: "fixture apply requires expected_sha256".to_string(),
            stage_dir: None,
            stage_evidence_path: None,
            staged_asset_path: None,
            verification_status: None,
            source_authenticity_status: None,
            source_trust_decision: None,
            publisher_key_fingerprint_sha256: None,
            target_fixture_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_path: None,
            expected_sha256: None,
            staged_sha256: None,
            installed_sha256: None,
            rollback_sha256: None,
            evidence_path: Some("fixture/update-apply-fixture.json".to_string()),
            write_error: None,
            plan,
        };

        let decision = ArtifactDecision::from_update_apply_fixture_evidence(&record);

        assert_eq!(decision.verdict, ArtifactVerdict::Refused);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::None);
        assert_eq!(decision.action_plan.path_action, None);
        assert!(decision.action_plan.no_mutation);
        assert_eq!(decision.evidence.source_authenticity, None);
        assert_eq!(
            decision.evidence.policy_verdict,
            Some("refused".to_string())
        );
    }

    #[test]
    fn artifact_decision_wraps_update_apply_fixture_rollback_failed_as_risk() {
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: UpdateApplyPlanStatus::Planned,
            reason: "fixture apply plan executes only inside fixture and rolls back".to_string(),
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: Some("fixture/stage".to_string()),
            staged_asset_path: Some("fixture/stage/gh_mirror_gui.exe".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            target_exe_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_exe_path: Some("fixture/gh_mirror_gui.exe.bak-fixture".to_string()),
            reversible: true,
            no_mutation: false,
            steps: vec![],
        };
        let record = UpdateApplyFixtureEvidenceRecord {
            schema_version: 1,
            ok: false,
            fixture_only: true,
            no_live_mutation: true,
            rollback_ok: false,
            status: UpdateApplyFixtureStatus::RollbackFailed,
            reason: "fixture apply verified but rollback failed".to_string(),
            stage_dir: Some("fixture/stage".to_string()),
            stage_evidence_path: Some("fixture/stage/update-candidate-stage.json".to_string()),
            staged_asset_path: Some("fixture/stage/gh_mirror_gui.exe".to_string()),
            verification_status: Some("VERIFIED".to_string()),
            source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
            source_trust_decision: Some("TRUSTED".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            target_fixture_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_path: Some("fixture/gh_mirror_gui.exe.bak-fixture".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            staged_sha256: Some("FILESHA".to_string()),
            installed_sha256: Some("FILESHA".to_string()),
            rollback_sha256: None,
            evidence_path: Some("fixture/update-apply-fixture.json".to_string()),
            write_error: None,
            plan,
        };

        let decision = ArtifactDecision::from_update_apply_fixture_evidence(&record);

        assert_eq!(decision.verdict, ArtifactVerdict::Risk);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::AuditOnly);
        assert!(!decision.action_plan.no_mutation);
    }

    #[test]
    fn artifact_decision_does_not_trust_fixture_success_without_hash_match() {
        let plan = UpdateApplyPlan {
            schema_version: 1,
            status: UpdateApplyPlanStatus::Planned,
            reason: "fixture apply plan executes only inside fixture and rolls back".to_string(),
            repo: "owner/repo".to_string(),
            release_tag: "v1.2.3".to_string(),
            stage_dir: Some("fixture/stage".to_string()),
            staged_asset_path: Some("fixture/stage/gh_mirror_gui.exe".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            target_exe_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_exe_path: Some("fixture/gh_mirror_gui.exe.bak-fixture".to_string()),
            reversible: true,
            no_mutation: false,
            steps: vec![],
        };
        let record = UpdateApplyFixtureEvidenceRecord {
            schema_version: 1,
            ok: true,
            fixture_only: true,
            no_live_mutation: true,
            rollback_ok: true,
            status: UpdateApplyFixtureStatus::AppliedAndRolledBack,
            reason: "fixture apply backed up, replaced, verified, and rolled back".to_string(),
            stage_dir: Some("fixture/stage".to_string()),
            stage_evidence_path: Some("fixture/stage/update-candidate-stage.json".to_string()),
            staged_asset_path: Some("fixture/stage/gh_mirror_gui.exe".to_string()),
            verification_status: Some("VERIFIED".to_string()),
            source_authenticity_status: Some("TRUSTED_SIGNATURE".to_string()),
            source_trust_decision: Some("TRUSTED".to_string()),
            publisher_key_fingerprint_sha256: Some("FINGERPRINT".to_string()),
            target_fixture_path: Some("fixture/gh_mirror_gui.exe".to_string()),
            backup_path: Some("fixture/gh_mirror_gui.exe.bak-fixture".to_string()),
            expected_sha256: Some("FILESHA".to_string()),
            staged_sha256: Some("FILESHA".to_string()),
            installed_sha256: Some("DIFFERENT".to_string()),
            rollback_sha256: Some("ORIGINALSHA".to_string()),
            evidence_path: Some("fixture/update-apply-fixture.json".to_string()),
            write_error: None,
            plan,
        };

        let decision = ArtifactDecision::from_update_apply_fixture_evidence(&record);

        assert_eq!(decision.verdict, ArtifactVerdict::Refused);
        assert_eq!(decision.action_plan.kind, ArtifactActionKind::None);
    }
}
