use crate::update_apply_plan::{UpdateApplyPlan, UpdateApplyPlanStatus};
use crate::update_apply_readiness::{
    self, ManualApprovalState, UpdateApplyReadinessRecord, UpdateApplyReadinessStatus,
};
use crate::update_candidate::{UpdateCandidateStageReport, UpdateCandidateStageStatus};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const UPDATE_APPLY_BUNDLE_MODULE_OWNER: &str = "src/update_apply_bundle.rs";
const UPDATE_APPLY_BUNDLE_SCHEMA_VERSION: u32 = 1;
const DEFAULT_APPROVAL_TTL_SECONDS: u64 = 15 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateApplyBundleStatus {
    Refused,
    BundlePrepared,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyBundle {
    pub schema_version: u32,
    pub module_owner: String,
    pub status: UpdateApplyBundleStatus,
    pub reason: String,
    pub repo: String,
    pub release_tag: String,
    pub stage_dir: Option<String>,
    pub stage_evidence_path: Option<String>,
    pub readiness_evidence_path: Option<String>,
    pub staged_asset_path: Option<String>,
    pub expected_sha256: Option<String>,
    pub staged_sha256: Option<String>,
    pub verification_status: Option<String>,
    pub source_authenticity_status: Option<String>,
    pub source_trust_decision: Option<String>,
    pub publisher_key_fingerprint_sha256: Option<String>,
    pub target_current_exe_path: Option<String>,
    pub target_canonical_path: Option<String>,
    pub target_before_sha256: Option<String>,
    pub staged_asset_canonical_path: Option<String>,
    pub backup_destination_path: Option<String>,
    pub backup_boundary_path: Option<String>,
    pub helper_copy_path: Option<String>,
    pub helper_copy_sha256: Option<String>,
    pub approval_id: String,
    pub approval_granted_at_unix_ms: u64,
    pub approval_expires_at_unix_ms: u64,
    pub manual_approval_state: ManualApprovalState,
    pub rollback_after_apply: bool,
    pub no_system_persistence: bool,
    pub plan: UpdateApplyPlan,
    pub refusal_reasons: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyBundleEvidenceRecord {
    pub schema_version: u32,
    pub ok: bool,
    pub no_live_mutation: bool,
    pub apply_performed: bool,
    pub install_performed: bool,
    pub bundle_hash: Option<String>,
    pub evidence_path: Option<String>,
    pub bundle_path: Option<String>,
    pub write_error: Option<String>,
    pub bundle: UpdateApplyBundle,
    pub readiness: UpdateApplyReadinessRecord,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct UpdateApplyBundleOptions<'a> {
    pub(crate) approval_id: Option<&'a str>,
    pub(crate) approval_ttl_seconds: u64,
    pub(crate) rollback_after_apply: bool,
    pub(crate) helper_copy_path: Option<&'a Path>,
    pub(crate) helper_copy_sha256: Option<&'a str>,
}

impl<'a> UpdateApplyBundleOptions<'a> {
    pub(crate) fn ui_default() -> Self {
        Self {
            approval_id: None,
            approval_ttl_seconds: DEFAULT_APPROVAL_TTL_SECONDS,
            rollback_after_apply: true,
            helper_copy_path: None,
            helper_copy_sha256: None,
        }
    }

    pub(crate) fn selftest(
        helper_copy_path: &'a Path,
        helper_copy_sha256: &'a str,
        rollback_after_apply: bool,
    ) -> Self {
        Self {
            approval_id: Some("fixture-helper-approval"),
            approval_ttl_seconds: DEFAULT_APPROVAL_TTL_SECONDS,
            rollback_after_apply,
            helper_copy_path: Some(helper_copy_path),
            helper_copy_sha256: Some(helper_copy_sha256),
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn sha256_bytes_upper(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:X}", hasher.finalize())
}

pub(crate) fn sha256_file_upper(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|e| format!("Read {}: {e}", path.display()))?;
    Ok(sha256_bytes_upper(&bytes))
}

pub(crate) fn paths_equal_if_available(left: &Path, right: &Path) -> bool {
    match (left.canonicalize(), right.canonicalize()) {
        (Ok(left), Ok(right)) => left == right,
        _ => left == right,
    }
}

pub(crate) fn path_is_within_if_available(child: &Path, parent: &Path) -> bool {
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

fn approval_id_or_default(input: Option<&str>) -> String {
    input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("manual-approval-{}-{}", now_unix_ms(), std::process::id()))
}

fn empty_bundle_from_readiness(
    readiness: &UpdateApplyReadinessRecord,
    options: UpdateApplyBundleOptions<'_>,
    now_ms: u64,
) -> UpdateApplyBundle {
    UpdateApplyBundle {
        schema_version: UPDATE_APPLY_BUNDLE_SCHEMA_VERSION,
        module_owner: UPDATE_APPLY_BUNDLE_MODULE_OWNER.to_string(),
        status: UpdateApplyBundleStatus::Refused,
        reason: "controlled apply bundle not prepared".to_string(),
        repo: readiness.repo.clone(),
        release_tag: readiness.release_tag.clone(),
        stage_dir: readiness.stage_dir.clone(),
        stage_evidence_path: readiness.stage_evidence_path.clone(),
        readiness_evidence_path: readiness.evidence_path.clone(),
        staged_asset_path: readiness.staged_asset_path.clone(),
        expected_sha256: readiness.expected_sha256.clone(),
        staged_sha256: readiness.staged_sha256.clone(),
        verification_status: readiness.verification_status.clone(),
        source_authenticity_status: readiness.source_authenticity_status.clone(),
        source_trust_decision: readiness.source_trust_decision.clone(),
        publisher_key_fingerprint_sha256: readiness.publisher_key_fingerprint_sha256.clone(),
        target_current_exe_path: readiness.target_current_exe_path.clone(),
        target_canonical_path: readiness.target_canonical_path.clone(),
        target_before_sha256: None,
        staged_asset_canonical_path: readiness.staged_asset_canonical_path.clone(),
        backup_destination_path: readiness.backup_destination_path.clone(),
        backup_boundary_path: readiness.backup_boundary_path.clone(),
        helper_copy_path: options
            .helper_copy_path
            .map(|path| path.display().to_string()),
        helper_copy_sha256: options.helper_copy_sha256.map(str::to_string),
        approval_id: approval_id_or_default(options.approval_id),
        approval_granted_at_unix_ms: now_ms,
        approval_expires_at_unix_ms: now_ms.saturating_add(options.approval_ttl_seconds * 1000),
        manual_approval_state: readiness.manual_approval_state,
        rollback_after_apply: options.rollback_after_apply,
        no_system_persistence: true,
        plan: readiness.plan.clone(),
        refusal_reasons: Vec::new(),
    }
}

fn refused_record(
    readiness: UpdateApplyReadinessRecord,
    options: UpdateApplyBundleOptions<'_>,
    reason: impl Into<String>,
) -> UpdateApplyBundleEvidenceRecord {
    let now_ms = now_unix_ms();
    let reason = reason.into();
    let mut bundle = empty_bundle_from_readiness(&readiness, options, now_ms);
    bundle.reason = reason.clone();
    bundle.refusal_reasons.push(reason);
    UpdateApplyBundleEvidenceRecord {
        schema_version: UPDATE_APPLY_BUNDLE_SCHEMA_VERSION,
        ok: false,
        no_live_mutation: true,
        apply_performed: false,
        install_performed: false,
        bundle_hash: None,
        evidence_path: None,
        bundle_path: None,
        write_error: None,
        bundle,
        readiness,
    }
}

fn bundle_hash(bundle: &UpdateApplyBundle) -> Result<String, String> {
    let bytes = serde_json::to_vec(bundle).map_err(|e| format!("Serialize apply bundle: {e}"))?;
    Ok(sha256_bytes_upper(&bytes))
}

pub(crate) fn bundle_payload_hash_upper(bundle: &UpdateApplyBundle) -> Result<String, String> {
    bundle_hash(bundle)
}

pub(crate) fn build_update_apply_bundle_from_readiness(
    readiness: UpdateApplyReadinessRecord,
    options: UpdateApplyBundleOptions<'_>,
) -> UpdateApplyBundleEvidenceRecord {
    if let Some(error) = readiness.write_error.clone() {
        return refused_record(
            readiness,
            options,
            format!("controlled apply bundle requires readable readiness evidence: {error}"),
        );
    }
    if readiness.manual_approval_state != ManualApprovalState::Granted {
        return refused_record(
            readiness,
            options,
            "controlled apply bundle requires granted manual approval",
        );
    }
    if readiness.status != UpdateApplyReadinessStatus::ReadyForManualApply || !readiness.ok {
        let status = readiness.status;
        return refused_record(
            readiness,
            options,
            format!(
                "controlled apply bundle requires READY_FOR_MANUAL_APPLY readiness, got {:?}",
                status
            ),
        );
    }
    if !readiness.no_live_mutation || readiness.apply_performed || readiness.install_performed {
        return refused_record(
            readiness,
            options,
            "controlled apply bundle refuses readiness that already mutated or installed",
        );
    }
    if readiness.plan.status != UpdateApplyPlanStatus::Planned
        || !readiness.plan.no_mutation
        || !readiness.plan.reversible
    {
        return refused_record(
            readiness,
            options,
            "controlled apply bundle requires a reversible no-mutation readiness plan",
        );
    }

    let target_path = match readiness.target_current_exe_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return refused_record(
                readiness,
                options,
                "controlled apply bundle requires target current exe path",
            )
        }
    };
    let target_before_sha256 = match sha256_file_upper(&target_path) {
        Ok(sha) => sha,
        Err(e) => {
            return refused_record(
                readiness,
                options,
                format!("controlled apply bundle could not hash target before apply: {e}"),
            )
        }
    };

    let helper_copy_sha256 = match options.helper_copy_path {
        Some(path) => match sha256_file_upper(path) {
            Ok(observed) => {
                if let Some(expected) = options.helper_copy_sha256 {
                    if !observed.eq_ignore_ascii_case(expected) {
                        return refused_record(
                            readiness,
                            options,
                            format!(
                                "controlled apply bundle helper copy hash mismatch: observed {observed}, expected {expected}"
                            ),
                        );
                    }
                }
                Some(observed)
            }
            Err(e) => {
                return refused_record(
                    readiness,
                    options,
                    format!("controlled apply bundle could not hash helper copy: {e}"),
                )
            }
        },
        None => options.helper_copy_sha256.map(str::to_string),
    };

    let now_ms = now_unix_ms();
    let mut bundle = empty_bundle_from_readiness(&readiness, options, now_ms);
    bundle.status = UpdateApplyBundleStatus::BundlePrepared;
    bundle.reason =
        "controlled apply bundle prepared from trusted readiness and granted manual approval"
            .to_string();
    bundle.target_before_sha256 = Some(target_before_sha256);
    bundle.target_canonical_path = canonical_display(&target_path).or(bundle.target_canonical_path);
    bundle.helper_copy_sha256 = helper_copy_sha256;
    let bundle_hash = match bundle_hash(&bundle) {
        Ok(hash) => Some(hash),
        Err(e) => {
            return refused_record(
                readiness,
                options,
                format!("controlled apply bundle could not hash bundle payload: {e}"),
            )
        }
    };

    UpdateApplyBundleEvidenceRecord {
        schema_version: UPDATE_APPLY_BUNDLE_SCHEMA_VERSION,
        ok: true,
        no_live_mutation: true,
        apply_performed: false,
        install_performed: false,
        bundle_hash,
        evidence_path: None,
        bundle_path: None,
        write_error: None,
        bundle,
        readiness,
    }
}

pub(crate) fn write_update_apply_bundle_evidence_for_stage2(
    stage_report: &UpdateCandidateStageReport,
    target_current_exe_path: &Path,
    backup_boundary_dir: Option<&Path>,
    manual_approval_state: ManualApprovalState,
    options: UpdateApplyBundleOptions<'_>,
) -> UpdateApplyBundleEvidenceRecord {
    let readiness = update_apply_readiness::write_update_apply_readiness_evidence_for_stage2(
        stage_report,
        target_current_exe_path,
        backup_boundary_dir,
        manual_approval_state,
    );
    let mut record = build_update_apply_bundle_from_readiness(readiness, options);

    let stage_dir = match stage_report.stage_dir.as_deref() {
        Some(dir) if !dir.trim().is_empty() => PathBuf::from(dir),
        _ => {
            record.write_error =
                Some("controlled apply bundle evidence requires stage_dir".to_string());
            record.ok = false;
            return record;
        }
    };
    let evidence_path = stage_dir.join("update-apply-bundle.json");
    record.evidence_path = Some(evidence_path.display().to_string());
    record.bundle_path = record.evidence_path.clone();
    let generated_at_unix_ms = now_unix_ms();
    let payload = serde_json::json!({
        "schema_version": UPDATE_APPLY_BUNDLE_SCHEMA_VERSION,
        "generated_at_unix_ms": generated_at_unix_ms,
        "no_live_mutation": record.no_live_mutation,
        "apply_performed": record.apply_performed,
        "install_performed": record.install_performed,
        "record": &record,
    });
    match crate::evidence_ledger::write_json_pretty(&evidence_path, &payload) {
        Ok(()) => {}
        Err(e) => {
            record.write_error = Some(format!(
                "write controlled apply bundle evidence failed: {e}"
            ));
            record.ok = false;
        }
    }
    record
}

fn write_selftest_json(json_out: Option<PathBuf>, pretty_report: &str) -> Result<(), String> {
    if let Some(json_path) = json_out {
        if let Some(parent) = json_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Create bundle selftest JSON dir: {e}"))?;
        }
        fs::write(&json_path, format!("{pretty_report}\n"))
            .map_err(|e| format!("Write update apply bundle selftest JSON: {e}"))?;
    }
    Ok(())
}

pub(crate) fn parse_json_arg(args: &[String], flag_name: &str) -> Result<Option<PathBuf>, String> {
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

pub(crate) fn unique_update_apply_selftest_root(prefix: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "gh_mirror_gui_{prefix}_{}_{}",
        std::process::id(),
        nonce
    ))
}

pub(crate) fn selftest_stage_report(
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

pub(crate) fn run_update_apply_bundle_contract_selftest(args: &[String]) -> Result<(), String> {
    let json_out = parse_json_arg(args, "--update-apply-bundle-contract-selftest")?;

    let root = unique_update_apply_selftest_root("update_apply_bundle_selftest");
    let stage_dir = root.join("stage");
    fs::create_dir_all(&stage_dir).map_err(|e| format!("Create apply-bundle selftest dir: {e}"))?;
    let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
    fs::write(&staged_asset_path, b"trusted staged update bytes")
        .map_err(|e| format!("Write staged bundle asset fixture: {e}"))?;
    let expected_sha256 = sha256_file_upper(&staged_asset_path)?;
    let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
    fs::write(&stage_evidence_path, b"{}")
        .map_err(|e| format!("Write stage bundle evidence fixture: {e}"))?;
    let target_fixture_path = root.join("gh_mirror_gui.exe");
    fs::write(&target_fixture_path, b"original trusted app bytes")
        .map_err(|e| format!("Write target bundle fixture: {e}"))?;
    let target_before_sha256 = sha256_file_upper(&target_fixture_path)?;
    let current_exe_path =
        std::env::current_exe().map_err(|e| format!("current executable path unavailable: {e}"))?;
    let current_exe_before_sha256 = sha256_file_upper(&current_exe_path)?;
    let stage_report = selftest_stage_report(
        &root,
        &stage_dir,
        &staged_asset_path,
        &stage_evidence_path,
        &expected_sha256,
    );

    let record = write_update_apply_bundle_evidence_for_stage2(
        &stage_report,
        &target_fixture_path,
        Some(&stage_dir),
        ManualApprovalState::Granted,
        UpdateApplyBundleOptions {
            rollback_after_apply: true,
            ..UpdateApplyBundleOptions::ui_default()
        },
    );
    let current_exe_after_sha256 = sha256_file_upper(&current_exe_path)?;
    let current_exe_unchanged =
        current_exe_before_sha256.eq_ignore_ascii_case(&current_exe_after_sha256);
    let bundle_ready = record
        .bundle_path
        .as_deref()
        .map(|path| Path::new(path).is_file())
        .unwrap_or(false);
    let artifact_decision =
        crate::artifact_decision::ArtifactDecision::from_update_apply_bundle_evidence(&record);
    let ok = record.ok
        && record.no_live_mutation
        && !record.apply_performed
        && !record.install_performed
        && matches!(
            record.bundle.status,
            UpdateApplyBundleStatus::BundlePrepared
        )
        && record.readiness.status == UpdateApplyReadinessStatus::ReadyForManualApply
        && record.readiness.manual_approval_state == ManualApprovalState::Granted
        && record.bundle.no_system_persistence
        && record.bundle.rollback_after_apply
        && record.bundle.target_before_sha256.as_deref() == Some(target_before_sha256.as_str())
        && record.bundle.approval_expires_at_unix_ms > record.bundle.approval_granted_at_unix_ms
        && record
            .bundle_hash
            .as_deref()
            .map(|hash| !hash.is_empty())
            .unwrap_or(false)
        && bundle_ready
        && current_exe_unchanged
        && artifact_decision.verdict == crate::artifact_decision::ArtifactVerdict::BundlePrepared;

    let report = serde_json::json!({
        "schema_version": UPDATE_APPLY_BUNDLE_SCHEMA_VERSION,
        "ok": ok,
        "module_owner": UPDATE_APPLY_BUNDLE_MODULE_OWNER,
        "no_live_mutation": record.no_live_mutation,
        "apply_performed": record.apply_performed,
        "install_performed": record.install_performed,
        "status": record.bundle.status,
        "bundle_hash": record.bundle_hash,
        "approval_expires_at_unix_ms": record.bundle.approval_expires_at_unix_ms,
        "target_before_sha256": target_before_sha256,
        "bundle_ready": bundle_ready,
        "no_system_persistence": record.bundle.no_system_persistence,
        "record": record,
        "artifact_decision": artifact_decision,
        "current_exe": {
            "path": current_exe_path.display().to_string(),
            "before_sha256": current_exe_before_sha256,
            "after_sha256": current_exe_after_sha256,
            "unchanged": current_exe_unchanged,
        },
        "fixture": {
            "root": root.display().to_string(),
            "stage_dir": stage_dir.display().to_string(),
            "stage_evidence_path": stage_evidence_path.display().to_string(),
            "staged_asset_path": staged_asset_path.display().to_string(),
            "target_fixture_path": target_fixture_path.display().to_string(),
            "expected_sha256": expected_sha256,
        }
    });
    let pretty_report = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialize bundle selftest JSON: {e}"))?;
    write_selftest_json(json_out, &pretty_report)?;
    println!("{pretty_report}");
    if !ok {
        return Err("update apply bundle contract selftest did not prepare a granted no-live-mutation bundle".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bundle_fixture(
        name: &str,
    ) -> (
        PathBuf,
        PathBuf,
        PathBuf,
        UpdateCandidateStageReport,
        String,
    ) {
        let root = unique_update_apply_selftest_root(name);
        let stage_dir = root.join("stage");
        fs::create_dir_all(&stage_dir).expect("create bundle fixture stage");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged update bytes").expect("write staged");
        let expected_sha256 = sha256_file_upper(&staged_asset_path).expect("hash staged");
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("write evidence");
        let target = root.join("gh_mirror_gui.exe");
        fs::write(&target, b"original bytes").expect("write target");
        let report = selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &expected_sha256,
        );
        (root, stage_dir, target, report, expected_sha256)
    }

    #[test]
    fn update_apply_bundle_requires_granted_manual_approval() {
        let (_root, stage_dir, target, report, _expected) =
            bundle_fixture("bundle_requires_approval");
        let record = write_update_apply_bundle_evidence_for_stage2(
            &report,
            &target,
            Some(&stage_dir),
            ManualApprovalState::Required,
            UpdateApplyBundleOptions::ui_default(),
        );

        assert!(!record.ok);
        assert_eq!(record.bundle.status, UpdateApplyBundleStatus::Refused);
        assert!(record
            .bundle
            .reason
            .contains("requires granted manual approval"));
        assert!(record.no_live_mutation);
        assert!(!record.apply_performed);
        assert!(!record.install_performed);
    }

    #[test]
    fn update_apply_bundle_prepares_granted_helper_boundary_without_mutation() {
        let (_root, stage_dir, target, report, _expected) = bundle_fixture("bundle_prepares");
        let target_before = sha256_file_upper(&target).expect("hash target before");
        let record = write_update_apply_bundle_evidence_for_stage2(
            &report,
            &target,
            Some(&stage_dir),
            ManualApprovalState::Granted,
            UpdateApplyBundleOptions {
                rollback_after_apply: true,
                ..UpdateApplyBundleOptions::ui_default()
            },
        );
        let target_after = sha256_file_upper(&target).expect("hash target after");

        assert!(record.ok);
        assert_eq!(
            record.bundle.status,
            UpdateApplyBundleStatus::BundlePrepared
        );
        assert_eq!(
            record.bundle.target_before_sha256.as_deref(),
            Some(target_before.as_str())
        );
        assert_eq!(target_before, target_after);
        assert!(record.bundle.no_system_persistence);
        assert!(record.bundle.rollback_after_apply);
        assert!(record
            .bundle_hash
            .as_deref()
            .map(|hash| !hash.is_empty())
            .unwrap_or(false));
        assert!(record
            .bundle_path
            .as_deref()
            .map(|path| Path::new(path).is_file())
            .unwrap_or(false));
    }
}
