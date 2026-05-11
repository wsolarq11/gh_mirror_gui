use crate::update_apply_bundle::{
    self, path_is_within_if_available, paths_equal_if_available, sha256_file_upper,
    UpdateApplyBundleEvidenceRecord, UpdateApplyBundleStatus,
};
use crate::update_apply_readiness::{ManualApprovalState, UpdateApplyReadinessStatus};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const UPDATE_APPLY_HELPER_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateApplyHelperStatus {
    Refused,
    AppliedAndVerified,
    RollbackOk,
    RollbackFailed,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TargetLockPreflight {
    pub attempted: bool,
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateApplyHelperReceipt {
    pub schema_version: u32,
    pub ok: bool,
    pub status: UpdateApplyHelperStatus,
    pub reason: String,
    pub states: Vec<String>,
    pub fixture_only: bool,
    pub no_live_current_exe_mutation: bool,
    pub no_system_persistence: bool,
    pub helper_current_exe_path: Option<String>,
    pub helper_copy_path: Option<String>,
    pub helper_copy_sha256: Option<String>,
    pub helper_copy_sha256_match: bool,
    pub helper_current_exe_is_target: bool,
    pub bundle_path: Option<String>,
    pub bundle_hash: Option<String>,
    pub receipt_path: Option<String>,
    pub approval_id: Option<String>,
    pub approval_expires_at_unix_ms: Option<u64>,
    pub target_path: Option<String>,
    pub staged_asset_path: Option<String>,
    pub backup_path: Option<String>,
    pub backup_boundary_path: Option<String>,
    pub target_before_sha256: Option<String>,
    pub staged_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub installed_sha256: Option<String>,
    pub rollback_sha256: Option<String>,
    pub target_after_sha256: Option<String>,
    pub target_lock_preflight: TargetLockPreflight,
    pub backup_performed: bool,
    pub replace_performed: bool,
    pub rollback_attempted: bool,
    pub rollback_ok: bool,
    pub target_restored: bool,
    pub write_error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default)]
struct HelperApplyOptions {
    force_rollback_failure_after_backup: bool,
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn initial_receipt(
    bundle_record: Option<UpdateApplyBundleEvidenceRecord>,
    bundle_path: &Path,
    receipt_path: &Path,
    helper_current_exe_path: &Path,
) -> UpdateApplyHelperReceipt {
    let (bundle_hash, approval_id, approval_expires_at_unix_ms) = bundle_record
        .as_ref()
        .map(|record| {
            (
                record.bundle_hash.clone(),
                Some(record.bundle.approval_id.clone()),
                Some(record.bundle.approval_expires_at_unix_ms),
            )
        })
        .unwrap_or((None, None, None));
    UpdateApplyHelperReceipt {
        schema_version: UPDATE_APPLY_HELPER_SCHEMA_VERSION,
        ok: false,
        status: UpdateApplyHelperStatus::Refused,
        reason: "update apply helper refused before mutation".to_string(),
        states: Vec::new(),
        fixture_only: false,
        no_live_current_exe_mutation: true,
        no_system_persistence: true,
        helper_current_exe_path: Some(helper_current_exe_path.display().to_string()),
        helper_copy_path: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.helper_copy_path.clone()),
        helper_copy_sha256: None,
        helper_copy_sha256_match: false,
        helper_current_exe_is_target: false,
        bundle_path: Some(bundle_path.display().to_string()),
        bundle_hash,
        receipt_path: Some(receipt_path.display().to_string()),
        approval_id,
        approval_expires_at_unix_ms,
        target_path: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.target_current_exe_path.clone()),
        staged_asset_path: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.staged_asset_path.clone()),
        backup_path: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.backup_destination_path.clone()),
        backup_boundary_path: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.backup_boundary_path.clone()),
        target_before_sha256: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.target_before_sha256.clone()),
        staged_sha256: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.staged_sha256.clone()),
        expected_sha256: bundle_record
            .as_ref()
            .and_then(|record| record.bundle.expected_sha256.clone()),
        installed_sha256: None,
        rollback_sha256: None,
        target_after_sha256: None,
        target_lock_preflight: TargetLockPreflight {
            attempted: false,
            ok: false,
            error: None,
        },
        backup_performed: false,
        replace_performed: false,
        rollback_attempted: false,
        rollback_ok: false,
        target_restored: false,
        write_error: None,
    }
}

fn write_receipt(
    mut receipt: UpdateApplyHelperReceipt,
    receipt_path: &Path,
) -> Result<UpdateApplyHelperReceipt, String> {
    if let Some(parent) = receipt_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Create helper receipt dir: {e}"))?;
    }
    receipt.receipt_path = Some(receipt_path.display().to_string());
    let payload = serde_json::json!({
        "schema_version": UPDATE_APPLY_HELPER_SCHEMA_VERSION,
        "generated_at_unix_ms": now_unix_ms(),
        "record": &receipt,
    });
    match crate::evidence_ledger::write_json_pretty(receipt_path, &payload) {
        Ok(()) => Ok(receipt),
        Err(e) => {
            receipt.write_error = Some(format!("write update apply helper receipt failed: {e}"));
            Err(receipt.write_error.clone().unwrap_or_else(|| e.to_string()))
        }
    }
}

fn finish_refused(
    mut receipt: UpdateApplyHelperReceipt,
    reason: impl Into<String>,
    receipt_path: &Path,
) -> Result<UpdateApplyHelperReceipt, String> {
    receipt.ok = false;
    receipt.status = UpdateApplyHelperStatus::Refused;
    receipt.reason = reason.into();
    write_receipt(receipt, receipt_path)
}

fn rollback_target(backup_path: &Path, target_path: &Path) -> Result<String, String> {
    fs::copy(backup_path, target_path).map_err(|e| {
        format!(
            "rollback target {} from backup {} failed: {e}",
            target_path.display(),
            backup_path.display()
        )
    })?;
    sha256_file_upper(target_path)
}

fn read_bundle_record(bundle_path: &Path) -> Result<UpdateApplyBundleEvidenceRecord, String> {
    let text = fs::read_to_string(bundle_path).map_err(|e| {
        format!(
            "Read update apply bundle {} failed: {e}",
            bundle_path.display()
        )
    })?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Parse update apply bundle JSON: {e}"))?;
    if let Some(record) = value.get("record") {
        serde_json::from_value(record.clone())
            .map_err(|e| format!("Parse update apply bundle record JSON: {e}"))
    } else {
        serde_json::from_value(value)
            .map_err(|e| format!("Parse update apply bundle record JSON: {e}"))
    }
}

fn read_receipt_record(receipt_path: &Path) -> Result<UpdateApplyHelperReceipt, String> {
    let text = fs::read_to_string(receipt_path)
        .map_err(|e| format!("Read helper receipt {} failed: {e}", receipt_path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| format!("Parse helper receipt JSON: {e}"))?;
    if let Some(record) = value.get("record") {
        serde_json::from_value(record.clone())
            .map_err(|e| format!("Parse helper receipt record JSON: {e}"))
    } else {
        serde_json::from_value(value).map_err(|e| format!("Parse helper receipt record JSON: {e}"))
    }
}

fn option_eq_ignore_ascii_case(left: &Option<String>, right: &Option<String>) -> bool {
    match (left.as_deref(), right.as_deref()) {
        (Some(left), Some(right)) => left.eq_ignore_ascii_case(right),
        (None, None) => true,
        _ => false,
    }
}

fn option_is_value(value: &Option<String>, expected: &str) -> bool {
    value
        .as_deref()
        .map(|value| value.eq_ignore_ascii_case(expected))
        .unwrap_or(false)
}

fn option_is_non_blank(value: &Option<String>) -> bool {
    value
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

fn apply_bundle_with_options(
    bundle_record: UpdateApplyBundleEvidenceRecord,
    bundle_path: &Path,
    receipt_path: &Path,
    helper_current_exe_path: &Path,
    options: HelperApplyOptions,
) -> Result<UpdateApplyHelperReceipt, String> {
    let mut receipt = initial_receipt(
        Some(bundle_record.clone()),
        bundle_path,
        receipt_path,
        helper_current_exe_path,
    );
    receipt.fixture_only = bundle_record.bundle.rollback_after_apply;

    if !bundle_record.ok || bundle_record.bundle.status != UpdateApplyBundleStatus::BundlePrepared {
        return finish_refused(
            receipt,
            "update apply helper requires a prepared bundle record",
            receipt_path,
        );
    }
    if bundle_record.bundle.manual_approval_state != ManualApprovalState::Granted {
        return finish_refused(
            receipt,
            "update apply helper requires granted manual approval",
            receipt_path,
        );
    }
    if bundle_record.bundle.approval_expires_at_unix_ms <= now_unix_ms() {
        return finish_refused(
            receipt,
            "update apply helper approval expired",
            receipt_path,
        );
    }
    if !bundle_record.bundle.no_system_persistence {
        return finish_refused(
            receipt,
            "update apply helper refuses bundles that request system persistence",
            receipt_path,
        );
    }

    let recorded_bundle_hash = match bundle_record.bundle_hash.as_deref() {
        Some(hash) if !hash.trim().is_empty() => hash.trim().to_ascii_uppercase(),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires recorded bundle hash",
                receipt_path,
            )
        }
    };
    let observed_bundle_hash =
        match update_apply_bundle::bundle_payload_hash_upper(&bundle_record.bundle) {
            Ok(hash) => hash,
            Err(e) => return finish_refused(receipt, e, receipt_path),
        };
    if !observed_bundle_hash.eq_ignore_ascii_case(&recorded_bundle_hash) {
        return finish_refused(
            receipt,
            "update apply helper refuses bundle hash mismatch",
            receipt_path,
        );
    }
    receipt.bundle_hash = Some(observed_bundle_hash);

    if !bundle_record.readiness.ok
        || bundle_record.readiness.status != UpdateApplyReadinessStatus::ReadyForManualApply
        || bundle_record.readiness.manual_approval_state != ManualApprovalState::Granted
        || !bundle_record.readiness.no_live_mutation
        || bundle_record.readiness.apply_performed
        || bundle_record.readiness.install_performed
    {
        return finish_refused(
            receipt,
            "update apply helper requires granted ready-for-manual-apply readiness evidence",
            receipt_path,
        );
    }
    if !option_is_value(&bundle_record.bundle.verification_status, "VERIFIED")
        || !option_is_value(
            &bundle_record.bundle.source_authenticity_status,
            "TRUSTED_SIGNATURE",
        )
        || !option_is_value(&bundle_record.bundle.source_trust_decision, "TRUSTED")
        || !option_is_non_blank(&bundle_record.bundle.publisher_key_fingerprint_sha256)
    {
        return finish_refused(
            receipt,
            "update apply helper requires verified trusted signed source evidence",
            receipt_path,
        );
    }
    if !option_eq_ignore_ascii_case(
        &bundle_record.bundle.verification_status,
        &bundle_record.readiness.verification_status,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.source_authenticity_status,
        &bundle_record.readiness.source_authenticity_status,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.source_trust_decision,
        &bundle_record.readiness.source_trust_decision,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.publisher_key_fingerprint_sha256,
        &bundle_record.readiness.publisher_key_fingerprint_sha256,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.readiness_evidence_path,
        &bundle_record.readiness.evidence_path,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.stage_evidence_path,
        &bundle_record.readiness.stage_evidence_path,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.staged_asset_path,
        &bundle_record.readiness.staged_asset_path,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.expected_sha256,
        &bundle_record.readiness.expected_sha256,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.target_current_exe_path,
        &bundle_record.readiness.target_current_exe_path,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.backup_destination_path,
        &bundle_record.readiness.backup_destination_path,
    ) || !option_eq_ignore_ascii_case(
        &bundle_record.bundle.backup_boundary_path,
        &bundle_record.readiness.backup_boundary_path,
    ) {
        return finish_refused(
            receipt,
            "update apply helper refuses bundle/readiness evidence mismatch",
            receipt_path,
        );
    }

    let readiness_evidence_path = match bundle_record.bundle.readiness_evidence_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires readiness evidence path",
                receipt_path,
            )
        }
    };
    if !readiness_evidence_path.is_file() {
        return finish_refused(
            receipt,
            format!(
                "update apply helper readiness evidence file missing: {}",
                readiness_evidence_path.display()
            ),
            receipt_path,
        );
    }
    let stage_evidence_path = match bundle_record.bundle.stage_evidence_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires stage evidence path",
                receipt_path,
            )
        }
    };
    if !stage_evidence_path.is_file() {
        return finish_refused(
            receipt,
            format!(
                "update apply helper stage evidence file missing: {}",
                stage_evidence_path.display()
            ),
            receipt_path,
        );
    }

    let helper_copy_path = match bundle_record.bundle.helper_copy_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires recorded helper copy path",
                receipt_path,
            )
        }
    };
    receipt.helper_copy_path = Some(helper_copy_path.display().to_string());
    if !paths_equal_if_available(helper_current_exe_path, &helper_copy_path) {
        return finish_refused(
            receipt,
            "update apply helper current exe must match recorded helper copy path",
            receipt_path,
        );
    }
    if !helper_copy_path.is_file() {
        return finish_refused(
            receipt,
            format!(
                "update apply helper copy is not a file: {}",
                helper_copy_path.display()
            ),
            receipt_path,
        );
    }
    let expected_helper_sha = match bundle_record.bundle.helper_copy_sha256.as_deref() {
        Some(sha) if !sha.trim().is_empty() => sha.trim().to_ascii_uppercase(),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires recorded helper copy hash",
                receipt_path,
            )
        }
    };
    let helper_sha = match sha256_file_upper(helper_current_exe_path) {
        Ok(sha) => sha,
        Err(e) => return finish_refused(receipt, e, receipt_path),
    };
    receipt.helper_copy_sha256 = Some(helper_sha.clone());
    receipt.helper_copy_sha256_match = expected_helper_sha.eq_ignore_ascii_case(&helper_sha);
    if !receipt.helper_copy_sha256_match {
        return finish_refused(
            receipt,
            "update apply helper copy hash does not match bundle",
            receipt_path,
        );
    }

    let target_path = match bundle_record.bundle.target_current_exe_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires target path",
                receipt_path,
            )
        }
    };
    let staged_asset_path = match bundle_record.bundle.staged_asset_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires staged asset path",
                receipt_path,
            )
        }
    };
    let backup_path = match bundle_record.bundle.backup_destination_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires backup path",
                receipt_path,
            )
        }
    };
    let backup_boundary = match bundle_record.bundle.backup_boundary_path.as_deref() {
        Some(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires backup boundary path",
                receipt_path,
            )
        }
    };
    receipt.target_path = Some(target_path.display().to_string());
    receipt.staged_asset_path = Some(staged_asset_path.display().to_string());
    receipt.backup_path = Some(backup_path.display().to_string());
    receipt.backup_boundary_path = Some(backup_boundary.display().to_string());
    receipt.helper_current_exe_is_target =
        paths_equal_if_available(helper_current_exe_path, &target_path);
    if receipt.helper_current_exe_is_target {
        return finish_refused(
            receipt,
            "update apply helper refuses to run from the target executable path",
            receipt_path,
        );
    }
    if paths_equal_if_available(&target_path, &staged_asset_path) {
        return finish_refused(
            receipt,
            "update apply helper refuses target equal to staged asset",
            receipt_path,
        );
    }
    if paths_equal_if_available(&target_path, &backup_path)
        || paths_equal_if_available(&staged_asset_path, &backup_path)
    {
        return finish_refused(
            receipt,
            "update apply helper refuses unsafe backup destination collision",
            receipt_path,
        );
    }
    if !path_is_within_if_available(&backup_path, &backup_boundary) {
        return finish_refused(
            receipt,
            "update apply helper requires backup path inside recorded backup boundary",
            receipt_path,
        );
    }
    if !target_path.is_file() {
        return finish_refused(
            receipt,
            format!(
                "update apply helper target is not a file: {}",
                target_path.display()
            ),
            receipt_path,
        );
    }
    if !staged_asset_path.is_file() {
        return finish_refused(
            receipt,
            format!(
                "update apply helper staged asset is not a file: {}",
                staged_asset_path.display()
            ),
            receipt_path,
        );
    }
    if backup_path.exists() {
        return finish_refused(
            receipt,
            format!(
                "update apply helper refuses to overwrite existing backup: {}",
                backup_path.display()
            ),
            receipt_path,
        );
    }

    let target_before_sha256 = match sha256_file_upper(&target_path) {
        Ok(sha) => sha,
        Err(e) => return finish_refused(receipt, e, receipt_path),
    };
    receipt.target_before_sha256 = Some(target_before_sha256.clone());
    if bundle_record
        .bundle
        .target_before_sha256
        .as_deref()
        .map(|expected| !expected.eq_ignore_ascii_case(&target_before_sha256))
        .unwrap_or(true)
    {
        return finish_refused(
            receipt,
            "update apply helper refuses target-before hash drift",
            receipt_path,
        );
    }
    let staged_sha256 = match sha256_file_upper(&staged_asset_path) {
        Ok(sha) => sha,
        Err(e) => return finish_refused(receipt, e, receipt_path),
    };
    receipt.staged_sha256 = Some(staged_sha256.clone());
    let expected_sha256 = match bundle_record.bundle.expected_sha256.as_deref() {
        Some(sha) if !sha.trim().is_empty() => sha.trim().to_ascii_uppercase(),
        _ => {
            return finish_refused(
                receipt,
                "update apply helper requires expected sha256",
                receipt_path,
            )
        }
    };
    receipt.expected_sha256 = Some(expected_sha256.clone());
    if !staged_sha256.eq_ignore_ascii_case(&expected_sha256) {
        return finish_refused(
            receipt,
            "update apply helper refuses staged asset hash mismatch",
            receipt_path,
        );
    }

    receipt.target_lock_preflight.attempted = true;
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&target_path)
    {
        Ok(file) => {
            drop(file);
            receipt.target_lock_preflight.ok = true;
            receipt.states.push("TARGET_LOCK_PREFLIGHT_OK".to_string());
        }
        Err(e) => {
            receipt.target_lock_preflight.error = Some(e.to_string());
            return finish_refused(
                receipt,
                format!("update apply helper target lock preflight failed: {e}"),
                receipt_path,
            );
        }
    }

    if let Some(parent) = backup_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Create backup dir failed: {e}"))?;
    }
    if let Err(e) = fs::copy(&target_path, &backup_path) {
        return finish_refused(
            receipt,
            format!("update apply helper backup failed before replace: {e}"),
            receipt_path,
        );
    }
    receipt.backup_performed = true;
    receipt.states.push("BACKED_UP".to_string());

    if options.force_rollback_failure_after_backup {
        if let Err(e) = fs::remove_file(&backup_path) {
            receipt.status = UpdateApplyHelperStatus::RollbackFailed;
            receipt.reason =
                format!("update apply helper could not inject rollback failure after backup: {e}");
            receipt.states.push("ROLLBACK_FAILED".to_string());
            return write_receipt(receipt, receipt_path);
        }
        receipt.rollback_attempted = true;
        match rollback_target(&backup_path, &target_path) {
            Ok(sha) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    "update apply helper forced rollback failure after backup".to_string();
                receipt.states.push("ROLLBACK_FAILED".to_string());
                return write_receipt(receipt, receipt_path);
            }
            Err(error) => {
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    format!("update apply helper forced rollback failure after backup: {error}");
                receipt.states.push("ROLLBACK_FAILED".to_string());
                return write_receipt(receipt, receipt_path);
            }
        }
    }

    if let Err(e) = fs::copy(&staged_asset_path, &target_path) {
        receipt.rollback_attempted = true;
        let rollback_result = rollback_target(&backup_path, &target_path);
        match rollback_result {
            Ok(sha) if sha.eq_ignore_ascii_case(&target_before_sha256) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.rollback_ok = true;
                receipt.target_restored = true;
                receipt.states.push("ROLLBACK_OK".to_string());
                return finish_refused(
                    receipt,
                    format!("update apply helper replace failed; rollback restored target: {e}"),
                    receipt_path,
                );
            }
            Ok(sha) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    format!("update apply helper replace failed and rollback hash mismatch: {e}");
                receipt.states.push("ROLLBACK_FAILED".to_string());
                return write_receipt(receipt, receipt_path);
            }
            Err(rollback_error) => {
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason = format!(
                    "update apply helper replace failed and rollback failed: {e}; {rollback_error}"
                );
                receipt.states.push("ROLLBACK_FAILED".to_string());
                return write_receipt(receipt, receipt_path);
            }
        }
    }
    receipt.replace_performed = true;
    receipt.states.push("APPLIED".to_string());

    let installed_sha256 = match sha256_file_upper(&target_path) {
        Ok(sha) => sha,
        Err(e) => return finish_refused(receipt, e, receipt_path),
    };
    receipt.installed_sha256 = Some(installed_sha256.clone());
    if !installed_sha256.eq_ignore_ascii_case(&expected_sha256) {
        receipt.rollback_attempted = true;
        let rollback_result = rollback_target(&backup_path, &target_path);
        match rollback_result {
            Ok(sha) if sha.eq_ignore_ascii_case(&target_before_sha256) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.rollback_ok = true;
                receipt.target_restored = true;
                receipt.states.push("ROLLBACK_OK".to_string());
                return finish_refused(
                    receipt,
                    "update apply helper installed hash mismatch; rollback restored target",
                    receipt_path,
                );
            }
            Ok(sha) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    "update apply helper installed hash mismatch and rollback hash mismatch"
                        .to_string();
                receipt.states.push("ROLLBACK_FAILED".to_string());
                return write_receipt(receipt, receipt_path);
            }
            Err(e) => {
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    format!("update apply helper installed hash mismatch and rollback failed: {e}");
                receipt.states.push("ROLLBACK_FAILED".to_string());
                return write_receipt(receipt, receipt_path);
            }
        }
    }
    receipt.states.push("APPLIED_AND_VERIFIED".to_string());

    if bundle_record.bundle.rollback_after_apply {
        receipt.rollback_attempted = true;
        let rollback_result = rollback_target(&backup_path, &target_path);
        match rollback_result {
            Ok(sha) if sha.eq_ignore_ascii_case(&target_before_sha256) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.rollback_ok = true;
                receipt.target_restored = true;
                receipt.status = UpdateApplyHelperStatus::RollbackOk;
                receipt.ok = true;
                receipt.reason =
                    "update apply helper backed up, replaced, verified, and rolled back"
                        .to_string();
                receipt.states.push("ROLLBACK_OK".to_string());
                write_receipt(receipt, receipt_path)
            }
            Ok(sha) => {
                receipt.rollback_sha256 = Some(sha.clone());
                receipt.target_after_sha256 = Some(sha);
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    "update apply helper verified replacement but rollback hash mismatch"
                        .to_string();
                receipt.states.push("ROLLBACK_FAILED".to_string());
                write_receipt(receipt, receipt_path)
            }
            Err(e) => {
                receipt.status = UpdateApplyHelperStatus::RollbackFailed;
                receipt.reason =
                    format!("update apply helper verified replacement but rollback failed: {e}");
                receipt.states.push("ROLLBACK_FAILED".to_string());
                write_receipt(receipt, receipt_path)
            }
        }
    } else {
        let target_after_sha256 = sha256_file_upper(&target_path)?;
        receipt.target_after_sha256 = Some(target_after_sha256.clone());
        receipt.target_restored = false;
        receipt.status = UpdateApplyHelperStatus::AppliedAndVerified;
        receipt.ok = true;
        receipt.reason =
            "update apply helper backed up, replaced, and verified staged target".to_string();
        write_receipt(receipt, receipt_path)
    }
}

pub(crate) fn run_update_apply_helper(args: &[String]) -> Result<(), String> {
    let mut bundle_path: Option<PathBuf> = None;
    let mut receipt_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bundle" => {
                i += 1;
                bundle_path = args.get(i).map(PathBuf::from);
            }
            "--receipt" => {
                i += 1;
                receipt_path = args.get(i).map(PathBuf::from);
            }
            other => return Err(format!("unknown --update-apply-helper option: {other}")),
        }
        i += 1;
    }
    let bundle_path = bundle_path.ok_or_else(|| "--bundle requires a path".to_string())?;
    let receipt_path = receipt_path.ok_or_else(|| "--receipt requires a path".to_string())?;
    let helper_current_exe_path = std::env::current_exe()
        .map_err(|e| format!("current helper executable path unavailable: {e}"))?;
    let record = read_bundle_record(&bundle_path)?;
    let receipt = apply_bundle_with_options(
        record,
        &bundle_path,
        &receipt_path,
        &helper_current_exe_path,
        HelperApplyOptions::default(),
    )?;
    let pretty = serde_json::to_string_pretty(&serde_json::json!({ "record": &receipt }))
        .map_err(|e| format!("Serialize helper receipt stdout: {e}"))?;
    println!("{pretty}");
    if !receipt.ok {
        return Err(receipt.reason);
    }
    Ok(())
}
fn write_selftest_json(json_out: Option<PathBuf>, pretty_report: &str) -> Result<(), String> {
    if let Some(json_path) = json_out {
        if let Some(parent) = json_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Create helper selftest JSON dir: {e}"))?;
        }
        fs::write(&json_path, format!("{pretty_report}\n"))
            .map_err(|e| format!("Write update apply helper selftest JSON: {e}"))?;
    }
    Ok(())
}

pub(crate) fn run_update_apply_helper_selftest(args: &[String]) -> Result<(), String> {
    let json_out = update_apply_bundle::parse_json_arg(args, "--update-apply-helper-selftest")?;

    let root =
        update_apply_bundle::unique_update_apply_selftest_root("update_apply_helper_selftest");
    let stage_dir = root.join("stage");
    let helper_dir = root.join("helper");
    fs::create_dir_all(&stage_dir).map_err(|e| format!("Create helper selftest stage dir: {e}"))?;
    fs::create_dir_all(&helper_dir)
        .map_err(|e| format!("Create helper selftest helper dir: {e}"))?;

    let current_exe_path =
        std::env::current_exe().map_err(|e| format!("current executable path unavailable: {e}"))?;
    let current_exe_before_sha256 = sha256_file_upper(&current_exe_path)?;
    let helper_copy_path = helper_dir.join("gh_mirror_gui-helper.exe");
    fs::copy(&current_exe_path, &helper_copy_path).map_err(|e| {
        format!(
            "Copy current exe {} to helper {} failed: {e}",
            current_exe_path.display(),
            helper_copy_path.display()
        )
    })?;
    let helper_copy_sha256 = sha256_file_upper(&helper_copy_path)?;

    let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
    fs::write(&staged_asset_path, b"trusted staged update bytes")
        .map_err(|e| format!("Write helper staged asset fixture: {e}"))?;
    let expected_sha256 = sha256_file_upper(&staged_asset_path)?;
    let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
    fs::write(&stage_evidence_path, b"{}")
        .map_err(|e| format!("Write helper stage evidence fixture: {e}"))?;
    let target_fixture_path = root.join("gh_mirror_gui.exe");
    fs::write(&target_fixture_path, b"original trusted app bytes")
        .map_err(|e| format!("Write helper target fixture: {e}"))?;
    let target_before_sha256 = sha256_file_upper(&target_fixture_path)?;
    let stage_report = update_apply_bundle::selftest_stage_report(
        &root,
        &stage_dir,
        &staged_asset_path,
        &stage_evidence_path,
        &expected_sha256,
    );
    let bundle_record = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
        &stage_report,
        &target_fixture_path,
        Some(&stage_dir),
        ManualApprovalState::Granted,
        update_apply_bundle::UpdateApplyBundleOptions::selftest(
            &helper_copy_path,
            &helper_copy_sha256,
            true,
        ),
    );
    let bundle_path = bundle_record
        .bundle_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| "helper selftest bundle path missing".to_string())?;
    let helper_receipt_path = stage_dir.join("update-apply-helper-receipt.json");
    let output = Command::new(&helper_copy_path)
        .arg("--update-apply-helper")
        .arg("--bundle")
        .arg(&bundle_path)
        .arg("--receipt")
        .arg(&helper_receipt_path)
        .output()
        .map_err(|e| format!("Run update apply helper copy failed: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "update apply helper copy exited with {}; stdout={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let success_receipt = read_receipt_record(&helper_receipt_path)?;
    let target_after_success_sha256 = sha256_file_upper(&target_fixture_path)?;

    let forced_target_path = root.join("gh_mirror_gui-force.exe");
    fs::write(&forced_target_path, b"original forced app bytes")
        .map_err(|e| format!("Write forced target fixture: {e}"))?;
    let forced_original_sha256 = sha256_file_upper(&forced_target_path)?;
    let forced_bundle_record = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
        &stage_report,
        &forced_target_path,
        Some(&stage_dir),
        ManualApprovalState::Granted,
        update_apply_bundle::UpdateApplyBundleOptions::selftest(
            &helper_copy_path,
            &helper_copy_sha256,
            true,
        ),
    );
    let forced_bundle_path = forced_bundle_record
        .bundle_path
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| "forced helper selftest bundle path missing".to_string())?;
    let forced_receipt_path = stage_dir.join("update-apply-helper-forced-rollback-receipt.json");
    let forced_receipt = apply_bundle_with_options(
        forced_bundle_record,
        &forced_bundle_path,
        &forced_receipt_path,
        &helper_copy_path,
        HelperApplyOptions {
            force_rollback_failure_after_backup: true,
        },
    )?;
    let forced_target_after_sha256 = sha256_file_upper(&forced_target_path)?;
    let current_exe_after_sha256 = sha256_file_upper(&current_exe_path)?;
    let current_exe_unchanged =
        current_exe_before_sha256.eq_ignore_ascii_case(&current_exe_after_sha256);
    let helper_current_exe_is_not_target = !success_receipt.helper_current_exe_is_target;
    let success_decision =
        crate::artifact_decision::ArtifactDecision::from_update_apply_helper_receipt(
            &success_receipt,
        );
    let forced_decision =
        crate::artifact_decision::ArtifactDecision::from_update_apply_helper_receipt(
            &forced_receipt,
        );

    let ok = success_receipt.ok
        && success_receipt.fixture_only
        && success_receipt.no_live_current_exe_mutation
        && success_receipt.no_system_persistence
        && success_receipt.helper_copy_sha256_match
        && success_receipt.target_lock_preflight.ok
        && success_receipt.backup_performed
        && success_receipt.replace_performed
        && success_receipt.rollback_attempted
        && success_receipt.rollback_ok
        && success_receipt.target_restored
        && success_receipt.installed_sha256.as_deref() == Some(expected_sha256.as_str())
        && target_after_success_sha256.eq_ignore_ascii_case(&target_before_sha256)
        && forced_receipt.backup_performed
        && forced_receipt.rollback_attempted
        && !forced_receipt.rollback_ok
        && !forced_receipt.target_restored
        && forced_target_after_sha256.eq_ignore_ascii_case(&forced_original_sha256)
        && helper_current_exe_is_not_target
        && current_exe_unchanged
        && success_decision.verdict == crate::artifact_decision::ArtifactVerdict::RollbackOk;

    let report = serde_json::json!({
        "schema_version": UPDATE_APPLY_HELPER_SCHEMA_VERSION,
        "ok": ok,
        "fixture_only": success_receipt.fixture_only,
        "no_live_current_exe_mutation": success_receipt.no_live_current_exe_mutation,
        "no_system_persistence": success_receipt.no_system_persistence,
        "helper_copy_sha256": helper_copy_sha256,
        "bundle_hash": bundle_record.bundle_hash,
        "approval_expires_at_unix_ms": bundle_record.bundle.approval_expires_at_unix_ms,
        "target_before_sha256": target_before_sha256,
        "target_lock_preflight": success_receipt.target_lock_preflight,
        "helper_current_exe_is_not_target": helper_current_exe_is_not_target,
        "target_restored": success_receipt.target_restored,
        "rollback_ok": success_receipt.rollback_ok,
        "success_receipt": success_receipt,
        "forced_failure_receipt": forced_receipt,
        "artifact_decision": success_decision,
        "forced_artifact_decision": forced_decision,
        "current_exe": {
            "path": current_exe_path.display().to_string(),
            "before_sha256": current_exe_before_sha256,
            "after_sha256": current_exe_after_sha256,
            "unchanged": current_exe_unchanged,
        },
        "fixture": {
            "root": root.display().to_string(),
            "stage_dir": stage_dir.display().to_string(),
            "helper_copy_path": helper_copy_path.display().to_string(),
            "bundle_path": bundle_path.display().to_string(),
            "helper_receipt_path": helper_receipt_path.display().to_string(),
            "stage_evidence_path": stage_evidence_path.display().to_string(),
            "staged_asset_path": staged_asset_path.display().to_string(),
            "target_fixture_path": target_fixture_path.display().to_string(),
            "expected_sha256": expected_sha256,
            "target_after_success_sha256": target_after_success_sha256,
            "target_before_sha256": target_before_sha256,
            "forced_original_sha256": forced_original_sha256,
            "forced_target_after_sha256": forced_target_after_sha256,
        }
    });
    let pretty_report = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("Serialize helper selftest JSON: {e}"))?;
    write_selftest_json(json_out, &pretty_report)?;
    println!("{pretty_report}");
    if !ok {
        return Err("update apply helper selftest did not prove helper backup/replace/verify/rollback boundary".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_apply_helper_refuses_current_exe_as_target() {
        let root =
            update_apply_bundle::unique_update_apply_selftest_root("helper_refuses_current_exe");
        let stage_dir = root.join("stage");
        fs::create_dir_all(&stage_dir).expect("create helper refuse stage");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged update bytes").expect("write staged");
        let expected_sha256 = sha256_file_upper(&staged_asset_path).expect("hash staged");
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("write evidence");
        let current_exe = std::env::current_exe().expect("current exe");
        let current_sha_before = sha256_file_upper(&current_exe).expect("hash current before");
        let helper_sha = current_sha_before.clone();
        let report = update_apply_bundle::selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &expected_sha256,
        );
        let bundle = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
            &report,
            &current_exe,
            Some(&stage_dir),
            ManualApprovalState::Granted,
            update_apply_bundle::UpdateApplyBundleOptions::selftest(
                &current_exe,
                &helper_sha,
                true,
            ),
        );
        let bundle_path = bundle
            .bundle_path
            .as_deref()
            .map(PathBuf::from)
            .expect("bundle path");
        let receipt_path = stage_dir.join("receipt-refused.json");
        let receipt = apply_bundle_with_options(
            bundle,
            &bundle_path,
            &receipt_path,
            &current_exe,
            HelperApplyOptions::default(),
        )
        .expect("refusal receipt should still write");
        let current_sha_after = sha256_file_upper(&current_exe).expect("hash current after");

        assert!(!receipt.ok);
        assert_eq!(receipt.status, UpdateApplyHelperStatus::Refused);
        assert!(receipt.helper_current_exe_is_target);
        assert!(!receipt.backup_performed);
        assert_eq!(current_sha_before, current_sha_after);
    }

    #[test]
    fn update_apply_helper_rolls_back_forced_failure_after_backup() {
        let root = update_apply_bundle::unique_update_apply_selftest_root("helper_forced_rollback");
        let stage_dir = root.join("stage");
        let helper_dir = root.join("helper");
        fs::create_dir_all(&stage_dir).expect("create stage");
        fs::create_dir_all(&helper_dir).expect("create helper dir");
        let current_exe = std::env::current_exe().expect("current exe");
        let helper_copy = helper_dir.join("helper.exe");
        fs::copy(&current_exe, &helper_copy).expect("copy helper");
        let helper_sha = sha256_file_upper(&helper_copy).expect("hash helper");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged update bytes").expect("write staged");
        let expected_sha256 = sha256_file_upper(&staged_asset_path).expect("hash staged");
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("write evidence");
        let target_path = root.join("target.exe");
        fs::write(&target_path, b"original bytes").expect("write target");
        let original_sha = sha256_file_upper(&target_path).expect("hash target");
        let report = update_apply_bundle::selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &expected_sha256,
        );
        let bundle = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
            &report,
            &target_path,
            Some(&stage_dir),
            ManualApprovalState::Granted,
            update_apply_bundle::UpdateApplyBundleOptions::selftest(
                &helper_copy,
                &helper_sha,
                true,
            ),
        );
        let bundle_path = bundle
            .bundle_path
            .as_deref()
            .map(PathBuf::from)
            .expect("bundle path");
        let receipt_path = stage_dir.join("receipt-forced.json");
        let receipt = apply_bundle_with_options(
            bundle,
            &bundle_path,
            &receipt_path,
            &helper_copy,
            HelperApplyOptions {
                force_rollback_failure_after_backup: true,
            },
        )
        .expect("forced receipt");
        let final_sha = sha256_file_upper(&target_path).expect("hash final");

        assert!(!receipt.ok);
        assert_eq!(receipt.status, UpdateApplyHelperStatus::RollbackFailed);
        assert!(receipt.backup_performed);
        assert!(receipt.rollback_attempted);
        assert!(!receipt.rollback_ok);
        assert!(!receipt.target_restored);
        assert_eq!(final_sha, original_sha);
    }

    #[test]
    fn update_apply_helper_refuses_missing_helper_copy_identity() {
        let root =
            update_apply_bundle::unique_update_apply_selftest_root("helper_missing_identity");
        let stage_dir = root.join("stage");
        fs::create_dir_all(&stage_dir).expect("create stage");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged update bytes").expect("write staged");
        let expected_sha256 = sha256_file_upper(&staged_asset_path).expect("hash staged");
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("write evidence");
        let target_path = root.join("target.exe");
        fs::write(&target_path, b"original bytes").expect("write target");
        let original_sha = sha256_file_upper(&target_path).expect("hash target");
        let report = update_apply_bundle::selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &expected_sha256,
        );
        let bundle = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
            &report,
            &target_path,
            Some(&stage_dir),
            ManualApprovalState::Granted,
            update_apply_bundle::UpdateApplyBundleOptions::ui_default(),
        );
        let bundle_path = bundle
            .bundle_path
            .as_deref()
            .map(PathBuf::from)
            .expect("bundle path");
        let current_exe = std::env::current_exe().expect("current exe");
        let receipt = apply_bundle_with_options(
            bundle,
            &bundle_path,
            &stage_dir.join("receipt-missing-helper.json"),
            &current_exe,
            HelperApplyOptions::default(),
        )
        .expect("refusal receipt");
        let final_sha = sha256_file_upper(&target_path).expect("hash final");

        assert!(!receipt.ok);
        assert_eq!(receipt.status, UpdateApplyHelperStatus::Refused);
        assert!(receipt.reason.contains("recorded helper copy path"));
        assert!(!receipt.backup_performed);
        assert_eq!(final_sha, original_sha);
    }

    #[test]
    fn update_apply_helper_refuses_missing_evidence_before_backup() {
        let root =
            update_apply_bundle::unique_update_apply_selftest_root("helper_missing_evidence");
        let stage_dir = root.join("stage");
        let helper_dir = root.join("helper");
        fs::create_dir_all(&stage_dir).expect("create stage");
        fs::create_dir_all(&helper_dir).expect("create helper");
        let current_exe = std::env::current_exe().expect("current exe");
        let helper_copy = helper_dir.join("helper.exe");
        fs::copy(&current_exe, &helper_copy).expect("copy helper");
        let helper_sha = sha256_file_upper(&helper_copy).expect("hash helper");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged update bytes").expect("write staged");
        let expected_sha256 = sha256_file_upper(&staged_asset_path).expect("hash staged");
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("write evidence");
        let target_path = root.join("target.exe");
        fs::write(&target_path, b"original bytes").expect("write target");
        let original_sha = sha256_file_upper(&target_path).expect("hash target");
        let report = update_apply_bundle::selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &expected_sha256,
        );
        let bundle = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
            &report,
            &target_path,
            Some(&stage_dir),
            ManualApprovalState::Granted,
            update_apply_bundle::UpdateApplyBundleOptions::selftest(
                &helper_copy,
                &helper_sha,
                true,
            ),
        );
        let readiness_path = bundle
            .bundle
            .readiness_evidence_path
            .as_deref()
            .map(PathBuf::from)
            .expect("readiness evidence path");
        fs::remove_file(readiness_path).expect("remove readiness evidence");
        let bundle_path = bundle
            .bundle_path
            .as_deref()
            .map(PathBuf::from)
            .expect("bundle path");
        let receipt = apply_bundle_with_options(
            bundle,
            &bundle_path,
            &stage_dir.join("receipt-missing-evidence.json"),
            &helper_copy,
            HelperApplyOptions::default(),
        )
        .expect("refusal receipt");
        let final_sha = sha256_file_upper(&target_path).expect("hash final");

        assert!(!receipt.ok);
        assert_eq!(receipt.status, UpdateApplyHelperStatus::Refused);
        assert!(receipt.reason.contains("readiness evidence file missing"));
        assert!(!receipt.backup_performed);
        assert_eq!(final_sha, original_sha);
    }

    #[test]
    fn update_apply_helper_refuses_bundle_hash_drift_before_backup() {
        let root = update_apply_bundle::unique_update_apply_selftest_root("helper_bundle_drift");
        let stage_dir = root.join("stage");
        let helper_dir = root.join("helper");
        fs::create_dir_all(&stage_dir).expect("create stage");
        fs::create_dir_all(&helper_dir).expect("create helper");
        let current_exe = std::env::current_exe().expect("current exe");
        let helper_copy = helper_dir.join("helper.exe");
        fs::copy(&current_exe, &helper_copy).expect("copy helper");
        let helper_sha = sha256_file_upper(&helper_copy).expect("hash helper");
        let staged_asset_path = stage_dir.join("gh_mirror_gui.exe");
        fs::write(&staged_asset_path, b"trusted staged update bytes").expect("write staged");
        let expected_sha256 = sha256_file_upper(&staged_asset_path).expect("hash staged");
        let stage_evidence_path = stage_dir.join("update-candidate-stage.json");
        fs::write(&stage_evidence_path, b"{}").expect("write evidence");
        let target_path = root.join("target.exe");
        fs::write(&target_path, b"original bytes").expect("write target");
        let original_sha = sha256_file_upper(&target_path).expect("hash target");
        let report = update_apply_bundle::selftest_stage_report(
            &root,
            &stage_dir,
            &staged_asset_path,
            &stage_evidence_path,
            &expected_sha256,
        );
        let mut bundle = update_apply_bundle::write_update_apply_bundle_evidence_for_stage2(
            &report,
            &target_path,
            Some(&stage_dir),
            ManualApprovalState::Granted,
            update_apply_bundle::UpdateApplyBundleOptions::selftest(
                &helper_copy,
                &helper_sha,
                true,
            ),
        );
        bundle.bundle.reason.push_str(" tampered");
        let bundle_path = bundle
            .bundle_path
            .as_deref()
            .map(PathBuf::from)
            .expect("bundle path");
        let receipt = apply_bundle_with_options(
            bundle,
            &bundle_path,
            &stage_dir.join("receipt-bundle-drift.json"),
            &helper_copy,
            HelperApplyOptions::default(),
        )
        .expect("refusal receipt");
        let final_sha = sha256_file_upper(&target_path).expect("hash final");

        assert!(!receipt.ok);
        assert_eq!(receipt.status, UpdateApplyHelperStatus::Refused);
        assert!(receipt.reason.contains("bundle hash mismatch"));
        assert!(!receipt.backup_performed);
        assert_eq!(final_sha, original_sha);
    }
}
