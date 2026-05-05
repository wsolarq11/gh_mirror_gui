#[cfg(test)]
use crate::source_trust::{SourceAuthenticityStatus, SourceTrustDecision, SourceTrustEvidence};
use crate::source_trust::{SourceTrustPolicyConfig, SourceTrustPolicySnapshot};
use crate::verification::VerificationStatus;
use crate::verification::{VerificationReport, VerificationTrustDecision};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MismatchFilePolicy {
    #[default]
    Quarantine,
    Delete,
}

impl MismatchFilePolicy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quarantine => "QUARANTINE",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TrustPolicyConfig {
    pub unknown_keep_file: bool,
    pub unknown_allow_open: bool,
    pub mismatch_file_policy: MismatchFilePolicy,
    pub source_trust: SourceTrustPolicyConfig,
}

impl Default for TrustPolicyConfig {
    fn default() -> Self {
        Self {
            unknown_keep_file: true,
            unknown_allow_open: false,
            mismatch_file_policy: MismatchFilePolicy::Quarantine,
            source_trust: SourceTrustPolicyConfig::default(),
        }
    }
}

impl TrustPolicyConfig {
    pub(crate) fn snapshot(&self) -> TrustPolicySnapshot {
        TrustPolicySnapshot {
            schema_version: 2,
            unknown_keep_file: self.unknown_keep_file,
            unknown_allow_open: self.unknown_allow_open,
            mismatch_file_policy: self.mismatch_file_policy.as_str().to_string(),
            source_trust: self.source_trust.snapshot(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct TrustPolicySnapshot {
    pub(crate) schema_version: u32,
    pub(crate) unknown_keep_file: bool,
    pub(crate) unknown_allow_open: bool,
    pub(crate) mismatch_file_policy: String,
    #[serde(default)]
    pub(crate) source_trust: SourceTrustPolicySnapshot,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FileDispositionAction {
    Keep,
    Quarantine,
    Delete,
}

impl FileDispositionAction {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Keep => "KEEP",
            Self::Quarantine => "QUARANTINE",
            Self::Delete => "DELETE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PlannedFileDisposition {
    pub(crate) action: FileDispositionAction,
    pub(crate) original_path: PathBuf,
    pub(crate) final_path: Option<PathBuf>,
}

impl PlannedFileDisposition {
    pub(crate) fn record(&self) -> FileDispositionRecord {
        FileDispositionRecord {
            schema_version: 1,
            action: self.action.as_str().to_string(),
            original_path: self.original_path.to_string_lossy().to_string(),
            final_path: self
                .final_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct FileDispositionRecord {
    pub(crate) schema_version: u32,
    pub(crate) action: String,
    pub(crate) original_path: String,
    pub(crate) final_path: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppliedFileDisposition {
    pub action: FileDispositionAction,
    pub original_path: PathBuf,
    pub final_path: Option<PathBuf>,
}

#[cfg(test)]
pub(crate) fn trust_decision_for_status(status: &VerificationStatus) -> VerificationTrustDecision {
    status.trust_decision()
}

#[cfg(test)]
pub(crate) fn trust_decision_for_report(report: &VerificationReport) -> VerificationTrustDecision {
    report.effective_trust_decision()
}

pub(crate) fn plan_file_disposition(
    path: &Path,
    status: &VerificationStatus,
    policy: &TrustPolicyConfig,
) -> PlannedFileDisposition {
    let original_path = path.to_path_buf();
    match status {
        VerificationStatus::Verified => PlannedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path,
            final_path: Some(path.to_path_buf()),
        },
        VerificationStatus::Unknown if policy.unknown_keep_file => PlannedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path,
            final_path: Some(path.to_path_buf()),
        },
        VerificationStatus::Unknown => PlannedFileDisposition {
            action: FileDispositionAction::Delete,
            original_path,
            final_path: None,
        },
        VerificationStatus::Mismatch => match policy.mismatch_file_policy {
            MismatchFilePolicy::Quarantine => PlannedFileDisposition {
                action: FileDispositionAction::Quarantine,
                original_path,
                final_path: Some(quarantine_path_for(path)),
            },
            MismatchFilePolicy::Delete => PlannedFileDisposition {
                action: FileDispositionAction::Delete,
                original_path,
                final_path: None,
            },
        },
    }
}

pub(crate) fn plan_file_disposition_for_report(
    path: &Path,
    report: &VerificationReport,
    policy: &TrustPolicyConfig,
) -> PlannedFileDisposition {
    match report.effective_trust_decision() {
        VerificationTrustDecision::Trusted => PlannedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: path.to_path_buf(),
            final_path: Some(path.to_path_buf()),
        },
        VerificationTrustDecision::Risk => {
            plan_file_disposition(path, &VerificationStatus::Unknown, policy)
        }
        VerificationTrustDecision::Block => match report.status {
            VerificationStatus::Unknown => {
                plan_file_disposition(path, &VerificationStatus::Unknown, policy)
            }
            VerificationStatus::Verified | VerificationStatus::Mismatch => {
                plan_file_disposition(path, &VerificationStatus::Mismatch, policy)
            }
        },
    }
}

pub(crate) fn apply_file_disposition(
    plan: &PlannedFileDisposition,
) -> Result<AppliedFileDisposition, String> {
    match plan.action {
        FileDispositionAction::Keep => Ok(AppliedFileDisposition {
            action: plan.action,
            original_path: plan.original_path.clone(),
            final_path: plan.final_path.clone(),
        }),
        FileDispositionAction::Delete => {
            fs::remove_file(&plan.original_path).map_err(|e| {
                format!(
                    "Delete untrusted download error ({}): {e}",
                    plan.original_path.display()
                )
            })?;
            Ok(AppliedFileDisposition {
                action: plan.action,
                original_path: plan.original_path.clone(),
                final_path: None,
            })
        }
        FileDispositionAction::Quarantine => {
            let Some(final_path) = &plan.final_path else {
                return Err("Quarantine disposition was missing a final path".to_string());
            };
            if let Some(parent) = final_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("Create quarantine dir error: {e}"))?;
            }
            fs::rename(&plan.original_path, final_path).map_err(|e| {
                format!(
                    "Quarantine untrusted download error ({} -> {}): {e}",
                    plan.original_path.display(),
                    final_path.display()
                )
            })?;
            Ok(AppliedFileDisposition {
                action: plan.action,
                original_path: plan.original_path.clone(),
                final_path: Some(final_path.clone()),
            })
        }
    }
}

#[cfg(test)]
pub(crate) fn open_location_button_label(
    status: &VerificationStatus,
    disposition: &AppliedFileDisposition,
    policy: &TrustPolicyConfig,
) -> Option<&'static str> {
    match status {
        VerificationStatus::Verified if disposition.final_path.is_some() => Some("📂 Open Folder"),
        VerificationStatus::Unknown
            if policy.unknown_keep_file
                && policy.unknown_allow_open
                && disposition.final_path.is_some() =>
        {
            Some("📂 Open Folder")
        }
        VerificationStatus::Mismatch
            if disposition.action == FileDispositionAction::Quarantine
                && disposition.final_path.is_some() =>
        {
            Some("📦 Open Quarantine")
        }
        _ => None,
    }
}

#[cfg(test)]
pub(crate) fn open_location_button_label_for_report(
    report: &VerificationReport,
    disposition: &AppliedFileDisposition,
    policy: &TrustPolicyConfig,
) -> Option<&'static str> {
    match report.effective_trust_decision() {
        VerificationTrustDecision::Trusted if disposition.final_path.is_some() => {
            Some("📂 Open Folder")
        }
        VerificationTrustDecision::Risk
            if report.status == VerificationStatus::Unknown
                && policy.unknown_keep_file
                && policy.unknown_allow_open
                && disposition.final_path.is_some() =>
        {
            Some("📂 Open Folder")
        }
        VerificationTrustDecision::Block
            if disposition.action == FileDispositionAction::Quarantine
                && disposition.final_path.is_some() =>
        {
            if report.status == VerificationStatus::Verified {
                Some("📦 Open Untrusted Source")
            } else {
                Some("📦 Open Quarantine")
            }
        }
        _ => None,
    }
}

pub fn open_location_button_label_for_facts(
    hash_status: &str,
    policy_verdict: &str,
    disposition: &AppliedFileDisposition,
    policy: &TrustPolicyConfig,
) -> Option<&'static str> {
    match policy_verdict {
        "TRUSTED" if disposition.final_path.is_some() => Some("📂 Open Folder"),
        "RISK"
            if hash_status == "UNKNOWN"
                && policy.unknown_keep_file
                && policy.unknown_allow_open
                && disposition.final_path.is_some() =>
        {
            Some("📂 Open Folder")
        }
        "BLOCK"
            if disposition.action == FileDispositionAction::Quarantine
                && disposition.final_path.is_some() =>
        {
            if hash_status == "VERIFIED" {
                Some("📦 Open Untrusted Source")
            } else {
                Some("📦 Open Quarantine")
            }
        }
        _ => None,
    }
}

pub fn file_disposition_summary(disposition: &AppliedFileDisposition) -> String {
    match disposition.action {
        FileDispositionAction::Keep => "file kept".to_string(),
        FileDispositionAction::Delete => "file deleted by trust policy".to_string(),
        FileDispositionAction::Quarantine => disposition
            .final_path
            .as_ref()
            .map(|path| format!("file quarantined to {}", path.display()))
            .unwrap_or_else(|| "file quarantined".to_string()),
    }
}

fn quarantine_path_for(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(sanitize_file_name)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "download".to_string());
    parent.join(".gh_mirror_gui-quarantine").join(format!(
        "{file_name}.mismatch.{}.quarantine",
        unique_nonce()
    ))
}

fn sanitize_file_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string()
}

fn unique_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = unique_nonce();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_trust_policy_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    #[test]
    fn trust_policy_defaults_are_conservative_but_download_compatible() {
        let policy = TrustPolicyConfig::default();

        assert!(policy.unknown_keep_file);
        assert!(!policy.unknown_allow_open);
        assert_eq!(policy.mismatch_file_policy, MismatchFilePolicy::Quarantine);
        assert!(!policy.source_trust.require_trusted_source);
        assert!(policy.source_trust.trusted_publisher_key.is_empty());
        assert_eq!(policy.snapshot().schema_version, 2);
        assert_eq!(policy.snapshot().source_trust.schema_version, 1);
        assert_eq!(
            trust_decision_for_status(&VerificationStatus::Verified),
            VerificationTrustDecision::Trusted
        );
        assert_eq!(
            trust_decision_for_status(&VerificationStatus::Mismatch),
            VerificationTrustDecision::Block
        );
        assert_eq!(
            trust_decision_for_status(&VerificationStatus::Unknown),
            VerificationTrustDecision::Risk
        );
    }

    #[test]
    fn file_disposition_plans_cover_verified_mismatch_and_unknown_policy() {
        let path = PathBuf::from(r"C:\downloads\app.exe");
        let default_policy = TrustPolicyConfig::default();

        let verified = plan_file_disposition(&path, &VerificationStatus::Verified, &default_policy);
        assert_eq!(verified.action, FileDispositionAction::Keep);
        assert_eq!(verified.final_path.as_deref(), Some(path.as_path()));

        let mismatch = plan_file_disposition(&path, &VerificationStatus::Mismatch, &default_policy);
        assert_eq!(mismatch.action, FileDispositionAction::Quarantine);
        assert!(mismatch
            .final_path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".gh_mirror_gui-quarantine"));

        let delete_mismatch = plan_file_disposition(
            &path,
            &VerificationStatus::Mismatch,
            &TrustPolicyConfig {
                mismatch_file_policy: MismatchFilePolicy::Delete,
                ..TrustPolicyConfig::default()
            },
        );
        assert_eq!(delete_mismatch.action, FileDispositionAction::Delete);
        assert_eq!(delete_mismatch.final_path, None);

        let unknown_keep =
            plan_file_disposition(&path, &VerificationStatus::Unknown, &default_policy);
        assert_eq!(unknown_keep.action, FileDispositionAction::Keep);

        let unknown_delete = plan_file_disposition(
            &path,
            &VerificationStatus::Unknown,
            &TrustPolicyConfig {
                unknown_keep_file: false,
                ..TrustPolicyConfig::default()
            },
        );
        assert_eq!(unknown_delete.action, FileDispositionAction::Delete);
    }

    #[test]
    fn source_trust_required_policy_quarantines_hash_verified_untrusted_source() {
        let path = PathBuf::from(r"C:\downloads\app.exe");
        let policy = TrustPolicyConfig {
            source_trust: SourceTrustPolicyConfig {
                require_trusted_source: true,
                trusted_publisher_key: String::new(),
            },
            ..TrustPolicyConfig::default()
        };
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC"
                .to_string(),
            expected_sha256: Some(
                "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string(),
            ),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: Some(SourceTrustEvidence {
                schema_version: 1,
                status: SourceAuthenticityStatus::MissingSignature,
                decision: SourceTrustDecision::Block,
                required: true,
                source_asset_name: Some("SHA256SUMS.txt".to_string()),
                signature_asset_name: None,
                trusted_publisher_key_fingerprint_sha256: None,
                detail: "missing signature".to_string(),
            }),
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };

        let decision = trust_decision_for_report(&report);
        let disposition = plan_file_disposition_for_report(&path, &report, &policy);

        assert_eq!(decision, VerificationTrustDecision::Block);
        assert_eq!(disposition.action, FileDispositionAction::Quarantine);
        assert!(disposition
            .final_path
            .as_ref()
            .unwrap()
            .to_string_lossy()
            .contains(".gh_mirror_gui-quarantine"));
    }

    #[test]
    fn applies_quarantine_and_delete_file_dispositions() {
        let mismatch_path = unique_test_path("mismatch.exe");
        fs::write(&mismatch_path, b"mismatch").unwrap();
        let mismatch_plan = plan_file_disposition(
            &mismatch_path,
            &VerificationStatus::Mismatch,
            &TrustPolicyConfig::default(),
        );

        let mismatch_applied = apply_file_disposition(&mismatch_plan).unwrap();

        assert!(!mismatch_path.exists());
        assert_eq!(mismatch_applied.action, FileDispositionAction::Quarantine);
        assert!(mismatch_applied.final_path.as_ref().unwrap().exists());
        let _ = fs::remove_file(mismatch_applied.final_path.unwrap());

        let unknown_path = unique_test_path("unknown.exe");
        fs::write(&unknown_path, b"unknown").unwrap();
        let unknown_plan = plan_file_disposition(
            &unknown_path,
            &VerificationStatus::Unknown,
            &TrustPolicyConfig {
                unknown_keep_file: false,
                ..TrustPolicyConfig::default()
            },
        );

        let unknown_applied = apply_file_disposition(&unknown_plan).unwrap();

        assert!(!unknown_path.exists());
        assert_eq!(unknown_applied.action, FileDispositionAction::Delete);
        assert_eq!(unknown_applied.final_path, None);
    }

    #[test]
    fn gui_open_location_decision_respects_trust_policy() {
        let path = PathBuf::from("app.exe");
        let kept = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: path.clone(),
            final_path: Some(path.clone()),
        };
        let quarantined = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: path.clone(),
            final_path: Some(PathBuf::from(".gh_mirror_gui-quarantine/app.exe")),
        };
        let deleted = AppliedFileDisposition {
            action: FileDispositionAction::Delete,
            original_path: path,
            final_path: None,
        };

        assert_eq!(
            open_location_button_label(
                &VerificationStatus::Verified,
                &kept,
                &TrustPolicyConfig::default()
            ),
            Some("📂 Open Folder")
        );
        assert_eq!(
            open_location_button_label(
                &VerificationStatus::Unknown,
                &kept,
                &TrustPolicyConfig::default()
            ),
            None
        );
        assert_eq!(
            open_location_button_label(
                &VerificationStatus::Unknown,
                &kept,
                &TrustPolicyConfig {
                    unknown_allow_open: true,
                    ..TrustPolicyConfig::default()
                }
            ),
            Some("📂 Open Folder")
        );
        assert_eq!(
            open_location_button_label(
                &VerificationStatus::Mismatch,
                &quarantined,
                &TrustPolicyConfig::default()
            ),
            Some("📦 Open Quarantine")
        );
        assert_eq!(
            open_location_button_label(
                &VerificationStatus::Unknown,
                &deleted,
                &TrustPolicyConfig {
                    unknown_allow_open: true,
                    unknown_keep_file: false,
                    ..TrustPolicyConfig::default()
                }
            ),
            None
        );
    }

    #[test]
    fn gui_open_location_decision_blocks_untrusted_verified_source() {
        let path = PathBuf::from("app.exe");
        let quarantined = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: path.clone(),
            final_path: Some(PathBuf::from(".gh_mirror_gui-quarantine/app.exe")),
        };
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC"
                .to_string(),
            expected_sha256: Some(
                "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string(),
            ),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: Some(SourceTrustEvidence {
                schema_version: 1,
                status: SourceAuthenticityStatus::BadSignature,
                decision: SourceTrustDecision::Block,
                required: false,
                source_asset_name: Some("SHA256SUMS.txt".to_string()),
                signature_asset_name: Some("SHA256SUMS.txt.sig".to_string()),
                trusted_publisher_key_fingerprint_sha256: Some("fingerprint".to_string()),
                detail: "bad signature".to_string(),
            }),
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };

        assert_eq!(
            open_location_button_label_for_report(
                &report,
                &quarantined,
                &TrustPolicyConfig::default()
            ),
            Some("📦 Open Untrusted Source")
        );
    }
}
