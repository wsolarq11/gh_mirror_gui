use std::path::Path;

use crate::trust_policy::{
    file_disposition_summary, AppliedFileDisposition, TrustPolicyConfig, TrustPolicySnapshot,
};
use crate::verification::VerificationReport;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrustCenterSnapshot {
    pub(crate) downloaded_asset: String,
    pub(crate) hash_status: String,
    pub(crate) file_sha256: String,
    pub(crate) expected_sha256: String,
    pub(crate) source_authenticity: String,
    pub(crate) source_trust_detail: String,
    pub(crate) source_asset: String,
    pub(crate) signature_asset: String,
    pub(crate) publisher_key_fingerprint: String,
    pub(crate) publisher_key_source: String,
    pub(crate) policy_verdict: String,
    pub(crate) policy_at_decision: String,
    pub(crate) evidence_path: String,
    pub(crate) evidence_access: String,
    pub(crate) file_disposition: String,
    pub(crate) final_path: String,
}

pub(crate) fn trust_center_snapshot(
    report: &VerificationReport,
    evidence_path: Option<&Path>,
    disposition: &AppliedFileDisposition,
    policy_snapshot: &TrustPolicySnapshot,
    publisher_key_source: Option<&str>,
) -> TrustCenterSnapshot {
    let source_trust = report.source_trust.as_ref();
    let publisher_key_fingerprint = source_trust
        .and_then(|trust| trust.trusted_publisher_key_fingerprint_sha256.as_deref())
        .or(policy_snapshot
            .source_trust
            .trusted_publisher_key_fingerprint_sha256
            .as_deref())
        .unwrap_or("not pinned")
        .to_string();
    let publisher_key_source = publisher_key_source_label_for_fingerprint(
        &publisher_key_fingerprint,
        publisher_key_source,
    );

    TrustCenterSnapshot {
        downloaded_asset: report.asset_name.clone(),
        hash_status: report.status.as_str().to_string(),
        file_sha256: report.file_sha256.clone(),
        expected_sha256: report
            .expected_sha256
            .clone()
            .unwrap_or_else(|| "not available".to_string()),
        source_authenticity: source_trust
            .map(|trust| trust.status_label().to_string())
            .unwrap_or_else(|| "NOT_APPLICABLE".to_string()),
        source_trust_detail: source_trust
            .map(|trust| trust.detail.clone())
            .unwrap_or_else(|| "no source trust evidence recorded".to_string()),
        source_asset: report
            .source
            .as_deref()
            .or_else(|| source_trust.and_then(|trust| trust.source_asset_name.as_deref()))
            .unwrap_or("none")
            .to_string(),
        signature_asset: source_trust
            .and_then(|trust| trust.signature_asset_name.as_deref())
            .unwrap_or("none")
            .to_string(),
        publisher_key_fingerprint,
        publisher_key_source,
        policy_verdict: report.effective_trust_decision().as_str().to_string(),
        policy_at_decision: format_trust_policy_snapshot(policy_snapshot),
        evidence_path: evidence_path
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "not recorded".to_string()),
        evidence_access: evidence_access_status(evidence_path),
        file_disposition: format!(
            "{} ({})",
            disposition.action.as_str(),
            file_disposition_summary(disposition)
        ),
        final_path: disposition
            .final_path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "none".to_string()),
    }
}

pub(crate) fn publisher_key_source_label_for_policy(
    trust_policy: &TrustPolicyConfig,
    publisher_key_source: &str,
) -> String {
    if !trust_policy.source_trust.has_trusted_key() {
        "not pinned".to_string()
    } else {
        publisher_key_source_label_for_fingerprint("pinned", Some(publisher_key_source))
    }
}

pub(crate) fn format_trust_policy_snapshot(policy: &TrustPolicySnapshot) -> String {
    let signed_source = if policy.source_trust.require_trusted_source {
        "required"
    } else {
        "optional"
    };
    let publisher_key = policy
        .source_trust
        .trusted_publisher_key_fingerprint_sha256
        .as_deref()
        .unwrap_or("not pinned");
    let unknown = match (policy.unknown_keep_file, policy.unknown_allow_open) {
        (true, true) => "KEEP/open allowed",
        (true, false) => "KEEP/open blocked",
        (false, _) => "DELETE/open blocked",
    };
    format!(
        "signed_source={signed_source}; publisher_key={publisher_key}; UNKNOWN={unknown}; MISMATCH={}",
        policy.mismatch_file_policy
    )
}

pub(crate) fn publisher_key_source_label_for_fingerprint(
    publisher_key_fingerprint: &str,
    publisher_key_source: Option<&str>,
) -> String {
    if publisher_key_fingerprint == "not pinned" {
        return "not pinned".to_string();
    }
    publisher_key_source
        .map(str::trim)
        .filter(|source| !source.is_empty())
        .unwrap_or("not recorded")
        .to_string()
}

pub(crate) fn evidence_access_status(evidence_path: Option<&Path>) -> String {
    match evidence_path {
        None => "not recorded".to_string(),
        Some(path) if path.is_file() => "ready to open".to_string(),
        Some(_) => "recorded but missing on disk".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::trust_center_snapshot;
    use crate::source_trust::{
        self, SourceAuthenticityStatus, SourceTrustDecision, SourceTrustEvidence,
    };
    use crate::trust_policy::{
        AppliedFileDisposition, FileDispositionAction, MismatchFilePolicy, TrustPolicyConfig,
    };
    use crate::verification::{VerificationReport, VerificationStatus};

    fn unique_test_path(name: &str) -> PathBuf {
        let mut path = std::env::temp_dir();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        path.push(format!("gh_mirror_gui_trust_center_{nonce}_{name}"));
        path
    }

    #[test]
    fn trust_center_snapshot_displays_backend_verdict_and_publisher_pin() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = source_trust::public_key_from_private_seed(private_key).unwrap();
        let fingerprint = source_trust::trusted_key_fingerprint(&public_key).unwrap();
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "gh_mirror_gui.exe".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: Some(hash.to_string()),
            source: Some("release-provenance.json".to_string()),
            source_trust: Some(SourceTrustEvidence {
                schema_version: 1,
                status: SourceAuthenticityStatus::TrustedSignature,
                decision: SourceTrustDecision::Trusted,
                required: true,
                source_asset_name: Some("release-provenance.json".to_string()),
                signature_asset_name: Some("release-provenance.json.sig".to_string()),
                trusted_publisher_key_fingerprint_sha256: Some(fingerprint.clone()),
                detail:
                    "release-provenance.json signature verified with pinned Ed25519 publisher key"
                        .to_string(),
            }),
            detail: "SHA256 matched release-provenance.json".to_string(),
        };
        let policy = TrustPolicyConfig {
            source_trust: source_trust::SourceTrustPolicyConfig {
                require_trusted_source: true,
                trusted_publisher_key: public_key,
            },
            ..TrustPolicyConfig::default()
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("gh_mirror_gui.exe"),
            final_path: Some(PathBuf::from(r"C:\Downloads\gh_mirror_gui.exe")),
        };
        let evidence_path = unique_test_path("missing-download-evidence.json");

        let snapshot = trust_center_snapshot(
            &report,
            Some(&evidence_path),
            &disposition,
            &policy.snapshot(),
            Some("GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub"),
        );

        assert_eq!(snapshot.hash_status, "VERIFIED");
        assert_eq!(snapshot.downloaded_asset, "gh_mirror_gui.exe");
        assert_eq!(snapshot.file_sha256, hash);
        assert_eq!(snapshot.expected_sha256, hash);
        assert_eq!(snapshot.source_authenticity, "TRUSTED_SIGNATURE");
        assert_eq!(
            snapshot.source_trust_detail,
            "release-provenance.json signature verified with pinned Ed25519 publisher key"
        );
        assert_eq!(snapshot.source_asset, "release-provenance.json");
        assert_eq!(snapshot.signature_asset, "release-provenance.json.sig");
        assert_eq!(snapshot.publisher_key_fingerprint, fingerprint);
        assert_eq!(
            snapshot.publisher_key_source,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub"
        );
        assert_eq!(snapshot.policy_verdict, "TRUSTED");
        assert!(snapshot
            .policy_at_decision
            .contains("signed_source=required"));
        assert!(snapshot.policy_at_decision.contains(&fingerprint));
        assert_eq!(snapshot.evidence_path, evidence_path.display().to_string());
        assert_eq!(snapshot.evidence_access, "recorded but missing on disk");
        assert_eq!(snapshot.file_disposition, "KEEP (file kept)");
        assert_eq!(snapshot.final_path, r"C:\Downloads\gh_mirror_gui.exe");
    }

    #[test]
    fn trust_center_snapshot_uses_recorded_policy_snapshot_for_last_download() {
        let recorded_key = source_trust::public_key_from_private_seed(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let current_key = source_trust::public_key_from_private_seed(
            "2222222222222222222222222222222222222222222222222222222222222222",
        )
        .unwrap();
        let recorded_fingerprint = source_trust::trusted_key_fingerprint(&recorded_key).unwrap();
        let current_fingerprint = source_trust::trusted_key_fingerprint(&current_key).unwrap();
        let recorded_policy = TrustPolicyConfig {
            unknown_keep_file: false,
            mismatch_file_policy: MismatchFilePolicy::Delete,
            source_trust: source_trust::SourceTrustPolicyConfig {
                require_trusted_source: true,
                trusted_publisher_key: recorded_key,
            },
            ..TrustPolicyConfig::default()
        }
        .snapshot();
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "gh_mirror_gui.exe".to_string(),
            file_sha256: "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC"
                .to_string(),
            expected_sha256: Some(
                "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string(),
            ),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: None,
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("gh_mirror_gui.exe"),
            final_path: Some(PathBuf::from(r"C:\Downloads\gh_mirror_gui.exe")),
        };

        let snapshot = trust_center_snapshot(
            &report,
            None,
            &disposition,
            &recorded_policy,
            Some("local file C:\\Keys\\publisher-key.ed25519.pub"),
        );

        assert_eq!(snapshot.publisher_key_fingerprint, recorded_fingerprint);
        assert!(snapshot
            .policy_at_decision
            .contains("signed_source=required"));
        assert!(snapshot
            .policy_at_decision
            .contains("UNKNOWN=DELETE/open blocked"));
        assert!(snapshot.policy_at_decision.contains("MISMATCH=DELETE"));
        assert!(snapshot.policy_at_decision.contains(&recorded_fingerprint));
        assert!(!snapshot.policy_at_decision.contains(&current_fingerprint));
        assert_eq!(
            snapshot.publisher_key_source,
            "local file C:\\Keys\\publisher-key.ed25519.pub"
        );
        assert_eq!(snapshot.evidence_path, "not recorded");
        assert_eq!(snapshot.evidence_access, "not recorded");
    }

    #[test]
    fn trust_center_snapshot_marks_publisher_key_source_unrecorded_when_missing() {
        let recorded_key = source_trust::public_key_from_private_seed(
            "1111111111111111111111111111111111111111111111111111111111111111",
        )
        .unwrap();
        let recorded_policy = TrustPolicyConfig {
            source_trust: source_trust::SourceTrustPolicyConfig {
                require_trusted_source: true,
                trusted_publisher_key: recorded_key,
            },
            ..TrustPolicyConfig::default()
        }
        .snapshot();
        let report = VerificationReport {
            status: VerificationStatus::Unknown,
            asset_name: "gh_mirror_gui.exe".to_string(),
            file_sha256: "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC"
                .to_string(),
            expected_sha256: None,
            source: None,
            source_trust: None,
            detail: "No verification asset found".to_string(),
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("gh_mirror_gui.exe"),
            final_path: Some(PathBuf::from(r"C:\Downloads\gh_mirror_gui.exe")),
        };

        let snapshot = trust_center_snapshot(&report, None, &disposition, &recorded_policy, None);

        assert_ne!(snapshot.publisher_key_fingerprint, "not pinned");
        assert_eq!(snapshot.publisher_key_source, "not recorded");
        assert_eq!(
            snapshot.source_trust_detail,
            "no source trust evidence recorded"
        );
        assert_eq!(snapshot.evidence_access, "not recorded");
    }

    #[test]
    fn trust_center_snapshot_surfaces_backend_source_trust_detail() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = source_trust::public_key_from_private_seed(private_key).unwrap();
        let fingerprint = source_trust::trusted_key_fingerprint(&public_key).unwrap();
        let detail = "SHA256SUMS.txt detached signature did not verify: invalid Ed25519 signature";
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "gh_mirror_gui.exe".to_string(),
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
                required: true,
                source_asset_name: Some("SHA256SUMS.txt".to_string()),
                signature_asset_name: Some("SHA256SUMS.txt.sig".to_string()),
                trusted_publisher_key_fingerprint_sha256: Some(fingerprint),
                detail: detail.to_string(),
            }),
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };
        let policy = TrustPolicyConfig {
            source_trust: source_trust::SourceTrustPolicyConfig {
                require_trusted_source: true,
                trusted_publisher_key: public_key,
            },
            ..TrustPolicyConfig::default()
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: PathBuf::from("gh_mirror_gui.exe"),
            final_path: Some(PathBuf::from(r"C:\Downloads\gh_mirror_gui.exe.quarantine")),
        };

        let snapshot = trust_center_snapshot(&report, None, &disposition, &policy.snapshot(), None);

        assert_eq!(snapshot.hash_status, "VERIFIED");
        assert_eq!(snapshot.source_authenticity, "BAD_SIGNATURE");
        assert_eq!(snapshot.policy_verdict, "BLOCK");
        assert_eq!(snapshot.source_asset, "SHA256SUMS.txt");
        assert_eq!(snapshot.signature_asset, "SHA256SUMS.txt.sig");
        assert_eq!(snapshot.source_trust_detail, detail);
        assert_eq!(snapshot.evidence_path, "not recorded");
        assert_eq!(snapshot.evidence_access, "not recorded");
    }

    #[test]
    fn trust_center_snapshot_marks_openable_evidence_path() {
        let evidence_path = unique_test_path("trust-center-evidence.json");
        fs::write(&evidence_path, "{}\n").unwrap();
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "gh_mirror_gui.exe".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: Some(hash.to_string()),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: None,
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("gh_mirror_gui.exe"),
            final_path: Some(PathBuf::from(r"C:\Downloads\gh_mirror_gui.exe")),
        };

        let snapshot = trust_center_snapshot(
            &report,
            Some(&evidence_path),
            &disposition,
            &TrustPolicyConfig::default().snapshot(),
            None,
        );

        assert_eq!(snapshot.evidence_path, evidence_path.display().to_string());
        assert_eq!(snapshot.evidence_access, "ready to open");

        let _ = fs::remove_file(evidence_path);
    }

    #[test]
    fn trust_center_snapshot_includes_downloaded_asset_hash_context() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let report = VerificationReport {
            status: VerificationStatus::Unknown,
            asset_name: "portable.zip".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: None,
            source: None,
            source_trust: None,
            detail: "No verification asset found".to_string(),
        };
        let disposition = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("portable.zip"),
            final_path: Some(PathBuf::from(r"C:\Downloads\portable.zip")),
        };

        let snapshot = trust_center_snapshot(
            &report,
            None,
            &disposition,
            &TrustPolicyConfig::default().snapshot(),
            None,
        );

        assert_eq!(snapshot.downloaded_asset, "portable.zip");
        assert_eq!(snapshot.file_sha256, hash);
        assert_eq!(snapshot.expected_sha256, "not available");
        assert_eq!(snapshot.hash_status, "UNKNOWN");
        assert_eq!(snapshot.policy_verdict, "RISK");
    }
}
