use crate::download::{sha256_file, DownloadProbe, SelectedDownloadStrategy};
use crate::source_trust::SourceTrustEvidence;
use crate::trust_policy::{FileDispositionRecord, PlannedFileDisposition, TrustPolicyConfig};
use crate::verification::VerificationReport;
use directories::ProjectDirs;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

static VERIFICATION_EVIDENCE_NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct BenchHistoryEntry {
    pub(crate) schema_version: u32,
    pub(crate) url: String,
    pub(crate) variant: String,
    pub(crate) mode: String,
    pub(crate) total_bytes: u64,
    pub(crate) segment_size: Option<u64>,
    pub(crate) concurrency: Option<usize>,
    pub(crate) download_ms: u128,
    pub(crate) avg_mib_s: f64,
    pub(crate) sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_trust_decision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_asset_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_file_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_source_trust: Option<SourceTrustEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_detail: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_evidence_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_policy: Option<crate::trust_policy::TrustPolicySnapshot>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_file_disposition: Option<FileDispositionRecord>,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
    pub(crate) recorded_at_epoch_secs: u64,
}

pub fn default_history_path() -> PathBuf {
    ProjectDirs::from("com", "gh_mirror_gui", "gh_mirror_gui")
        .map(|dirs| dirs.data_local_dir().join("bench-history.jsonl"))
        .unwrap_or_else(|| PathBuf::from("target").join("bench-history.jsonl"))
}

pub(crate) fn load_bench_history(
    path: &Option<PathBuf>,
    url: &str,
    probe: &DownloadProbe,
) -> Vec<BenchHistoryEntry> {
    let Some(path) = path else {
        return Vec::new();
    };
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };

    text.lines()
        .filter_map(|line| serde_json::from_str::<BenchHistoryEntry>(line).ok())
        .filter(|entry| {
            entry.url == url
                && entry.total_bytes == probe.total
                && entry.etag == probe.etag
                && entry.last_modified == probe.last_modified
        })
        .collect()
}

pub(crate) fn history_avg_for_variant(history: &[BenchHistoryEntry], variant: &str) -> Option<f64> {
    let values = history
        .iter()
        .filter(|entry| entry.variant == variant && entry.avg_mib_s.is_finite())
        .map(|entry| entry.avg_mib_s)
        .collect::<Vec<_>>();
    if values.is_empty() {
        None
    } else {
        Some(values.iter().sum::<f64>() / values.len() as f64)
    }
}

pub(crate) fn unix_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn append_bench_history_entry(
    path: &Option<PathBuf>,
    entry: &BenchHistoryEntry,
) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    crate::evidence_ledger::append_jsonl(path, entry)
}

#[derive(serde::Serialize)]
struct VerificationEvidenceRecord {
    schema_version: u32,
    url: String,
    output: String,
    output_size: u64,
    variant: String,
    mode: String,
    total_bytes: u64,
    etag: Option<String>,
    last_modified: Option<String>,
    recorded_at_epoch_secs: u64,
    asset_name: String,
    status: String,
    trust_decision: String,
    file_sha256: String,
    expected_sha256: Option<String>,
    source: Option<String>,
    source_trust: Option<SourceTrustEvidence>,
    detail: String,
    policy: Option<crate::trust_policy::TrustPolicySnapshot>,
    file_disposition: Option<FileDispositionRecord>,
}

struct VerificationEvidenceInput<'a> {
    history_path: &'a Option<PathBuf>,
    url: &'a str,
    output: &'a Path,
    file_bytes: u64,
    probe: &'a DownloadProbe,
    strategy: &'a SelectedDownloadStrategy,
    recorded_at_epoch_secs: u64,
    report: &'a VerificationReport,
    policy: Option<&'a TrustPolicyConfig>,
    file_disposition: Option<&'a PlannedFileDisposition>,
}

#[derive(Clone, Copy)]
pub(crate) struct VerificationHistoryContext<'a> {
    pub(crate) report: &'a VerificationReport,
    pub(crate) policy: &'a TrustPolicyConfig,
    pub(crate) file_disposition: &'a PlannedFileDisposition,
}

fn sanitize_evidence_name(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    let trimmed = sanitized.trim_matches('_');
    if trimmed.is_empty() {
        "download".to_string()
    } else {
        trimmed.to_string()
    }
}

fn write_verification_evidence(
    input: VerificationEvidenceInput<'_>,
) -> Result<Option<PathBuf>, String> {
    let VerificationEvidenceInput {
        history_path,
        url,
        output,
        file_bytes,
        probe,
        strategy,
        recorded_at_epoch_secs,
        report,
        policy,
        file_disposition,
    } = input;
    let Some(history_path) = history_path else {
        return Ok(None);
    };
    let parent = history_path
        .parent()
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));
    let evidence_dir = parent.join("verification-evidence");
    fs::create_dir_all(&evidence_dir)
        .map_err(|e| format!("Create verification evidence dir error: {e}"))?;
    let evidence_nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let evidence_counter = VERIFICATION_EVIDENCE_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let evidence_path = evidence_dir.join(format!(
        "{}-{}-{}-{}-{}-{}.json",
        recorded_at_epoch_secs,
        evidence_nonce,
        std::process::id(),
        evidence_counter,
        report.status.as_str().to_ascii_lowercase(),
        sanitize_evidence_name(&report.asset_name)
    ));
    let record = VerificationEvidenceRecord {
        schema_version: 1,
        url: url.to_string(),
        output: output.to_string_lossy().to_string(),
        output_size: file_bytes,
        variant: strategy.variant.clone(),
        mode: if strategy.config.is_some() {
            "adaptive".to_string()
        } else {
            "single".to_string()
        },
        total_bytes: probe.total,
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
        recorded_at_epoch_secs,
        asset_name: report.asset_name.clone(),
        status: report.status.as_str().to_string(),
        trust_decision: report.effective_trust_decision().as_str().to_string(),
        file_sha256: report.file_sha256.clone(),
        expected_sha256: report.expected_sha256.clone(),
        source: report.source.clone(),
        source_trust: report.source_trust.clone(),
        detail: report.detail.clone(),
        policy: policy.map(TrustPolicyConfig::snapshot),
        file_disposition: file_disposition.map(PlannedFileDisposition::record),
    };
    crate::evidence_ledger::write_json_pretty(&evidence_path, &record)?;
    Ok(Some(evidence_path))
}

pub(crate) fn append_download_history(
    path: &Option<PathBuf>,
    url: &str,
    output: &PathBuf,
    probe: &DownloadProbe,
    strategy: &SelectedDownloadStrategy,
    download_elapsed: Duration,
    verification: Option<VerificationHistoryContext<'_>>,
) -> Result<Option<PathBuf>, String> {
    let file_bytes = fs::metadata(output)
        .map_err(|e| format!("History output stat error: {e}"))?
        .len();
    let download_ms = download_elapsed.as_millis();
    let avg_mib_s = if download_ms > 0 {
        (file_bytes as f64) / (download_ms as f64 / 1000.0) / (1024.0 * 1024.0)
    } else {
        0.0
    };
    let sha256 = sha256_file(output)?;
    let _history_matches = strategy.history_matches;
    let recorded_at_epoch_secs = unix_epoch_secs();
    let verification_evidence_path = if let Some(context) = verification {
        write_verification_evidence(VerificationEvidenceInput {
            history_path: path,
            url,
            output: output.as_path(),
            file_bytes,
            probe,
            strategy,
            recorded_at_epoch_secs,
            report: context.report,
            policy: Some(context.policy),
            file_disposition: Some(context.file_disposition),
        })?
    } else {
        None
    };
    let entry = BenchHistoryEntry {
        schema_version: 1,
        url: url.to_string(),
        variant: strategy.variant.clone(),
        mode: if strategy.config.is_some() {
            "adaptive".to_string()
        } else {
            "single".to_string()
        },
        total_bytes: probe.total,
        segment_size: strategy.config.map(|config| config.segment_size),
        concurrency: strategy.config.map(|config| config.concurrency),
        download_ms,
        avg_mib_s,
        sha256,
        verification_status: verification.map(|context| context.report.status.as_str().to_string()),
        verification_trust_decision: verification.map(|context| {
            context
                .report
                .effective_trust_decision()
                .as_str()
                .to_string()
        }),
        verification_asset_name: verification.map(|context| context.report.asset_name.clone()),
        verification_file_sha256: verification.map(|context| context.report.file_sha256.clone()),
        verification_source: verification.and_then(|context| context.report.source.clone()),
        verification_source_trust: verification
            .and_then(|context| context.report.source_trust.clone()),
        expected_sha256: verification.and_then(|context| context.report.expected_sha256.clone()),
        verification_detail: verification.map(|context| context.report.detail.clone()),
        verification_evidence_path: verification_evidence_path
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        verification_policy: verification.map(|context| context.policy.snapshot()),
        verification_file_disposition: verification
            .map(|context| context.file_disposition.record()),
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
        recorded_at_epoch_secs,
    };
    append_bench_history_entry(path, &entry)?;
    Ok(verification_evidence_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::SelectedDownloadStrategy;
    use crate::source_trust::{SourceAuthenticityStatus, SourceTrustDecision, SourceTrustEvidence};
    use crate::trust_policy::{plan_file_disposition, TrustPolicyConfig};
    use crate::verification::{VerificationReport, VerificationStatus};

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_history_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    #[test]
    fn append_download_history_records_reviewable_verification_evidence() {
        let output = unique_test_path("app.exe");
        let history = unique_test_path("bench-history.jsonl");
        fs::write(&output, b"history payload").unwrap();
        let probe = DownloadProbe {
            total: fs::metadata(&output).unwrap().len(),
            range_supported: false,
            etag: Some("\"etag\"".to_string()),
            last_modified: None,
        };
        let strategy = SelectedDownloadStrategy {
            variant: "single".to_string(),
            config: None,
            history_matches: 0,
        };
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: sha256_file(&output).unwrap(),
            expected_sha256: Some(sha256_file(&output).unwrap()),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: Some(SourceTrustEvidence {
                schema_version: 1,
                status: SourceAuthenticityStatus::TrustedSignature,
                decision: SourceTrustDecision::Trusted,
                required: true,
                source_asset_name: Some("SHA256SUMS.txt".to_string()),
                signature_asset_name: Some("SHA256SUMS.txt.sig".to_string()),
                trusted_publisher_key_fingerprint_sha256: Some("ABCDEF".to_string()),
                detail: "signature verified".to_string(),
            }),
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };
        let policy = TrustPolicyConfig::default();
        let disposition = plan_file_disposition(&output, &report.status, &policy);

        let evidence_path = append_download_history(
            &Some(history.clone()),
            "https://example.test/app.exe",
            &output,
            &probe,
            &strategy,
            Duration::from_millis(10),
            Some(VerificationHistoryContext {
                report: &report,
                policy: &policy,
                file_disposition: &disposition,
            }),
        )
        .unwrap();
        let evidence_path = evidence_path.unwrap();
        let line = fs::read_to_string(&history).unwrap();
        let entry = serde_json::from_str::<BenchHistoryEntry>(line.trim()).unwrap();

        assert_eq!(entry.verification_status.as_deref(), Some("VERIFIED"));
        assert_eq!(
            entry.verification_trust_decision.as_deref(),
            Some("TRUSTED")
        );
        assert_eq!(entry.verification_asset_name.as_deref(), Some("app.exe"));
        assert_eq!(
            entry.verification_file_sha256.as_deref(),
            Some(report.file_sha256.as_str())
        );
        assert_eq!(entry.verification_source.as_deref(), Some("SHA256SUMS.txt"));
        assert_eq!(
            entry
                .verification_source_trust
                .as_ref()
                .map(|trust| trust.status.as_str()),
            Some("TRUSTED_SIGNATURE")
        );
        assert_eq!(entry.expected_sha256, report.expected_sha256);
        assert_eq!(
            entry.verification_evidence_path.as_deref(),
            Some(evidence_path.to_string_lossy().as_ref())
        );
        assert_eq!(
            entry
                .verification_policy
                .as_ref()
                .map(|policy| policy.schema_version),
            Some(2)
        );
        assert_eq!(
            entry
                .verification_file_disposition
                .as_ref()
                .map(|disposition| disposition.action.as_str()),
            Some("KEEP")
        );

        let evidence = fs::read_to_string(&evidence_path).unwrap();
        let evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();
        assert_eq!(evidence["status"], "VERIFIED");
        assert_eq!(evidence["trust_decision"], "TRUSTED");
        assert_eq!(evidence["asset_name"], "app.exe");
        assert_eq!(evidence["file_sha256"], report.file_sha256);
        assert_eq!(evidence["source_trust"]["schema_version"], 1);
        assert_eq!(evidence["source_trust"]["status"], "TRUSTED_SIGNATURE");
        assert_eq!(evidence["source_trust"]["decision"], "TRUSTED");
        assert_eq!(evidence["policy"]["schema_version"], 2);
        assert_eq!(evidence["policy"]["source_trust"]["schema_version"], 1);
        assert_eq!(evidence["policy"]["mismatch_file_policy"], "QUARANTINE");
        assert_eq!(evidence["file_disposition"]["schema_version"], 1);
        assert_eq!(evidence["file_disposition"]["action"], "KEEP");
        let _ = fs::remove_file(output);
        let _ = fs::remove_file(history);
        let _ = fs::remove_file(evidence_path);
    }

    #[test]
    fn append_download_history_records_block_and_risk_evidence_decisions() {
        for (status, expected_decision) in [
            (VerificationStatus::Mismatch, "BLOCK"),
            (VerificationStatus::Unknown, "RISK"),
        ] {
            let output = unique_test_path(&format!("{}-app.exe", expected_decision));
            let history = unique_test_path(&format!("{}-bench-history.jsonl", expected_decision));
            fs::write(&output, format!("payload {expected_decision}")).unwrap();
            let probe = DownloadProbe {
                total: fs::metadata(&output).unwrap().len(),
                range_supported: false,
                etag: None,
                last_modified: None,
            };
            let strategy = SelectedDownloadStrategy {
                variant: "single".to_string(),
                config: None,
                history_matches: 0,
            };
            let report = VerificationReport {
                status,
                asset_name: "app.exe".to_string(),
                file_sha256: sha256_file(&output).unwrap(),
                expected_sha256: if expected_decision == "BLOCK" {
                    Some(
                        "B9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC"
                            .to_string(),
                    )
                } else {
                    None
                },
                source: if expected_decision == "BLOCK" {
                    Some("SHA256SUMS.txt".to_string())
                } else {
                    None
                },
                source_trust: None,
                detail: format!("trust decision {expected_decision}"),
            };
            let policy = TrustPolicyConfig::default();
            let disposition = plan_file_disposition(&output, &report.status, &policy);

            let evidence_path = append_download_history(
                &Some(history.clone()),
                "https://example.test/app.exe",
                &output,
                &probe,
                &strategy,
                Duration::from_millis(10),
                Some(VerificationHistoryContext {
                    report: &report,
                    policy: &policy,
                    file_disposition: &disposition,
                }),
            )
            .unwrap()
            .unwrap();
            let line = fs::read_to_string(&history).unwrap();
            let entry = serde_json::from_str::<BenchHistoryEntry>(line.trim()).unwrap();
            assert_eq!(
                entry.verification_trust_decision.as_deref(),
                Some(expected_decision)
            );
            let evidence = fs::read_to_string(&evidence_path).unwrap();
            let evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();
            assert_eq!(evidence["trust_decision"], expected_decision);
            assert_eq!(evidence["status"], report.status.as_str());
            assert_eq!(evidence["policy"]["schema_version"], 2);
            assert_eq!(evidence["file_disposition"]["schema_version"], 1);
            assert_eq!(
                evidence["file_disposition"]["action"],
                if expected_decision == "BLOCK" {
                    "QUARANTINE"
                } else {
                    "KEEP"
                }
            );

            let _ = fs::remove_file(output);
            let _ = fs::remove_file(history);
            let _ = fs::remove_file(evidence_path);
        }
    }

    #[test]
    fn history_evidence_records_source_trust_schema() {
        let output = unique_test_path("source-trust-app.exe");
        let history = unique_test_path("source-trust-bench-history.jsonl");
        fs::write(&output, b"history source trust payload").unwrap();
        let probe = DownloadProbe {
            total: fs::metadata(&output).unwrap().len(),
            range_supported: false,
            etag: None,
            last_modified: None,
        };
        let strategy = SelectedDownloadStrategy {
            variant: "single".to_string(),
            config: None,
            history_matches: 0,
        };
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: sha256_file(&output).unwrap(),
            expected_sha256: Some(sha256_file(&output).unwrap()),
            source: Some("release-provenance.json".to_string()),
            source_trust: Some(SourceTrustEvidence {
                schema_version: 1,
                status: SourceAuthenticityStatus::BadSignature,
                decision: SourceTrustDecision::Block,
                required: false,
                source_asset_name: Some("release-provenance.json".to_string()),
                signature_asset_name: Some("release-provenance.json.sig".to_string()),
                trusted_publisher_key_fingerprint_sha256: Some("ABCDEF".to_string()),
                detail: "bad signature".to_string(),
            }),
            detail: "SHA256 matched release-provenance.json".to_string(),
        };
        let policy = TrustPolicyConfig::default();
        let disposition = plan_file_disposition(&output, &VerificationStatus::Mismatch, &policy);

        let evidence_path = append_download_history(
            &Some(history.clone()),
            "https://example.test/app.exe",
            &output,
            &probe,
            &strategy,
            Duration::from_millis(10),
            Some(VerificationHistoryContext {
                report: &report,
                policy: &policy,
                file_disposition: &disposition,
            }),
        )
        .unwrap()
        .unwrap();
        let line = fs::read_to_string(&history).unwrap();
        let entry = serde_json::from_str::<BenchHistoryEntry>(line.trim()).unwrap();
        let evidence = fs::read_to_string(&evidence_path).unwrap();
        let evidence: serde_json::Value = serde_json::from_str(&evidence).unwrap();

        assert_eq!(entry.verification_status.as_deref(), Some("VERIFIED"));
        assert_eq!(entry.verification_trust_decision.as_deref(), Some("BLOCK"));
        assert_eq!(
            entry
                .verification_source_trust
                .as_ref()
                .map(|trust| trust.decision.as_str()),
            Some("BLOCK")
        );
        assert_eq!(evidence["status"], "VERIFIED");
        assert_eq!(evidence["trust_decision"], "BLOCK");
        assert_eq!(evidence["source_trust"]["status"], "BAD_SIGNATURE");
        assert_eq!(
            evidence["source_trust"]["source_asset_name"],
            "release-provenance.json"
        );
        assert_eq!(
            evidence["source_trust"]["signature_asset_name"],
            "release-provenance.json.sig"
        );

        let _ = fs::remove_file(output);
        let _ = fs::remove_file(history);
        let _ = fs::remove_file(evidence_path);
    }
}
