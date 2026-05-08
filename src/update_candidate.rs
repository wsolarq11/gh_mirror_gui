use crate::releases::{ReleaseAsset, ReleaseQuery, ReleaseQueryKind, ResolvedRelease};
use crate::source_adapter::{GitHubReleaseAdapter, SourceAdapter};
use crate::source_spec::SourceSpec;
use crate::source_trust::{
    import_publisher_key_pin_from_release_asset, not_applicable_source_trust, publisher_key_asset,
    SourceAuthenticityStatus, SourceTrustDecision, SourceTrustEvidence, SourceTrustPolicyConfig,
};
use crate::verification::{VerificationReport, VerificationStatus};
use crate::verifier_adapter::{GitHubReleaseVerifierAdapter, VerifierAdapter};
use reqwest::{blocking::Client, Url};
use std::cmp::Ordering;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const UPDATE_CANDIDATE_SCHEMA_VERSION: u32 = 1;
const UPDATE_CANDIDATE_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION: u32 = 1;
const UPDATE_CANDIDATE_STAGE_EVIDENCE_SCHEMA_VERSION: u32 = 1;
const SELF_UPDATE_OWNER: &str = "wsolarq11";
const SELF_UPDATE_REPO: &str = "gh_mirror_gui";
const SELF_UPDATE_ASSET_NAME: &str = "gh_mirror_gui.exe";
const MAX_SELF_UPDATE_CANDIDATE_BYTES: u64 = 256 * 1024 * 1024;
const UPDATE_CANDIDATE_USER_AGENT: &str = "gh_mirror_gui-update-candidate";
const RELEASE_VERIFY_ASSET_CACHE_DIR_ENV: &str = "GH_MIRROR_GUI_RELEASE_VERIFY_ASSET_CACHE_DIR";

pub(crate) struct UpdateCandidateCheckConfig<'a> {
    pub(crate) current_version: &'a str,
    pub(crate) source_trust_policy: &'a SourceTrustPolicyConfig,
    pub(crate) evidence_dir: &'a Path,
    pub(crate) api_base: Option<&'a str>,
}

pub(crate) struct UpdateCandidateStageConfig<'a> {
    pub(crate) current_version: &'a str,
    pub(crate) source_trust_policy: &'a SourceTrustPolicyConfig,
    pub(crate) evidence_dir: &'a Path,
    pub(crate) stage_root: &'a Path,
    pub(crate) api_base: Option<&'a str>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateCandidateStageStatus {
    Staged,
    NoUpdate,
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateCandidateStageReport {
    pub schema_version: u32,
    pub status: UpdateCandidateStageStatus,
    pub repo: String,
    pub release_tag: String,
    pub release_url: String,
    pub stage_dir: Option<String>,
    pub staged_asset_path: Option<String>,
    pub staged_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub publisher_key_fingerprint_sha256: Option<String>,
    pub reason: String,
    pub no_install: bool,
    pub check_report: UpdateCandidateCheckReport,
    pub evidence_path: Option<String>,
    pub evidence_write_error: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateCandidateStatus {
    Candidate,
    NoUpdate,
    Refused,
}

impl UpdateCandidateStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Candidate => "CANDIDATE",
            Self::NoUpdate => "NO_UPDATE",
            Self::Refused => "REFUSED",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateCandidateEvaluation {
    pub schema_version: u32,
    pub status: UpdateCandidateStatus,
    pub current_version: String,
    pub candidate_version: String,
    pub release_tag: String,
    pub asset_name: String,
    pub reason: String,
    pub verification_status: String,
    pub file_sha256: Option<String>,
    pub expected_sha256: Option<String>,
    pub verification_source: Option<String>,
    pub source_authenticity_status: Option<String>,
    pub source_trust_decision: Option<String>,
    pub publisher_key_fingerprint_sha256: Option<String>,
    pub evidence_path: Option<String>,
    pub no_mutation: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UpdateCandidateCheckReport {
    pub schema_version: u32,
    pub repo: String,
    pub release_tag: String,
    pub release_url: String,
    pub asset_name: String,
    pub release_publisher_key_fingerprint_sha256: Option<String>,
    pub evaluation: UpdateCandidateEvaluation,
    pub evidence_write_error: Option<String>,
}

impl UpdateCandidateCheckReport {
    pub fn status_display(&self) -> &'static str {
        match self.evaluation.status {
            UpdateCandidateStatus::Candidate => "candidate",
            UpdateCandidateStatus::NoUpdate => "no-update",
            UpdateCandidateStatus::Refused => "refused",
        }
    }

    pub fn refusal_reason(&self) -> Option<&str> {
        if self.evaluation.status == UpdateCandidateStatus::Refused {
            Some(self.evaluation.reason.as_str())
        } else {
            None
        }
    }

    pub fn publisher_key_fingerprint_sha256(&self) -> Option<&str> {
        self.evaluation
            .publisher_key_fingerprint_sha256
            .as_deref()
            .or(self.release_publisher_key_fingerprint_sha256.as_deref())
    }
}

pub(crate) struct UpdateCandidateInput<'a> {
    pub(crate) current_version: &'a str,
    pub(crate) release_tag: &'a str,
    pub(crate) asset_name: &'a str,
    pub(crate) verification_report: &'a VerificationReport,
    pub(crate) evidence_path: Option<&'a str>,
}

pub(crate) fn check_latest_update_candidate(
    client: &Client,
    config: UpdateCandidateCheckConfig<'_>,
) -> UpdateCandidateCheckReport {
    let repo = format!("{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}");
    let lookup_query = ReleaseQuery {
        owner: SELF_UPDATE_OWNER.to_string(),
        repo: SELF_UPDATE_REPO.to_string(),
        kind: ReleaseQueryKind::Latest,
    };

    let lookup_spec = SourceSpec::GitHubRelease {
        query: lookup_query,
    };
    let release =
        GitHubReleaseAdapter.resolve_release_assets(client, config.api_base, &lookup_spec);

    let release = match release {
        Ok(release) => release,
        Err(e) => {
            let evidence_path =
                allocate_update_candidate_evidence_path(config.evidence_dir, "lookup-failed");
            let evidence_path_str = evidence_path
                .as_deref()
                .map(|path| path.display().to_string());
            let evaluation = refused_update_candidate_evaluation(
                config.current_version,
                "unknown",
                SELF_UPDATE_ASSET_NAME,
                format!("latest release lookup failed: {e}"),
                None,
                evidence_path_str.as_deref(),
            );
            let report = UpdateCandidateCheckReport {
                schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
                repo,
                release_tag: "unknown".to_string(),
                release_url: "unknown".to_string(),
                asset_name: SELF_UPDATE_ASSET_NAME.to_string(),
                release_publisher_key_fingerprint_sha256: None,
                evaluation,
                evidence_write_error: None,
            };
            return finish_update_candidate_check_report(report, evidence_path);
        }
    };

    evaluate_resolved_latest_release(client, config, repo, release)
}

pub(crate) fn stage_latest_update_candidate(
    client: &Client,
    config: UpdateCandidateStageConfig<'_>,
) -> UpdateCandidateStageReport {
    let repo = format!("{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}");
    let check_report = check_latest_update_candidate(
        client,
        UpdateCandidateCheckConfig {
            current_version: config.current_version,
            source_trust_policy: config.source_trust_policy,
            evidence_dir: config.evidence_dir,
            api_base: config.api_base,
        },
    );

    let publisher_key_fingerprint = check_report
        .publisher_key_fingerprint_sha256()
        .map(|v| v.to_string());

    match check_report.evaluation.status {
        UpdateCandidateStatus::NoUpdate => UpdateCandidateStageReport {
            schema_version: UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION,
            status: UpdateCandidateStageStatus::NoUpdate,
            repo,
            release_tag: check_report.release_tag.clone(),
            release_url: check_report.release_url.clone(),
            stage_dir: None,
            staged_asset_path: None,
            staged_sha256: None,
            expected_sha256: None,
            publisher_key_fingerprint_sha256: publisher_key_fingerprint,
            reason: check_report.evaluation.reason.clone(),
            no_install: true,
            check_report,
            evidence_path: None,
            evidence_write_error: None,
        },
        UpdateCandidateStatus::Refused => UpdateCandidateStageReport {
            schema_version: UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION,
            status: UpdateCandidateStageStatus::Refused,
            repo,
            release_tag: check_report.release_tag.clone(),
            release_url: check_report.release_url.clone(),
            stage_dir: None,
            staged_asset_path: None,
            staged_sha256: None,
            expected_sha256: None,
            publisher_key_fingerprint_sha256: publisher_key_fingerprint,
            reason: check_report.evaluation.reason.clone(),
            no_install: true,
            check_report,
            evidence_path: None,
            evidence_write_error: None,
        },
        UpdateCandidateStatus::Candidate => {
            let stage_dir = config
                .stage_root
                .join(sanitize_evidence_component(&check_report.release_tag));
            let evidence_path = stage_dir.join("update-candidate-stage.json");

            let mut report = match stage_candidate_from_check_report(
                client,
                &check_report,
                &stage_dir,
                config.api_base,
            ) {
                Ok(staged) => staged,
                Err(e) => UpdateCandidateStageReport {
                    schema_version: UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION,
                    status: UpdateCandidateStageStatus::Refused,
                    repo,
                    release_tag: check_report.release_tag.clone(),
                    release_url: check_report.release_url.clone(),
                    stage_dir: Some(stage_dir.display().to_string()),
                    staged_asset_path: None,
                    staged_sha256: None,
                    expected_sha256: None,
                    publisher_key_fingerprint_sha256: publisher_key_fingerprint.clone(),
                    reason: e,
                    no_install: true,
                    check_report: check_report.clone(),
                    evidence_path: Some(evidence_path.display().to_string()),
                    evidence_write_error: None,
                },
            };

            report.evidence_path = Some(evidence_path.display().to_string());
            if let Err(e) = write_update_candidate_stage_evidence(&evidence_path, &report) {
                report.evidence_write_error = Some(e);
            }
            report
        }
    }
}

pub(crate) fn refused_update_candidate_check_report(
    current_version: &str,
    reason: impl Into<String>,
    evidence_dir: &Path,
) -> UpdateCandidateCheckReport {
    let evidence_path = allocate_update_candidate_evidence_path(evidence_dir, "runtime-refused");
    let evidence_path_str = evidence_path
        .as_deref()
        .map(|path| path.display().to_string());
    let evaluation = refused_update_candidate_evaluation(
        current_version,
        "unknown",
        SELF_UPDATE_ASSET_NAME,
        reason,
        None,
        evidence_path_str.as_deref(),
    );
    let report = UpdateCandidateCheckReport {
        schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
        repo: format!("{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}"),
        release_tag: "unknown".to_string(),
        release_url: "unknown".to_string(),
        asset_name: SELF_UPDATE_ASSET_NAME.to_string(),
        release_publisher_key_fingerprint_sha256: None,
        evaluation,
        evidence_write_error: None,
    };
    finish_update_candidate_check_report(report, evidence_path)
}

pub(crate) fn refused_update_candidate_stage_report(
    current_version: &str,
    reason: impl Into<String>,
    evidence_dir: &Path,
) -> UpdateCandidateStageReport {
    let reason = reason.into();
    let check_report =
        refused_update_candidate_check_report(current_version, reason.clone(), evidence_dir);
    let publisher_key_fingerprint = check_report
        .publisher_key_fingerprint_sha256()
        .map(|v| v.to_string());

    let mut report = UpdateCandidateStageReport {
        schema_version: UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION,
        status: UpdateCandidateStageStatus::Refused,
        repo: format!("{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}"),
        release_tag: check_report.release_tag.clone(),
        release_url: check_report.release_url.clone(),
        stage_dir: None,
        staged_asset_path: None,
        staged_sha256: None,
        expected_sha256: None,
        publisher_key_fingerprint_sha256: publisher_key_fingerprint,
        reason,
        no_install: true,
        check_report,
        evidence_path: None,
        evidence_write_error: None,
    };

    if let Some(evidence_path) =
        allocate_update_candidate_evidence_path(evidence_dir, "stage-runtime-refused")
    {
        report.evidence_path = Some(evidence_path.display().to_string());
        if let Err(e) = write_update_candidate_stage_evidence(&evidence_path, &report) {
            report.evidence_write_error = Some(e);
        }
    }
    report
}

pub(crate) fn run_update_candidate_latest_selftest(args: &[String]) -> Result<(), String> {
    let mut json_out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                i += 1;
                json_out = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --update-candidate-latest-selftest option: {other}"
                ));
            }
        }
        i += 1;
    }

    let evidence_dir = json_out
        .as_ref()
        .and_then(|path| path.parent())
        .map(|path| path.join("update-candidate-latest-evidence"))
        .unwrap_or_else(|| std::env::temp_dir().join("gh_mirror_gui-update-candidate-evidence"));
    let policy = SourceTrustPolicyConfig::default();
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| format!("Build update candidate selftest client: {e}"))?;
    let report = check_latest_update_candidate(
        &client,
        UpdateCandidateCheckConfig {
            current_version: env!("CARGO_PKG_VERSION"),
            source_trust_policy: &policy,
            evidence_dir: &evidence_dir,
            api_base: None,
        },
    );
    let evidence_ready = report
        .evaluation
        .evidence_path
        .as_deref()
        .is_some_and(|path| Path::new(path).is_file());
    let ok = report.release_tag != "unknown"
        && report.evaluation.no_mutation
        && report.evidence_write_error.is_none()
        && evidence_ready;
    let status = report.evaluation.status.as_str();
    let output = serde_json::json!({
        "schema_version": UPDATE_CANDIDATE_SCHEMA_VERSION,
        "ok": ok,
        "status": status,
        "allowed_statuses": ["CANDIDATE", "NO_UPDATE", "REFUSED"],
        "no_mutation": report.evaluation.no_mutation,
        "evidence_ready": evidence_ready,
        "report": report,
    });
    let pretty =
        serde_json::to_string_pretty(&output).map_err(|e| format!("Serialize JSON: {e}"))?;
    if let Some(json_path) = json_out {
        std::fs::write(&json_path, format!("{pretty}\n"))
            .map_err(|e| format!("Write update candidate latest selftest JSON: {e}"))?;
    }
    println!("{pretty}");
    if ok {
        Ok(())
    } else {
        Err("update candidate latest selftest did not produce a live no-mutation verdict with evidence".to_string())
    }
}

pub(crate) fn run_update_candidate_stage_selftest(args: &[String]) -> Result<(), String> {
    let mut json_out: Option<PathBuf> = None;
    let mut current_version_override: Option<String> = None;
    let mut trusted_publisher_key_file: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                i += 1;
                json_out = args.get(i).map(PathBuf::from);
            }
            "--current-version" => {
                i += 1;
                current_version_override = args.get(i).cloned();
            }
            "--trusted-publisher-key-file" => {
                i += 1;
                trusted_publisher_key_file = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --update-candidate-stage-selftest option: {other}"
                ));
            }
        }
        i += 1;
    }

    let base_dir = json_out
        .as_ref()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let evidence_dir = base_dir.join(format!(
        "update-candidate-stage-selftest-evidence-{}-{}",
        std::process::id(),
        nonce
    ));
    let stage_root = base_dir.join(format!(
        "update-candidate-stage-selftest-stage-{}-{}",
        std::process::id(),
        nonce
    ));

    let mut policy = SourceTrustPolicyConfig::default();
    if let Some(path) = trusted_publisher_key_file.as_ref() {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Read trusted publisher key file {}: {e}", path.display()))?;
        policy.trusted_publisher_key = crate::source_trust::normalize_public_key_pin(&text)?;
    }
    let current_version = current_version_override
        .as_deref()
        .unwrap_or(env!("CARGO_PKG_VERSION"));
    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("Build update candidate stage selftest client: {e}"))?;
    let report = stage_latest_update_candidate(
        &client,
        UpdateCandidateStageConfig {
            current_version,
            source_trust_policy: &policy,
            evidence_dir: &evidence_dir,
            stage_root: &stage_root,
            api_base: None,
        },
    );

    let check_evidence_ready = report
        .check_report
        .evaluation
        .evidence_path
        .as_deref()
        .is_some_and(|path| Path::new(path).is_file());

    let stage_evidence_ready = match report.status {
        UpdateCandidateStageStatus::Staged => report
            .evidence_path
            .as_deref()
            .is_some_and(|path| Path::new(path).is_file()),
        _ => true,
    };

    let stage_dir_ready = match report.status {
        UpdateCandidateStageStatus::Staged => report
            .stage_dir
            .as_deref()
            .is_some_and(|dir| Path::new(dir).is_dir()),
        _ => true,
    };

    let staged_asset_ready = match report.status {
        UpdateCandidateStageStatus::Staged => report
            .staged_asset_path
            .as_deref()
            .is_some_and(|path| Path::new(path).is_file()),
        _ => true,
    };

    let ok = report.release_tag != "unknown"
        && report.no_install
        && report.check_report.evaluation.no_mutation
        && report.check_report.evidence_write_error.is_none()
        && check_evidence_ready
        && report.evidence_write_error.is_none()
        && stage_evidence_ready
        && stage_dir_ready
        && staged_asset_ready;

    let output = serde_json::json!({
        "schema_version": UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION,
        "ok": ok,
        "status": report.status,
        "allowed_statuses": ["STAGED", "NO_UPDATE", "REFUSED"],
        "input": {
            "current_version": current_version,
            "trusted_publisher_key_file": trusted_publisher_key_file.as_ref().map(|path| path.display().to_string()),
        },
        "no_mutation": report.check_report.evaluation.no_mutation,
        "no_install": report.no_install,
        "check_evidence_ready": check_evidence_ready,
        "stage_evidence_ready": stage_evidence_ready,
        "report": report,
    });
    let pretty =
        serde_json::to_string_pretty(&output).map_err(|e| format!("Serialize JSON: {e}"))?;
    if let Some(json_path) = json_out {
        std::fs::write(&json_path, format!("{pretty}\n"))
            .map_err(|e| format!("Write update candidate stage selftest JSON: {e}"))?;
    }
    println!("{pretty}");
    if ok {
        Ok(())
    } else {
        Err(
            "update candidate stage selftest did not produce a live no-install verdict with evidence"
                .to_string(),
        )
    }
}

pub(crate) fn evaluate_update_candidate(
    input: UpdateCandidateInput<'_>,
) -> UpdateCandidateEvaluation {
    let candidate_version = version_from_release_tag(input.release_tag);
    let mut evaluation = UpdateCandidateEvaluation {
        schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
        status: UpdateCandidateStatus::Refused,
        current_version: input.current_version.to_string(),
        candidate_version: candidate_version.clone(),
        release_tag: input.release_tag.to_string(),
        asset_name: input.asset_name.to_string(),
        reason: String::new(),
        verification_status: input.verification_report.status.as_str().to_string(),
        file_sha256: Some(input.verification_report.file_sha256.clone()),
        expected_sha256: input.verification_report.expected_sha256.clone(),
        verification_source: input.verification_report.source.clone(),
        source_authenticity_status: input
            .verification_report
            .source_trust
            .as_ref()
            .map(|evidence| evidence.status_label().to_string()),
        source_trust_decision: input
            .verification_report
            .source_trust
            .as_ref()
            .map(|evidence| evidence.decision_label().to_string()),
        publisher_key_fingerprint_sha256: input
            .verification_report
            .source_trust
            .as_ref()
            .and_then(|evidence| evidence.trusted_publisher_key_fingerprint_sha256.clone()),
        evidence_path: input.evidence_path.map(ToString::to_string),
        no_mutation: true,
    };

    let Some(version_order) = compare_versions(input.current_version, &candidate_version) else {
        evaluation.reason =
            "current or candidate version is not a dotted numeric version".to_string();
        return evaluation;
    };
    if version_order != Ordering::Less {
        evaluation.status = UpdateCandidateStatus::NoUpdate;
        evaluation.reason = "candidate version is not newer than the running version".to_string();
        return evaluation;
    }

    if input.asset_name != SELF_UPDATE_ASSET_NAME {
        evaluation.reason = format!(
            "self-update candidate asset must be {SELF_UPDATE_ASSET_NAME}, got {}",
            input.asset_name
        );
        return evaluation;
    }
    if input.verification_report.asset_name != input.asset_name {
        evaluation.reason = format!(
            "verification report asset {} does not match candidate asset {}",
            input.verification_report.asset_name, input.asset_name
        );
        return evaluation;
    }
    if input.verification_report.status != VerificationStatus::Verified {
        evaluation.reason = format!(
            "candidate artifact hash status is {}",
            input.verification_report.status.as_str()
        );
        return evaluation;
    }
    if input.verification_report.effective_trust_decision()
        != crate::verification::VerificationTrustDecision::Trusted
    {
        evaluation.reason = "candidate verification report is not trusted by policy".to_string();
        return evaluation;
    }

    let Some(source_trust) = input.verification_report.source_trust.as_ref() else {
        evaluation.reason = "candidate is missing source authenticity evidence".to_string();
        return evaluation;
    };
    if source_trust.status != SourceAuthenticityStatus::TrustedSignature
        || source_trust.decision != SourceTrustDecision::Trusted
    {
        evaluation.reason = format!(
            "candidate source authenticity is {} / {}",
            source_trust.status_label(),
            source_trust.decision_label()
        );
        return evaluation;
    }
    if source_trust
        .trusted_publisher_key_fingerprint_sha256
        .as_deref()
        .is_none_or(str::is_empty)
    {
        evaluation.reason = "candidate has no pinned publisher key fingerprint".to_string();
        return evaluation;
    }
    if source_trust.signature_asset_name.is_none() || source_trust.source_asset_name.is_none() {
        evaluation.reason =
            "candidate source trust evidence is missing source/signature asset names".to_string();
        return evaluation;
    }

    evaluation.status = UpdateCandidateStatus::Candidate;
    evaluation.reason =
        "newer candidate passed hash, signed source, publisher key, and policy checks".to_string();
    evaluation
}

fn evaluate_resolved_latest_release(
    client: &Client,
    config: UpdateCandidateCheckConfig<'_>,
    repo: String,
    release: ResolvedRelease,
) -> UpdateCandidateCheckReport {
    let evidence_path =
        allocate_update_candidate_evidence_path(config.evidence_dir, &release.tag_name);
    let evidence_path_str = evidence_path
        .as_deref()
        .map(|path| path.display().to_string());
    let release_publisher_key_fingerprint = release_publisher_key_fingerprint(client, &release)
        .ok()
        .flatten();
    let required_policy = required_self_update_source_policy(config.source_trust_policy);

    let Some(asset_index) = self_update_asset_index(&release) else {
        let evaluation = refused_update_candidate_evaluation(
            config.current_version,
            &release.tag_name,
            SELF_UPDATE_ASSET_NAME,
            format!("latest release does not contain required asset {SELF_UPDATE_ASSET_NAME}"),
            release_publisher_key_fingerprint.clone(),
            evidence_path_str.as_deref(),
        );
        let report = UpdateCandidateCheckReport {
            schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
            repo,
            release_tag: release.tag_name,
            release_url: release.html_url,
            asset_name: SELF_UPDATE_ASSET_NAME.to_string(),
            release_publisher_key_fingerprint_sha256: release_publisher_key_fingerprint,
            evaluation,
            evidence_write_error: None,
        };
        return finish_update_candidate_check_report(report, evidence_path);
    };

    let asset = release.assets[asset_index].clone();
    let candidate_version = version_from_release_tag(&release.tag_name);
    let version_order = compare_versions(config.current_version, &candidate_version);
    if version_order != Some(Ordering::Less) {
        let verification_report = not_downloaded_verification_report(
            &asset.name,
            &required_policy,
            "latest release is not newer; candidate artifact was not downloaded",
        );
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: config.current_version,
            release_tag: &release.tag_name,
            asset_name: &asset.name,
            verification_report: &verification_report,
            evidence_path: evidence_path_str.as_deref(),
        });
        let report = UpdateCandidateCheckReport {
            schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
            repo,
            release_tag: release.tag_name,
            release_url: release.html_url,
            asset_name: asset.name,
            release_publisher_key_fingerprint_sha256: release_publisher_key_fingerprint,
            evaluation,
            evidence_write_error: None,
        };
        return finish_update_candidate_check_report(report, evidence_path);
    }

    if asset.size > MAX_SELF_UPDATE_CANDIDATE_BYTES {
        let evaluation = refused_update_candidate_evaluation(
            config.current_version,
            &release.tag_name,
            &asset.name,
            format!(
                "{} is too large for a no-mutation update candidate check: {} bytes",
                asset.name, asset.size
            ),
            release_publisher_key_fingerprint.clone(),
            evidence_path_str.as_deref(),
        );
        let report = UpdateCandidateCheckReport {
            schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
            repo,
            release_tag: release.tag_name,
            release_url: release.html_url,
            asset_name: asset.name,
            release_publisher_key_fingerprint_sha256: release_publisher_key_fingerprint,
            evaluation,
            evidence_write_error: None,
        };
        return finish_update_candidate_check_report(report, evidence_path);
    }
    if !required_policy.has_trusted_key() {
        let evaluation = refused_update_candidate_evaluation(
            config.current_version,
            &release.tag_name,
            &asset.name,
            "self-update candidate check requires a pinned Ed25519 publisher key before downloading a candidate",
            release_publisher_key_fingerprint.clone(),
            evidence_path_str.as_deref(),
        );
        let report = UpdateCandidateCheckReport {
            schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
            repo,
            release_tag: release.tag_name,
            release_url: release.html_url,
            asset_name: asset.name,
            release_publisher_key_fingerprint_sha256: release_publisher_key_fingerprint,
            evaluation,
            evidence_write_error: None,
        };
        return finish_update_candidate_check_report(report, evidence_path);
    }

    let temp_path = temp_update_candidate_path(&asset.name);
    let verification_report = download_and_verify_update_candidate(
        client,
        &release,
        asset_index,
        &asset,
        &temp_path,
        &required_policy,
    );
    let _ = fs::remove_file(&temp_path);

    let verification_report = match verification_report {
        Ok(report) => report,
        Err(e) => {
            let evaluation = refused_update_candidate_evaluation(
                config.current_version,
                &release.tag_name,
                &asset.name,
                e,
                release_publisher_key_fingerprint.clone(),
                evidence_path_str.as_deref(),
            );
            let report = UpdateCandidateCheckReport {
                schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
                repo,
                release_tag: release.tag_name,
                release_url: release.html_url,
                asset_name: asset.name,
                release_publisher_key_fingerprint_sha256: release_publisher_key_fingerprint,
                evaluation,
                evidence_write_error: None,
            };
            return finish_update_candidate_check_report(report, evidence_path);
        }
    };

    let evaluation = evaluate_update_candidate(UpdateCandidateInput {
        current_version: config.current_version,
        release_tag: &release.tag_name,
        asset_name: &asset.name,
        verification_report: &verification_report,
        evidence_path: evidence_path_str.as_deref(),
    });
    let report = UpdateCandidateCheckReport {
        schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
        repo,
        release_tag: release.tag_name,
        release_url: release.html_url,
        asset_name: asset.name,
        release_publisher_key_fingerprint_sha256: release_publisher_key_fingerprint,
        evaluation,
        evidence_write_error: None,
    };
    finish_update_candidate_check_report(report, evidence_path)
}

fn download_and_verify_update_candidate(
    client: &Client,
    release: &ResolvedRelease,
    asset_index: usize,
    asset: &ReleaseAsset,
    temp_path: &Path,
    required_policy: &SourceTrustPolicyConfig,
) -> Result<VerificationReport, String> {
    download_release_asset_to_path(client, asset, temp_path)?;
    let verification_plan =
        GitHubReleaseVerifierAdapter.verification_plan_for_selected_asset(release, asset_index);
    GitHubReleaseVerifierAdapter.verify_downloaded_file(
        client,
        temp_path,
        &asset.name,
        verification_plan.as_ref(),
        required_policy,
    )
}

fn download_release_asset_to_path(
    client: &Client,
    asset: &ReleaseAsset,
    output: &Path,
) -> Result<(), String> {
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("Create update candidate temp dir: {e}"))?;
    }
    if copy_release_verify_cached_asset(asset, output)? {
        return Ok(());
    }

    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let (url, accept_octet_stream) = match (token.is_some(), asset.api_url.as_deref()) {
        (true, Some(api_url)) => (api_url, true),
        _ => (asset.browser_download_url.as_str(), false),
    };

    crate::url_policy::parse_and_validate_https_github_official_url(
        url,
        "update candidate asset url",
    )?;

    let mut request = client
        .get(url)
        .header("User-Agent", UPDATE_CANDIDATE_USER_AGENT);
    if accept_octet_stream {
        request = request.header("Accept", "application/octet-stream");
    }
    if let Some(token) = token.as_deref() {
        if accept_octet_stream {
            request = request.bearer_auth(token);
        }
    }
    let mut response = request
        .send()
        .map_err(|e| format!("Download update candidate {} failed: {e}", asset.name))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "Download update candidate {} failed: HTTP {}",
            asset.name,
            status.as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|len| len > MAX_SELF_UPDATE_CANDIDATE_BYTES)
    {
        return Err(format!(
            "{} response is too large for a no-mutation update candidate check",
            asset.name
        ));
    }

    let mut file =
        fs::File::create(output).map_err(|e| format!("Create update candidate temp file: {e}"))?;
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = response
            .read(&mut buffer)
            .map_err(|e| format!("Read update candidate body failed: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > MAX_SELF_UPDATE_CANDIDATE_BYTES {
            let _ = fs::remove_file(output);
            return Err(format!(
                "{} response exceeded update candidate size limit",
                asset.name
            ));
        }
        file.write_all(&buffer[..n])
            .map_err(|e| format!("Write update candidate temp file failed: {e}"))?;
    }
    store_release_verify_cached_asset(asset, output)?;
    Ok(())
}

fn copy_release_verify_cached_asset(asset: &ReleaseAsset, output: &Path) -> Result<bool, String> {
    let Some(cache_path) = release_verify_asset_cache_path(asset) else {
        return Ok(false);
    };
    if !cache_path.is_file() {
        return Ok(false);
    }

    let metadata = fs::metadata(&cache_path)
        .map_err(|e| format!("Read release-verify asset cache metadata failed: {e}"))?;
    if metadata.len() != asset.size {
        let _ = fs::remove_file(&cache_path);
        return Ok(false);
    }
    fs::copy(&cache_path, output).map_err(|e| {
        format!(
            "Copy release-verify asset cache {} to {} failed: {e}",
            cache_path.display(),
            output.display()
        )
    })?;
    Ok(true)
}

fn store_release_verify_cached_asset(asset: &ReleaseAsset, source: &Path) -> Result<(), String> {
    let Some(cache_path) = release_verify_asset_cache_path(asset) else {
        return Ok(());
    };
    let metadata = fs::metadata(source)
        .map_err(|e| format!("Read downloaded update candidate metadata failed: {e}"))?;
    if metadata.len() != asset.size {
        return Ok(());
    }

    if let Some(parent) = cache_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Create release-verify asset cache dir failed: {e}"))?;
    }
    fs::copy(source, &cache_path).map_err(|e| {
        format!(
            "Store release-verify asset cache {} failed: {e}",
            cache_path.display()
        )
    })?;
    Ok(())
}

fn release_verify_asset_cache_path(asset: &ReleaseAsset) -> Option<PathBuf> {
    let root = std::env::var_os(RELEASE_VERIFY_ASSET_CACHE_DIR_ENV)?;
    let name = release_verify_asset_cache_name(asset)?;
    Some(PathBuf::from(root).join(name))
}

fn release_verify_asset_cache_name(asset: &ReleaseAsset) -> Option<String> {
    let url = Url::parse(&asset.browser_download_url).ok()?;
    if url.scheme() != "https" || url.host_str() != Some("github.com") {
        return None;
    }
    let segments: Vec<_> = url.path_segments()?.collect();
    if segments.len() < 6
        || segments.get(2) != Some(&"releases")
        || segments.get(3) != Some(&"download")
    {
        return None;
    }

    let owner = segments[0];
    let repo = segments[1];
    let tag = segments[4];
    Some(sanitize_release_verify_cache_name(&format!(
        "{owner}-{repo}-{tag}-size-{}-{}",
        asset.size, asset.name
    )))
}

fn sanitize_release_verify_cache_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

fn release_publisher_key_fingerprint(
    client: &Client,
    release: &ResolvedRelease,
) -> Result<Option<String>, String> {
    let Some(asset) = publisher_key_asset(&release.assets) else {
        return Ok(None);
    };
    import_publisher_key_pin_from_release_asset(client, asset)
        .map(|pin| Some(pin.fingerprint_sha256))
}

fn self_update_asset_index(release: &ResolvedRelease) -> Option<usize> {
    release
        .assets
        .iter()
        .position(|asset| asset.name == SELF_UPDATE_ASSET_NAME)
}

fn required_self_update_source_policy(policy: &SourceTrustPolicyConfig) -> SourceTrustPolicyConfig {
    SourceTrustPolicyConfig {
        require_trusted_source: true,
        trusted_publisher_key: policy.trusted_publisher_key.clone(),
    }
}

fn not_downloaded_verification_report(
    asset_name: &str,
    policy: &SourceTrustPolicyConfig,
    detail: &str,
) -> VerificationReport {
    VerificationReport {
        status: VerificationStatus::Unknown,
        asset_name: asset_name.to_string(),
        file_sha256: "not downloaded".to_string(),
        expected_sha256: None,
        source: None,
        source_trust: Some(not_applicable_source_trust(policy, detail)),
        detail: detail.to_string(),
    }
}

fn refused_update_candidate_evaluation(
    current_version: &str,
    release_tag: &str,
    asset_name: &str,
    reason: impl Into<String>,
    publisher_key_fingerprint_sha256: Option<String>,
    evidence_path: Option<&str>,
) -> UpdateCandidateEvaluation {
    UpdateCandidateEvaluation {
        schema_version: UPDATE_CANDIDATE_SCHEMA_VERSION,
        status: UpdateCandidateStatus::Refused,
        current_version: current_version.to_string(),
        candidate_version: version_from_release_tag(release_tag),
        release_tag: release_tag.to_string(),
        asset_name: asset_name.to_string(),
        reason: reason.into(),
        verification_status: "NOT_EVALUATED".to_string(),
        file_sha256: None,
        expected_sha256: None,
        verification_source: None,
        source_authenticity_status: None,
        source_trust_decision: None,
        publisher_key_fingerprint_sha256,
        evidence_path: evidence_path.map(ToString::to_string),
        no_mutation: true,
    }
}

fn finish_update_candidate_check_report(
    mut report: UpdateCandidateCheckReport,
    evidence_path: Option<PathBuf>,
) -> UpdateCandidateCheckReport {
    if let Some(path) = evidence_path {
        if let Err(e) = write_update_candidate_evidence(&path, &report) {
            report.evidence_write_error = Some(e);
        }
    }
    report
}

fn allocate_update_candidate_evidence_path(
    evidence_dir: &Path,
    release_tag: &str,
) -> Option<PathBuf> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Some(evidence_dir.join(format!(
        "{}-{}-{}.json",
        now.as_secs(),
        now.as_nanos(),
        sanitize_evidence_component(release_tag)
    )))
}

fn temp_update_candidate_path(asset_name: &str) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    std::env::temp_dir()
        .join("gh_mirror_gui-update-candidate")
        .join(format!(
            "{}-{}-{}",
            std::process::id(),
            now.as_nanos(),
            sanitize_evidence_component(asset_name)
        ))
}

fn write_update_candidate_evidence(
    path: &Path,
    report: &UpdateCandidateCheckReport,
) -> Result<(), String> {
    let record = serde_json::json!({
        "schema_version": UPDATE_CANDIDATE_EVIDENCE_SCHEMA_VERSION,
        "no_mutation": true,
        "repo": &report.repo,
        "release_tag": &report.release_tag,
        "release_url": &report.release_url,
        "asset_name": &report.asset_name,
        "release_publisher_key_fingerprint_sha256": &report.release_publisher_key_fingerprint_sha256,
        "evaluation": &report.evaluation,
    });
    crate::evidence_ledger::write_json_pretty(path, &record)
}

fn stage_candidate_from_check_report(
    client: &Client,
    check_report: &UpdateCandidateCheckReport,
    stage_dir: &Path,
    api_base: Option<&str>,
) -> Result<UpdateCandidateStageReport, String> {
    if check_report.evaluation.status != UpdateCandidateStatus::Candidate {
        return Err("stage requires a CANDIDATE check report".to_string());
    }
    if check_report.evaluation.verification_status != "VERIFIED" {
        return Err(format!(
            "stage requires a VERIFIED candidate, got {}",
            check_report.evaluation.verification_status
        ));
    }

    fs::create_dir_all(stage_dir).map_err(|e| format!("Create stage dir: {e}"))?;

    let query = ReleaseQuery {
        owner: SELF_UPDATE_OWNER.to_string(),
        repo: SELF_UPDATE_REPO.to_string(),
        kind: ReleaseQueryKind::Tag(check_report.release_tag.clone()),
    };
    let spec = SourceSpec::GitHubRelease { query };
    let release = GitHubReleaseAdapter
        .resolve_release_assets(client, api_base, &spec)
        .map_err(|e| format!("Stage candidate release lookup failed: {e}"))?;

    let Some(asset_index) = self_update_asset_index(&release) else {
        return Err(format!(
            "stage candidate release {} missing required asset {}",
            release.tag_name, SELF_UPDATE_ASSET_NAME
        ));
    };
    let asset = release.assets[asset_index].clone();

    let tmp_path = stage_dir.join(format!("{}.staging.tmp", asset.name));
    download_release_asset_to_path(client, &asset, &tmp_path)?;
    let sha256 = crate::download::sha256_file(&tmp_path)?;
    if let Some(expected) = check_report.evaluation.expected_sha256.as_deref() {
        if sha256 != expected.to_ascii_uppercase() {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!(
                "staged candidate sha256 {sha256} did not match expected {expected}"
            ));
        }
    }

    let staged_path = stage_dir.join(&asset.name);
    fs::rename(&tmp_path, &staged_path)
        .or_else(|_| {
            fs::copy(&tmp_path, &staged_path)
                .map(|_| ())
                .and_then(|_| fs::remove_file(&tmp_path))
        })
        .map_err(|e| format!("Finalize staged candidate file: {e}"))?;

    for name in [
        "publisher-key.ed25519.pub",
        "SHA256SUMS.txt",
        "SHA256SUMS.txt.sig",
        "release-provenance.json",
        "release-provenance.json.sig",
    ] {
        if let Some(asset) = release.assets.iter().find(|asset| asset.name == name) {
            let out = stage_dir.join(name);
            download_release_asset_to_path(client, asset, &out)?;
        }
    }

    Ok(UpdateCandidateStageReport {
        schema_version: UPDATE_CANDIDATE_STAGE_SCHEMA_VERSION,
        status: UpdateCandidateStageStatus::Staged,
        repo: format!("{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}"),
        release_tag: check_report.release_tag.clone(),
        release_url: check_report.release_url.clone(),
        stage_dir: Some(stage_dir.display().to_string()),
        staged_asset_path: Some(staged_path.display().to_string()),
        staged_sha256: Some(sha256),
        expected_sha256: check_report.evaluation.expected_sha256.clone(),
        publisher_key_fingerprint_sha256: check_report
            .publisher_key_fingerprint_sha256()
            .map(|v| v.to_string()),
        reason: "staged verified candidate (no install)".to_string(),
        no_install: true,
        check_report: check_report.clone(),
        evidence_path: None,
        evidence_write_error: None,
    })
}

fn write_update_candidate_stage_evidence(
    path: &Path,
    report: &UpdateCandidateStageReport,
) -> Result<(), String> {
    let record = serde_json::json!({
        "schema_version": UPDATE_CANDIDATE_STAGE_EVIDENCE_SCHEMA_VERSION,
        "no_install": true,
        "repo": &report.repo,
        "release_tag": &report.release_tag,
        "release_url": &report.release_url,
        "status": report.status,
        "reason": &report.reason,
        "publisher_key_fingerprint_sha256": &report.publisher_key_fingerprint_sha256,
        "stage_dir": &report.stage_dir,
        "staged_asset_path": &report.staged_asset_path,
        "staged_sha256": &report.staged_sha256,
        "expected_sha256": &report.expected_sha256,
        "check_report": &report.check_report,
    });
    crate::evidence_ledger::write_json_pretty(path, &record)
}

fn sanitize_evidence_component(value: &str) -> String {
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
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

pub(crate) fn run_update_candidate_contract_selftest(args: &[String]) -> Result<(), String> {
    let mut json_out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {
                i += 1;
                json_out = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --update-candidate-contract-selftest option: {other}"
                ));
            }
        }
        i += 1;
    }

    let cases = contract_selftest_cases();
    assert_case_status(
        &cases,
        "newer_trusted_candidate",
        UpdateCandidateStatus::Candidate,
    )?;
    assert_case_status(
        &cases,
        "same_version_no_update",
        UpdateCandidateStatus::NoUpdate,
    )?;
    assert_case_status(
        &cases,
        "bad_signature_refused",
        UpdateCandidateStatus::Refused,
    )?;
    assert_case_status(
        &cases,
        "missing_key_refused",
        UpdateCandidateStatus::Refused,
    )?;
    assert_case_status(
        &cases,
        "unsigned_required_refused",
        UpdateCandidateStatus::Refused,
    )?;
    let case_report = cases
        .iter()
        .map(|(name, evaluation)| {
            serde_json::json!({
                "name": name,
                "status": evaluation.status.as_str(),
                "evaluation": evaluation,
            })
        })
        .collect::<Vec<_>>();

    let report = serde_json::json!({
        "schema_version": UPDATE_CANDIDATE_SCHEMA_VERSION,
        "ok": true,
        "contract": "no-mutation update candidate",
        "self_update_asset_name": SELF_UPDATE_ASSET_NAME,
        "no_mutation": true,
        "cases": case_report,
    });
    let pretty =
        serde_json::to_string_pretty(&report).map_err(|e| format!("Serialize JSON: {e}"))?;
    if let Some(json_path) = json_out {
        std::fs::write(&json_path, format!("{pretty}\n"))
            .map_err(|e| format!("Write update candidate selftest JSON: {e}"))?;
    }
    println!("{pretty}");
    Ok(())
}

fn assert_case_status(
    cases: &[(String, UpdateCandidateEvaluation)],
    name: &str,
    status: UpdateCandidateStatus,
) -> Result<(), String> {
    let Some((_, evaluation)) = cases.iter().find(|(case_name, _)| case_name == name) else {
        return Err(format!("missing update candidate selftest case: {name}"));
    };
    if evaluation.status != status {
        return Err(format!(
            "update candidate selftest case {name} was {}, expected {}",
            evaluation.status.as_str(),
            status.as_str()
        ));
    }
    Ok(())
}

fn contract_selftest_cases() -> Vec<(String, UpdateCandidateEvaluation)> {
    vec![
        (
            "newer_trusted_candidate".to_string(),
            evaluate_update_candidate(UpdateCandidateInput {
                current_version: "0.1.3",
                release_tag: "v0.1.4",
                asset_name: SELF_UPDATE_ASSET_NAME,
                verification_report: &trusted_report(),
                evidence_path: Some("target/update-candidate/evidence.json"),
            }),
        ),
        (
            "same_version_no_update".to_string(),
            evaluate_update_candidate(UpdateCandidateInput {
                current_version: "0.1.3",
                release_tag: "v0.1.3",
                asset_name: SELF_UPDATE_ASSET_NAME,
                verification_report: &trusted_report(),
                evidence_path: Some("target/update-candidate/evidence.json"),
            }),
        ),
        (
            "bad_signature_refused".to_string(),
            evaluate_update_candidate(UpdateCandidateInput {
                current_version: "0.1.3",
                release_tag: "v0.1.4",
                asset_name: SELF_UPDATE_ASSET_NAME,
                verification_report: &untrusted_source_report(
                    SourceAuthenticityStatus::BadSignature,
                    SourceTrustDecision::Block,
                    Some("ABCDEF"),
                ),
                evidence_path: Some("target/update-candidate/bad-signature.json"),
            }),
        ),
        (
            "missing_key_refused".to_string(),
            evaluate_update_candidate(UpdateCandidateInput {
                current_version: "0.1.3",
                release_tag: "v0.1.4",
                asset_name: SELF_UPDATE_ASSET_NAME,
                verification_report: &untrusted_source_report(
                    SourceAuthenticityStatus::NoTrustedKey,
                    SourceTrustDecision::Block,
                    None,
                ),
                evidence_path: Some("target/update-candidate/missing-key.json"),
            }),
        ),
        (
            "unsigned_required_refused".to_string(),
            evaluate_update_candidate(UpdateCandidateInput {
                current_version: "0.1.3",
                release_tag: "v0.1.4",
                asset_name: SELF_UPDATE_ASSET_NAME,
                verification_report: &untrusted_source_report(
                    SourceAuthenticityStatus::MissingSignature,
                    SourceTrustDecision::Block,
                    Some("ABCDEF"),
                ),
                evidence_path: Some("target/update-candidate/missing-signature.json"),
            }),
        ),
    ]
}

fn trusted_report() -> VerificationReport {
    VerificationReport {
        status: VerificationStatus::Verified,
        asset_name: SELF_UPDATE_ASSET_NAME.to_string(),
        file_sha256: "11".repeat(32),
        expected_sha256: Some("11".repeat(32)),
        source: Some("release-provenance.json".to_string()),
        source_trust: Some(source_trust(
            SourceAuthenticityStatus::TrustedSignature,
            SourceTrustDecision::Trusted,
            Some("ABCDEF"),
        )),
        detail: "SHA256 matched release-provenance.json".to_string(),
    }
}

fn untrusted_source_report(
    status: SourceAuthenticityStatus,
    decision: SourceTrustDecision,
    fingerprint: Option<&str>,
) -> VerificationReport {
    VerificationReport {
        status: VerificationStatus::Verified,
        asset_name: SELF_UPDATE_ASSET_NAME.to_string(),
        file_sha256: "11".repeat(32),
        expected_sha256: Some("11".repeat(32)),
        source: Some("release-provenance.json".to_string()),
        source_trust: Some(source_trust(status, decision, fingerprint)),
        detail: "SHA256 matched release-provenance.json".to_string(),
    }
}

fn source_trust(
    status: SourceAuthenticityStatus,
    decision: SourceTrustDecision,
    fingerprint: Option<&str>,
) -> SourceTrustEvidence {
    SourceTrustEvidence {
        schema_version: 1,
        status,
        decision,
        required: true,
        source_asset_name: Some("release-provenance.json".to_string()),
        signature_asset_name: Some("release-provenance.json.sig".to_string()),
        trusted_publisher_key_fingerprint_sha256: fingerprint.map(ToString::to_string),
        detail: format!("source authenticity {}", status.as_str()),
    }
}

fn version_from_release_tag(tag: &str) -> String {
    tag.trim().trim_start_matches('v').to_string()
}

fn compare_versions(current: &str, candidate: &str) -> Option<Ordering> {
    let current = parse_dotted_version(current)?;
    let candidate = parse_dotted_version(candidate)?;
    let max_len = current.len().max(candidate.len());
    for idx in 0..max_len {
        let left = *current.get(idx).unwrap_or(&0);
        let right = *candidate.get(idx).unwrap_or(&0);
        match left.cmp(&right) {
            Ordering::Equal => {}
            order => return Some(order),
        }
    }
    Some(Ordering::Equal)
}

fn parse_dotted_version(value: &str) -> Option<Vec<u64>> {
    let core = value
        .trim()
        .trim_start_matches('v')
        .split(['-', '+'])
        .next()?;
    if core.is_empty() {
        return None;
    }
    core.split('.')
        .map(|part| {
            if part.is_empty() || !part.chars().all(|c| c.is_ascii_digit()) {
                None
            } else {
                part.parse::<u64>().ok()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_trust::{
        public_key_from_private_seed, sign_ed25519_detached, trusted_key_fingerprint,
    };
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    struct RouteResponse {
        status: &'static str,
        content_type: &'static str,
        body: Vec<u8>,
    }

    fn serve_routes<F>(
        expected_requests: usize,
        make_routes: F,
    ) -> (String, thread::JoinHandle<Vec<String>>)
    where
        F: FnOnce(&str) -> HashMap<String, RouteResponse>,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let routes = make_routes(&base);
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap();
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/")
                    .to_string();
                requests.push(request);
                let fallback = RouteResponse {
                    status: "404 Not Found",
                    content_type: "text/plain",
                    body: b"not found".to_vec(),
                };
                let response = routes.get(&path).unwrap_or(&fallback);
                let header = format!(
                    "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.status,
                    response.content_type,
                    response.body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&response.body).unwrap();
            }
            requests
        });

        (base, handle)
    }

    fn unique_evidence_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_update_candidate_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    fn test_client() -> Client {
        Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        let digest = Sha256::digest(bytes);
        digest.iter().map(|byte| format!("{byte:02X}")).collect()
    }

    #[test]
    fn release_verify_asset_cache_name_is_scoped_to_github_release_assets() {
        let asset = ReleaseAsset {
            name: "gh_mirror_gui.exe".to_string(),
            size: 8056832,
            browser_download_url:
                "https://github.com/wsolarq11/gh_mirror_gui/releases/download/v0.1.6/gh_mirror_gui.exe"
                    .to_string(),
            content_type: Some("application/x-msdownload".to_string()),
            api_url: None,
        };

        assert_eq!(
            release_verify_asset_cache_name(&asset).as_deref(),
            Some("wsolarq11-gh_mirror_gui-v0.1.6-size-8056832-gh_mirror_gui.exe")
        );

        let loopback_asset = ReleaseAsset {
            browser_download_url: "http://127.0.0.1:9000/gh_mirror_gui.exe".to_string(),
            ..asset
        };
        assert!(release_verify_asset_cache_name(&loopback_asset).is_none());
    }

    fn signed_release_routes(
        base: &str,
        tag: &str,
        exe_body: &[u8],
        public_key: &str,
    ) -> HashMap<String, RouteResponse> {
        let exe_sha256 = sha256_hex(exe_body);
        let checksums = format!("{exe_sha256}  {SELF_UPDATE_ASSET_NAME}\n");
        let signature = sign_ed25519_detached(checksums.as_bytes(), TEST_PRIVATE_KEY).unwrap();
        let api_body = serde_json::json!({
            "tag_name": tag,
            "name": tag,
            "html_url": format!("https://github.com/{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}/releases/tag/{tag}"),
            "assets": [
                {
                    "name": SELF_UPDATE_ASSET_NAME,
                    "size": exe_body.len(),
                    "browser_download_url": format!("{base}/{SELF_UPDATE_ASSET_NAME}"),
                    "content_type": "application/x-msdownload"
                },
                {
                    "name": "publisher-key.ed25519.pub",
                    "size": public_key.len(),
                    "browser_download_url": format!("{base}/publisher-key.ed25519.pub"),
                    "content_type": "application/octet-stream"
                },
                {
                    "name": "SHA256SUMS.txt",
                    "size": checksums.len(),
                    "browser_download_url": format!("{base}/SHA256SUMS.txt"),
                    "content_type": "text/plain"
                },
                {
                    "name": "SHA256SUMS.txt.sig",
                    "size": signature.len(),
                    "browser_download_url": format!("{base}/SHA256SUMS.txt.sig"),
                    "content_type": "application/octet-stream"
                }
            ]
        });

        HashMap::from([
            (
                format!("/repos/{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}/releases/latest"),
                RouteResponse {
                    status: "200 OK",
                    content_type: "application/json",
                    body: serde_json::to_vec(&api_body).unwrap(),
                },
            ),
            (
                format!("/repos/{SELF_UPDATE_OWNER}/{SELF_UPDATE_REPO}/releases/tags/{tag}"),
                RouteResponse {
                    status: "200 OK",
                    content_type: "application/json",
                    body: serde_json::to_vec(&api_body).unwrap(),
                },
            ),
            (
                format!("/{SELF_UPDATE_ASSET_NAME}"),
                RouteResponse {
                    status: "200 OK",
                    content_type: "application/x-msdownload",
                    body: exe_body.to_vec(),
                },
            ),
            (
                "/publisher-key.ed25519.pub".to_string(),
                RouteResponse {
                    status: "200 OK",
                    content_type: "application/octet-stream",
                    body: format!("{public_key}\n").into_bytes(),
                },
            ),
            (
                "/SHA256SUMS.txt".to_string(),
                RouteResponse {
                    status: "200 OK",
                    content_type: "text/plain",
                    body: checksums.into_bytes(),
                },
            ),
            (
                "/SHA256SUMS.txt.sig".to_string(),
                RouteResponse {
                    status: "200 OK",
                    content_type: "application/octet-stream",
                    body: signature.into_bytes(),
                },
            ),
        ])
    }

    const TEST_PRIVATE_KEY: &str =
        "1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn latest_update_check_reports_no_update_without_downloading_candidate() {
        let public_key = public_key_from_private_seed(TEST_PRIVATE_KEY).unwrap();
        let expected_fingerprint = trusted_key_fingerprint(&public_key).unwrap();
        let exe_body = b"current public release binary";
        let (api_base, server) = serve_routes(2, |base| {
            signed_release_routes(base, "v0.1.3", exe_body, &public_key)
        });
        let evidence_dir = unique_evidence_dir("no_update");
        let policy = SourceTrustPolicyConfig::default();

        let report = check_latest_update_candidate(
            &test_client(),
            UpdateCandidateCheckConfig {
                current_version: "0.1.3",
                source_trust_policy: &policy,
                evidence_dir: &evidence_dir,
                api_base: Some(&api_base),
            },
        );
        let requests = server.join().unwrap();

        assert_eq!(report.evaluation.status, UpdateCandidateStatus::NoUpdate);
        assert_eq!(report.status_display(), "no-update");
        assert!(report.evaluation.no_mutation);
        assert_eq!(
            report.publisher_key_fingerprint_sha256(),
            Some(expected_fingerprint.as_str())
        );
        assert!(Path::new(report.evaluation.evidence_path.as_ref().unwrap()).is_file());
        assert!(!requests
            .iter()
            .any(|request| request.starts_with("GET /gh_mirror_gui.exe ")));
        let _ = std::fs::remove_dir_all(evidence_dir);
    }

    #[test]
    fn latest_update_check_accepts_newer_signed_candidate_with_pinned_key() {
        let public_key = public_key_from_private_seed(TEST_PRIVATE_KEY).unwrap();
        let expected_fingerprint = trusted_key_fingerprint(&public_key).unwrap();
        let exe_body = b"new trusted candidate binary";
        let (api_base, server) = serve_routes(5, |base| {
            signed_release_routes(base, "v0.1.4", exe_body, &public_key)
        });
        let evidence_dir = unique_evidence_dir("candidate");
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: false,
            trusted_publisher_key: public_key,
        };

        let report = check_latest_update_candidate(
            &test_client(),
            UpdateCandidateCheckConfig {
                current_version: "0.1.3",
                source_trust_policy: &policy,
                evidence_dir: &evidence_dir,
                api_base: Some(&api_base),
            },
        );
        let requests = server.join().unwrap();

        assert_eq!(report.evaluation.status, UpdateCandidateStatus::Candidate);
        assert!(report.evaluation.no_mutation);
        assert_eq!(
            report
                .evaluation
                .publisher_key_fingerprint_sha256
                .as_deref(),
            Some(expected_fingerprint.as_str())
        );
        assert_eq!(report.evaluation.verification_status, "VERIFIED");
        assert_eq!(
            report.evaluation.source_authenticity_status.as_deref(),
            Some("TRUSTED_SIGNATURE")
        );
        assert!(Path::new(report.evaluation.evidence_path.as_ref().unwrap()).is_file());
        assert!(requests
            .iter()
            .any(|request| request.starts_with("GET /gh_mirror_gui.exe ")));
        let _ = std::fs::remove_dir_all(evidence_dir);
    }

    #[test]
    fn latest_update_stage_stages_newer_signed_candidate_to_local_directory() {
        let public_key = public_key_from_private_seed(TEST_PRIVATE_KEY).unwrap();
        let expected_fingerprint = trusted_key_fingerprint(&public_key).unwrap();
        let exe_body = b"new trusted candidate binary for staging";
        let (api_base, server) = serve_routes(10, |base| {
            signed_release_routes(base, "v0.1.4", exe_body, &public_key)
        });
        let evidence_dir = unique_evidence_dir("stage_evidence");
        let stage_root = unique_evidence_dir("stage_root");
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: false,
            trusted_publisher_key: public_key,
        };

        let report = stage_latest_update_candidate(
            &test_client(),
            UpdateCandidateStageConfig {
                current_version: "0.1.3",
                source_trust_policy: &policy,
                evidence_dir: &evidence_dir,
                stage_root: &stage_root,
                api_base: Some(&api_base),
            },
        );
        let requests = server.join().unwrap();

        assert_eq!(report.status, UpdateCandidateStageStatus::Staged);
        assert!(report.no_install);
        assert_eq!(report.release_tag, "v0.1.4");
        assert_eq!(
            report.publisher_key_fingerprint_sha256.as_deref(),
            Some(expected_fingerprint.as_str())
        );
        let stage_dir = PathBuf::from(report.stage_dir.as_ref().unwrap());
        assert!(stage_dir.is_dir());
        let staged_asset = PathBuf::from(report.staged_asset_path.as_ref().unwrap());
        assert!(staged_asset.is_file());
        assert!(stage_dir.join("SHA256SUMS.txt").is_file());
        assert!(stage_dir.join("SHA256SUMS.txt.sig").is_file());
        assert!(stage_dir.join("publisher-key.ed25519.pub").is_file());
        assert!(stage_dir.join("update-candidate-stage.json").is_file());
        assert_eq!(
            report.staged_sha256.as_deref(),
            report.expected_sha256.as_deref()
        );
        let expected_sha = sha256_hex(exe_body);
        assert_eq!(report.staged_sha256.as_deref(), Some(expected_sha.as_str()));
        assert!(requests.iter().any(|request| request
            .starts_with("GET /repos/wsolarq11/gh_mirror_gui/releases/tags/v0.1.4 ")));
        assert_eq!(
            requests
                .iter()
                .filter(|request| request.starts_with("GET /gh_mirror_gui.exe "))
                .count(),
            2
        );

        let _ = std::fs::remove_dir_all(evidence_dir);
        let _ = std::fs::remove_dir_all(stage_root);
    }

    #[test]
    fn latest_update_check_refuses_newer_candidate_without_pinned_key_before_download() {
        let public_key = public_key_from_private_seed(TEST_PRIVATE_KEY).unwrap();
        let expected_fingerprint = trusted_key_fingerprint(&public_key).unwrap();
        let exe_body = b"new candidate that must not be downloaded without a pin";
        let (api_base, server) = serve_routes(2, |base| {
            signed_release_routes(base, "v0.1.4", exe_body, &public_key)
        });
        let evidence_dir = unique_evidence_dir("missing_pin");
        let policy = SourceTrustPolicyConfig::default();

        let report = check_latest_update_candidate(
            &test_client(),
            UpdateCandidateCheckConfig {
                current_version: "0.1.3",
                source_trust_policy: &policy,
                evidence_dir: &evidence_dir,
                api_base: Some(&api_base),
            },
        );
        let requests = server.join().unwrap();

        assert_eq!(report.evaluation.status, UpdateCandidateStatus::Refused);
        assert!(report
            .refusal_reason()
            .unwrap()
            .contains("requires a pinned Ed25519 publisher key"));
        assert_eq!(
            report.publisher_key_fingerprint_sha256(),
            Some(expected_fingerprint.as_str())
        );
        assert!(report.evaluation.no_mutation);
        assert!(!requests
            .iter()
            .any(|request| request.starts_with("GET /gh_mirror_gui.exe ")));
        let _ = std::fs::remove_dir_all(evidence_dir);
    }

    #[test]
    fn refused_update_candidate_stage_report_writes_a_reviewable_evidence_record() {
        let evidence_dir = unique_evidence_dir("refused_stage");
        let report = refused_update_candidate_stage_report(
            "0.1.6",
            "self-update client build failed",
            &evidence_dir,
        );

        assert_eq!(report.status, UpdateCandidateStageStatus::Refused);
        assert!(report.no_install);
        assert!(report.check_report.evaluation.no_mutation);

        let stage_evidence = report
            .evidence_path
            .as_deref()
            .expect("stage refused report should record an evidence path");
        assert!(Path::new(stage_evidence).is_file());

        let check_evidence = report
            .check_report
            .evaluation
            .evidence_path
            .as_deref()
            .expect("refused check report should record an evidence path");
        assert!(Path::new(check_evidence).is_file());

        let _ = std::fs::remove_dir_all(evidence_dir);
    }

    #[test]
    fn update_candidate_accepts_newer_trusted_signed_release() {
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: "0.1.3",
            release_tag: "v0.1.4",
            asset_name: SELF_UPDATE_ASSET_NAME,
            verification_report: &trusted_report(),
            evidence_path: Some("evidence.json"),
        });

        assert_eq!(evaluation.status, UpdateCandidateStatus::Candidate);
        assert!(evaluation.no_mutation);
        assert_eq!(
            evaluation.source_authenticity_status.as_deref(),
            Some("TRUSTED_SIGNATURE")
        );
        assert_eq!(evaluation.evidence_path.as_deref(), Some("evidence.json"));
    }

    #[test]
    fn update_candidate_treats_same_version_as_no_update() {
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: "0.1.3",
            release_tag: "v0.1.3",
            asset_name: SELF_UPDATE_ASSET_NAME,
            verification_report: &trusted_report(),
            evidence_path: Some("evidence.json"),
        });

        assert_eq!(evaluation.status, UpdateCandidateStatus::NoUpdate);
        assert!(evaluation.reason.contains("not newer"));
    }

    #[test]
    fn update_candidate_refuses_bad_signature() {
        let report = untrusted_source_report(
            SourceAuthenticityStatus::BadSignature,
            SourceTrustDecision::Block,
            Some("ABCDEF"),
        );
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: "0.1.3",
            release_tag: "v0.1.4",
            asset_name: SELF_UPDATE_ASSET_NAME,
            verification_report: &report,
            evidence_path: Some("bad.json"),
        });

        assert_eq!(evaluation.status, UpdateCandidateStatus::Refused);
        assert!(evaluation.reason.contains("not trusted by policy"));
    }

    #[test]
    fn update_candidate_refuses_missing_publisher_key() {
        let report = untrusted_source_report(
            SourceAuthenticityStatus::NoTrustedKey,
            SourceTrustDecision::Block,
            None,
        );
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: "0.1.3",
            release_tag: "v0.1.4",
            asset_name: SELF_UPDATE_ASSET_NAME,
            verification_report: &report,
            evidence_path: Some("missing-key.json"),
        });

        assert_eq!(evaluation.status, UpdateCandidateStatus::Refused);
        assert!(evaluation.reason.contains("not trusted by policy"));
    }

    #[test]
    fn update_candidate_refuses_unsigned_required_source() {
        let report = untrusted_source_report(
            SourceAuthenticityStatus::MissingSignature,
            SourceTrustDecision::Block,
            Some("ABCDEF"),
        );
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: "0.1.3",
            release_tag: "v0.1.4",
            asset_name: SELF_UPDATE_ASSET_NAME,
            verification_report: &report,
            evidence_path: Some("missing-signature.json"),
        });

        assert_eq!(evaluation.status, UpdateCandidateStatus::Refused);
        assert!(evaluation.reason.contains("not trusted by policy"));
    }

    #[test]
    fn update_candidate_refuses_non_self_update_asset() {
        let evaluation = evaluate_update_candidate(UpdateCandidateInput {
            current_version: "0.1.3",
            release_tag: "v0.1.4",
            asset_name: "README.md",
            verification_report: &trusted_report(),
            evidence_path: Some("evidence.json"),
        });

        assert_eq!(evaluation.status, UpdateCandidateStatus::Refused);
        assert!(evaluation.reason.contains(SELF_UPDATE_ASSET_NAME));
    }

    #[test]
    fn update_candidate_version_compare_handles_numeric_tags() {
        assert_eq!(compare_versions("0.1.3", "0.1.4"), Some(Ordering::Less));
        assert_eq!(
            compare_versions("v0.1.10", "0.1.4"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_versions("0.1.3", "0.1.3+build"),
            Some(Ordering::Equal)
        );
        assert_eq!(compare_versions("0.1.x", "0.1.4"), None);
    }
}
