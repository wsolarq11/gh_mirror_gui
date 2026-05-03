use crate::source_trust::{SourceAuthenticityStatus, SourceTrustDecision, SourceTrustEvidence};
use crate::verification::{VerificationReport, VerificationStatus};
use std::cmp::Ordering;
use std::path::PathBuf;

const UPDATE_CANDIDATE_SCHEMA_VERSION: u32 = 1;
const SELF_UPDATE_ASSET_NAME: &str = "gh_mirror_gui.exe";

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum UpdateCandidateStatus {
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
pub(crate) struct UpdateCandidateEvaluation {
    pub(crate) schema_version: u32,
    pub(crate) status: UpdateCandidateStatus,
    pub(crate) current_version: String,
    pub(crate) candidate_version: String,
    pub(crate) release_tag: String,
    pub(crate) asset_name: String,
    pub(crate) reason: String,
    pub(crate) verification_status: String,
    pub(crate) source_authenticity_status: Option<String>,
    pub(crate) source_trust_decision: Option<String>,
    pub(crate) publisher_key_fingerprint_sha256: Option<String>,
    pub(crate) evidence_path: Option<String>,
    pub(crate) no_mutation: bool,
}

pub(crate) struct UpdateCandidateInput<'a> {
    pub(crate) current_version: &'a str,
    pub(crate) release_tag: &'a str,
    pub(crate) asset_name: &'a str,
    pub(crate) verification_report: &'a VerificationReport,
    pub(crate) evidence_path: Option<&'a str>,
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
