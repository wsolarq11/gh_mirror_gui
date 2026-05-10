use crate::artifact_decision::{ArtifactActionPathKind, ArtifactDecision};
use crate::download::DownloadControl;
use crate::download::DownloadProbe;
use crate::download::SelectedDownloadStrategy;
use crate::evidence_ledger::{EvidenceLedger, FileSystemEvidenceLedger};
use crate::github_intent::{parse_github_intent, ParsedGithubIntent};
use crate::releases::{ReleaseQuery, ResolvedRelease};
use crate::source_adapter::{GitHubReleaseAdapter, SourceAdapter};
use crate::source_spec::SourceSpec;
use crate::source_trust::SourceTrustPolicyConfig;
use crate::trust_policy::{AppliedFileDisposition, PlannedFileDisposition, TrustPolicyConfig};
use crate::update_apply_plan::{
    UpdateApplyFixtureEvidenceRecord, UpdateApplyPlan, UpdateApplyPlanEvidenceRecord,
};
use crate::update_candidate::{UpdateCandidateCheckReport, UpdateCandidateStageReport};
use crate::verification::{DownloadVerificationPlan, VerificationReport};
use crate::verifier_adapter::{GitHubReleaseVerifierAdapter, VerifierAdapter};
use reqwest::blocking::Client;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

/// Core runtime orchestrator.
///
/// This is an internal "composition point" that wires together stable artifact-decision seams.
///
/// Long-term direction:
/// - `backend_contract` stays a small, stable front door (DTOs + a few use-cases)
/// - this runtime becomes the internal pipeline entrypoint
/// - adapters evolve behind seams to grow from "GitHub Release" toward an Artifact Trust Broker
pub(crate) struct CoreRuntime {
    source_adapter: Box<dyn SourceAdapter>,
    verifier_adapter: Box<dyn VerifierAdapter>,
    evidence_ledger: Box<dyn EvidenceLedger>,
}

pub(crate) struct DownloadWithStrategyContractInput<'a> {
    pub(crate) client: &'a Client,
    pub(crate) url: &'a str,
    pub(crate) save_path: &'a str,
    pub(crate) probe: &'a DownloadProbe,
    pub(crate) strategy: &'a SelectedDownloadStrategy,
    pub(crate) ctrl: &'a Arc<DownloadControl>,
    pub(crate) progress_tx: &'a mpsc::Sender<(u64, u64, f64, f64)>,
}

pub(crate) struct AppendDownloadHistoryInput<'a> {
    pub(crate) history_path: &'a PathBuf,
    pub(crate) url: &'a str,
    pub(crate) output: &'a PathBuf,
    pub(crate) probe: &'a DownloadProbe,
    pub(crate) strategy: &'a SelectedDownloadStrategy,
    pub(crate) download_elapsed: std::time::Duration,
    pub(crate) verification: Option<crate::history::VerificationHistoryContext<'a>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreClientSettings {
    proxy: String,
    allow_invalid_certs: bool,
}

impl CoreClientSettings {
    pub(crate) fn new(proxy: String, allow_invalid_certs: bool) -> Self {
        Self {
            proxy,
            allow_invalid_certs,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreDownloadSpec {
    pub(crate) url: String,
    pub(crate) filename: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CoreDownloadIntent {
    DirectDownload {
        spec: CoreDownloadSpec,
        human_readable_label: String,
    },
    NeedsAssetPick {
        query: ReleaseQuery,
        picker_hint: Option<String>,
    },
    Unsupported {
        reason: String,
        suggested_examples: Vec<String>,
    },
}

impl From<ParsedGithubIntent> for CoreDownloadIntent {
    fn from(intent: ParsedGithubIntent) -> Self {
        match intent {
            ParsedGithubIntent::DirectDownload {
                url,
                filename,
                label,
            } => CoreDownloadIntent::DirectDownload {
                spec: CoreDownloadSpec { url, filename },
                human_readable_label: label,
            },
            ParsedGithubIntent::ReleaseQuery { query, picker_hint } => {
                CoreDownloadIntent::NeedsAssetPick { query, picker_hint }
            }
            ParsedGithubIntent::Unsupported {
                reason,
                suggested_examples,
            } => CoreDownloadIntent::Unsupported {
                reason,
                suggested_examples,
            },
        }
    }
}

pub(crate) struct RunDownloadContractInput<'a> {
    pub(crate) settings: &'a CoreClientSettings,
    pub(crate) effective_url: &'a str,
    pub(crate) save_path: PathBuf,
    pub(crate) asset_name: String,
    pub(crate) verification_release: Option<ResolvedRelease>,
    pub(crate) verification_asset_index: Option<usize>,
    pub(crate) trust_policy: TrustPolicyConfig,
    pub(crate) publisher_key_source_at_decision: String,
    pub(crate) history_path: PathBuf,
    pub(crate) ctrl: &'a Arc<DownloadControl>,
    pub(crate) progress_tx: &'a mpsc::Sender<(u64, u64, f64, f64)>,
}

pub(crate) struct RunDownloadContractOutput {
    pub(crate) original_path: PathBuf,
    pub(crate) trust_center: CoreTrustCenterSnapshot,
    pub(crate) evidence_path: Option<PathBuf>,
    pub(crate) file_disposition: AppliedFileDisposition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreTrustCenterSnapshot {
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreDisplayRow {
    pub(crate) label: &'static str,
    pub(crate) value: String,
}

impl CoreDisplayRow {
    pub(crate) fn new(label: &'static str, value: impl Into<String>) -> Self {
        Self {
            label,
            value: value.into(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CorePathActionKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CorePathAction {
    pub(crate) label: &'static str,
    pub(crate) path: String,
    pub(crate) missing_message: String,
    pub(crate) kind: CorePathActionKind,
}

impl CorePathAction {
    pub(crate) fn file(
        label: &'static str,
        path: impl Into<String>,
        missing_message: impl Into<String>,
    ) -> Self {
        Self {
            label,
            path: path.into(),
            missing_message: missing_message.into(),
            kind: CorePathActionKind::File,
        }
    }

    pub(crate) fn directory(
        label: &'static str,
        path: impl Into<String>,
        missing_message: impl Into<String>,
    ) -> Self {
        Self {
            label,
            path: path.into(),
            missing_message: missing_message.into(),
            kind: CorePathActionKind::Directory,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CoreStatusNoticeLevel {
    Good,
    Warning,
    Error,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CoreStatusNotice {
    pub(crate) level: CoreStatusNoticeLevel,
    pub(crate) message: &'static str,
    pub(crate) retry_label: Option<&'static str>,
}

impl CoreStatusNotice {
    pub(crate) fn new(
        level: CoreStatusNoticeLevel,
        message: &'static str,
        retry_label: Option<&'static str>,
    ) -> Self {
        Self {
            level,
            message,
            retry_label,
        }
    }
}

impl From<crate::trust_center::TrustCenterSnapshot> for CoreTrustCenterSnapshot {
    fn from(snapshot: crate::trust_center::TrustCenterSnapshot) -> Self {
        Self {
            downloaded_asset: snapshot.downloaded_asset,
            hash_status: snapshot.hash_status,
            file_sha256: snapshot.file_sha256,
            expected_sha256: snapshot.expected_sha256,
            source_authenticity: snapshot.source_authenticity,
            source_trust_detail: snapshot.source_trust_detail,
            source_asset: snapshot.source_asset,
            signature_asset: snapshot.signature_asset,
            publisher_key_fingerprint: snapshot.publisher_key_fingerprint,
            publisher_key_source: snapshot.publisher_key_source,
            policy_verdict: snapshot.policy_verdict,
            policy_at_decision: snapshot.policy_at_decision,
            evidence_path: snapshot.evidence_path,
            evidence_access: snapshot.evidence_access,
            file_disposition: snapshot.file_disposition,
            final_path: snapshot.final_path,
        }
    }
}

impl Default for CoreRuntime {
    fn default() -> Self {
        Self::new(
            Box::new(GitHubReleaseAdapter),
            Box::new(GitHubReleaseVerifierAdapter),
            Box::new(FileSystemEvidenceLedger),
        )
    }
}

impl CoreRuntime {
    pub(crate) fn new(
        source_adapter: Box<dyn SourceAdapter>,
        verifier_adapter: Box<dyn VerifierAdapter>,
        evidence_ledger: Box<dyn EvidenceLedger>,
    ) -> Self {
        Self {
            source_adapter,
            verifier_adapter,
            evidence_ledger,
        }
    }

    pub(crate) fn resolve_release_assets(
        &self,
        client: &Client,
        api_base: Option<&str>,
        query: &ReleaseQuery,
    ) -> Result<ResolvedRelease, String> {
        let spec = SourceSpec::GitHubRelease {
            query: query.clone(),
        };
        self.resolve_source_spec(client, api_base, &spec)
    }

    pub(crate) fn resolve_source_spec(
        &self,
        client: &Client,
        api_base: Option<&str>,
        spec: &SourceSpec,
    ) -> Result<ResolvedRelease, String> {
        self.source_adapter
            .resolve_release_assets(client, api_base, spec)
    }

    pub(crate) fn import_publisher_key_from_release_asset(
        &self,
        client: &Client,
        asset: &crate::releases::ReleaseAsset,
    ) -> Result<crate::source_trust::ImportedPublisherKeyPin, String> {
        crate::source_trust::import_publisher_key_pin_from_release_asset(client, asset)
    }

    pub(crate) fn resolve_download_intent(&self, input: &str) -> CoreDownloadIntent {
        parse_github_intent(input).into()
    }

    pub(crate) fn official_github_artifact_hosts(&self) -> &'static [&'static str] {
        crate::url_policy::official_github_artifact_hosts()
    }

    pub(crate) fn default_history_path(&self) -> PathBuf {
        crate::history::default_history_path()
    }

    pub(crate) fn release_query_selector_label(&self, query: &ReleaseQuery) -> String {
        query.selector_label()
    }

    pub(crate) fn release_asset_picker_label(
        &self,
        asset: &crate::releases::ReleaseAsset,
    ) -> String {
        format!("{} ({})", asset.name, Self::format_asset_size(asset.size))
    }

    fn format_asset_size(bytes: u64) -> String {
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
        } else if bytes >= 1024 {
            format!("{:.1} KiB", bytes as f64 / 1024.0)
        } else {
            format!("{bytes} B")
        }
    }

    pub(crate) fn trust_policy_from_settings(
        &self,
        unknown_keep_file: bool,
        unknown_allow_open: bool,
        mismatch_file_policy: crate::trust_policy::MismatchFilePolicy,
        require_trusted_source: bool,
        trusted_publisher_key: String,
    ) -> TrustPolicyConfig {
        TrustPolicyConfig {
            unknown_keep_file,
            unknown_allow_open,
            mismatch_file_policy,
            source_trust: SourceTrustPolicyConfig {
                require_trusted_source,
                trusted_publisher_key,
            },
        }
    }

    pub(crate) fn apply_imported_publisher_key_pin(
        &self,
        trust_policy: &mut TrustPolicyConfig,
        publisher_key_source: &mut String,
        imported: crate::source_trust::ImportedPublisherKeyPin,
        source_label: String,
    ) -> String {
        trust_policy.source_trust.trusted_publisher_key = imported.public_key;
        *publisher_key_source = source_label.clone();
        let short_fingerprint = imported
            .fingerprint_sha256
            .chars()
            .take(12)
            .collect::<String>();
        format!(
            "Imported Ed25519 publisher key from {} · fingerprint {}…",
            source_label, short_fingerprint
        )
    }

    pub(crate) fn source_trust_policy_config(
        &self,
        trust_policy: &TrustPolicyConfig,
    ) -> SourceTrustPolicyConfig {
        trust_policy.source_trust.clone()
    }

    pub(crate) fn source_trust_requires_signed(&self, trust_policy: &TrustPolicyConfig) -> bool {
        trust_policy.source_trust.require_trusted_source
    }

    pub(crate) fn set_source_trust_requires_signed(
        &self,
        trust_policy: &mut TrustPolicyConfig,
        require_trusted_source: bool,
    ) {
        trust_policy.source_trust.require_trusted_source = require_trusted_source;
    }

    pub(crate) fn trusted_publisher_key_text(&self, trust_policy: &TrustPolicyConfig) -> String {
        trust_policy.source_trust.trusted_publisher_key.clone()
    }

    pub(crate) fn set_trusted_publisher_key_from_manual_input(
        &self,
        trust_policy: &mut TrustPolicyConfig,
        publisher_key_source: &mut String,
        trusted_publisher_key: String,
    ) {
        if trust_policy.source_trust.trusted_publisher_key != trusted_publisher_key {
            *publisher_key_source = "manual/pasted key in Trust policy UI".to_string();
        }
        trust_policy.source_trust.trusted_publisher_key = trusted_publisher_key;
    }

    pub(crate) fn set_trusted_publisher_key_pin(
        &self,
        trust_policy: &mut TrustPolicyConfig,
        publisher_key_source: &mut String,
        trusted_publisher_key: String,
        source_label: String,
    ) -> String {
        trust_policy.source_trust.trusted_publisher_key = trusted_publisher_key;
        *publisher_key_source = source_label.clone();
        let fingerprint = self
            .trusted_publisher_key_fingerprint(trust_policy)
            .unwrap_or_else(|| "unknown".to_string());
        let short_fingerprint = fingerprint.chars().take(12).collect::<String>();
        format!(
            "Imported Ed25519 publisher key from {} · fingerprint {}…",
            source_label, short_fingerprint
        )
    }

    pub(crate) fn normalize_trusted_publisher_key(
        &self,
        trust_policy: &mut TrustPolicyConfig,
        publisher_key_source: &mut String,
    ) -> Result<String, String> {
        let pin = crate::source_trust::normalize_public_key_pin(
            &trust_policy.source_trust.trusted_publisher_key,
        )?;
        trust_policy.source_trust.trusted_publisher_key = pin;
        if publisher_key_source.trim().is_empty() {
            *publisher_key_source = "manual/pasted key normalized locally".to_string();
        }
        Ok("Normalized Ed25519 publisher key".to_string())
    }

    pub(crate) fn clear_trusted_publisher_key(
        &self,
        trust_policy: &mut TrustPolicyConfig,
        publisher_key_source: &mut String,
    ) {
        trust_policy.source_trust.trusted_publisher_key.clear();
        publisher_key_source.clear();
    }

    pub(crate) fn trusted_publisher_key_fingerprint(
        &self,
        trust_policy: &TrustPolicyConfig,
    ) -> Option<String> {
        crate::source_trust::trusted_key_fingerprint(
            &trust_policy.source_trust.trusted_publisher_key,
        )
    }

    pub(crate) fn build_client(
        &self,
        settings: &CoreClientSettings,
        timeout_secs: u64,
    ) -> Result<Client, String> {
        crate::download::build_client(&settings.proxy, timeout_secs, settings.allow_invalid_certs)
    }

    pub(crate) fn resolve_release_assets_for_query(
        &self,
        settings: &CoreClientSettings,
        query: &ReleaseQuery,
    ) -> Result<ResolvedRelease, String> {
        let client = self
            .build_client(settings, 30)
            .map_err(|e| format!("Release resolver client error: {e}"))?;
        self.resolve_release_assets(&client, None, query)
    }

    pub(crate) fn import_publisher_key_from_release_asset_for_settings(
        &self,
        settings: &CoreClientSettings,
        asset: &crate::releases::ReleaseAsset,
    ) -> Result<crate::source_trust::ImportedPublisherKeyPin, String> {
        let client = self
            .build_client(settings, 30)
            .map_err(|e| format!("Publisher key import client error: {e}"))?;
        self.import_publisher_key_from_release_asset(&client, asset)
    }

    pub(crate) fn run_update_candidate_check(
        &self,
        settings: &CoreClientSettings,
        current_version: &str,
        source_trust_policy: &SourceTrustPolicyConfig,
        evidence_dir: &Path,
    ) -> UpdateCandidateCheckReport {
        match self.build_client(settings, 60) {
            Ok(client) => self.check_latest_update_candidate(
                &client,
                current_version,
                source_trust_policy,
                evidence_dir,
                None,
            ),
            Err(e) => self.refused_update_candidate_check_report(
                current_version,
                format!("self-update client build failed: {e}"),
                evidence_dir,
            ),
        }
    }

    pub(crate) fn run_update_candidate_stage(
        &self,
        settings: &CoreClientSettings,
        current_version: &str,
        source_trust_policy: &SourceTrustPolicyConfig,
        evidence_dir: &Path,
        stage_root: &Path,
    ) -> UpdateCandidateStageReport {
        match self.build_client(settings, 60) {
            Ok(client) => self.stage_latest_update_candidate(
                &client,
                current_version,
                source_trust_policy,
                evidence_dir,
                stage_root,
                None,
            ),
            Err(e) => self.refused_update_candidate_stage_report(
                current_version,
                format!("self-update client build failed: {e}"),
                evidence_dir,
            ),
        }
    }

    fn log_download_error(&self, msg: &str) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let line = format!("[{ts}] {msg}");
        let _ = self.append_line(Path::new("download_error.log"), &line);
    }

    pub(crate) fn verification_plan_for_selected_asset(
        &self,
        release: &ResolvedRelease,
        asset_index: usize,
    ) -> Option<DownloadVerificationPlan> {
        self.verifier_adapter
            .verification_plan_for_selected_asset(release, asset_index)
    }

    pub(crate) fn verification_source_summary_for_selected_asset(
        &self,
        release: &ResolvedRelease,
        asset_index: usize,
    ) -> String {
        self.verification_plan_for_selected_asset(release, asset_index)
            .map(|plan| crate::verification::verification_source_summary(&plan))
            .unwrap_or_else(|| {
                "No checksum/provenance assets detected; result will be UNKNOWN".to_string()
            })
    }

    pub(crate) fn publisher_key_source_label_for_policy(
        &self,
        trust_policy: &TrustPolicyConfig,
        publisher_key_source: &str,
    ) -> String {
        crate::trust_center::publisher_key_source_label_for_policy(
            trust_policy,
            publisher_key_source,
        )
    }

    pub(crate) fn open_location_button_label_for_facts(
        &self,
        hash_status: &str,
        policy_verdict: &str,
        disposition: &AppliedFileDisposition,
        policy: &TrustPolicyConfig,
    ) -> Option<&'static str> {
        crate::trust_policy::open_location_button_label_for_facts(
            hash_status,
            policy_verdict,
            disposition,
            policy,
        )
    }

    pub(crate) fn file_disposition_summary(&self, disposition: &AppliedFileDisposition) -> String {
        crate::trust_policy::file_disposition_summary(disposition)
    }

    pub(crate) fn source_trust_status_summary(&self, snapshot: &CoreTrustCenterSnapshot) -> String {
        let signature = if snapshot.signature_asset != "none" {
            format!(" via {}", snapshot.signature_asset)
        } else {
            String::new()
        };
        let pin = if snapshot.publisher_key_fingerprint != "not pinned" {
            let short = snapshot
                .publisher_key_fingerprint
                .chars()
                .take(12)
                .collect::<String>();
            format!(" key={short}")
        } else {
            String::new()
        };
        format!(
            "{} decision={}{}{}",
            snapshot.source_authenticity, snapshot.policy_verdict, signature, pin
        )
    }

    pub(crate) fn download_completion_status(
        &self,
        snapshot: &CoreTrustCenterSnapshot,
        disposition: &AppliedFileDisposition,
    ) -> String {
        let short_hash = snapshot.file_sha256.chars().take(12).collect::<String>();
        let disposition_summary = self.file_disposition_summary(disposition);
        let source_trust = self.source_trust_status_summary(snapshot);
        match (
            snapshot.hash_status.as_str(),
            snapshot.policy_verdict.as_str(),
        ) {
            ("VERIFIED", "BLOCK") => format!(
                "❌ Verification BLOCKED · SHA256 matched {} but source authenticity is {} · {} · {}",
                snapshot.source_asset.as_str(),
                source_trust,
                disposition_summary,
                "retry or open evidence before trusting this file"
            ),
            ("VERIFIED", _) => format!(
                "✅ Download complete · VERIFIED SHA256={} via {} · source {} · {}",
                short_hash,
                snapshot.source_asset.as_str(),
                source_trust,
                disposition_summary
            ),
            ("MISMATCH", _) => format!(
                "❌ Verification BLOCKED · MISMATCH SHA256={} expected {} via {} · {} · retry or open evidence before trusting this file",
                short_hash,
                snapshot
                    .expected_sha256
                    .as_str()
                    .chars()
                    .take(12)
                    .collect::<String>(),
                snapshot.source_asset.as_str(),
                disposition_summary
            ),
            ("UNKNOWN", _) => format!(
                "⚠ Verification UNKNOWN risk · SHA256={} · {} · {}",
                short_hash,
                "no matching checksum/provenance could verify this file",
                disposition_summary
            ),
            (other, decision) => format!(
                "⚠ Verification {} ({}) · SHA256={} · {}",
                other, decision, short_hash, disposition_summary
            ),
        }
    }

    pub(crate) fn download_notification_status(
        &self,
        snapshot: &CoreTrustCenterSnapshot,
    ) -> String {
        match (
            snapshot.hash_status.as_str(),
            snapshot.policy_verdict.as_str(),
        ) {
            ("VERIFIED", "BLOCK") => "Download blocked (UNTRUSTED SOURCE)".to_string(),
            ("VERIFIED", _) => "Download complete (VERIFIED)".to_string(),
            ("MISMATCH", _) => "Download blocked (MISMATCH)".to_string(),
            ("UNKNOWN", _) => "Download saved with UNKNOWN verification risk".to_string(),
            _ => "Download completed with UNKNOWN verification risk".to_string(),
        }
    }

    pub(crate) fn last_download_status_notice(
        &self,
        hash_status: &str,
        policy_verdict: &str,
    ) -> Option<CoreStatusNotice> {
        match (hash_status, policy_verdict) {
            ("VERIFIED", "BLOCK") => Some(CoreStatusNotice::new(
                CoreStatusNoticeLevel::Error,
                "Blocked: checksum matched, but verification source signature is not trusted.",
                Some("🔁 Retry Download"),
            )),
            ("MISMATCH", _) => Some(CoreStatusNotice::new(
                CoreStatusNoticeLevel::Error,
                "Blocked: downloaded file does not match trusted checksum.",
                Some("🔁 Retry Download"),
            )),
            ("UNKNOWN", _) => Some(CoreStatusNotice::new(
                CoreStatusNoticeLevel::Warning,
                "Risk: no matching checksum/provenance could verify this file.",
                None,
            )),
            ("VERIFIED", _) => Some(CoreStatusNotice::new(
                CoreStatusNoticeLevel::Good,
                "Trusted: checksum/provenance hash and source policy passed.",
                None,
            )),
            _ => None,
        }
    }

    pub(crate) fn last_download_evidence_action(
        &self,
        evidence_path: Option<&Path>,
    ) -> Option<CorePathAction> {
        evidence_path.map(|path| {
            let path_text = path.display().to_string();
            CorePathAction::file(
                "📄 Open Evidence",
                path_text.clone(),
                format!("Evidence path recorded but file is missing: {path_text}"),
            )
        })
    }

    pub(crate) fn last_download_open_location_action(
        &self,
        hash_status: &str,
        policy_verdict: &str,
        disposition: &AppliedFileDisposition,
        trust_policy: &TrustPolicyConfig,
        download_path: &Path,
        save_dir: &Path,
    ) -> Option<CorePathAction> {
        self.open_location_button_label_for_facts(
            hash_status,
            policy_verdict,
            disposition,
            trust_policy,
        )
        .map(|label| {
            let folder = download_path.parent().unwrap_or(save_dir);
            let folder_text = folder.display().to_string();
            CorePathAction::directory(
                label,
                folder_text.clone(),
                format!("Download folder is recorded but not present on disk: {folder_text}"),
            )
        })
    }

    pub(crate) fn public_key_from_private_seed(
        &self,
        private_key_text: &str,
    ) -> Result<String, String> {
        crate::source_trust::public_key_from_private_seed(private_key_text)
    }

    pub(crate) fn sign_ed25519_detached(
        &self,
        message: &[u8],
        private_key_text: &str,
    ) -> Result<String, String> {
        crate::source_trust::sign_ed25519_detached(message, private_key_text)
    }

    pub(crate) fn verify_ed25519_detached(
        &self,
        message: &[u8],
        signature_text: &str,
        public_key_text: &str,
    ) -> Result<(), String> {
        crate::source_trust::verify_ed25519_detached(message, signature_text, public_key_text)
    }

    pub(crate) fn normalize_public_key_pin(&self, public_key_text: &str) -> Result<String, String> {
        crate::source_trust::normalize_public_key_pin(public_key_text)
    }

    pub(crate) fn import_publisher_key_pin_from_path(&self, path: &Path) -> Result<String, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Read publisher public key {}: {e}", path.display()))?;
        self.normalize_public_key_pin(&text)
    }

    pub(crate) fn trusted_key_fingerprint(&self, public_key_text: &str) -> Option<String> {
        crate::source_trust::trusted_key_fingerprint(public_key_text)
    }

    pub(crate) fn run_bench_download(&self, args: &[String]) -> Result<(), String> {
        crate::bench::run_bench_download(args)
    }

    pub(crate) fn run_staged_release_download_selftest(
        &self,
        args: &[String],
    ) -> Result<(), String> {
        crate::staged_release::run_staged_release_download_selftest(args)
    }

    pub(crate) fn run_update_candidate_contract_selftest(
        &self,
        args: &[String],
    ) -> Result<(), String> {
        crate::update_candidate::run_update_candidate_contract_selftest(args)
    }

    pub(crate) fn run_update_candidate_latest_selftest(
        &self,
        args: &[String],
    ) -> Result<(), String> {
        crate::update_candidate::run_update_candidate_latest_selftest(args)
    }

    pub(crate) fn run_update_candidate_stage_selftest(
        &self,
        args: &[String],
    ) -> Result<(), String> {
        crate::update_candidate::run_update_candidate_stage_selftest(args)
    }

    pub(crate) fn run_update_apply_plan_contract_selftest(
        &self,
        args: &[String],
    ) -> Result<(), String> {
        crate::update_apply_plan::run_update_apply_plan_contract_selftest(args)
    }

    pub(crate) fn run_update_apply_fixture_contract_selftest(
        &self,
        args: &[String],
    ) -> Result<(), String> {
        crate::update_apply_plan::run_update_apply_fixture_contract_selftest(args)
    }

    pub(crate) fn artifact_decision_from_update_candidate_check(
        &self,
        report: &UpdateCandidateCheckReport,
    ) -> ArtifactDecision {
        ArtifactDecision::from_update_candidate_check(report)
    }

    pub(crate) fn artifact_decision_from_update_candidate_stage(
        &self,
        report: &UpdateCandidateStageReport,
    ) -> ArtifactDecision {
        ArtifactDecision::from_update_candidate_stage(report)
    }

    pub(crate) fn artifact_decision_from_update_apply_plan(
        &self,
        plan: &UpdateApplyPlan,
        evidence_path: Option<&str>,
    ) -> ArtifactDecision {
        ArtifactDecision::from_update_apply_plan(plan, evidence_path)
    }

    pub(crate) fn artifact_decision_from_update_apply_plan_evidence(
        &self,
        plan: &UpdateApplyPlan,
        evidence: Option<&UpdateApplyPlanEvidenceRecord>,
    ) -> ArtifactDecision {
        self.artifact_decision_from_update_apply_plan(
            plan,
            evidence.and_then(|record| record.evidence_path.as_deref()),
        )
    }

    pub(crate) fn artifact_decision_from_update_apply_fixture_evidence(
        &self,
        evidence: &UpdateApplyFixtureEvidenceRecord,
    ) -> ArtifactDecision {
        ArtifactDecision::from_update_apply_fixture_evidence(evidence)
    }

    pub(crate) fn artifact_decision_rows(
        &self,
        decision: &ArtifactDecision,
    ) -> Vec<CoreDisplayRow> {
        vec![
            CoreDisplayRow::new("Contract", decision.contract.clone()),
            CoreDisplayRow::new("Intent", format!("{:?}", decision.intent)),
            CoreDisplayRow::new("Source", decision.candidate.source.clone()),
            CoreDisplayRow::new("Artifact", decision.candidate.artifact_name.clone()),
            CoreDisplayRow::new(
                "Version/tag",
                decision
                    .candidate
                    .version_or_tag
                    .as_deref()
                    .unwrap_or("unknown"),
            ),
            CoreDisplayRow::new(
                "URI",
                decision.candidate.uri.as_deref().unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Evidence path",
                decision
                    .evidence
                    .evidence_path
                    .as_deref()
                    .unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Hash status",
                decision
                    .evidence
                    .hash_status
                    .as_deref()
                    .unwrap_or("unknown"),
            ),
            CoreDisplayRow::new(
                "Source authenticity",
                decision
                    .evidence
                    .source_authenticity
                    .as_deref()
                    .unwrap_or("unknown"),
            ),
            CoreDisplayRow::new(
                "Publisher fingerprint",
                decision
                    .evidence
                    .publisher_key_fingerprint_sha256
                    .as_deref()
                    .unwrap_or("not available"),
            ),
            CoreDisplayRow::new(
                "Policy verdict",
                decision
                    .evidence
                    .policy_verdict
                    .as_deref()
                    .unwrap_or("unknown"),
            ),
            CoreDisplayRow::new("Verdict", format!("{:?}", decision.verdict)),
            CoreDisplayRow::new("Action", format!("{:?}", decision.action_plan.kind)),
            CoreDisplayRow::new("Action status", decision.action_plan.status.clone()),
            CoreDisplayRow::new("Action summary", decision.action_plan.summary.clone()),
            CoreDisplayRow::new("Reversible", decision.action_plan.reversible.to_string()),
            CoreDisplayRow::new("No mutation", decision.action_plan.no_mutation.to_string()),
            CoreDisplayRow::new("Steps", decision.action_plan.steps.len().to_string()),
        ]
    }

    pub(crate) fn artifact_decision_step_rows(&self, decision: &ArtifactDecision) -> Vec<String> {
        decision
            .action_plan
            .steps
            .iter()
            .enumerate()
            .map(|(idx, step)| format!("{}: {}", idx + 1, step))
            .collect()
    }

    pub(crate) fn artifact_decision_action_path(
        &self,
        decision: &ArtifactDecision,
    ) -> Option<CorePathAction> {
        decision
            .action_plan
            .path_action
            .as_ref()
            .map(|action| match action.kind {
                ArtifactActionPathKind::File => CorePathAction::file(
                    "📄 Open action file",
                    action.path.clone(),
                    action.missing_message.clone(),
                ),
                ArtifactActionPathKind::Directory => CorePathAction::directory(
                    "📁 Open action folder",
                    action.path.clone(),
                    action.missing_message.clone(),
                ),
            })
    }

    pub(crate) fn artifact_decision_evidence_action(
        &self,
        decision: &ArtifactDecision,
    ) -> Option<CorePathAction> {
        decision.evidence.evidence_path.as_ref().map(|path| {
            CorePathAction::file(
                "📄 Open decision evidence",
                path.clone(),
                "Decision evidence path is recorded but not present on disk.",
            )
        })
    }

    pub(crate) fn update_candidate_check_status_summary(
        &self,
        report: &UpdateCandidateCheckReport,
    ) -> String {
        format!(
            "Self-update check: {} ({})",
            report.status_display(),
            report.evaluation.reason
        )
    }

    pub(crate) fn update_candidate_check_rows(
        &self,
        report: &UpdateCandidateCheckReport,
    ) -> Vec<CoreDisplayRow> {
        vec![
            CoreDisplayRow::new("Status", report.status_display()),
            CoreDisplayRow::new(
                "Release",
                format!("{} @ {}", report.repo, report.release_tag),
            ),
            CoreDisplayRow::new("Asset", report.asset_name.clone()),
            CoreDisplayRow::new("Reason", report.evaluation.reason.clone()),
            CoreDisplayRow::new("refusal_reason", report.refusal_reason().unwrap_or("none")),
            CoreDisplayRow::new(
                "Publisher fingerprint",
                report
                    .publisher_key_fingerprint_sha256()
                    .unwrap_or("not available"),
            ),
            CoreDisplayRow::new(
                "Evidence path",
                report
                    .evaluation
                    .evidence_path
                    .as_deref()
                    .unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new("No mutation", report.evaluation.no_mutation.to_string()),
        ]
    }

    pub(crate) fn update_candidate_check_evidence_warning(
        &self,
        report: &UpdateCandidateCheckReport,
    ) -> Option<String> {
        report
            .evidence_write_error
            .as_ref()
            .map(|error| format!("Evidence write warning: {error}"))
    }

    pub(crate) fn update_candidate_check_evidence_action(
        &self,
        report: &UpdateCandidateCheckReport,
    ) -> Option<CorePathAction> {
        report.evaluation.evidence_path.as_ref().map(|path| {
            CorePathAction::file(
                "📄 Open Update Evidence",
                path.clone(),
                "Update evidence path is recorded but not present on disk.",
            )
        })
    }

    pub(crate) fn update_candidate_stage_status_summary(
        &self,
        report: &UpdateCandidateStageReport,
    ) -> String {
        format!(
            "Self-update stage: {} ({})",
            format!("{:?}", report.status).to_lowercase(),
            report.reason
        )
    }

    pub(crate) fn update_candidate_stage_rows(
        &self,
        report: &UpdateCandidateStageReport,
    ) -> Vec<CoreDisplayRow> {
        vec![
            CoreDisplayRow::new("Status", format!("{:?}", report.status).to_lowercase()),
            CoreDisplayRow::new(
                "Release",
                format!("{} @ {}", report.repo, report.release_tag),
            ),
            CoreDisplayRow::new("Reason", report.reason.clone()),
            CoreDisplayRow::new(
                "Publisher fingerprint",
                report
                    .publisher_key_fingerprint_sha256
                    .as_deref()
                    .unwrap_or("not available"),
            ),
            CoreDisplayRow::new(
                "Stage dir",
                report.stage_dir.as_deref().unwrap_or("not staged"),
            ),
            CoreDisplayRow::new(
                "Staged asset",
                report.staged_asset_path.as_deref().unwrap_or("none"),
            ),
            CoreDisplayRow::new(
                "Expected SHA256",
                report.expected_sha256.as_deref().unwrap_or("unknown"),
            ),
            CoreDisplayRow::new(
                "Staged SHA256",
                report.staged_sha256.as_deref().unwrap_or("unknown"),
            ),
            CoreDisplayRow::new(
                "Evidence path",
                report.evidence_path.as_deref().unwrap_or("not recorded"),
            ),
        ]
    }

    pub(crate) fn update_candidate_stage_evidence_warning(
        &self,
        report: &UpdateCandidateStageReport,
    ) -> Option<String> {
        report
            .evidence_write_error
            .as_ref()
            .map(|error| format!("Evidence write warning: {error}"))
    }

    pub(crate) fn update_candidate_stage_folder_action(
        &self,
        report: &UpdateCandidateStageReport,
    ) -> Option<CorePathAction> {
        report.stage_dir.as_ref().map(|path| {
            CorePathAction::directory(
                "📁 Open stage folder",
                path.clone(),
                "Stage folder path is recorded but not present on disk.",
            )
        })
    }

    pub(crate) fn update_candidate_stage_evidence_action(
        &self,
        report: &UpdateCandidateStageReport,
    ) -> Option<CorePathAction> {
        report.evidence_path.as_ref().map(|path| {
            CorePathAction::file(
                "📄 Open stage evidence",
                path.clone(),
                "Stage evidence path is recorded but not present on disk.",
            )
        })
    }

    pub(crate) fn describe_update_apply_step(
        &self,
        step: &crate::update_apply_plan::UpdateApplyStep,
    ) -> String {
        match step {
            crate::update_apply_plan::UpdateApplyStep::VerifyStagedCandidateSha256 {
                path,
                expected_sha256,
            } => format!("Verify staged candidate SHA256 at {path} == {expected_sha256}"),
            crate::update_apply_plan::UpdateApplyStep::BackupCurrentExecutable { from, to } => {
                format!("Backup current executable {from} -> {to}")
            }
            crate::update_apply_plan::UpdateApplyStep::ReplaceExecutableFromStage { from, to } => {
                format!("Replace executable from staged asset {from} -> {to}")
            }
            crate::update_apply_plan::UpdateApplyStep::VerifyInstalledExecutableSha256 {
                path,
                expected_sha256,
            } => format!("Verify installed executable SHA256 at {path} == {expected_sha256}"),
            crate::update_apply_plan::UpdateApplyStep::RollbackByRestoringBackup {
                from_backup,
                to_target,
            } => format!("Rollback by restoring backup {from_backup} -> {to_target}"),
        }
    }

    pub(crate) fn update_apply_plan_summary_rows(
        &self,
        plan: &UpdateApplyPlan,
        evidence: Option<&UpdateApplyPlanEvidenceRecord>,
    ) -> Vec<CoreDisplayRow> {
        vec![
            CoreDisplayRow::new("Status", format!("{:?}", plan.status).to_lowercase()),
            CoreDisplayRow::new("Reason", plan.reason.clone()),
            CoreDisplayRow::new("Release", format!("{} @ {}", plan.repo, plan.release_tag)),
            CoreDisplayRow::new(
                "Target exe",
                plan.target_exe_path.as_deref().unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Backup exe",
                plan.backup_exe_path.as_deref().unwrap_or("not planned"),
            ),
            CoreDisplayRow::new("Reversible", plan.reversible.to_string()),
            CoreDisplayRow::new("No mutation", plan.no_mutation.to_string()),
            CoreDisplayRow::new(
                "Evidence path",
                evidence
                    .and_then(|record| record.evidence_path.as_deref())
                    .unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new("Steps", plan.steps.len().to_string()),
        ]
    }

    pub(crate) fn update_apply_plan_step_rows(&self, plan: &UpdateApplyPlan) -> Vec<String> {
        plan.steps
            .iter()
            .enumerate()
            .map(|(idx, step)| format!("{}: {}", idx + 1, self.describe_update_apply_step(step)))
            .collect()
    }

    pub(crate) fn update_apply_plan_evidence_warning(
        &self,
        evidence: Option<&UpdateApplyPlanEvidenceRecord>,
    ) -> Option<String> {
        evidence
            .and_then(|record| record.write_error.as_deref())
            .map(|error| format!("Evidence write warning: {error}"))
    }

    pub(crate) fn update_apply_plan_evidence_action(
        &self,
        evidence: Option<&UpdateApplyPlanEvidenceRecord>,
    ) -> Option<CorePathAction> {
        evidence
            .and_then(|record| record.evidence_path.as_ref())
            .map(|path| {
                CorePathAction::file(
                    "📄 Open apply plan evidence",
                    path.clone(),
                    "Apply plan evidence path is recorded but not present on disk.",
                )
            })
    }

    pub(crate) fn update_apply_plan_missing_evidence_message(
        &self,
        evidence: Option<&UpdateApplyPlanEvidenceRecord>,
    ) -> Option<&'static str> {
        if evidence.is_none() {
            Some("Apply plan evidence is not recorded for this preview.")
        } else {
            None
        }
    }

    pub(crate) fn update_apply_fixture_summary_rows(
        &self,
        record: &UpdateApplyFixtureEvidenceRecord,
    ) -> Vec<CoreDisplayRow> {
        vec![
            CoreDisplayRow::new("Status", format!("{:?}", record.status).to_lowercase()),
            CoreDisplayRow::new("Reason", record.reason.clone()),
            CoreDisplayRow::new(
                "Release",
                format!("{} @ {}", record.plan.repo, record.plan.release_tag),
            ),
            CoreDisplayRow::new("Fixture only", record.fixture_only.to_string()),
            CoreDisplayRow::new("No live mutation", record.no_live_mutation.to_string()),
            CoreDisplayRow::new("Rollback ok", record.rollback_ok.to_string()),
            CoreDisplayRow::new(
                "Target fixture",
                record
                    .target_fixture_path
                    .as_deref()
                    .unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Backup",
                record.backup_path.as_deref().unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Expected SHA256",
                record.expected_sha256.as_deref().unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Installed SHA256",
                record.installed_sha256.as_deref().unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Rollback SHA256",
                record.rollback_sha256.as_deref().unwrap_or("not recorded"),
            ),
            CoreDisplayRow::new(
                "Evidence path",
                record.evidence_path.as_deref().unwrap_or("not recorded"),
            ),
        ]
    }

    pub(crate) fn update_apply_fixture_evidence_warning(
        &self,
        record: &UpdateApplyFixtureEvidenceRecord,
    ) -> Option<String> {
        record
            .write_error
            .as_deref()
            .map(|error| format!("Evidence write warning: {error}"))
    }

    pub(crate) fn update_apply_fixture_evidence_action(
        &self,
        record: &UpdateApplyFixtureEvidenceRecord,
    ) -> Option<CorePathAction> {
        record.evidence_path.as_ref().map(|path| {
            CorePathAction::file(
                "📄 Open fixture apply evidence",
                path.clone(),
                "Fixture apply evidence path is recorded but not present on disk.",
            )
        })
    }

    pub(crate) fn verification_plan_from_download_context(
        &self,
        release: Option<&ResolvedRelease>,
        asset_index: Option<usize>,
    ) -> Result<Option<DownloadVerificationPlan>, String> {
        match (release, asset_index) {
            (None, None) => Ok(None),
            (Some(release), Some(idx)) => {
                if release.assets.get(idx).is_none() {
                    return Err(format!(
                        "Download verification context is invalid: asset index {idx} is out of range (assets={})",
                        release.assets.len()
                    ));
                }
                Ok(self.verification_plan_for_selected_asset(release, idx))
            }
            _ => Err(
                "Download verification context is inconsistent (release + asset index must be both set or both absent)"
                    .to_string(),
            ),
        }
    }

    pub(crate) fn resolve_release_context_for_download_best_effort(
        &self,
        client: &Client,
        effective_url: &str,
        asset_name: &str,
    ) -> Option<(ResolvedRelease, usize)> {
        let spec = SourceSpec::GitHubReleaseAssetUrl {
            url: effective_url.to_string(),
        };
        let release = self.resolve_source_spec(client, None, &spec).ok()?;
        let idx = release
            .assets
            .iter()
            .position(|asset| asset.browser_download_url == effective_url)
            .or_else(|| {
                release
                    .assets
                    .iter()
                    .position(|asset| asset.name == asset_name)
            })?;
        Some((release, idx))
    }

    pub(crate) fn probe_download_best_effort(
        &self,
        client: &Client,
        url: &str,
    ) -> (DownloadProbe, Option<String>) {
        match crate::download::probe_download(client, url) {
            Ok(probe) => (probe, None),
            Err(e) => (
                DownloadProbe {
                    total: 0,
                    range_supported: false,
                    etag: None,
                    last_modified: None,
                },
                Some(e),
            ),
        }
    }

    pub(crate) fn choose_download_strategy(
        &self,
        history_path: Option<&PathBuf>,
        url: &str,
        probe: &DownloadProbe,
    ) -> SelectedDownloadStrategy {
        let history_path = history_path.cloned();
        let history = crate::history::load_bench_history(&history_path, url, probe);
        crate::bench::choose_history_backed_strategy(probe, &history)
    }

    pub(crate) fn download_with_strategy_contract(
        &self,
        input: DownloadWithStrategyContractInput<'_>,
    ) -> Result<(), String> {
        let DownloadWithStrategyContractInput {
            client,
            url,
            save_path,
            probe,
            strategy,
            ctrl,
            progress_tx,
        } = input;
        if let Err(e) = crate::download::download_with_strategy(
            client,
            url,
            save_path,
            probe,
            strategy,
            ctrl,
            progress_tx,
        ) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = self.append_line(
                Path::new("download_error.log"),
                &format!("[{ts}] download_with_strategy error: {e}"),
            );
            let _ = progress_tx.send((0, 0, 0.0, 0.0));
            return Err(e);
        }

        // Ensure the UI sees a non-error completion progress event even when the probe could
        // not determine a total size (probe.total == 0). Otherwise the (0,0) sentinel would
        // be indistinguishable from failure.
        let downloaded_bytes = std::fs::metadata(save_path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        let done_total = if downloaded_bytes > 0 {
            downloaded_bytes
        } else if probe.total > 0 {
            probe.total
        } else {
            1
        };
        let _ = progress_tx.send((done_total, done_total, 0.0, 0.0));

        Ok(())
    }

    pub(crate) fn verify_downloaded_file(
        &self,
        client: &Client,
        path: &Path,
        asset_name: &str,
        plan: Option<&DownloadVerificationPlan>,
        source_trust_policy: &SourceTrustPolicyConfig,
    ) -> Result<VerificationReport, String> {
        self.verifier_adapter.verify_downloaded_file(
            client,
            path,
            asset_name,
            plan,
            source_trust_policy,
        )
    }

    pub(crate) fn append_line(&self, path: &Path, line: &str) -> Result<(), String> {
        self.evidence_ledger.append_line(path, line)
    }

    pub(crate) fn append_download_history_best_effort(
        &self,
        input: AppendDownloadHistoryInput<'_>,
    ) -> Option<PathBuf> {
        let AppendDownloadHistoryInput {
            history_path,
            url,
            output,
            probe,
            strategy,
            download_elapsed,
            verification,
        } = input;

        match crate::history::append_download_history(
            &Some(history_path.clone()),
            url,
            output,
            probe,
            strategy,
            download_elapsed,
            verification,
        ) {
            Ok(evidence_path) => evidence_path,
            Err(e) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = self.append_line(
                    Path::new("download_error.log"),
                    &format!("[{ts}] append_download_history error: {e}"),
                );
                None
            }
        }
    }

    pub(crate) fn plan_file_disposition_for_report(
        &self,
        path: &Path,
        report: &VerificationReport,
        policy: &TrustPolicyConfig,
    ) -> PlannedFileDisposition {
        crate::trust_policy::plan_file_disposition_for_report(path, report, policy)
    }

    pub(crate) fn apply_file_disposition_contract(
        &self,
        plan: &PlannedFileDisposition,
    ) -> Result<AppliedFileDisposition, String> {
        match crate::trust_policy::apply_file_disposition(plan) {
            Ok(applied) => Ok(applied),
            Err(e) => {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let _ = self.append_line(
                    Path::new("download_error.log"),
                    &format!("[{ts}] apply_file_disposition error: {e}"),
                );
                Err(e)
            }
        }
    }

    pub(crate) fn trust_center_snapshot(
        &self,
        report: &crate::verification::VerificationReport,
        evidence_path: Option<&Path>,
        disposition: &AppliedFileDisposition,
        policy_snapshot: &crate::trust_policy::TrustPolicySnapshot,
        publisher_key_source: Option<&str>,
    ) -> crate::trust_center::TrustCenterSnapshot {
        crate::trust_center::trust_center_snapshot(
            report,
            evidence_path,
            disposition,
            policy_snapshot,
            publisher_key_source,
        )
    }

    pub(crate) fn run_download_contract(
        &self,
        input: RunDownloadContractInput<'_>,
    ) -> Result<RunDownloadContractOutput, String> {
        let RunDownloadContractInput {
            settings,
            effective_url,
            save_path,
            asset_name,
            mut verification_release,
            mut verification_asset_index,
            trust_policy,
            publisher_key_source_at_decision,
            history_path,
            ctrl,
            progress_tx,
        } = input;

        let client = match self.build_client(settings, 3600) {
            Ok(client) => client,
            Err(e) => {
                let _ = progress_tx.send((0, 0, 0.0, 0.0));
                return Err(format!("Client build error: {e}"));
            }
        };
        let client = &client;

        crate::url_policy::parse_and_validate_https_github_official_url(
            effective_url,
            "download url",
        )?;

        let (probe, probe_error) = self.probe_download_best_effort(client, effective_url);
        if let Some(e) = probe_error {
            self.log_download_error(&format!("probe_download error: {e}"));
        }

        let strategy = self.choose_download_strategy(Some(&history_path), effective_url, &probe);
        let save_path_str = save_path.to_string_lossy().to_string();
        let download_start = std::time::Instant::now();

        // Best-effort: when the UI provided no release context (direct URL input), try to map a GitHub
        // release asset download URL back to its release, so checksum/provenance verification can run.
        if verification_release.is_none() && verification_asset_index.is_none() {
            if let Some((release, idx)) = self.resolve_release_context_for_download_best_effort(
                client,
                effective_url,
                &asset_name,
            ) {
                verification_release = Some(release);
                verification_asset_index = Some(idx);
            }
        }

        let verification_plan = self.verification_plan_from_download_context(
            verification_release.as_ref(),
            verification_asset_index,
        )?;

        self.download_with_strategy_contract(DownloadWithStrategyContractInput {
            client,
            url: effective_url,
            save_path: &save_path_str,
            probe: &probe,
            strategy: &strategy,
            ctrl,
            progress_tx,
        })?;

        let verification = match self.verify_downloaded_file(
            client,
            &save_path,
            &asset_name,
            verification_plan.as_ref(),
            &trust_policy.source_trust,
        ) {
            Ok(report) => report,
            Err(e) => {
                self.log_download_error(&format!("verify_downloaded_file error: {e}"));
                return Err(format!(
                    "Download completed but SHA256 verification failed: {e}"
                ));
            }
        };

        let disposition_plan =
            self.plan_file_disposition_for_report(&save_path, &verification, &trust_policy);
        let evidence_path = self.append_download_history_best_effort(AppendDownloadHistoryInput {
            history_path: &history_path,
            url: effective_url,
            output: &save_path,
            probe: &probe,
            strategy: &strategy,
            download_elapsed: download_start.elapsed(),
            verification: Some(crate::history::VerificationHistoryContext {
                report: &verification,
                policy: &trust_policy,
                file_disposition: &disposition_plan,
            }),
        });

        let file_disposition = self
            .apply_file_disposition_contract(&disposition_plan)
            .map_err(|e| {
                format!("Download completed but trust policy file disposition failed: {e}")
            })?;

        let policy_snapshot = trust_policy.snapshot();
        let publisher_key_source = if publisher_key_source_at_decision.trim().is_empty() {
            None
        } else {
            Some(publisher_key_source_at_decision.as_str())
        };
        let trust_center = self.trust_center_snapshot(
            &verification,
            evidence_path.as_deref(),
            &file_disposition,
            &policy_snapshot,
            publisher_key_source,
        );

        Ok(RunDownloadContractOutput {
            original_path: save_path,
            trust_center: trust_center.into(),
            evidence_path,
            file_disposition,
        })
    }

    pub(crate) fn check_latest_update_candidate(
        &self,
        client: &Client,
        current_version: &str,
        source_trust_policy: &SourceTrustPolicyConfig,
        evidence_dir: &Path,
        api_base: Option<&str>,
    ) -> UpdateCandidateCheckReport {
        crate::update_candidate::check_latest_update_candidate(
            client,
            crate::update_candidate::UpdateCandidateCheckConfig {
                current_version,
                source_trust_policy,
                evidence_dir,
                api_base,
            },
        )
    }

    pub(crate) fn refused_update_candidate_check_report(
        &self,
        current_version: &str,
        reason: String,
        evidence_dir: &Path,
    ) -> UpdateCandidateCheckReport {
        crate::update_candidate::refused_update_candidate_check_report(
            current_version,
            reason,
            evidence_dir,
        )
    }

    pub(crate) fn stage_latest_update_candidate(
        &self,
        client: &Client,
        current_version: &str,
        source_trust_policy: &SourceTrustPolicyConfig,
        evidence_dir: &Path,
        stage_root: &Path,
        api_base: Option<&str>,
    ) -> UpdateCandidateStageReport {
        crate::update_candidate::stage_latest_update_candidate(
            client,
            crate::update_candidate::UpdateCandidateStageConfig {
                current_version,
                source_trust_policy,
                evidence_dir,
                stage_root,
                api_base,
            },
        )
    }

    pub(crate) fn refused_update_candidate_stage_report(
        &self,
        current_version: &str,
        reason: String,
        evidence_dir: &Path,
    ) -> UpdateCandidateStageReport {
        crate::update_candidate::refused_update_candidate_stage_report(
            current_version,
            reason,
            evidence_dir,
        )
    }

    pub(crate) fn build_update_apply_plan_for_stage2(
        &self,
        stage_report: &UpdateCandidateStageReport,
        target_exe_path: &Path,
    ) -> UpdateApplyPlan {
        let suffix = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(dur) => format!("{}-{}", dur.as_secs(), std::process::id()),
            Err(_) => format!("unknown-{}", std::process::id()),
        };
        crate::update_apply_plan::build_update_apply_plan(stage_report, target_exe_path, &suffix)
    }

    pub(crate) fn current_exe_update_apply_plan_for_stage2(
        &self,
        stage_report: &UpdateCandidateStageReport,
    ) -> Result<UpdateApplyPlan, String> {
        let target_exe_path = std::env::current_exe()
            .map_err(|e| format!("current executable path unavailable: {e}"))?;
        Ok(self.build_update_apply_plan_for_stage2(stage_report, &target_exe_path))
    }

    pub(crate) fn record_update_apply_plan_evidence_for_stage2(
        &self,
        stage_report: &UpdateCandidateStageReport,
        target_exe_path: &Path,
    ) -> UpdateApplyPlanEvidenceRecord {
        crate::update_apply_plan::write_update_apply_plan_evidence_for_stage2(
            stage_report,
            target_exe_path,
        )
    }

    pub(crate) fn record_update_apply_plan_evidence_for_current_exe(
        &self,
        stage_report: &UpdateCandidateStageReport,
    ) -> Result<UpdateApplyPlanEvidenceRecord, String> {
        let target_exe_path = std::env::current_exe()
            .map_err(|e| format!("current executable path unavailable: {e}"))?;
        Ok(self.record_update_apply_plan_evidence_for_stage2(stage_report, &target_exe_path))
    }

    pub(crate) fn apply_update_fixture_for_stage2(
        &self,
        stage_report: &UpdateCandidateStageReport,
        target_fixture_path: &Path,
    ) -> UpdateApplyFixtureEvidenceRecord {
        crate::update_apply_plan::apply_update_fixture_for_stage2(stage_report, target_fixture_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::releases::{ReleaseAsset, ReleaseQueryKind};
    use std::path::Path;
    use std::sync::{mpsc, Arc, Mutex};

    struct FakeSourceAdapter {
        calls: Arc<Mutex<usize>>,
        release: ResolvedRelease,
    }

    impl SourceAdapter for FakeSourceAdapter {
        fn resolve_release_assets(
            &self,
            _client: &Client,
            _api_base: Option<&str>,
            _spec: &SourceSpec,
        ) -> Result<ResolvedRelease, String> {
            *self.calls.lock().expect("lock") += 1;
            Ok(self.release.clone())
        }
    }

    struct FakeVerifierAdapter {
        plan_calls: Arc<Mutex<usize>>,
        verify_calls: Arc<Mutex<usize>>,
    }

    impl VerifierAdapter for FakeVerifierAdapter {
        fn verification_plan_for_selected_asset(
            &self,
            _release: &ResolvedRelease,
            _asset_index: usize,
        ) -> Option<DownloadVerificationPlan> {
            *self.plan_calls.lock().expect("lock") += 1;
            None
        }

        fn verify_downloaded_file(
            &self,
            _client: &Client,
            _path: &Path,
            _asset_name: &str,
            _plan: Option<&DownloadVerificationPlan>,
            _source_trust_policy: &SourceTrustPolicyConfig,
        ) -> Result<VerificationReport, String> {
            *self.verify_calls.lock().expect("lock") += 1;
            Err("fake verifier".to_string())
        }
    }

    struct FakeEvidenceLedger {
        lines: Arc<Mutex<Vec<String>>>,
    }

    impl EvidenceLedger for FakeEvidenceLedger {
        fn write_text(&self, _path: &Path, text: &str) -> Result<(), String> {
            self.lines
                .lock()
                .expect("lock")
                .push(format!("write:{text}"));
            Ok(())
        }

        fn append_line(&self, _path: &Path, line: &str) -> Result<(), String> {
            self.lines
                .lock()
                .expect("lock")
                .push(format!("append:{line}"));
            Ok(())
        }
    }

    #[test]
    fn core_runtime_new_wires_artifact_decision_seams() {
        let source_calls = Arc::new(Mutex::new(0usize));
        let plan_calls = Arc::new(Mutex::new(0usize));
        let verify_calls = Arc::new(Mutex::new(0usize));
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));

        let release = ResolvedRelease {
            owner: "example".to_string(),
            repo: "repo".to_string(),
            tag_name: "v1.0.0".to_string(),
            name: None,
            html_url: "https://github.com/example/repo/releases/tag/v1.0.0".to_string(),
            assets: vec![ReleaseAsset {
                name: "asset.bin".to_string(),
                size: 0,
                browser_download_url:
                    "https://github.com/example/repo/releases/download/v1.0.0/asset.bin".to_string(),
                content_type: None,
                api_url: None,
            }],
        };
        let runtime = CoreRuntime::new(
            Box::new(FakeSourceAdapter {
                calls: Arc::clone(&source_calls),
                release: release.clone(),
            }),
            Box::new(FakeVerifierAdapter {
                plan_calls: Arc::clone(&plan_calls),
                verify_calls: Arc::clone(&verify_calls),
            }),
            Box::new(FakeEvidenceLedger {
                lines: Arc::clone(&lines),
            }),
        );

        let client = Client::builder()
            .build()
            .expect("reqwest client build should succeed in unit tests");
        let query = ReleaseQuery {
            owner: "example".to_string(),
            repo: "repo".to_string(),
            kind: ReleaseQueryKind::Latest,
        };
        let got = runtime
            .resolve_release_assets(&client, None, &query)
            .expect("fake source adapter should return a release");
        assert_eq!(got, release);
        assert_eq!(*source_calls.lock().expect("lock"), 1);

        let _ = runtime.verification_plan_for_selected_asset(&release, 0);
        assert_eq!(*plan_calls.lock().expect("lock"), 1);

        let policy = SourceTrustPolicyConfig {
            require_trusted_source: true,
            trusted_publisher_key: String::new(),
        };
        let err = runtime
            .verify_downloaded_file(&client, Path::new("fake.bin"), "fake.bin", None, &policy)
            .expect_err("fake verifier returns an error");
        assert_eq!(err, "fake verifier");
        assert_eq!(*verify_calls.lock().expect("lock"), 1);

        runtime
            .append_line(Path::new("fake.log"), "hello")
            .expect("fake ledger should accept append");
        assert_eq!(
            lines.lock().expect("lock").as_slice(),
            ["append:hello".to_string()]
        );
    }

    #[test]
    fn core_runtime_owns_intent_and_verification_summary_routing() {
        let runtime = CoreRuntime::default();

        let intent = runtime.resolve_download_intent(
            "https://github.com/example/repo/releases/download/v1.0.0/asset.bin",
        );
        assert!(matches!(intent, CoreDownloadIntent::DirectDownload { .. }));

        let release = ResolvedRelease {
            owner: "example".to_string(),
            repo: "repo".to_string(),
            tag_name: "v1.0.0".to_string(),
            name: None,
            html_url: "https://github.com/example/repo/releases/tag/v1.0.0".to_string(),
            assets: vec![ReleaseAsset {
                name: "asset.bin".to_string(),
                size: 0,
                browser_download_url:
                    "https://github.com/example/repo/releases/download/v1.0.0/asset.bin".to_string(),
                content_type: None,
                api_url: None,
            }],
        };
        let summary = runtime.verification_source_summary_for_selected_asset(&release, 0);
        assert!(summary.contains("No checksum/provenance assets detected"));
    }

    #[test]
    fn core_runtime_resolves_download_release_context_via_source_adapter() {
        let source_calls = Arc::new(Mutex::new(0usize));
        let asset_url = "https://github.com/example/repo/releases/download/v1.0.0/asset.bin";
        let release = ResolvedRelease {
            owner: "example".to_string(),
            repo: "repo".to_string(),
            tag_name: "v1.0.0".to_string(),
            name: None,
            html_url: "https://github.com/example/repo/releases/tag/v1.0.0".to_string(),
            assets: vec![ReleaseAsset {
                name: "asset.bin".to_string(),
                size: 0,
                browser_download_url: asset_url.to_string(),
                content_type: None,
                api_url: None,
            }],
        };
        let runtime = CoreRuntime::new(
            Box::new(FakeSourceAdapter {
                calls: Arc::clone(&source_calls),
                release,
            }),
            Box::new(FakeVerifierAdapter {
                plan_calls: Arc::new(Mutex::new(0)),
                verify_calls: Arc::new(Mutex::new(0)),
            }),
            Box::new(FakeEvidenceLedger {
                lines: Arc::new(Mutex::new(Vec::new())),
            }),
        );
        let client = Client::builder()
            .build()
            .expect("reqwest client build should succeed in unit tests");

        let (resolved, idx) = runtime
            .resolve_release_context_for_download_best_effort(&client, asset_url, "asset.bin")
            .expect("fake source adapter should map the asset URL back to release context");

        assert_eq!(idx, 0);
        assert_eq!(resolved.assets[0].browser_download_url, asset_url);
        assert_eq!(*source_calls.lock().expect("lock"), 1);
    }

    #[test]
    fn core_runtime_download_contract_owns_url_policy_gate() {
        let runtime = CoreRuntime::default();
        let (tx, _rx) = mpsc::channel();
        let ctrl = Arc::new(DownloadControl::new());

        let result = runtime.run_download_contract(RunDownloadContractInput {
            settings: &CoreClientSettings::new(String::new(), false),
            effective_url: "https://example.com/file.bin",
            save_path: PathBuf::from("target/core-runtime-url-policy.bin"),
            asset_name: "file.bin".to_string(),
            verification_release: None,
            verification_asset_index: None,
            trust_policy: TrustPolicyConfig::default(),
            publisher_key_source_at_decision: String::new(),
            history_path: PathBuf::from("target/core-runtime-url-policy-history.jsonl"),
            ctrl: &ctrl,
            progress_tx: &tx,
        });
        let err = match result {
            Ok(_) => {
                panic!("CoreRuntime should reject non-official artifact hosts before download")
            }
            Err(err) => err,
        };

        assert!(err.contains("unsupported host: example.com"));
    }

    #[test]
    fn core_runtime_build_client_owns_backend_settings() {
        let runtime = CoreRuntime::default();
        let settings = CoreClientSettings::new("not a url".to_string(), false);

        let result = runtime.build_client(&settings, 30);
        let err = match result {
            Ok(_) => panic!("CoreRuntime should reject invalid proxy settings"),
            Err(err) => err,
        };

        assert!(err.contains("Invalid proxy URL"));
    }
}
