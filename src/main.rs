mod backend_contract;
mod bench;
mod download;
mod history;
mod releases;
mod source_trust;
mod staged_release;
mod trust_center;
mod trust_policy;
mod update_candidate;
mod verification;

use backend_contract::{BackendClientSettings, DownloadCompletion};
#[cfg(test)]
use bench::choose_history_backed_strategy;
#[cfg(test)]
use bench::parse_bench_config;
use bench::run_bench_download;
use directories::UserDirs;
#[cfg(test)]
use download::{build_client, probe_download, DownloadProbe};
use download::{build_effective_url, extract_filename, format_speed, sha256_file, DownloadControl};
#[cfg(test)]
use download::{
    download_segmented, download_single, SegmentedDownloadConfig, SEGMENT_CONCURRENCY, SEGMENT_SIZE,
};
use eframe::egui;
use eframe::Storage;
use history::default_history_path;
#[cfg(test)]
use history::BenchHistoryEntry;
use notify_rust::Notification;
use releases::{
    asset_picker_label, is_github_release_asset_download_url, parse_release_query, ResolvedRelease,
};
use reqwest::blocking::Client;
use rfd::FileDialog;
use source_trust::{normalize_public_key_pin, trusted_key_fingerprint, ImportedPublisherKeyPin};
use staged_release::run_staged_release_download_selftest;
use std::env;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use trust_center::{
    publisher_key_source_label_for_policy, trust_center_snapshot, TrustCenterSnapshot,
};
#[cfg(test)]
use trust_policy::FileDispositionAction;
use trust_policy::{
    file_disposition_summary, open_location_button_label_for_report, AppliedFileDisposition,
    MismatchFilePolicy, TrustPolicyConfig, TrustPolicySnapshot,
};
use update_candidate::{
    run_update_candidate_contract_selftest, run_update_candidate_latest_selftest,
    run_update_candidate_stage_selftest, UpdateCandidateCheckReport, UpdateCandidateStageReport,
};
use verification::{
    verification_plan_for_selected_asset, verification_source_summary, DownloadVerificationPlan,
    VerificationReport, VerificationStatus,
};

const RELEASE_PRIVATE_KEY_ENV: &str = "RELEASE_ED25519_PRIVATE_KEY_HEX";
const LEGACY_RELEASE_PRIVATE_KEY_ENV: &str = "GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX";
const RELEASE_PUBLIC_KEY_ASSET: &str = "publisher-key.ed25519.pub";
const SHA256SUMS_ASSET: &str = "SHA256SUMS.txt";
const SHA256SUMS_SIGNATURE_ASSET: &str = "SHA256SUMS.txt.sig";
const PROVENANCE_ASSET: &str = "release-provenance.json";
const PROVENANCE_SIGNATURE_ASSET: &str = "release-provenance.json.sig";
const SIGNATURE_FORMAT: &str = "ed25519-detached-hex";

fn format_download_completion_status(
    report: &VerificationReport,
    disposition: &AppliedFileDisposition,
) -> String {
    let short_hash = report.file_sha256.chars().take(12).collect::<String>();
    let disposition_summary = file_disposition_summary(disposition);
    let source_trust = source_trust_status_summary(report);
    match (report.status.clone(), report.effective_trust_decision()) {
        (VerificationStatus::Verified, verification::VerificationTrustDecision::Block) => format!(
            "❌ Verification BLOCKED · SHA256 matched {} but source authenticity is {} · {} · {}",
            report.source.as_deref().unwrap_or("verification asset"),
            source_trust,
            disposition_summary,
            "retry or open evidence before trusting this file"
        ),
        (VerificationStatus::Verified, _) => format!(
            "✅ Download complete · VERIFIED SHA256={} via {} · source {} · {}",
            short_hash,
            report.source.as_deref().unwrap_or("verification asset"),
            source_trust,
            disposition_summary
        ),
        (VerificationStatus::Mismatch, _) => format!(
            "❌ Verification BLOCKED · MISMATCH SHA256={} expected {} via {} · {} · retry or open evidence before trusting this file",
            short_hash,
            report
                .expected_sha256
                .as_deref()
                .map(|hash| hash.chars().take(12).collect::<String>())
                .unwrap_or_else(|| "unknown".to_string()),
            report.source.as_deref().unwrap_or("verification asset"),
            disposition_summary
        ),
        (VerificationStatus::Unknown, _) => format!(
            "⚠ Verification UNKNOWN risk · SHA256={} · {} · {}",
            short_hash, report.detail, disposition_summary
        ),
    }
}

fn format_download_notification_status(report: &VerificationReport) -> String {
    match (report.status.clone(), report.effective_trust_decision()) {
        (VerificationStatus::Verified, verification::VerificationTrustDecision::Block) => {
            "Download blocked (UNTRUSTED SOURCE)".to_string()
        }
        (VerificationStatus::Verified, _) => "Download complete (VERIFIED)".to_string(),
        (VerificationStatus::Mismatch, _) => "Download blocked (MISMATCH)".to_string(),
        (VerificationStatus::Unknown, _) => {
            "Download saved with UNKNOWN verification risk".to_string()
        }
    }
}

fn source_trust_status_summary(report: &VerificationReport) -> String {
    report
        .source_trust
        .as_ref()
        .map(|trust| {
            let signature = trust
                .signature_asset_name
                .as_deref()
                .map(|asset| format!(" via {asset}"))
                .unwrap_or_default();
            let pin = trust
                .trusted_publisher_key_fingerprint_sha256
                .as_deref()
                .map(|fingerprint| {
                    let short = fingerprint.chars().take(12).collect::<String>();
                    format!(" key={short}")
                })
                .unwrap_or_default();
            format!(
                "{} decision={}{}{}",
                trust.status_label(),
                trust.decision_label(),
                signature,
                pin
            )
        })
        .unwrap_or_else(|| "NOT_APPLICABLE".to_string())
}

fn render_trust_center_snapshot(ui: &mut egui::Ui, snapshot: &TrustCenterSnapshot) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Trust Center").strong());
        egui::Grid::new("trust_center_last_download")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Downloaded asset");
                ui.label(&snapshot.downloaded_asset);
                ui.end_row();

                ui.label("Hash status");
                ui.label(&snapshot.hash_status);
                ui.end_row();

                ui.label("File SHA256");
                ui.label(&snapshot.file_sha256);
                ui.end_row();

                ui.label("Expected SHA256");
                ui.label(&snapshot.expected_sha256);
                ui.end_row();

                ui.label("Source authenticity");
                ui.label(&snapshot.source_authenticity);
                ui.end_row();

                ui.label("Source trust detail");
                ui.label(&snapshot.source_trust_detail);
                ui.end_row();

                ui.label("Verification source");
                ui.label(&snapshot.source_asset);
                ui.end_row();

                ui.label("Signature asset");
                ui.label(&snapshot.signature_asset);
                ui.end_row();

                ui.label("Publisher key fingerprint");
                ui.label(&snapshot.publisher_key_fingerprint);
                ui.end_row();

                ui.label("Publisher key source");
                ui.label(&snapshot.publisher_key_source);
                ui.end_row();

                ui.label("Policy verdict");
                ui.label(&snapshot.policy_verdict);
                ui.end_row();

                ui.label("Policy at decision");
                ui.label(&snapshot.policy_at_decision);
                ui.end_row();

                ui.label("Evidence path");
                ui.label(&snapshot.evidence_path);
                ui.end_row();

                ui.label("Evidence access");
                ui.label(&snapshot.evidence_access);
                ui.end_row();

                ui.label("File disposition");
                ui.label(&snapshot.file_disposition);
                ui.end_row();

                ui.label("Final path");
                ui.label(&snapshot.final_path);
                ui.end_row();
            });
    });
}

fn render_update_candidate_check(ui: &mut egui::Ui, report: &UpdateCandidateCheckReport) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Trust Center · Self-update Stage 1").strong());
        ui.small(
            "Backend/core verdict only: no install, no exe replacement, no system persistence.",
        );
        egui::Grid::new("trust_center_update_candidate")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Status");
                ui.label(report.status_display());
                ui.end_row();

                ui.label("Release");
                ui.label(format!("{} @ {}", report.repo, report.release_tag));
                ui.end_row();

                ui.label("Asset");
                ui.label(&report.asset_name);
                ui.end_row();

                ui.label("Reason");
                ui.label(&report.evaluation.reason);
                ui.end_row();

                ui.label("refusal_reason");
                ui.label(report.refusal_reason().unwrap_or("none"));
                ui.end_row();

                ui.label("Publisher fingerprint");
                ui.label(
                    report
                        .publisher_key_fingerprint_sha256()
                        .unwrap_or("not available"),
                );
                ui.end_row();

                ui.label("Evidence path");
                ui.label(
                    report
                        .evaluation
                        .evidence_path
                        .as_deref()
                        .unwrap_or("not recorded"),
                );
                ui.end_row();

                ui.label("No mutation");
                ui.label(report.evaluation.no_mutation.to_string());
                ui.end_row();
            });

        if let Some(error) = &report.evidence_write_error {
            ui.colored_label(
                egui::Color32::from_rgb(220, 160, 0),
                format!("Evidence write warning: {error}"),
            );
        }
        if let Some(path) = report.evaluation.evidence_path.as_deref() {
            let evidence_path = Path::new(path);
            if evidence_path.is_file() {
                if ui.button("📄 Open Update Evidence").clicked() {
                    let _ = open::that(evidence_path);
                }
            } else {
                ui.small("Update evidence path is recorded but not present on disk.");
            }
        }
    });
}

fn render_update_candidate_stage(ui: &mut egui::Ui, report: &UpdateCandidateStageReport) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Self-update Stage 2 (staging)").strong());
        ui.small("No install: stages a verified candidate to a local folder and records evidence.");

        egui::Grid::new("trust_center_update_stage")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Status");
                ui.label(format!("{:?}", report.status).to_lowercase());
                ui.end_row();

                ui.label("Release");
                ui.label(format!("{} @ {}", report.repo, report.release_tag));
                ui.end_row();

                ui.label("Reason");
                ui.label(&report.reason);
                ui.end_row();

                ui.label("Publisher fingerprint");
                ui.label(
                    report
                        .publisher_key_fingerprint_sha256
                        .as_deref()
                        .unwrap_or("not available"),
                );
                ui.end_row();

                ui.label("Stage dir");
                ui.label(report.stage_dir.as_deref().unwrap_or("not staged"));
                ui.end_row();

                ui.label("Staged asset");
                ui.label(report.staged_asset_path.as_deref().unwrap_or("none"));
                ui.end_row();

                ui.label("Expected SHA256");
                ui.label(report.expected_sha256.as_deref().unwrap_or("unknown"));
                ui.end_row();

                ui.label("Staged SHA256");
                ui.label(report.staged_sha256.as_deref().unwrap_or("unknown"));
                ui.end_row();

                ui.label("Evidence path");
                ui.label(report.evidence_path.as_deref().unwrap_or("not recorded"));
                ui.end_row();
            });

        if let Some(error) = &report.evidence_write_error {
            ui.colored_label(
                egui::Color32::from_rgb(220, 160, 0),
                format!("Evidence write warning: {error}"),
            );
        }

        if let Some(dir) = report.stage_dir.as_deref() {
            let stage_dir = Path::new(dir);
            if stage_dir.is_dir() && ui.button("📁 Open stage folder").clicked() {
                let _ = open::that(stage_dir);
            }
        }
        if let Some(path) = report.evidence_path.as_deref() {
            let evidence_path = Path::new(path);
            if evidence_path.is_file() && ui.button("📄 Open stage evidence").clicked() {
                let _ = open::that(evidence_path);
            }
        }
    });
}

fn import_publisher_key_pin_from_path(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Read publisher public key {}: {e}", path.display()))?;
    normalize_public_key_pin(&text)
}

fn apply_imported_publisher_key_pin(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
    imported: ImportedPublisherKeyPin,
    source_label: impl Into<String>,
) -> String {
    trust_policy.source_trust.trusted_publisher_key = imported.public_key;
    let source_label = source_label.into();
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

fn status_color(status: &str) -> egui::Color32 {
    if status.contains('❌') {
        egui::Color32::from_rgb(220, 70, 70)
    } else if status.contains('⚠') {
        egui::Color32::from_rgb(220, 160, 0)
    } else {
        egui::Color32::from_rgb(0, 180, 0)
    }
}

// ---------------------------------------------------------------------------
// App state and UI constants
// ---------------------------------------------------------------------------

const SPEED_TEST_TIMEOUT_SECS: u64 = 5;

/// Known mirror sites.  First entry must be "Direct (no mirror)"
const MIRRORS: &[(&str, &str)] = &[("Direct (no mirror)", "")];
type ReleaseLookupMessage = (String, Result<ResolvedRelease, String>);
type PublisherKeyImportMessage = (String, Result<ImportedPublisherKeyPin, String>);
type UpdateCandidateCheckMessage = UpdateCandidateCheckReport;
type UpdateCandidateStageMessage = UpdateCandidateStageReport;
type DownloadResultMessage = Result<DownloadCompletion, String>;

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedState {
    selected_mirror: usize,
    save_dir: String,
    proxy: String,
    #[serde(default)]
    allow_invalid_certs: bool,
    #[serde(default = "default_unknown_keep_file")]
    trust_unknown_keep_file: bool,
    #[serde(default)]
    trust_unknown_allow_open: bool,
    #[serde(default)]
    trust_mismatch_file_policy: MismatchFilePolicy,
    #[serde(default)]
    source_trust_require_signed: bool,
    #[serde(default)]
    source_trust_publisher_key: String,
    #[serde(default)]
    source_trust_publisher_key_source: String,
    #[serde(default)]
    history_path: String,
}

fn default_unknown_keep_file() -> bool {
    true
}

struct GhMirrorGui {
    url: String,
    save_dir: PathBuf,
    proxy: String,
    allow_invalid_certs: bool,
    trust_policy: TrustPolicyConfig,
    publisher_key_source: String,
    history_path: String,
    status: String,
    progress: f32,
    speed_text: String,
    elapsed_text: String,
    download_thread: Option<thread::JoinHandle<()>>,
    control: Option<Arc<DownloadControl>>,
    progress_rx: Option<mpsc::Receiver<(u64, u64, f64, f64)>>,
    download_result_rx: Option<mpsc::Receiver<DownloadResultMessage>>,
    // Mirror-related fields
    mirrors: Vec<String>,     // human-readable names
    mirror_urls: Vec<String>, // actual URL prefixes
    selected_mirror: usize,   // index
    speed_test_status: String,
    speed_test_thread: Option<thread::JoinHandle<()>>,
    speed_test_rx: Option<mpsc::Receiver<usize>>,
    speed_test_progress_rx: Option<mpsc::Receiver<(usize, Option<Duration>)>>,
    speed_test_results: Vec<Option<Duration>>,
    speed_test_completed: usize, // how many mirrors have been tested
    // GitHub release discovery
    release_status: String,
    release: Option<ResolvedRelease>,
    selected_release_asset: Option<usize>,
    release_lookup_thread: Option<thread::JoinHandle<()>>,
    release_lookup_rx: Option<mpsc::Receiver<ReleaseLookupMessage>>,
    release_lookup_input: Option<String>,
    publisher_key_import_thread: Option<thread::JoinHandle<()>>,
    publisher_key_import_rx: Option<mpsc::Receiver<PublisherKeyImportMessage>>,
    publisher_key_import_asset_url: Option<String>,
    publisher_key_import_source_label: Option<String>,
    update_candidate_status: String,
    update_candidate_report: Option<UpdateCandidateCheckReport>,
    update_candidate_thread: Option<thread::JoinHandle<()>>,
    update_candidate_rx: Option<mpsc::Receiver<UpdateCandidateCheckMessage>>,
    update_stage_status: String,
    update_stage_report: Option<UpdateCandidateStageReport>,
    update_stage_thread: Option<thread::JoinHandle<()>>,
    update_stage_rx: Option<mpsc::Receiver<UpdateCandidateStageMessage>>,
    // Persisted state
    download_complete_notified: bool,
    last_download_path: Option<PathBuf>,
    last_verification: Option<VerificationReport>,
    last_verification_evidence_path: Option<PathBuf>,
    last_trust_policy_snapshot: Option<TrustPolicySnapshot>,
    last_publisher_key_source_at_decision: Option<String>,
    last_file_disposition: Option<AppliedFileDisposition>,
}

impl GhMirrorGui {
    fn new(storage: Option<&dyn Storage>) -> Self {
        let names: Vec<String> = MIRRORS.iter().map(|(name, _)| name.to_string()).collect();
        let urls: Vec<String> = MIRRORS.iter().map(|(_, url)| url.to_string()).collect();

        // Load persisted state
        let mut selected_mirror = 0usize;
        let mut save_dir = UserDirs::new()
            .and_then(|d| d.download_dir().map(|p| p.to_string_lossy().to_string()))
            .unwrap_or_else(|| ".".to_string());
        let mut proxy = String::new();
        let mut allow_invalid_certs = false;
        let mut trust_policy = TrustPolicyConfig::default();
        let mut publisher_key_source = String::new();
        let mut history_path = String::new();
        if let Some(storage) = storage {
            if let Some(json) = storage.get_string("app_settings") {
                if let Ok(state) = serde_json::from_str::<SavedState>(&json) {
                    selected_mirror = state.selected_mirror;
                    if !state.save_dir.is_empty() {
                        save_dir = state.save_dir;
                    }
                    proxy = state.proxy;
                    allow_invalid_certs = state.allow_invalid_certs;
                    trust_policy = TrustPolicyConfig {
                        unknown_keep_file: state.trust_unknown_keep_file,
                        unknown_allow_open: state.trust_unknown_allow_open,
                        mismatch_file_policy: state.trust_mismatch_file_policy,
                        source_trust: source_trust::SourceTrustPolicyConfig {
                            require_trusted_source: state.source_trust_require_signed,
                            trusted_publisher_key: state.source_trust_publisher_key,
                        },
                    };
                    publisher_key_source = state.source_trust_publisher_key_source;
                    history_path = state.history_path;
                }
            }
        }

        let (final_tx, final_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let test_urls = urls.clone();
        let handle = thread::spawn(move || {
            let best = run_speed_test(&test_urls, &progress_tx);
            let _ = final_tx.send(best);
        });

        Self {
            url: String::new(),
            save_dir: PathBuf::from(&save_dir),
            proxy,
            allow_invalid_certs,
            trust_policy,
            publisher_key_source,
            history_path,
            status: String::from("Ready"),
            progress: 0.0,
            speed_text: String::new(),
            elapsed_text: String::new(),
            download_thread: None,
            control: None,
            progress_rx: None,
            download_result_rx: None,
            mirrors: names,
            mirror_urls: urls,
            selected_mirror,
            speed_test_status: String::from("Testing mirrors..."),
            speed_test_thread: Some(handle),
            speed_test_rx: Some(final_rx),
            speed_test_progress_rx: Some(progress_rx),
            speed_test_results: vec![None; MIRRORS.len()],
            speed_test_completed: 0,
            release_status: String::new(),
            release: None,
            selected_release_asset: None,
            release_lookup_thread: None,
            release_lookup_rx: None,
            release_lookup_input: None,
            publisher_key_import_thread: None,
            publisher_key_import_rx: None,
            publisher_key_import_asset_url: None,
            publisher_key_import_source_label: None,
            update_candidate_status: String::new(),
            update_candidate_report: None,
            update_candidate_thread: None,
            update_candidate_rx: None,
            update_stage_status: String::new(),
            update_stage_report: None,
            update_stage_thread: None,
            update_stage_rx: None,
            download_complete_notified: false,
            last_download_path: None,
            last_verification: None,
            last_verification_evidence_path: None,
            last_trust_policy_snapshot: None,
            last_publisher_key_source_at_decision: None,
            last_file_disposition: None,
        }
    }

    fn retest_mirrors(&mut self) {
        if self.speed_test_thread.is_some() {
            return;
        }
        let (final_tx, final_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let test_urls = self.mirror_urls.clone();
        let handle = thread::spawn(move || {
            let best = run_speed_test(&test_urls, &progress_tx);
            let _ = final_tx.send(best);
        });
        self.speed_test_status = String::from("Testing mirrors...");
        self.speed_test_thread = Some(handle);
        self.speed_test_rx = Some(final_rx);
        self.speed_test_progress_rx = Some(progress_rx);
        self.speed_test_results = vec![None; MIRRORS.len()];
        self.speed_test_completed = 0;
    }

    fn effective_history_path(&self) -> PathBuf {
        history_path_from_setting(&self.history_path)
    }

    fn update_candidate_evidence_dir(&self) -> PathBuf {
        self.effective_history_path()
            .parent()
            .map(|path| path.join("update-candidate-evidence"))
            .unwrap_or_else(|| PathBuf::from("update-candidate-evidence"))
    }

    fn update_candidate_stage_root(&self) -> PathBuf {
        self.effective_history_path()
            .parent()
            .map(|path| path.join("update-candidate-staging"))
            .unwrap_or_else(|| PathBuf::from("update-candidate-staging"))
    }

    fn clear_release_lookup_result(&mut self) {
        self.release = None;
        self.selected_release_asset = None;
        self.release_status.clear();
        self.release_lookup_input = None;
        self.publisher_key_import_thread = None;
        self.publisher_key_import_rx = None;
        self.publisher_key_import_asset_url = None;
        self.publisher_key_import_source_label = None;
    }

    fn start_update_candidate_check(&mut self) {
        if self.update_candidate_thread.is_some() {
            self.update_candidate_status =
                "Self-update candidate check is already running...".to_string();
            return;
        }

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let source_trust_policy = self.trust_policy.source_trust.clone();
        let evidence_dir = self.update_candidate_evidence_dir();
        let (tx, rx) = mpsc::channel::<UpdateCandidateCheckMessage>();
        self.update_candidate_status =
            "Checking latest self-update candidate (no install)...".to_string();
        self.update_candidate_rx = Some(rx);
        self.update_candidate_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let report = backend_contract::run_update_candidate_check(
                &settings,
                env!("CARGO_PKG_VERSION"),
                &source_trust_policy,
                &evidence_dir,
            );
            let _ = tx.send(report);
        }));
    }

    fn start_update_candidate_stage(&mut self) {
        if self.update_stage_thread.is_some() {
            self.update_stage_status = "Update candidate staging is already running...".to_string();
            return;
        }

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let source_trust_policy = self.trust_policy.source_trust.clone();
        let evidence_dir = self.update_candidate_evidence_dir();
        let stage_root = self.update_candidate_stage_root();
        let (tx, rx) = mpsc::channel::<UpdateCandidateStageMessage>();
        self.update_stage_status =
            "Staging latest self-update candidate (no install)...".to_string();
        self.update_stage_rx = Some(rx);
        self.update_stage_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let report = backend_contract::run_update_candidate_stage(
                &settings,
                env!("CARGO_PKG_VERSION"),
                &source_trust_policy,
                &evidence_dir,
                &stage_root,
            );
            let _ = tx.send(report);
        }));
    }

    fn start_release_lookup(&mut self) {
        if self.release_lookup_thread.is_some() {
            self.release_lookup_thread = None;
            self.release_lookup_rx = None;
            self.release_lookup_input = None;
        }

        let input = self.url.trim().to_string();
        let query = match parse_release_query(&input) {
            Ok(query) => query,
            Err(e) => {
                self.release = None;
                self.selected_release_asset = None;
                self.release_status = format!("❌ {e}");
                self.status = self.release_status.clone();
                return;
            }
        };

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let (tx, rx) = mpsc::channel::<ReleaseLookupMessage>();
        let status = format!(
            "Resolving {} {} assets...",
            query.repo_slug(),
            query.selector_label()
        );
        self.release_status = status.clone();
        self.status = status;
        self.release = None;
        self.selected_release_asset = None;
        self.release_lookup_input = Some(input.clone());
        self.release_lookup_rx = Some(rx);
        self.release_lookup_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result = backend_contract::resolve_release_assets_for_query(&settings, &query);
            let _ = tx.send((input, result));
        }));
    }

    fn input_requires_release_asset_choice(&self) -> bool {
        parse_release_query(&self.url).is_ok() && !is_github_release_asset_download_url(&self.url)
    }

    fn selected_release_verification_plan(&self) -> Option<DownloadVerificationPlan> {
        let release = self.release.as_ref()?;
        let asset_index = self.selected_release_asset?;
        verification_plan_for_selected_asset(release, asset_index)
    }

    fn apply_selected_release_asset(&mut self) -> bool {
        let selected = self
            .release
            .as_ref()
            .and_then(|release| {
                self.selected_release_asset
                    .and_then(|idx| release.assets.get(idx))
            })
            .map(|asset| (asset.name.clone(), asset.browser_download_url.clone()));

        if let Some((name, url)) = selected {
            self.url = url;
            self.status = format!("Selected release asset: {name}");
            true
        } else {
            false
        }
    }

    fn start_import_publisher_key_from_selected_release(&mut self) {
        if self.publisher_key_import_thread.is_some() {
            self.status = "Publisher key import is already running...".to_string();
            return;
        }

        let Some((asset, source_label)) = self.release.as_ref().and_then(|release| {
            source_trust::publisher_key_asset(&release.assets)
                .cloned()
                .map(|asset| {
                    let source_label = format!(
                        "GitHub Release {}/{}@{} asset {}",
                        release.owner, release.repo, release.tag_name, asset.name
                    );
                    (asset, source_label)
                })
        }) else {
            self.status =
                "No publisher-key.ed25519.pub asset was found in this release".to_string();
            return;
        };

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let asset_url = asset.browser_download_url.clone();
        let asset_name = asset.name.clone();
        let (tx, rx) = mpsc::channel::<PublisherKeyImportMessage>();
        self.publisher_key_import_asset_url = Some(asset_url.clone());
        self.publisher_key_import_source_label = Some(source_label);
        self.publisher_key_import_rx = Some(rx);
        self.publisher_key_import_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result =
                backend_contract::import_publisher_key_from_release_asset(&settings, &asset);
            let _ = tx.send((asset_url, result));
        }));
        self.status = format!("Importing Ed25519 publisher key from {asset_name}...");
    }

    fn start_download(&mut self) {
        if self.url.trim().is_empty() {
            self.status = String::from("Please enter a URL first");
            return;
        }
        if self.download_thread.is_some() {
            self.status = String::from("Download already in progress");
            return;
        }
        if self.input_requires_release_asset_choice() {
            if self.release_lookup_thread.is_some() {
                self.status = String::from("Release asset lookup is still running...");
                return;
            }
            if self.release.is_none() {
                self.start_release_lookup();
                self.status = String::from("Resolving release assets before download...");
                return;
            }
            if !self.apply_selected_release_asset() {
                self.status = String::from("Choose a release asset first");
                return;
            }
        }

        let save_path = match self.choose_save_path() {
            Some(p) => p,
            None => return,
        };
        let verification_plan = self.selected_release_verification_plan();
        let asset_name = verification_plan
            .as_ref()
            .map(|plan| plan.asset_name.clone())
            .or_else(|| extract_filename(&self.url))
            .unwrap_or_else(|| String::from("download"));

        self.download_complete_notified = false;
        self.last_download_path = None;
        self.last_verification = None;
        self.last_verification_evidence_path = None;
        self.last_trust_policy_snapshot = None;
        self.last_publisher_key_source_at_decision = None;
        self.last_file_disposition = None;
        let control = DownloadControl::new();
        let ctrl = control.clone();
        let effective_url = build_effective_url(&self.mirror_urls[self.selected_mirror], &self.url);
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let trust_policy = self.trust_policy.clone();
        let publisher_key_source_at_decision =
            publisher_key_source_label_for_policy(&trust_policy, &self.publisher_key_source);
        let history_path = self.effective_history_path();
        let (progress_tx, progress_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel::<DownloadResultMessage>();
        self.progress_rx = Some(progress_rx);
        self.download_result_rx = Some(result_rx);

        self.progress = 0.0;
        self.speed_text.clear();
        self.elapsed_text.clear();
        self.status = verification_plan
            .as_ref()
            .map(|plan| format!("Starting download... {}", verification_source_summary(plan)))
            .unwrap_or_else(|| String::from("Starting download... verification will be UNKNOWN"));

        self.download_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result = backend_contract::run_download_contract(
                &settings,
                backend_contract::DownloadContractInput {
                    effective_url,
                    save_path,
                    asset_name,
                    verification_plan,
                    trust_policy,
                    publisher_key_source_at_decision,
                    history_path,
                },
                &ctrl,
                &progress_tx,
            );

            let _ = result_tx.send(result);
        }));

        self.control = Some(control);
    }

    fn choose_save_path(&mut self) -> Option<PathBuf> {
        let default_name = extract_filename(&self.url).unwrap_or_else(|| String::from("download"));
        let file = FileDialog::new()
            .set_directory(&self.save_dir)
            .set_file_name(&default_name)
            .save_file();
        if let Some(path) = file {
            self.save_dir = path.parent().unwrap_or(&self.save_dir).to_path_buf();
            Some(path)
        } else {
            None
        }
    }
}

impl eframe::App for GhMirrorGui {
    fn save(&mut self, storage: &mut dyn Storage) {
        let state = SavedState {
            selected_mirror: self.selected_mirror,
            save_dir: self.save_dir.to_string_lossy().to_string(),
            proxy: self.proxy.clone(),
            allow_invalid_certs: self.allow_invalid_certs,
            trust_unknown_keep_file: self.trust_policy.unknown_keep_file,
            trust_unknown_allow_open: self.trust_policy.unknown_allow_open,
            trust_mismatch_file_policy: self.trust_policy.mismatch_file_policy,
            source_trust_require_signed: self.trust_policy.source_trust.require_trusted_source,
            source_trust_publisher_key: self
                .trust_policy
                .source_trust
                .trusted_publisher_key
                .clone(),
            source_trust_publisher_key_source: self.publisher_key_source.clone(),
            history_path: self.history_path.clone(),
        };
        if let Ok(json) = serde_json::to_string(&state) {
            storage.set_string("app_settings", json);
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Check for speed test completion
        if let Some(rx) = &self.speed_test_rx {
            if let Ok(best_idx) = rx.try_recv() {
                self.selected_mirror = best_idx;
                self.speed_test_status = if best_idx > 0 {
                    let best_name = &self.mirrors[best_idx];
                    let best_time = self.speed_test_results[best_idx]
                        .map(|d| format!("{:.0}ms", d.as_secs_f64() * 1000.0))
                        .unwrap_or_else(|| String::from("N/A"));
                    format!("✅ Best: {} ({})", best_name, best_time)
                } else {
                    String::from("⚠ Direct is fastest (no mirror)")
                };
                self.speed_test_thread = None;
                self.speed_test_rx = None;
            }
        }

        // Process per-mirror progress
        if let Some(rx) = &self.speed_test_progress_rx {
            while let Ok((idx, duration_opt)) = rx.try_recv() {
                self.speed_test_results[idx] = duration_opt;
                self.speed_test_completed += 1;
                if self.speed_test_completed >= self.mirrors.len() {
                    self.speed_test_status = String::from("✅ All mirrors tested");
                }
            }
        }

        // Process GitHub release discovery result
        if let Some(rx) = &self.release_lookup_rx {
            if let Ok((input, result)) = rx.try_recv() {
                let is_current = self.release_lookup_input.as_deref() == Some(input.as_str());
                self.release_lookup_thread = None;
                self.release_lookup_rx = None;
                self.release_lookup_input = None;

                if is_current {
                    match result {
                        Ok(release) => {
                            let asset_count = release.assets.len();
                            self.selected_release_asset =
                                if asset_count > 0 { Some(0) } else { None };
                            self.release_status = if asset_count > 0 {
                                format!(
                                    "✅ {} assets found for {}/{}@{}",
                                    asset_count, release.owner, release.repo, release.tag_name
                                )
                            } else {
                                format!(
                                    "⚠ No assets found for {}/{}@{}",
                                    release.owner, release.repo, release.tag_name
                                )
                            };
                            self.status = self.release_status.clone();
                            self.release = Some(release);
                        }
                        Err(e) => {
                            self.release = None;
                            self.selected_release_asset = None;
                            self.release_status = format!("❌ {e}");
                            self.status = self.release_status.clone();
                        }
                    }
                }
            }
        }

        // Process selected-release publisher key import result.
        if let Some(rx) = &self.publisher_key_import_rx {
            if let Ok((asset_url, result)) = rx.try_recv() {
                let is_current =
                    self.publisher_key_import_asset_url.as_deref() == Some(asset_url.as_str());
                self.publisher_key_import_thread = None;
                self.publisher_key_import_rx = None;
                self.publisher_key_import_asset_url = None;
                let source_label = self
                    .publisher_key_import_source_label
                    .take()
                    .unwrap_or_else(|| format!("GitHub Release asset {asset_url}"));

                if is_current {
                    match result {
                        Ok(imported) => {
                            self.status = apply_imported_publisher_key_pin(
                                &mut self.trust_policy,
                                &mut self.publisher_key_source,
                                imported,
                                source_label,
                            );
                        }
                        Err(e) => {
                            self.status = format!("❌ Publisher key import failed: {e}");
                        }
                    }
                }
            }
        }

        // Process latest self-update candidate check result. This is no-mutation:
        // backend/core reports candidate/no-update/refused only; UI just displays it.
        if let Some(rx) = &self.update_candidate_rx {
            if let Ok(report) = rx.try_recv() {
                self.update_candidate_thread = None;
                self.update_candidate_rx = None;
                self.update_candidate_status = format!(
                    "Self-update check: {} ({})",
                    report.status_display(),
                    report.evaluation.reason
                );
                self.status = self.update_candidate_status.clone();
                self.update_candidate_report = Some(report);
            }
        }

        // Process self-update Stage 2 staging result. This stage still performs no install:
        // it only stages a verified candidate to a local directory and records evidence.
        if let Some(rx) = &self.update_stage_rx {
            if let Ok(report) = rx.try_recv() {
                self.update_stage_thread = None;
                self.update_stage_rx = None;
                self.update_stage_status =
                    format!("Self-update stage: {:?} ({})", report.status, report.reason);
                self.status = self.update_stage_status.clone();
                self.update_stage_report = Some(report);
            }
        }

        // Process download progress
        let progress_rx = self.progress_rx.take();
        if let Some(rx) = progress_rx {
            let mut keep_progress_rx = true;
            while let Ok((downloaded, total, speed, elapsed)) = rx.try_recv() {
                if total > 0 {
                    self.progress = (downloaded as f32) / (total as f32);
                }
                if downloaded == 0 && total == 0 {
                    // Error state
                    self.status = String::from("❌ Download failed");
                    self.download_thread = None;
                    self.control = None;
                    keep_progress_rx = false;
                } else if downloaded >= total && total > 0 {
                    self.progress = 1.0;
                    self.status = String::from("Download complete; verifying SHA256...");
                    self.speed_text.clear();
                    self.elapsed_text.clear();
                    keep_progress_rx = false;
                } else {
                    self.speed_text = format_speed(speed);
                    let total_min = elapsed / 60.0;
                    let total_sec = elapsed % 60.0;
                    self.elapsed_text = format!("{:02.0}:{:04.1}", total_min, total_sec);
                }
            }
            if keep_progress_rx && self.download_thread.is_some() {
                self.progress_rx = Some(rx);
            }
        }

        // Process final download result including checksum/provenance verification.
        let download_result_rx = self.download_result_rx.take();
        if let Some(rx) = download_result_rx {
            match rx.try_recv() {
                Ok(Ok(completion)) => {
                    self.status = format_download_completion_status(
                        &completion.verification,
                        &completion.file_disposition,
                    );
                    self.last_download_path = completion.file_disposition.final_path.clone();
                    self.last_verification = Some(completion.verification.clone());
                    self.last_verification_evidence_path = completion.evidence_path.clone();
                    self.last_trust_policy_snapshot = Some(completion.policy_snapshot.clone());
                    self.last_publisher_key_source_at_decision =
                        Some(completion.publisher_key_source_at_decision.clone());
                    self.last_file_disposition = Some(completion.file_disposition.clone());
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                    if !self.download_complete_notified {
                        self.download_complete_notified = true;
                        let save_path_str = completion
                            .file_disposition
                            .final_path
                            .as_ref()
                            .unwrap_or(&completion.original_path)
                            .to_string_lossy()
                            .to_string();
                        let status = format_download_notification_status(&completion.verification);
                        thread::spawn(move || {
                            let _ = Notification::new()
                                .summary("gh_mirror_gui")
                                .body(&format!("{status}\nSaved to: {save_path_str}"))
                                .show();
                        });
                    }
                }
                Ok(Err(e)) => {
                    self.status = format!("❌ Download failed: {e}");
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.download_result_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = String::from("❌ Download failed: worker exited unexpectedly");
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                }
            }
        }

        // Draw UI
        egui::CentralPanel::default().show(ctx, |ui| {
            // Drag-drop handling
            if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
                let dropped = ctx.input(|i| i.raw.dropped_files.clone());
                if let Some(file) = dropped.first() {
                    if let Some(path_str) = &file.path {
                        self.url = path_str.to_string_lossy().to_string();
                    }
                }
            }

            ui.heading("🚀 GitHub Mirror Downloader");
            ui.separator();

            // URL input
            ui.horizontal(|ui| {
                ui.label("URL:");
                let url_response = ui.text_edit_singleline(&mut self.url);
                if url_response.changed() {
                    self.clear_release_lookup_result();
                }
                if url_response.lost_focus()
                    && ui.input(|i| i.key_pressed(egui::Key::Enter))
                    && parse_release_query(&self.url).is_ok()
                {
                    self.start_release_lookup();
                }
                if ui.button("📋 Paste").clicked() {
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        if let Ok(text) = clipboard.get_text() {
                            self.url = text;
                            self.clear_release_lookup_result();
                            if parse_release_query(&self.url).is_ok() {
                                self.start_release_lookup();
                            }
                        }
                    }
                }
                if ui.button("🗑 Clear").clicked() {
                    self.url.clear();
                    self.clear_release_lookup_result();
                }
            });

            // GitHub release discovery and asset picker
            ui.horizontal(|ui| {
                if ui.button("🔎 Find release assets").clicked() {
                    self.start_release_lookup();
                }
                if self.release_lookup_thread.is_some() {
                    ui.label("⏳ Resolving release assets...");
                } else if !self.release_status.is_empty() {
                    ui.label(egui::RichText::new(&self.release_status).strong());
                }
            });

            if let Some(release) = self.release.clone() {
                ui.group(|ui| {
                    let release_name = release
                        .name
                        .as_ref()
                        .filter(|name| !name.trim().is_empty())
                        .map(|name| format!(" - {name}"))
                        .unwrap_or_default();
                    ui.label(format!(
                        "Release: {}/{} @ {}{}",
                        release.owner, release.repo, release.tag_name, release_name
                    ));

                    if let Some(publisher_key_asset) =
                        source_trust::publisher_key_asset(&release.assets)
                    {
                        ui.horizontal(|ui| {
                            ui.label(format!("Publisher key: {}", publisher_key_asset.name));
                            let importing = self.publisher_key_import_thread.is_some();
                            if ui
                                .add_enabled(
                                    !importing,
                                    egui::Button::new("Pin publisher key from release"),
                                )
                                .clicked()
                            {
                                self.start_import_publisher_key_from_selected_release();
                            }
                            if importing {
                                ui.label("⏳ Importing...");
                            }
                        });
                    } else {
                        ui.small("No publisher-key.ed25519.pub asset detected for one-click pinning.");
                    }

                    if release.assets.is_empty() {
                        ui.label("This release has no downloadable assets.");
                    } else {
                        if self
                            .selected_release_asset
                            .map(|idx| idx >= release.assets.len())
                            .unwrap_or(true)
                        {
                            self.selected_release_asset = Some(0);
                        }
                        let selected_idx = self.selected_release_asset.unwrap_or(0);
                        let selected_text = asset_picker_label(&release.assets[selected_idx]);

                        ui.horizontal(|ui| {
                            ui.label("Asset:");
                            egui::ComboBox::from_id_salt("release_asset_select")
                                .selected_text(selected_text)
                                .show_ui(ui, |ui| {
                                    for (idx, asset) in release.assets.iter().enumerate() {
                                        if ui
                                            .selectable_label(
                                                self.selected_release_asset == Some(idx),
                                                asset_picker_label(asset),
                                            )
                                            .clicked()
                                        {
                                            self.selected_release_asset = Some(idx);
                                        }
                                    }
                                });
                            if ui.button("Use selected asset").clicked() {
                                self.apply_selected_release_asset();
                            }
                            if ui.button("Open release").clicked() {
                                let _ = open::that(&release.html_url);
                            }
                        });

                        if let Some(asset) = release.assets.get(selected_idx) {
                            let content_type = asset
                                .content_type
                                .as_deref()
                                .unwrap_or("unknown content type");
                            ui.label(format!("{} · {}", asset_picker_label(asset), content_type));
                            if let Some(plan) =
                                verification_plan_for_selected_asset(&release, selected_idx)
                            {
                                ui.label(verification_source_summary(&plan));
                            }
                            ui.monospace(&asset.browser_download_url);
                        }
                    }
                });
            }

            // Mirror selector + speed test
            ui.horizontal(|ui| {
                ui.label("Mirror:");
                egui::ComboBox::from_id_salt("mirror_select")
                    .selected_text(&self.mirrors[self.selected_mirror])
                    .show_ui(ui, |ui| {
                        for (i, name) in self.mirrors.iter().enumerate() {
                            if ui.selectable_label(false, name).clicked() {
                                self.selected_mirror = i;
                            }
                        }
                    });
                if ui.button("🔄 Retest").clicked() {
                    self.retest_mirrors();
                }
            });

            // Speed test progress
            if self.speed_test_thread.is_some() || self.speed_test_completed > 0 {
                ui.separator();
                if self.speed_test_thread.is_some() {
                    ui.label("⏳ Testing mirrors...");
                } else {
                    ui.label(egui::RichText::new(&self.speed_test_status).strong());
                }
                // Show per-mirror results with color
                let tested = self.speed_test_completed.min(self.mirrors.len());
                if tested > 0 {
                    let pct = (tested as f32) / (self.mirrors.len() as f32);
                    ui.add(egui::ProgressBar::new(pct).text(format!(
                        "{}/{}",
                        tested,
                        self.mirrors.len()
                    )));
                }
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .show(ui, |ui| {
                        for (i, name) in self.mirrors.iter().enumerate() {
                            match &self.speed_test_results[i] {
                                Some(dur) => {
                                    let ms = dur.as_secs_f64() * 1000.0;
                                    let color = latency_color(ms);
                                    let mark = if self.selected_mirror == i
                                        && self.speed_test_thread.is_none()
                                    {
                                        "⭐"
                                    } else {
                                        "  "
                                    };
                                    ui.label(
                                        egui::RichText::new(format!(
                                            "{} {} {:.0} ms",
                                            mark, name, ms
                                        ))
                                        .color(color),
                                    );
                                }
                                None => {
                                    if i < self.speed_test_completed {
                                        ui.label(format!("  {} ❌ timeout", name));
                                    } else {
                                        ui.label(format!("  {} ⏳", name));
                                    }
                                }
                            }
                        }
                    });
            }

            ui.separator();

            // Save directory
            ui.horizontal(|ui| {
                ui.label("Save to:");
                ui.label(self.save_dir.to_string_lossy().to_string());
                if ui.button("📁 Browse...").clicked() {
                    if let Some(dir) = FileDialog::new()
                        .set_directory(&self.save_dir)
                        .pick_folder()
                    {
                        self.save_dir = dir;
                    }
                }
            });

            // Proxy
            ui.horizontal(|ui| {
                ui.label("Proxy:");
                ui.text_edit_singleline(&mut self.proxy);
                if ui.button("🗑 Clear").clicked() {
                    self.proxy.clear();
                }
            });
            ui.horizontal(|ui| {
                ui.checkbox(
                    &mut self.allow_invalid_certs,
                    "Allow invalid TLS certificates (unsafe)",
                );
                if self.allow_invalid_certs {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 180, 0),
                        "Only use this for trusted debugging proxies.",
                    );
                }
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("Trust policy").strong());
                ui.checkbox(
                    &mut self.trust_policy.unknown_keep_file,
                    "Keep UNKNOWN downloads",
                );
                if !self.trust_policy.unknown_keep_file {
                    self.trust_policy.unknown_allow_open = false;
                }
                ui.add_enabled_ui(self.trust_policy.unknown_keep_file, |ui| {
                    ui.checkbox(
                        &mut self.trust_policy.unknown_allow_open,
                        "Allow Open Folder for UNKNOWN downloads",
                    );
                });
                ui.horizontal(|ui| {
                    ui.label("MISMATCH file action:");
                    egui::ComboBox::from_id_salt("mismatch_file_policy")
                        .selected_text(self.trust_policy.mismatch_file_policy.as_str())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.trust_policy.mismatch_file_policy,
                                MismatchFilePolicy::Quarantine,
                                "QUARANTINE",
                            );
                            ui.selectable_value(
                                &mut self.trust_policy.mismatch_file_policy,
                                MismatchFilePolicy::Delete,
                                "DELETE",
                            );
                        });
                });
                ui.separator();
                ui.label(egui::RichText::new("Verification source trust").strong());
                ui.checkbox(
                    &mut self.trust_policy.source_trust.require_trusted_source,
                    "Require signed checksum/provenance source",
                );
                ui.horizontal(|ui| {
                    ui.label("Pinned Ed25519 publisher key:");
                    let publisher_key_before =
                        self.trust_policy.source_trust.trusted_publisher_key.clone();
                    let changed = ui
                        .text_edit_singleline(
                        &mut self.trust_policy.source_trust.trusted_publisher_key,
                        )
                        .changed();
                    if changed
                        && self.trust_policy.source_trust.trusted_publisher_key
                            != publisher_key_before
                    {
                        self.publisher_key_source =
                            "manual/pasted key in Trust policy UI".to_string();
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button("Import public key").clicked() {
                        if let Some(path) = FileDialog::new()
                            .add_filter("Public key", &["pub", "txt"])
                            .pick_file()
                        {
                            match import_publisher_key_pin_from_path(&path) {
                                Ok(pin) => {
                                    self.trust_policy.source_trust.trusted_publisher_key = pin;
                                    self.publisher_key_source =
                                        format!("local file {}", path.display());
                                    let fingerprint = trusted_key_fingerprint(
                                        &self.trust_policy.source_trust.trusted_publisher_key,
                                    )
                                    .unwrap_or_else(|| "unknown".to_string());
                                    let short_fingerprint =
                                        fingerprint.chars().take(12).collect::<String>();
                                    self.status = format!(
                                        "Imported Ed25519 publisher key from {} · fingerprint {}…",
                                        self.publisher_key_source, short_fingerprint
                                    );
                                }
                                Err(e) => {
                                    self.status =
                                        format!("❌ Public key import failed: {e}");
                                }
                            }
                        }
                    }
                    if ui.button("Normalize key").clicked() {
                        match normalize_public_key_pin(
                            &self.trust_policy.source_trust.trusted_publisher_key,
                        ) {
                            Ok(pin) => {
                                self.trust_policy.source_trust.trusted_publisher_key = pin;
                                if self.publisher_key_source.trim().is_empty() {
                                    self.publisher_key_source =
                                        "manual/pasted key normalized locally".to_string();
                                }
                                self.status = "Normalized Ed25519 publisher key".to_string();
                            }
                            Err(e) => {
                                self.status = format!("❌ Publisher key is invalid: {e}");
                            }
                        }
                    }
                    if ui.button("Clear key").clicked() {
                        self.trust_policy.source_trust.trusted_publisher_key.clear();
                        self.publisher_key_source.clear();
                    }
                });
                if let Some(fingerprint) =
                    trusted_key_fingerprint(&self.trust_policy.source_trust.trusted_publisher_key)
                {
                    ui.small(format!("Pinned key SHA256 fingerprint: {fingerprint}"));
                    ui.small(format!(
                        "Pinned key source: {}",
                        publisher_key_source_label_for_policy(
                            &self.trust_policy,
                            &self.publisher_key_source
                        )
                    ));
                } else if self.trust_policy.source_trust.require_trusted_source {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 70, 70),
                        "Required policy needs a pinned Ed25519 public key and .sig source assets.",
                    );
                } else {
                    ui.small("No key pinned: hash verification still works, but source authenticity is not checked.");
                }
                ui.horizontal(|ui| {
                    ui.label("History/evidence path:");
                    ui.text_edit_singleline(&mut self.history_path);
                    if ui.button("Default").clicked() {
                        self.history_path.clear();
                    }
                });
                ui.small(format!(
                    "Effective history: {}",
                    self.effective_history_path().display()
                ));
                ui.small("Open Evidence uses the exact JSON evidence path recorded for the completed download.");
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("Self-update Stage 1").strong());
                ui.small("Checks the public latest release and only reports candidate / no-update / refused.");
                ui.horizontal(|ui| {
                    let running = self.update_candidate_thread.is_some();
                    if ui
                        .add_enabled(
                            !running,
                            egui::Button::new("Check latest self-update candidate"),
                        )
                        .clicked()
                    {
                        self.start_update_candidate_check();
                    }
                    if running {
                        ui.label("⏳ Checking...");
                    } else if !self.update_candidate_status.is_empty() {
                        ui.label(&self.update_candidate_status);
                    }
                });
                if let Some(report) = &self.update_candidate_report {
                    render_update_candidate_check(ui, report);
                }
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new("Self-update Stage 2").strong());
                ui.small("Stages a verified candidate to a local folder (still no install).");
                ui.horizontal(|ui| {
                    let running = self.update_stage_thread.is_some();
                    if ui
                        .add_enabled(!running, egui::Button::new("Stage latest candidate (no install)"))
                        .clicked()
                    {
                        self.start_update_candidate_stage();
                    }
                    if running {
                        ui.label("⏳ Staging...");
                    } else if !self.update_stage_status.is_empty() {
                        ui.label(&self.update_stage_status);
                    }
                });
                if let Some(report) = &self.update_stage_report {
                    render_update_candidate_stage(ui, report);
                }
            });

            // Action buttons
            ui.horizontal(|ui| {
                if ui.button("⬇ Download").clicked() {
                    self.start_download();
                }
                if let Some(ctrl) = &self.control {
                    if ctrl.is_paused() {
                        if ui.button("▶ Resume").clicked() {
                            ctrl.resume();
                        }
                    } else {
                        if ui.button("⏸ Pause").clicked() {
                            ctrl.pause();
                        }
                    }
                    if ui.button("❌ Cancel").clicked() {
                        ctrl.cancel();
                        self.download_thread = None;
                        self.control = None;
                        self.status = String::from("Cancelled");
                    }
                }
            });

            if let Some(report) = self.last_verification.clone() {
                ui.horizontal(|ui| {
                    match (report.status.clone(), report.effective_trust_decision()) {
                        (
                            VerificationStatus::Verified,
                            verification::VerificationTrustDecision::Block,
                        ) => {
                            ui.colored_label(
                                egui::Color32::from_rgb(220, 70, 70),
                                "Blocked: checksum matched, but verification source signature is not trusted.",
                            );
                            if self.download_thread.is_none()
                                && ui.button("🔁 Retry Download").clicked()
                            {
                                self.start_download();
                            }
                        }
                        (VerificationStatus::Mismatch, _) => {
                            ui.colored_label(
                                egui::Color32::from_rgb(220, 70, 70),
                                "Blocked: downloaded file does not match trusted checksum.",
                            );
                            if self.download_thread.is_none()
                                && ui.button("🔁 Retry Download").clicked()
                            {
                                self.start_download();
                            }
                        }
                        (VerificationStatus::Unknown, _) => {
                            ui.colored_label(
                                egui::Color32::from_rgb(220, 160, 0),
                                "Risk: no matching checksum/provenance could verify this file.",
                            );
                        }
                        (VerificationStatus::Verified, _) => {
                            ui.colored_label(
                                egui::Color32::from_rgb(0, 180, 0),
                                "Trusted: checksum/provenance hash and source policy passed.",
                            );
                        }
                    }

                    if let Some(evidence_path) = &self.last_verification_evidence_path {
                        if evidence_path.is_file() {
                            if ui.button("📄 Open Evidence").clicked() {
                                let _ = open::that(evidence_path);
                            }
                        } else {
                            ui.add_enabled(false, egui::Button::new("📄 Evidence Missing"));
                            ui.small(format!(
                                "Evidence path recorded but file is missing: {}",
                                evidence_path.display()
                            ));
                        }
                    }
                    if let (Some(download_path), Some(disposition)) =
                        (&self.last_download_path, &self.last_file_disposition)
                    {
                        if let Some(label) = open_location_button_label_for_report(
                            &report,
                            disposition,
                            &self.trust_policy,
                        ) {
                            if ui.button(label).clicked() {
                                let folder = download_path.parent().unwrap_or(&self.save_dir);
                                if folder.exists() {
                                    let _ = open::that(folder);
                                }
                            }
                        }
                    }
                });
                ui.small(format!(
                    "Source authenticity: {}",
                    source_trust_status_summary(&report)
                ));
                if let Some(disposition) = &self.last_file_disposition {
                    ui.small(file_disposition_summary(disposition));
                    let policy_snapshot = self
                        .last_trust_policy_snapshot
                        .clone()
                        .unwrap_or_else(|| self.trust_policy.snapshot());
                    let snapshot = trust_center_snapshot(
                        &report,
                        self.last_verification_evidence_path.as_deref(),
                        disposition,
                        &policy_snapshot,
                        self.last_publisher_key_source_at_decision.as_deref(),
                    );
                    render_trust_center_snapshot(ui, &snapshot);
                }
            }

            // Progress bar and info — always visible during download
            if self.download_thread.is_some() || self.progress > 0.0 || !self.speed_text.is_empty()
            {
                let pct_text = format!("{:.1}%", self.progress * 100.0);
                ui.add(egui::ProgressBar::new(self.progress).text(pct_text));
                if !self.speed_text.is_empty() || !self.elapsed_text.is_empty() {
                    ui.horizontal(|ui| {
                        ui.label(&self.speed_text);
                        ui.label(&self.elapsed_text);
                    });
                }
            }

            // Status label
            ui.label(egui::RichText::new(&self.status).color(status_color(&self.status)));
        });
    }
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

fn history_path_from_setting(value: &str) -> PathBuf {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        default_history_path()
    } else {
        PathBuf::from(trimmed)
    }
}

fn latency_color(ms: f64) -> egui::Color32 {
    if ms < 200.0 {
        egui::Color32::from_rgb(0, 200, 0) // green
    } else if ms < 500.0 {
        egui::Color32::from_rgb(255, 200, 0) // yellow/orange
    } else {
        egui::Color32::from_rgb(255, 80, 80) // red
    }
}

fn run_speed_test(
    mirror_urls: &[String],
    progress_tx: &mpsc::Sender<(usize, Option<Duration>)>,
) -> usize {
    let client = match Client::builder()
        .timeout(Duration::from_secs(SPEED_TEST_TIMEOUT_SECS))
        .build()
    {
        Ok(c) => c,
        Err(_) => return 0,
    };

    let test_target = "https://github.com";
    let mut best_idx = 0;
    let mut best_time = Duration::from_secs(999);

    for (i, url) in mirror_urls.iter().enumerate() {
        let test_url = if url.is_empty() {
            test_target.to_string()
        } else {
            format!("{}{}", url, test_target)
        };

        let start = Instant::now();
        let result = client.head(&test_url).send();
        let elapsed = start.elapsed();

        if result.is_ok() {
            let _ = progress_tx.send((i, Some(elapsed)));
            if elapsed < best_time {
                best_time = elapsed;
                best_idx = i;
            }
        } else {
            let _ = progress_tx.send((i, None));
        }
    }

    best_idx
}

fn load_release_private_key_seed() -> Result<(String, &'static str), String> {
    for env_name in [RELEASE_PRIVATE_KEY_ENV, LEGACY_RELEASE_PRIVATE_KEY_ENV] {
        if let Ok(value) = env::var(env_name) {
            if !value.trim().is_empty() {
                return Ok((value, env_name));
            }
        }
    }

    Err(format!(
        "{RELEASE_PRIVATE_KEY_ENV} is required (32-byte Ed25519 seed encoded as 64 hex characters)"
    ))
}

fn write_text_file(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create dir error: {e}"))?;
    }
    std::fs::write(path, text).map_err(|e| format!("Write {} error: {e}", path.display()))
}

fn release_signing_required_assets() -> [&'static str; 6] {
    [
        "gh_mirror_gui.exe",
        SHA256SUMS_ASSET,
        SHA256SUMS_SIGNATURE_ASSET,
        PROVENANCE_ASSET,
        PROVENANCE_SIGNATURE_ASSET,
        RELEASE_PUBLIC_KEY_ASSET,
    ]
}

fn run_release_signing_doctor(args: &[String]) -> Result<(), String> {
    let mut fixture_dir = PathBuf::from("target/release-signing-fixture");
    let mut json_out = None;
    let mut public_key_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fixture-dir" => {
                i += 1;
                fixture_dir = args
                    .get(i)
                    .map(PathBuf::from)
                    .ok_or_else(|| "--fixture-dir requires a path".to_string())?;
            }
            "--json" => {
                i += 1;
                json_out = Some(
                    args.get(i)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--json requires a path".to_string())?,
                );
            }
            "--public-key-out" => {
                i += 1;
                public_key_out = Some(
                    args.get(i)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--public-key-out requires a path".to_string())?,
                );
            }
            other => return Err(format!("unknown --release-signing-doctor option: {other}")),
        }
        i += 1;
    }

    let (private_key, private_key_env) = load_release_private_key_seed()?;
    let public_key = source_trust::public_key_from_private_seed(&private_key)?;
    let fingerprint = trusted_key_fingerprint(&public_key)
        .ok_or_else(|| "derived Ed25519 public key fingerprint failed".to_string())?;

    std::fs::create_dir_all(&fixture_dir).map_err(|e| format!("Create fixture dir error: {e}"))?;
    let source_path = fixture_dir.join(SHA256SUMS_ASSET);
    let signature_path = fixture_dir.join(SHA256SUMS_SIGNATURE_ASSET);
    let public_key_path =
        public_key_out.unwrap_or_else(|| fixture_dir.join(RELEASE_PUBLIC_KEY_ASSET));
    let fixture_text = concat!(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "  gh_mirror_gui.exe\n"
    );
    write_text_file(&source_path, fixture_text)?;
    let signature = source_trust::sign_ed25519_detached(fixture_text.as_bytes(), &private_key)?;
    write_text_file(&signature_path, &format!("{signature}\n"))?;
    write_text_file(&public_key_path, &format!("{public_key}\n"))?;
    source_trust::verify_ed25519_detached(fixture_text.as_bytes(), &signature, &public_key)?;

    let report = serde_json::json!({
        "schema_version": 1,
        "ok": true,
        "private_key_env": private_key_env,
        "required_repository_secret": RELEASE_PRIVATE_KEY_ENV,
        "private_key_material": "not_recorded",
        "signature_format": SIGNATURE_FORMAT,
        "public_key": {
            "asset_name": RELEASE_PUBLIC_KEY_ASSET,
            "path": public_key_path,
            "value": public_key,
            "fingerprint_sha256": fingerprint,
        },
        "fixture": {
            "source_asset_name": SHA256SUMS_ASSET,
            "signature_asset_name": SHA256SUMS_SIGNATURE_ASSET,
            "source_path": source_path,
            "signature_path": signature_path,
            "source_bytes_signed": true,
            "signature_hex_chars": signature.len(),
            "verified": true,
        },
        "next_release_required_assets": release_signing_required_assets(),
        "workflow_contract": {
            "refuses_unsigned_release": true,
            "uploads_public_key_pin_asset": RELEASE_PUBLIC_KEY_ASSET,
            "uploads_signature_assets": [
                SHA256SUMS_SIGNATURE_ASSET,
                PROVENANCE_SIGNATURE_ASSET,
            ],
        },
    });
    let pretty_report =
        serde_json::to_string_pretty(&report).map_err(|e| format!("Serialize doctor JSON: {e}"))?;
    if let Some(json_path) = json_out {
        write_text_file(&json_path, &format!("{pretty_report}\n"))?;
    }
    println!("{pretty_report}");
    Ok(())
}

fn run_sign_verification_source(args: &[String]) -> Result<(), String> {
    let mut source = None;
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                i += 1;
                source = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --sign-verification-source option: {other}"
                ))
            }
        }
        i += 1;
    }

    let source = source.ok_or_else(|| "--source is required".to_string())?;
    let out = out.ok_or_else(|| "--out is required".to_string())?;
    let (private_key, _) = load_release_private_key_seed()?;
    let source_bytes =
        std::fs::read(&source).map_err(|e| format!("Read source asset error: {e}"))?;
    let signature = source_trust::sign_ed25519_detached(&source_bytes, &private_key)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create signature dir error: {e}"))?;
    }
    std::fs::write(&out, format!("{signature}\n"))
        .map_err(|e| format!("Write signature asset error: {e}"))?;
    println!(
        "signed verification source {} -> {}",
        source.display(),
        out.display()
    );
    Ok(())
}

fn run_verify_verification_source(args: &[String]) -> Result<(), String> {
    let mut source = None;
    let mut signature = None;
    let mut public_key = None;
    let mut public_key_file = None;
    let mut json_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                i += 1;
                source = args.get(i).map(PathBuf::from);
            }
            "--signature" => {
                i += 1;
                signature = args.get(i).map(PathBuf::from);
            }
            "--public-key" => {
                i += 1;
                public_key = args.get(i).cloned();
            }
            "--public-key-file" => {
                i += 1;
                public_key_file = args.get(i).map(PathBuf::from);
            }
            "--json" => {
                i += 1;
                json_out = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --verify-verification-source option: {other}"
                ))
            }
        }
        i += 1;
    }

    let source = source.ok_or_else(|| "--source is required".to_string())?;
    let signature = signature.ok_or_else(|| "--signature is required".to_string())?;
    if public_key.is_some() == public_key_file.is_some() {
        return Err("provide exactly one of --public-key or --public-key-file".to_string());
    }

    let source_bytes =
        std::fs::read(&source).map_err(|e| format!("Read source asset error: {e}"))?;
    let signature_text = std::fs::read_to_string(&signature)
        .map_err(|e| format!("Read signature asset error: {e}"))?;
    let (public_key_text, public_key_source) = if let Some(path) = public_key_file {
        (
            std::fs::read_to_string(&path)
                .map_err(|e| format!("Read public key asset error: {e}"))?,
            path.display().to_string(),
        )
    } else {
        (
            public_key.expect("checked exactly one public key source"),
            "--public-key".to_string(),
        )
    };
    let public_key = normalize_public_key_pin(&public_key_text)?;
    source_trust::verify_ed25519_detached(&source_bytes, signature_text.trim(), &public_key)?;
    let fingerprint = trusted_key_fingerprint(&public_key)
        .ok_or_else(|| "publisher key fingerprint failed".to_string())?;
    let source_sha256 = sha256_file(&source)?;

    let report = serde_json::json!({
        "schema_version": 1,
        "ok": true,
        "signature_format": SIGNATURE_FORMAT,
        "source": {
            "path": source,
            "size": source_bytes.len(),
            "sha256": source_sha256,
        },
        "signature": {
            "path": signature,
            "hex_chars": signature_text.trim().len(),
            "verified": true,
        },
        "public_key": {
            "source": public_key_source,
            "fingerprint_sha256": fingerprint,
        },
    });
    let pretty_report =
        serde_json::to_string_pretty(&report).map_err(|e| format!("Serialize verify JSON: {e}"))?;
    if let Some(json_path) = json_out {
        write_text_file(&json_path, &format!("{pretty_report}\n"))?;
    }
    println!("{pretty_report}");
    Ok(())
}

fn main() -> Result<(), eframe::Error> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(|s| s.as_str()) == Some("--release-signing-doctor") {
        if let Err(e) = run_release_signing_doctor(&args[1..]) {
            eprintln!("release signing doctor failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--sign-verification-source") {
        if let Err(e) = run_sign_verification_source(&args[1..]) {
            eprintln!("sign verification source failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--verify-verification-source") {
        if let Err(e) = run_verify_verification_source(&args[1..]) {
            eprintln!("verify verification source failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--bench-download") {
        if let Err(e) = run_bench_download(&args[1..]) {
            eprintln!("benchmark failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--staged-release-download-selftest") {
        if let Err(e) = run_staged_release_download_selftest(&args[1..]) {
            eprintln!("staged release download selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-contract-selftest") {
        if let Err(e) = run_update_candidate_contract_selftest(&args[1..]) {
            eprintln!("update candidate contract selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-latest-selftest") {
        if let Err(e) = run_update_candidate_latest_selftest(&args[1..]) {
            eprintln!("update candidate latest selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-stage-selftest") {
        if let Err(e) = run_update_candidate_stage_selftest(&args[1..]) {
            eprintln!("update candidate stage selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 480.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };
    eframe::run_native(
        "GitHub Mirror Downloader",
        options,
        Box::new(|cc| Ok(Box::new(GhMirrorGui::new(cc.storage)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    #[test]
    fn verify_verification_source_cli_accepts_publisher_key_file() {
        let source = unique_test_path("signed-source.txt");
        let signature_path = unique_test_path("signed-source.txt.sig");
        let public_key_path = unique_test_path("publisher-key.ed25519.pub");
        let json_path = unique_test_path("verify-source.json");
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let source_bytes = b"release verification source bytes";
        fs::write(&source, source_bytes).unwrap();
        let signature = source_trust::sign_ed25519_detached(source_bytes, private_key).unwrap();
        let public_key = source_trust::public_key_from_private_seed(private_key).unwrap();
        fs::write(&signature_path, format!("{signature}\n")).unwrap();
        fs::write(&public_key_path, format!("ed25519:{public_key}\n")).unwrap();

        run_verify_verification_source(&[
            "--source".to_string(),
            source.display().to_string(),
            "--signature".to_string(),
            signature_path.display().to_string(),
            "--public-key-file".to_string(),
            public_key_path.display().to_string(),
            "--json".to_string(),
            json_path.display().to_string(),
        ])
        .unwrap();

        let report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["signature"]["verified"], true);
        assert_eq!(
            report["public_key"]["fingerprint_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );

        let _ = fs::remove_file(source);
        let _ = fs::remove_file(signature_path);
        let _ = fs::remove_file(public_key_path);
        let _ = fs::remove_file(json_path);
    }

    #[test]
    fn verify_verification_source_cli_rejects_bad_signature() {
        let source = unique_test_path("bad-signed-source.txt");
        let signature_path = unique_test_path("bad-signed-source.txt.sig");
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let source_bytes = b"release verification source bytes";
        fs::write(&source, source_bytes).unwrap();
        let mut signature = source_trust::sign_ed25519_detached(source_bytes, private_key).unwrap();
        signature.replace_range(0..2, "00");
        let public_key = source_trust::public_key_from_private_seed(private_key).unwrap();
        fs::write(&signature_path, format!("{signature}\n")).unwrap();

        let err = run_verify_verification_source(&[
            "--source".to_string(),
            source.display().to_string(),
            "--signature".to_string(),
            signature_path.display().to_string(),
            "--public-key".to_string(),
            public_key,
        ])
        .unwrap_err();
        assert!(err.contains("invalid Ed25519 signature"));

        let _ = fs::remove_file(source);
        let _ = fs::remove_file(signature_path);
    }

    fn serve_once(body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap();
            let req = String::from_utf8_lossy(&buf[..n]);

            let range_start = req
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("range") {
                        value.trim().strip_prefix("bytes=")?.strip_suffix('-')
                    } else {
                        None
                    }
                })
                .and_then(|start| start.parse::<usize>().ok())
                .unwrap_or(0);

            if range_start > 0 {
                let payload = &body[range_start..];
                let header = format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                    payload.len(),
                    range_start,
                    body.len() - 1,
                    body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(payload).unwrap();
            } else {
                let header = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
        });

        (format!("http://{addr}/file.bin"), handle)
    }

    fn parse_range(req: &str, body_len: usize) -> Option<(usize, usize)> {
        req.lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                if name.eq_ignore_ascii_case("range") {
                    value.trim().strip_prefix("bytes=")
                } else {
                    None
                }
            })
            .and_then(|range| {
                let (start, end) = range.split_once('-')?;
                let start = start.parse::<usize>().ok()?;
                let end = if end.is_empty() {
                    body_len.checked_sub(1)?
                } else {
                    end.parse::<usize>().ok()?
                };
                Some((start, end.min(body_len - 1)))
            })
    }

    fn serve_range_requests(
        body: Vec<u8>,
        expected_requests: usize,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            for _ in 0..expected_requests {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = [0u8; 4096];
                let n = stream.read(&mut buf).unwrap();
                let req = String::from_utf8_lossy(&buf[..n]);
                let method = req
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().next())
                    .unwrap_or("GET");

                if method == "HEAD" {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nETag: \"test-etag\"\r\nLast-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).unwrap();
                    continue;
                }

                if let Some((start, end)) = parse_range(&req, body.len()) {
                    let payload = &body[start..=end];
                    let header = format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nAccept-Ranges: bytes\r\nETag: \"test-etag\"\r\nLast-Modified: Mon, 01 Jan 2024 00:00:00 GMT\r\nConnection: close\r\n\r\n",
                        payload.len(),
                        start,
                        end,
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).unwrap();
                    stream.write_all(payload).unwrap();
                } else {
                    let header = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    stream.write_all(header.as_bytes()).unwrap();
                    stream.write_all(&body).unwrap();
                }
            }
        });

        (format!("http://{addr}/file.bin"), handle)
    }

    fn serve_ignore_range_once(body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        });

        (format!("http://{addr}/file.bin"), handle)
    }

    fn serve_drop_then_once(body: Vec<u8>) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut dropped_stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 256];
            let _ = dropped_stream.read(&mut buf);
            drop(dropped_stream);

            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).unwrap();
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
        });

        (format!("http://{addr}/file.bin"), handle)
    }

    #[test]
    fn url_helpers_cover_direct_and_mirror_cases() {
        assert_eq!(
            extract_filename("https://github.com/owner/repo/releases/download/v1/app.tar.gz"),
            Some("app.tar.gz".to_string())
        );
        assert_eq!(extract_filename("https://github.com/owner/repo/"), None);
        assert_eq!(
            build_effective_url("", "https://github.com/owner/repo"),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            build_effective_url("https://mirror.example/", "https://github.com/owner/repo"),
            "https://mirror.example/https://github.com/owner/repo"
        );
    }

    #[test]
    fn speed_formatting_covers_bytes_kb_and_mb() {
        assert_eq!(format_speed(0.5), "512.0 B/s");
        assert_eq!(format_speed(512.0), "512 KB/s");
        assert_eq!(format_speed(2048.0), "2.0 MB/s");
    }

    #[test]
    fn client_builder_rejects_invalid_proxy_url() {
        let err = build_client("http://127.0.0.1:abc", 5, false).unwrap_err();
        assert!(err.contains("Invalid proxy URL"));
    }

    #[test]
    fn saved_state_defaults_to_safe_tls() {
        let state: SavedState =
            serde_json::from_str(r#"{"selected_mirror":0,"save_dir":"","proxy":""}"#).unwrap();
        assert!(!state.allow_invalid_certs);
        assert!(state.trust_unknown_keep_file);
        assert!(!state.trust_unknown_allow_open);
        assert_eq!(
            state.trust_mismatch_file_policy,
            MismatchFilePolicy::Quarantine
        );
        assert!(!state.source_trust_require_signed);
        assert!(state.source_trust_publisher_key.is_empty());
        assert!(state.source_trust_publisher_key_source.is_empty());
        assert!(state.history_path.is_empty());
    }

    #[test]
    fn saved_state_persists_trust_policy_and_history_path() {
        let state: SavedState = serde_json::from_str(
            r#"{"selected_mirror":0,"save_dir":"C:\\Downloads","proxy":"","allow_invalid_certs":false,"trust_unknown_keep_file":false,"trust_unknown_allow_open":false,"trust_mismatch_file_policy":"DELETE","source_trust_require_signed":true,"source_trust_publisher_key":"D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A","source_trust_publisher_key_source":"GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub","history_path":"C:\\Evidence\\bench-history.jsonl"}"#,
        )
        .unwrap();

        assert!(!state.trust_unknown_keep_file);
        assert!(!state.trust_unknown_allow_open);
        assert_eq!(state.trust_mismatch_file_policy, MismatchFilePolicy::Delete);
        assert!(state.source_trust_require_signed);
        assert_eq!(
            state.source_trust_publisher_key,
            "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
        );
        assert_eq!(
            state.source_trust_publisher_key_source,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub"
        );
        assert_eq!(state.history_path, r"C:\Evidence\bench-history.jsonl");
    }

    #[test]
    fn publisher_key_import_accepts_release_public_key_asset() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = source_trust::public_key_from_private_seed(private_key).unwrap();
        let path = unique_test_path("publisher-key.ed25519.pub");
        fs::write(&path, format!("ed25519:{public_key}\r\n")).unwrap();

        let imported_pin = import_publisher_key_pin_from_path(&path).unwrap();

        assert_eq!(imported_pin, public_key);
        assert!(trusted_key_fingerprint(&imported_pin).is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn publisher_key_import_result_updates_trust_policy_pin_and_status() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = source_trust::public_key_from_private_seed(private_key).unwrap();
        let fingerprint = trusted_key_fingerprint(&public_key).unwrap();
        let imported = ImportedPublisherKeyPin {
            public_key: public_key.clone(),
            fingerprint_sha256: fingerprint.clone(),
            asset_name: "publisher-key.ed25519.pub".to_string(),
        };
        let mut policy = TrustPolicyConfig::default();
        let mut publisher_key_source = String::new();

        let status = apply_imported_publisher_key_pin(
            &mut policy,
            &mut publisher_key_source,
            imported,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub",
        );

        assert_eq!(policy.source_trust.trusted_publisher_key, public_key);
        assert!(status.contains("publisher-key.ed25519.pub"));
        assert!(status.contains(&fingerprint[..12]));
        assert_eq!(
            publisher_key_source,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub"
        );
    }

    #[test]
    fn history_path_setting_uses_default_when_blank_and_custom_when_set() {
        assert_eq!(history_path_from_setting("  "), default_history_path());
        assert_eq!(
            history_path_from_setting(r"C:\Evidence\bench-history.jsonl"),
            PathBuf::from(r"C:\Evidence\bench-history.jsonl")
        );
    }

    #[test]
    fn bench_config_accepts_explicit_unsafe_tls_flag() {
        let config = parse_bench_config(&[
            "--url".to_string(),
            "https://example.test/file.bin".to_string(),
            "--out".to_string(),
            "target/test.bin".to_string(),
            "--allow-invalid-certs".to_string(),
        ])
        .unwrap();
        assert!(config.allow_invalid_certs);
    }

    #[test]
    fn completion_status_makes_mismatch_blocking_and_unknown_risky() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let verified = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: Some(hash.to_string()),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: None,
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };
        let mismatch = VerificationReport {
            status: VerificationStatus::Mismatch,
            asset_name: "app.exe".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: Some(
                "B9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC".to_string(),
            ),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: None,
            detail: "SHA256 mismatch against SHA256SUMS.txt".to_string(),
        };
        let unknown = VerificationReport {
            status: VerificationStatus::Unknown,
            asset_name: "app.exe".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: None,
            source: None,
            source_trust: None,
            detail: "No checksum/provenance assets were detected".to_string(),
        };
        let kept = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("app.exe"),
            final_path: Some(PathBuf::from("app.exe")),
        };
        let quarantined = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: PathBuf::from("app.exe"),
            final_path: Some(PathBuf::from(".gh_mirror_gui-quarantine/app.exe")),
        };

        assert!(format_download_completion_status(&verified, &kept).contains("Download complete"));
        let mismatch_status = format_download_completion_status(&mismatch, &quarantined);
        assert!(mismatch_status.contains("Verification BLOCKED"));
        assert!(!mismatch_status.contains("Download complete"));
        assert!(mismatch_status.contains("file quarantined"));
        assert!(mismatch_status.contains("retry or open evidence"));
        let unknown_status = format_download_completion_status(&unknown, &kept);
        assert!(unknown_status.contains("Verification UNKNOWN risk"));
        assert!(!unknown_status.contains("✅"));
        assert_eq!(
            format_download_notification_status(&mismatch),
            "Download blocked (MISMATCH)"
        );
    }

    #[test]
    fn completion_status_blocks_untrusted_signed_source() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: Some(hash.to_string()),
            source: Some("SHA256SUMS.txt".to_string()),
            source_trust: Some(source_trust::SourceTrustEvidence {
                schema_version: 1,
                status: source_trust::SourceAuthenticityStatus::BadSignature,
                decision: source_trust::SourceTrustDecision::Block,
                required: false,
                source_asset_name: Some("SHA256SUMS.txt".to_string()),
                signature_asset_name: Some("SHA256SUMS.txt.sig".to_string()),
                trusted_publisher_key_fingerprint_sha256: Some("ABCDEF".to_string()),
                detail: "bad signature".to_string(),
            }),
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };
        let quarantined = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: PathBuf::from("app.exe"),
            final_path: Some(PathBuf::from(".gh_mirror_gui-quarantine/app.exe")),
        };

        let status = format_download_completion_status(&report, &quarantined);

        assert!(status.contains("Verification BLOCKED"));
        assert!(status.contains("source authenticity"));
        assert!(status.contains("BAD_SIGNATURE"));
        assert_eq!(
            format_download_notification_status(&report),
            "Download blocked (UNTRUSTED SOURCE)"
        );
    }

    #[test]
    fn history_backed_strategy_prefers_best_matching_full_download() {
        let probe = DownloadProbe {
            total: 32 * 1024 * 1024,
            range_supported: true,
            etag: Some("\"etag\"".to_string()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
        };
        let history = vec![
            BenchHistoryEntry {
                schema_version: 1,
                url: "https://example.test/file.bin".to_string(),
                variant: "seg-c4-s4m".to_string(),
                mode: "segmented".to_string(),
                total_bytes: probe.total,
                segment_size: Some(4 * 1024 * 1024),
                concurrency: Some(4),
                download_ms: 1000,
                avg_mib_s: 20.0,
                sha256: "hash".to_string(),
                verification_status: None,
                verification_trust_decision: None,
                verification_asset_name: None,
                verification_file_sha256: None,
                verification_source: None,
                verification_source_trust: None,
                expected_sha256: None,
                verification_detail: None,
                verification_evidence_path: None,
                verification_policy: None,
                verification_file_disposition: None,
                etag: probe.etag.clone(),
                last_modified: probe.last_modified.clone(),
                recorded_at_epoch_secs: 1,
            },
            BenchHistoryEntry {
                schema_version: 1,
                url: "https://example.test/file.bin".to_string(),
                variant: "seg-c8-s4m".to_string(),
                mode: "segmented".to_string(),
                total_bytes: probe.total,
                segment_size: Some(4 * 1024 * 1024),
                concurrency: Some(8),
                download_ms: 2000,
                avg_mib_s: 10.0,
                sha256: "hash".to_string(),
                verification_status: None,
                verification_trust_decision: None,
                verification_asset_name: None,
                verification_file_sha256: None,
                verification_source: None,
                verification_source_trust: None,
                expected_sha256: None,
                verification_detail: None,
                verification_evidence_path: None,
                verification_policy: None,
                verification_file_disposition: None,
                etag: probe.etag.clone(),
                last_modified: probe.last_modified.clone(),
                recorded_at_epoch_secs: 1,
            },
        ];

        let strategy = choose_history_backed_strategy(&probe, &history);

        assert_eq!(strategy.variant, "seg-c4-s4m");
        assert_eq!(strategy.config.unwrap().concurrency, 4);
        assert_eq!(strategy.config.unwrap().segment_size, 4 * 1024 * 1024);
        assert_eq!(strategy.history_matches, 2);
    }

    #[test]
    fn history_backed_strategy_uses_static_default_without_history() {
        let probe = DownloadProbe {
            total: 32 * 1024 * 1024,
            range_supported: true,
            etag: None,
            last_modified: None,
        };

        let strategy = choose_history_backed_strategy(&probe, &[]);

        assert_eq!(strategy.variant, "seg-c4-s4m");
        assert_eq!(strategy.config.unwrap().concurrency, SEGMENT_CONCURRENCY);
        assert_eq!(strategy.config.unwrap().segment_size, SEGMENT_SIZE);
        assert_eq!(strategy.history_matches, 0);
    }

    #[test]
    fn probe_download_detects_range_support_and_metadata() {
        let body = b"range probe payload".to_vec();
        let (url, server) = serve_range_requests(body.clone(), 2);
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();

        let probe = probe_download(&client, &url).unwrap();

        server.join().unwrap();
        assert_eq!(probe.total, body.len() as u64);
        assert!(probe.range_supported);
        assert_eq!(probe.etag, Some("\"test-etag\"".to_string()));
        assert_eq!(
            probe.last_modified,
            Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string())
        );
    }

    #[test]
    fn download_single_creates_new_temp_file_with_write_access() {
        let body = b"fresh download payload".to_vec();
        let (url, server) = serve_once(body.clone());
        let save_path = unique_test_path("fresh.bin");
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ctrl = DownloadControl::new();
        let (tx, rx) = mpsc::channel();

        download_single(
            &client,
            &url,
            save_path.to_str().unwrap(),
            body.len() as u64,
            &ctrl,
            &tx,
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(fs::read(&save_path).unwrap(), body);
        assert!(rx
            .try_iter()
            .any(|(downloaded, total, _, _)| downloaded > 0 && total == body.len() as u64));
        assert!(!save_path.with_extension("bin.part").exists());
        let _ = fs::remove_file(save_path);
    }

    #[test]
    fn download_single_retries_transient_request_send_failure() {
        let body = b"retry after dropped connection".to_vec();
        let (url, server) = serve_drop_then_once(body.clone());
        let save_path = unique_test_path("retry-send.bin");
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ctrl = DownloadControl::new();
        let (tx, _rx) = mpsc::channel();

        download_single(
            &client,
            &url,
            save_path.to_str().unwrap(),
            body.len() as u64,
            &ctrl,
            &tx,
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(fs::read(&save_path).unwrap(), body);
        let _ = fs::remove_file(save_path);
    }

    #[test]
    fn download_single_restarts_when_resume_range_is_ignored() {
        let body = b"server ignored range and returned full body".to_vec();
        let (url, server) = serve_ignore_range_once(body.clone());
        let save_path = unique_test_path("ignored-range.bin");
        let part_path = format!("{}.part", save_path.to_string_lossy());
        fs::write(&part_path, &body[..7]).unwrap();

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ctrl = DownloadControl::new();
        let (tx, _rx) = mpsc::channel();

        download_single(
            &client,
            &url,
            save_path.to_str().unwrap(),
            body.len() as u64,
            &ctrl,
            &tx,
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(fs::read(&save_path).unwrap(), body);
        assert!(!PathBuf::from(&part_path).exists());
        let _ = fs::remove_file(save_path);
    }

    #[test]
    fn download_segmented_writes_all_ranges_and_removes_resume_meta() {
        let body = (0..=255).cycle().take(1024).collect::<Vec<u8>>();
        let segment_size = 128;
        let request_count = body.len() / segment_size;
        let (url, server) = serve_range_requests(body.clone(), request_count);
        let save_path = unique_test_path("segmented.bin");
        let probe = DownloadProbe {
            total: body.len() as u64,
            range_supported: true,
            etag: Some("\"test-etag\"".to_string()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
        };
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ctrl = DownloadControl::new();
        let (tx, rx) = mpsc::channel();

        download_segmented(
            &client,
            &url,
            save_path.to_str().unwrap(),
            &probe,
            SegmentedDownloadConfig {
                segment_size: segment_size as u64,
                concurrency: 3,
            },
            &ctrl,
            &tx,
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(fs::read(&save_path).unwrap(), body);
        assert!(!PathBuf::from(format!("{}.part", save_path.to_string_lossy())).exists());
        assert!(!PathBuf::from(format!("{}.part.json", save_path.to_string_lossy())).exists());
        assert!(rx
            .try_iter()
            .any(|(downloaded, total, _, _)| downloaded == total && total == body.len() as u64));
        let _ = fs::remove_file(save_path);
    }

    #[test]
    fn download_single_resumes_existing_part_file_with_range_request() {
        let body = b"resume download payload".to_vec();
        let (url, server) = serve_once(body.clone());
        let save_path = unique_test_path("resume.bin");
        let part_path = format!("{}.part", save_path.to_string_lossy());
        fs::write(&part_path, &body[..7]).unwrap();

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ctrl = DownloadControl::new();
        let (tx, _rx) = mpsc::channel();

        download_single(
            &client,
            &url,
            save_path.to_str().unwrap(),
            body.len() as u64,
            &ctrl,
            &tx,
        )
        .unwrap();

        server.join().unwrap();
        assert_eq!(fs::read(&save_path).unwrap(), body);
        assert!(!PathBuf::from(&part_path).exists());
        let _ = fs::remove_file(save_path);
    }
}
