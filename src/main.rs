use backend_contract::{
    AppliedFileDisposition, DownloadControl, ImportedPublisherKeyPin, MismatchFilePolicy,
    ResolvedRelease, TrustCenterSnapshot, TrustPolicyConfig, UpdateCandidateCheckReport,
    UpdateCandidateStageReport,
};
use directories::UserDirs;
use eframe::egui;
use eframe::Storage;
use gh_mirror_gui::backend_contract;
use gh_mirror_gui::backend_contract::{BackendClientSettings, DownloadCompletion};
use notify_rust::Notification;
use reqwest::blocking::Client;
use rfd::FileDialog;
use std::env;
#[cfg(test)]
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

mod gui_common;
use gui_common::apply_imported_publisher_key_pin;
use gui_common::import_publisher_key_pin_from_path;
use gui_common::status_color;

mod gui_trust_center;
use gui_trust_center::format_download_completion_status;
use gui_trust_center::format_download_notification_status;
use gui_trust_center::render_trust_center_snapshot;
use gui_trust_center::source_trust_status_summary;

mod gui_update_candidate;
use gui_update_candidate::render_update_candidate_check;
use gui_update_candidate::render_update_candidate_stage;

const RELEASE_PRIVATE_KEY_ENV: &str = "RELEASE_ED25519_PRIVATE_KEY_HEX";
const LEGACY_RELEASE_PRIVATE_KEY_ENV: &str = "GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX";
const RELEASE_PUBLIC_KEY_ASSET: &str = "publisher-key.ed25519.pub";
const SHA256SUMS_ASSET: &str = "SHA256SUMS.txt";
const SHA256SUMS_SIGNATURE_ASSET: &str = "SHA256SUMS.txt.sig";
const PROVENANCE_ASSET: &str = "release-provenance.json";
const PROVENANCE_SIGNATURE_ASSET: &str = "release-provenance.json.sig";
const SIGNATURE_FORMAT: &str = "ed25519-detached-hex";

// ---------------------------------------------------------------------------
// App state and UI constants
// ---------------------------------------------------------------------------

const SPEED_TEST_TIMEOUT_SECS: u64 = 5;

/// Known mirror sites.  First entry must be "Direct (no mirror)"
const MIRRORS: &[(&str, &str)] = &[("Direct (no mirror)", "")];

fn normalize_mirror_index(index: usize) -> usize {
    if index < MIRRORS.len() {
        index
    } else {
        0
    }
}
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
    last_trust_center_snapshot: Option<TrustCenterSnapshot>,
    last_verification_evidence_path: Option<PathBuf>,
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
                        source_trust: backend_contract::SourceTrustPolicyConfig {
                            require_trusted_source: state.source_trust_require_signed,
                            trusted_publisher_key: state.source_trust_publisher_key,
                        },
                    };
                    publisher_key_source = state.source_trust_publisher_key_source;
                    history_path = state.history_path;
                }
            }
        }

        // Persisted states from older versions might point to a mirror index that no longer exists.
        // Prefer resetting to "Direct (no mirror)" instead of crashing (index out of range).
        selected_mirror = normalize_mirror_index(selected_mirror);

        let (
            speed_test_status,
            speed_test_thread,
            speed_test_rx,
            speed_test_progress_rx,
            speed_test_results,
            speed_test_completed,
        ) = if MIRRORS.len() <= 1 {
            (
                "Direct (no mirror)".to_string(),
                None,
                None,
                None,
                vec![None; MIRRORS.len()],
                MIRRORS.len(),
            )
        } else {
            let (final_tx, final_rx) = mpsc::channel();
            let (progress_tx, progress_rx) = mpsc::channel();
            let test_urls = urls.clone();
            let handle = thread::spawn(move || {
                let best = run_speed_test(&test_urls, &progress_tx);
                let _ = final_tx.send(best);
            });

            (
                "Testing mirrors...".to_string(),
                Some(handle),
                Some(final_rx),
                Some(progress_rx),
                vec![None; MIRRORS.len()],
                0,
            )
        };

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
            speed_test_status,
            speed_test_thread,
            speed_test_rx,
            speed_test_progress_rx,
            speed_test_results,
            speed_test_completed,
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
            last_trust_center_snapshot: None,
            last_verification_evidence_path: None,
            last_file_disposition: None,
        }
    }

    fn retest_mirrors(&mut self) {
        if self.speed_test_thread.is_some() {
            return;
        }
        if MIRRORS.len() <= 1 {
            // No mirrors to test. Keep the UI stable and avoid unnecessary network calls.
            self.selected_mirror = 0;
            self.speed_test_status = "Direct (no mirror)".to_string();
            self.speed_test_thread = None;
            self.speed_test_rx = None;
            self.speed_test_progress_rx = None;
            self.speed_test_results = vec![None; MIRRORS.len()];
            self.speed_test_completed = MIRRORS.len();
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
        let backend_contract::IntentDTO::NeedsAssetPick { query, .. } =
            backend_contract::resolve_download_intent(&input)
        else {
            self.release = None;
            self.selected_release_asset = None;
            self.release_status =
                "❌ GitHub intent did not resolve to a release asset picker input".to_string();
            self.status = self.release_status.clone();
            return;
        };

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let (tx, rx) = mpsc::channel::<ReleaseLookupMessage>();
        let kind_label = match &query.kind {
            backend_contract::ReleaseQueryKind::Latest => "latest".to_string(),
            backend_contract::ReleaseQueryKind::Tag(tag) => format!("tag {tag}"),
        };
        let status = format!(
            "Resolving {}/{} {kind_label} assets...",
            query.owner, query.repo
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
        matches!(
            backend_contract::resolve_download_intent(&self.url),
            backend_contract::IntentDTO::NeedsAssetPick { .. }
        )
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
            release
                .assets
                .iter()
                .find(|asset| asset.name == RELEASE_PUBLIC_KEY_ASSET)
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

        match backend_contract::resolve_download_intent(&self.url) {
            backend_contract::IntentDTO::DirectDownload { spec, .. } => {
                if spec.url != self.url {
                    self.url = spec.url;
                }
            }
            backend_contract::IntentDTO::NeedsAssetPick { .. } => {}
            backend_contract::IntentDTO::Unsupported { reason, .. } => {
                self.status = format!("❌ {reason}");
                return;
            }
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

        let (verification_release, verification_asset_index) =
            match (self.release.clone(), self.selected_release_asset) {
                (Some(release), Some(idx))
                    if release
                        .assets
                        .get(idx)
                        .is_some_and(|asset| asset.browser_download_url == self.url) =>
                {
                    (Some(release), Some(idx))
                }
                _ => (None, None),
            };

        let asset_name = verification_release
            .as_ref()
            .and_then(|release| {
                verification_asset_index
                    .and_then(|idx| release.assets.get(idx).map(|asset| asset.name.clone()))
            })
            .or_else(|| extract_filename(&self.url))
            .unwrap_or_else(|| String::from("download"));

        self.download_complete_notified = false;
        self.last_download_path = None;
        self.last_trust_center_snapshot = None;
        self.last_verification_evidence_path = None;
        self.last_file_disposition = None;
        let control = DownloadControl::new();
        let ctrl = control.clone();
        let effective_url = build_effective_url(&self.mirror_urls[self.selected_mirror], &self.url);
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let trust_policy = self.trust_policy.clone();
        let publisher_key_source_at_decision =
            backend_contract::publisher_key_source_label_for_policy(
                &trust_policy,
                &self.publisher_key_source,
            );
        let history_path = self.effective_history_path();
        let (progress_tx, progress_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel::<DownloadResultMessage>();
        self.progress_rx = Some(progress_rx);
        self.download_result_rx = Some(result_rx);

        self.progress = 0.0;
        self.speed_text.clear();
        self.elapsed_text.clear();
        self.status = verification_release
            .as_ref()
            .and_then(|release| {
                verification_asset_index.map(|idx| {
                    backend_contract::verification_source_summary_for_release_asset(release, idx)
                })
            })
            .map(|summary| format!("Starting download... {summary}"))
            .unwrap_or_else(|| String::from("Starting download... verification will be UNKNOWN"));

        self.download_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result = backend_contract::run_download_contract(
                &settings,
                backend_contract::DownloadContractInput {
                    effective_url,
                    save_path,
                    asset_name,
                    verification_release,
                    verification_asset_index,
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
                        &completion.trust_center,
                        &completion.file_disposition,
                    );
                    self.last_download_path = completion.file_disposition.final_path.clone();
                    self.last_trust_center_snapshot = Some(completion.trust_center.clone());
                    self.last_verification_evidence_path = completion.evidence_path.clone();
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
                        let status = format_download_notification_status(&completion.trust_center);
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
                    && matches!(
                        backend_contract::resolve_download_intent(&self.url),
                        backend_contract::IntentDTO::NeedsAssetPick { .. }
                    )
                {
                    self.start_release_lookup();
                }
                if ui.button("📋 Paste").clicked() {
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        if let Ok(text) = clipboard.get_text() {
                            self.url = text;
                            self.clear_release_lookup_result();
                            if matches!(
                                backend_contract::resolve_download_intent(&self.url),
                                backend_contract::IntentDTO::NeedsAssetPick { .. }
                            ) {
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

                    if let Some(publisher_key_asset) = release
                        .assets
                        .iter()
                        .find(|asset| asset.name == RELEASE_PUBLIC_KEY_ASSET)
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
                            ui.label(backend_contract::verification_source_summary_for_release_asset(
                                &release,
                                selected_idx,
                            ));
                            ui.monospace(&asset.browser_download_url);
                        }
                    }
                });
            }

            // Mirror selector + speed test
            //
            // Route guardrail: this project is not a mirror-list aggregator.
            // Today we ship "Direct (no mirror)" only. Keep the mirror UX hidden unless
            // we intentionally introduce multiple entries again under the same guardrails.
            if self.mirrors.len() > 1 {
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
            }

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
                ui.label(egui::RichText::new("Network policy").strong());
                ui.small("Outbound HTTP(S) requests are restricted to GitHub official artifact hosts (https only).");
                let hosts = backend_contract::official_github_artifact_hosts();
                ui.horizontal(|ui| {
                    if ui.button("Copy allowlist").clicked() {
                        let mut text = String::new();
                        for (i, host) in hosts.iter().enumerate() {
                            if i > 0 {
                                text.push('\n');
                            }
                            text.push_str(host);
                        }
                        ui.ctx().copy_text(text);
                        self.status = "Copied official artifact host allowlist to clipboard".to_string();
                    }
                    ui.small(format!("{} hosts", hosts.len()));
                });
                ui.collapsing("Show allowlist", |ui| {
                    for host in hosts {
                        ui.monospace(*host);
                    }
                });
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
                                    let fingerprint = backend_contract::trusted_key_fingerprint(
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
                        match backend_contract::normalize_public_key_pin(
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
                if let Some(fingerprint) = backend_contract::trusted_key_fingerprint(
                    &self.trust_policy.source_trust.trusted_publisher_key,
                )
                {
                    ui.small(format!("Pinned key SHA256 fingerprint: {fingerprint}"));
                    ui.small(format!(
                        "Pinned key source: {}",
                        backend_contract::publisher_key_source_label_for_policy(
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

            if let Some(snapshot) = self.last_trust_center_snapshot.clone() {
                ui.horizontal(|ui| {
                    match (snapshot.hash_status.as_str(), snapshot.policy_verdict.as_str()) {
                        ("VERIFIED", "BLOCK") => {
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
                        ("MISMATCH", _) => {
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
                        ("UNKNOWN", _) => {
                            ui.colored_label(
                                egui::Color32::from_rgb(220, 160, 0),
                                "Risk: no matching checksum/provenance could verify this file.",
                            );
                        }
                        ("VERIFIED", _) => {
                            ui.colored_label(
                                egui::Color32::from_rgb(0, 180, 0),
                                "Trusted: checksum/provenance hash and source policy passed.",
                            );
                        }
                        _ => {}
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
                        if let Some(label) = backend_contract::open_location_button_label_for_facts(
                            snapshot.hash_status.as_str(),
                            snapshot.policy_verdict.as_str(),
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
                    source_trust_status_summary(&snapshot)
                ));
                if let Some(disposition) = &self.last_file_disposition {
                    ui.small(backend_contract::file_disposition_summary(disposition));
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
        backend_contract::default_history_path()
    } else {
        PathBuf::from(trimmed)
    }
}

fn extract_filename(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(2, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() {
        Some(parts[0].to_string())
    } else {
        None
    }
}

fn build_effective_url(mirror_url: &str, raw_url: &str) -> String {
    if mirror_url.is_empty() {
        raw_url.to_string()
    } else {
        format!("{}{}", mirror_url, raw_url)
    }
}

fn format_speed(speed_kbps: f64) -> String {
    if speed_kbps > 1024.0 {
        format!("{:.1} MB/s", speed_kbps / 1024.0)
    } else if speed_kbps > 1.0 {
        format!("{:.0} KB/s", speed_kbps)
    } else {
        format!("{:.1} B/s", speed_kbps * 1024.0)
    }
}

fn sha256_file(path: &PathBuf) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    const HASH_BUFFER_SIZE: usize = 256 * 1024;

    let mut file = std::fs::File::open(path).map_err(|e| format!("Open hash input error: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        let n = std::io::Read::read(&mut file, &mut buf)
            .map_err(|e| format!("Hash read error: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:X}", hasher.finalize()))
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

fn asset_picker_label(asset: &backend_contract::ReleaseAsset) -> String {
    format!("{} ({})", asset.name, format_asset_size(asset.size))
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
    let public_key = backend_contract::public_key_from_private_seed(&private_key)?;
    let fingerprint = backend_contract::trusted_key_fingerprint(&public_key)
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
    let signature = backend_contract::sign_ed25519_detached(fixture_text.as_bytes(), &private_key)?;
    write_text_file(&signature_path, &format!("{signature}\n"))?;
    write_text_file(&public_key_path, &format!("{public_key}\n"))?;
    backend_contract::verify_ed25519_detached(fixture_text.as_bytes(), &signature, &public_key)?;

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
    let signature = backend_contract::sign_ed25519_detached(&source_bytes, &private_key)?;
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
    let public_key = backend_contract::normalize_public_key_pin(&public_key_text)?;
    backend_contract::verify_ed25519_detached(&source_bytes, signature_text.trim(), &public_key)?;
    let fingerprint = backend_contract::trusted_key_fingerprint(&public_key)
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

fn run_resolve_download_intent(args: &[String]) -> Result<(), String> {
    let mut input = None;
    let mut json_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = args.get(i).cloned();
            }
            "--json" => {
                i += 1;
                json_out = Some(
                    args.get(i)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--json requires a path".to_string())?,
                );
            }
            other if input.is_none() && !other.starts_with("--") => {
                input = Some(other.to_string());
            }
            other => return Err(format!("unknown --resolve-download-intent option: {other}")),
        }
        i += 1;
    }

    let input = input.ok_or_else(|| "--input is required".to_string())?;
    let intent = backend_contract::resolve_download_intent(&input);
    let pretty = serde_json::to_string_pretty(&intent)
        .map_err(|e| format!("Serialize intent JSON error: {e}"))?;
    if let Some(path) = json_out {
        write_text_file(&path, &format!("{pretty}\n"))?;
    }
    println!("{pretty}");
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

    if args.first().map(|s| s.as_str()) == Some("--resolve-download-intent") {
        if let Err(e) = run_resolve_download_intent(&args[1..]) {
            eprintln!("resolve download intent failed: {e}");
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
        if let Err(e) = backend_contract::run_bench_download(&args[1..]) {
            eprintln!("benchmark failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--staged-release-download-selftest") {
        if let Err(e) = backend_contract::run_staged_release_download_selftest(&args[1..]) {
            eprintln!("staged release download selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-contract-selftest") {
        if let Err(e) = backend_contract::run_update_candidate_contract_selftest(&args[1..]) {
            eprintln!("update candidate contract selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-latest-selftest") {
        if let Err(e) = backend_contract::run_update_candidate_latest_selftest(&args[1..]) {
            eprintln!("update candidate latest selftest failed: {e}");
            std::process::exit(2);
        }
        return Ok(());
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-stage-selftest") {
        if let Err(e) = backend_contract::run_update_candidate_stage_selftest(&args[1..]) {
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
    use backend_contract::FileDispositionAction;

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
        let signature = backend_contract::sign_ed25519_detached(source_bytes, private_key).unwrap();
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
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
        let mut signature =
            backend_contract::sign_ed25519_detached(source_bytes, private_key).unwrap();
        signature.replace_range(0..2, "00");
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
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
    fn normalize_mirror_index_resets_out_of_range_to_direct() {
        assert_eq!(normalize_mirror_index(0), 0);
        if MIRRORS.len() > 1 {
            assert_eq!(normalize_mirror_index(1), 1);
        }
        assert_eq!(normalize_mirror_index(MIRRORS.len()), 0);
        assert_eq!(normalize_mirror_index(usize::MAX), 0);
    }

    #[test]
    fn speed_formatting_covers_bytes_kb_and_mb() {
        assert_eq!(format_speed(0.5), "512.0 B/s");
        assert_eq!(format_speed(512.0), "512 KB/s");
        assert_eq!(format_speed(2048.0), "2.0 MB/s");
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
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
        let path = unique_test_path("publisher-key.ed25519.pub");
        fs::write(&path, format!("ed25519:{public_key}\r\n")).unwrap();

        let imported_pin = import_publisher_key_pin_from_path(&path).unwrap();

        assert_eq!(imported_pin, public_key);
        assert!(backend_contract::trusted_key_fingerprint(&imported_pin).is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn publisher_key_import_result_updates_trust_policy_pin_and_status() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
        let fingerprint = backend_contract::trusted_key_fingerprint(&public_key).unwrap();
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
        assert_eq!(
            history_path_from_setting("  "),
            backend_contract::default_history_path()
        );
        assert_eq!(
            history_path_from_setting(r"C:\Evidence\bench-history.jsonl"),
            PathBuf::from(r"C:\Evidence\bench-history.jsonl")
        );
    }

    #[test]
    fn completion_status_makes_mismatch_blocking_and_unknown_risky() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";

        fn mk_snapshot(
            hash: &str,
            hash_status: &str,
            policy_verdict: &str,
            expected_sha256: &str,
            source_authenticity: &str,
        ) -> TrustCenterSnapshot {
            TrustCenterSnapshot {
                downloaded_asset: "app.exe".to_string(),
                hash_status: hash_status.to_string(),
                file_sha256: hash.to_string(),
                expected_sha256: expected_sha256.to_string(),
                source_authenticity: source_authenticity.to_string(),
                source_trust_detail: "n/a".to_string(),
                source_asset: "SHA256SUMS.txt".to_string(),
                signature_asset: "none".to_string(),
                publisher_key_fingerprint: "not pinned".to_string(),
                publisher_key_source: "not recorded".to_string(),
                policy_verdict: policy_verdict.to_string(),
                policy_at_decision: "n/a".to_string(),
                evidence_path: "not recorded".to_string(),
                evidence_access: "not recorded".to_string(),
                file_disposition: "n/a".to_string(),
                final_path: "n/a".to_string(),
            }
        }

        let verified = mk_snapshot(hash, "VERIFIED", "TRUSTED", hash, "NOT_APPLICABLE");
        let mismatch = mk_snapshot(
            hash,
            "MISMATCH",
            "BLOCK",
            "B9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC",
            "NOT_APPLICABLE",
        );
        let unknown = mk_snapshot(hash, "UNKNOWN", "RISK", "not available", "NOT_APPLICABLE");
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
        let report = TrustCenterSnapshot {
            downloaded_asset: "app.exe".to_string(),
            hash_status: "VERIFIED".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: hash.to_string(),
            source_authenticity: "BAD_SIGNATURE".to_string(),
            source_trust_detail: "bad signature".to_string(),
            source_asset: "SHA256SUMS.txt".to_string(),
            signature_asset: "SHA256SUMS.txt.sig".to_string(),
            publisher_key_fingerprint: "ABCDEF".to_string(),
            publisher_key_source: "n/a".to_string(),
            policy_verdict: "BLOCK".to_string(),
            policy_at_decision: "n/a".to_string(),
            evidence_path: "not recorded".to_string(),
            evidence_access: "not recorded".to_string(),
            file_disposition: "n/a".to_string(),
            final_path: "n/a".to_string(),
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
}
