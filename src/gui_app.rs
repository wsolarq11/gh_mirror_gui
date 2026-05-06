use crate::gui_common::{
    apply_imported_publisher_key_pin, import_publisher_key_pin_from_path, status_color,
};
use crate::gui_helpers::{
    asset_picker_label, build_effective_url, extract_filename, format_speed,
    history_path_from_setting, latency_color, run_speed_test,
};
use crate::gui_mirrors::{normalize_mirror_index, MIRRORS, SPEED_TEST_TIMEOUT_SECS};
use crate::gui_trust_center::{
    format_download_completion_status, format_download_notification_status,
    render_trust_center_snapshot, source_trust_status_summary,
};
use crate::gui_update_candidate::{
    render_update_apply_plan_preview, render_update_candidate_check, render_update_candidate_stage,
};
use crate::RELEASE_PUBLIC_KEY_ASSET;
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
use rfd::FileDialog;
use std::env;
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

type ReleaseLookupMessage = (String, Result<ResolvedRelease, String>);
type PublisherKeyImportMessage = (String, Result<ImportedPublisherKeyPin, String>);
type UpdateCandidateCheckMessage = UpdateCandidateCheckReport;
type UpdateCandidateStageMessage = UpdateCandidateStageReport;
type DownloadResultMessage = Result<DownloadCompletion, String>;

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SavedState {
    pub(crate) selected_mirror: usize,
    pub(crate) save_dir: String,
    pub(crate) proxy: String,
    #[serde(default)]
    pub(crate) allow_invalid_certs: bool,
    #[serde(default = "default_unknown_keep_file")]
    pub(crate) trust_unknown_keep_file: bool,
    #[serde(default)]
    pub(crate) trust_unknown_allow_open: bool,
    #[serde(default)]
    pub(crate) trust_mismatch_file_policy: MismatchFilePolicy,
    #[serde(default)]
    pub(crate) source_trust_require_signed: bool,
    #[serde(default)]
    pub(crate) source_trust_publisher_key: String,
    #[serde(default)]
    pub(crate) source_trust_publisher_key_source: String,
    #[serde(default)]
    pub(crate) history_path: String,
}

fn default_unknown_keep_file() -> bool {
    true
}

pub(crate) struct GhMirrorGui {
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
    pub(crate) fn new(storage: Option<&dyn Storage>) -> Self {
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
                let best = run_speed_test(&test_urls, SPEED_TEST_TIMEOUT_SECS, &progress_tx);
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
            let best = run_speed_test(&test_urls, SPEED_TEST_TIMEOUT_SECS, &progress_tx);
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
                    ui.separator();
                    match std::env::current_exe() {
                        Ok(target_exe_path) => {
                            let plan = backend_contract::build_update_apply_plan_for_stage2(
                                report,
                                &target_exe_path,
                            );
                            render_update_apply_plan_preview(ui, &plan);
                        }
                        Err(e) => {
                            ui.small(format!(
                                "Update apply plan preview unavailable (current_exe error): {e}"
                            ));
                        }
                    }
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
