use crate::gui_common::{
    import_publisher_key_pin_from_path, render_backend_path_action, status_color,
};
use crate::gui_helpers::{
    build_effective_url, extract_filename, format_speed, history_path_from_setting, latency_color,
    run_speed_test,
};
use crate::gui_mirrors::{normalize_mirror_index, MIRRORS, SPEED_TEST_TIMEOUT_SECS};
use crate::gui_trust_center::{
    format_download_completion_status, format_download_notification_status,
    render_trust_center_snapshot, source_trust_status_summary,
};
use crate::gui_update_candidate::{
    render_update_apply_bundle_preview, render_update_apply_plan_preview,
    render_update_candidate_check, render_update_candidate_stage,
};
use crate::RELEASE_PUBLIC_KEY_ASSET;
use backend_contract::{
    AppliedFileDisposition, DownloadControl, ImportedPublisherKeyPin, MismatchFilePolicy,
    ResolvedRelease, TrustCenterSnapshot, TrustPolicyConfig, UpdateApplyBundleEvidenceRecord,
    UpdateApplyPlanEvidenceRecord, UpdateCandidateCheckReport, UpdateCandidateStageReport,
};
use directories::UserDirs;
use eframe::egui;
use eframe::Storage;
use gh_mirror_gui::backend_contract;
use gh_mirror_gui::backend_contract::{BackendClientSettings, DownloadCompletion};
use gh_mirror_gui::ui_projection::{
    layout_mode_for_width, project_download_progress, text as ui_text, LayoutMode, ProgressInput,
    ProgressProjection, TextKey, UiLocale,
};
use notify_rust::Notification;
use rfd::FileDialog;
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::Duration;

type ReleaseLookupMessage = (String, Result<ResolvedRelease, String>);
type PublisherKeyImportMessage = (String, Result<ImportedPublisherKeyPin, String>);
type UpdateCandidateCheckMessage = UpdateCandidateCheckReport;
type UpdateCandidateStageMessage = UpdateCandidateStageReport;
type DownloadResultMessage = Result<DownloadCompletion, String>;

fn backend_notice_color(level: backend_contract::BackendStatusNoticeLevel) -> egui::Color32 {
    match level {
        backend_contract::BackendStatusNoticeLevel::Good => egui::Color32::from_rgb(0, 180, 0),
        backend_contract::BackendStatusNoticeLevel::Warning => egui::Color32::from_rgb(220, 160, 0),
        backend_contract::BackendStatusNoticeLevel::Error => egui::Color32::from_rgb(220, 70, 70),
    }
}

fn release_lookup_non_picker_status(input: &str, intent: backend_contract::IntentDTO) -> String {
    match intent {
        backend_contract::IntentDTO::DirectDownload {
            human_readable_label,
            ..
        } => {
            let mut message = format!(
                "ℹ Direct GitHub download detected ({human_readable_label}). Click Download to download this URL; Find release assets only works with repo/release pages."
            );
            if let Some(release_url) = release_picker_url_from_archive_input(input) {
                message.push_str(&format!(
                    " To pick release assets for this tag, use {release_url}."
                ));
            }
            message
        }
        backend_contract::IntentDTO::Unsupported { reason, .. } => format!("❌ {reason}"),
        backend_contract::IntentDTO::NeedsAssetPick { .. } => {
            "Release asset picker input is ready".to_string()
        }
    }
}

fn release_picker_url_from_archive_input(input: &str) -> Option<String> {
    let normalized = if input.starts_with("https://") || input.starts_with("http://") {
        input.to_string()
    } else if input.starts_with("github.com/") || input.starts_with("www.github.com/") {
        format!("https://{input}")
    } else {
        return None;
    };
    let url = reqwest::Url::parse(&normalized).ok()?;
    let host = url.host_str()?.trim_start_matches("www.");
    if host != "github.com" {
        return None;
    }
    let segments = url
        .path_segments()?
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let [owner, repo, archive, refs, tags, tag_parts @ ..] = segments.as_slice() else {
        return None;
    };
    if *archive != "archive" || *refs != "refs" || *tags != "tags" || tag_parts.is_empty() {
        return None;
    }
    let tag = tag_parts.join("/");
    let tag = tag
        .strip_suffix(".tar.gz")
        .or_else(|| tag.strip_suffix(".tar.bz2"))
        .or_else(|| tag.strip_suffix(".zip"))
        .unwrap_or(&tag);
    if tag.is_empty() {
        return None;
    }
    Some(format!(
        "https://github.com/{owner}/{repo}/releases/tag/{tag}"
    ))
}

fn default_proxy_from_environment_or_system() -> Option<String> {
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Ok(value) = std::env::var(name) {
            if let Some(proxy) = normalize_proxy_url(&value, "http") {
                return Some(proxy);
            }
        }
    }
    detect_windows_user_proxy_url()
}

#[cfg(windows)]
fn detect_windows_user_proxy_url() -> Option<String> {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let enabled_output = Command::new("reg")
        .args(["query", key, "/v", "ProxyEnable"])
        .output()
        .ok()?;
    if !enabled_output.status.success() {
        return None;
    }
    let enabled_stdout = String::from_utf8_lossy(&enabled_output.stdout);
    if !reg_dword_enabled(&reg_query_value(&enabled_stdout, "ProxyEnable")?) {
        return None;
    }

    let server_output = Command::new("reg")
        .args(["query", key, "/v", "ProxyServer"])
        .output()
        .ok()?;
    if !server_output.status.success() {
        return None;
    }
    let server_stdout = String::from_utf8_lossy(&server_output.stdout);
    proxy_url_from_windows_proxy_server(&reg_query_value(&server_stdout, "ProxyServer")?)
}

#[cfg(not(windows))]
fn detect_windows_user_proxy_url() -> Option<String> {
    None
}

fn reg_query_value(stdout: &str, name: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with(name) {
            return None;
        }
        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 3 {
            return None;
        }
        Some(parts[2..].join(" "))
    })
}

fn reg_dword_enabled(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("0x1") || value == "1"
}

fn proxy_url_from_windows_proxy_server(value: &str) -> Option<String> {
    let entries = value.split(';').filter_map(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }
        if let Some((kind, address)) = entry.split_once('=') {
            Some((kind.trim().to_ascii_lowercase(), address.trim()))
        } else {
            Some(("http".to_string(), entry))
        }
    });

    let mut fallback = None;
    let mut http = None;
    let mut https = None;
    let mut socks = None;
    for (kind, address) in entries {
        match kind.as_str() {
            "https" => https = normalize_proxy_url(address, "http"),
            "http" => http = normalize_proxy_url(address, "http"),
            "socks" | "socks5" => socks = normalize_proxy_url(address, "socks5"),
            _ if fallback.is_none() => fallback = normalize_proxy_url(address, "http"),
            _ => {}
        }
    }

    https.or(http).or(socks).or(fallback)
}

fn normalize_proxy_url(value: &str, default_scheme: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.contains("://") {
        Some(value.to_string())
    } else {
        Some(format!("{default_scheme}://{value}"))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SavedState {
    pub(crate) selected_mirror: usize,
    pub(crate) save_dir: String,
    pub(crate) proxy: String,
    #[serde(default)]
    pub(crate) locale: UiLocale,
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
    locale: UiLocale,
    allow_invalid_certs: bool,
    trust_policy: TrustPolicyConfig,
    publisher_key_source: String,
    history_path: String,
    status: String,
    progress: f32,
    downloaded_bytes: u64,
    download_total_bytes: Option<u64>,
    download_speed_kib_per_second: f64,
    download_elapsed_seconds: f64,
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
    update_apply_plan_evidence_record: Option<UpdateApplyPlanEvidenceRecord>,
    update_apply_bundle_evidence_record: Option<UpdateApplyBundleEvidenceRecord>,
    update_apply_bundle_status: String,
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
        let mut locale = UiLocale::default();
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
                    locale = state.locale;
                    allow_invalid_certs = state.allow_invalid_certs;
                    trust_policy = backend_contract::trust_policy_from_settings(
                        state.trust_unknown_keep_file,
                        state.trust_unknown_allow_open,
                        state.trust_mismatch_file_policy,
                        state.source_trust_require_signed,
                        state.source_trust_publisher_key,
                    );
                    publisher_key_source = state.source_trust_publisher_key_source;
                    history_path = state.history_path;
                }
            }
        }

        // Persisted states from older versions might point to a mirror index that no longer exists.
        // Prefer resetting to "Direct (no mirror)" instead of crashing (index out of range).
        selected_mirror = normalize_mirror_index(selected_mirror);
        let detected_proxy = if proxy.trim().is_empty() {
            default_proxy_from_environment_or_system()
        } else {
            None
        };
        if let Some(default_proxy) = detected_proxy.as_ref() {
            proxy = default_proxy.clone();
        }
        let status = detected_proxy
            .as_ref()
            .map(|proxy| {
                format!(
                    "{} (system proxy detected: {proxy})",
                    ui_text(locale, TextKey::StatusReady)
                )
            })
            .unwrap_or_else(|| ui_text(locale, TextKey::StatusReady).to_string());

        let (
            speed_test_status,
            speed_test_thread,
            speed_test_rx,
            speed_test_progress_rx,
            speed_test_results,
            speed_test_completed,
        ) = if MIRRORS.len() <= 1 {
            (
                ui_text(locale, TextKey::StatusDirectNoMirror).to_string(),
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
                ui_text(locale, TextKey::StatusTestingMirrors).to_string(),
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
            locale,
            allow_invalid_certs,
            trust_policy,
            publisher_key_source,
            history_path,
            status,
            progress: 0.0,
            downloaded_bytes: 0,
            download_total_bytes: None,
            download_speed_kib_per_second: 0.0,
            download_elapsed_seconds: 0.0,
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
            update_apply_plan_evidence_record: None,
            update_apply_bundle_evidence_record: None,
            update_apply_bundle_status: String::new(),
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
            self.speed_test_status = self.t(TextKey::StatusDirectNoMirror).to_string();
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
        self.speed_test_status = self.t(TextKey::StatusTestingMirrors).to_string();
        self.speed_test_thread = Some(handle);
        self.speed_test_rx = Some(final_rx);
        self.speed_test_progress_rx = Some(progress_rx);
        self.speed_test_results = vec![None; MIRRORS.len()];
        self.speed_test_completed = 0;
    }

    fn effective_history_path(&self) -> PathBuf {
        history_path_from_setting(&self.history_path)
    }

    fn t(&self, key: TextKey) -> &'static str {
        ui_text(self.locale, key)
    }

    fn toggle_locale(&mut self) {
        self.locale = self.locale.toggle();
    }

    fn download_progress_projection(&self) -> Option<ProgressProjection> {
        if self.download_thread.is_none() && self.download_result_rx.is_none() {
            return None;
        }

        Some(project_download_progress(
            self.locale,
            ProgressInput {
                downloaded_bytes: self.downloaded_bytes,
                total_bytes: self.download_total_bytes,
                speed_kib_per_second: self.download_speed_kib_per_second,
                elapsed_seconds: self.download_elapsed_seconds,
            },
        ))
    }

    fn fill_default_proxy_if_blank(&mut self) -> Option<String> {
        if !self.proxy.trim().is_empty() {
            return None;
        }

        let proxy = default_proxy_from_environment_or_system()?;
        self.proxy = proxy.clone();
        Some(proxy)
    }

    fn render_command_panel(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_min_width(ui.available_width());
            let layout_mode = layout_mode_for_width(ui.available_width());
            let wide_layout = matches!(layout_mode, LayoutMode::Medium | LayoutMode::Wide);

            if wide_layout {
                let total_width = ui.available_width();
                let gap = ui.spacing().item_spacing.x;
                let left_width = (total_width * 0.618).clamp(420.0, total_width - 220.0);
                let right_width = (total_width - left_width - gap).max(220.0);

                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(left_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_command_primary_stack(ui, layout_mode);
                        },
                    );
                    ui.add_space(gap);
                    ui.allocate_ui_with_layout(
                        egui::vec2(right_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_command_hint_card(ui);
                        },
                    );
                });
            } else {
                self.render_command_primary_stack(ui, layout_mode);
                ui.separator();
                self.render_command_hint_card(ui);
            }
        });
    }

    fn render_command_primary_stack(&mut self, ui: &mut egui::Ui, layout_mode: LayoutMode) {
        ui.set_min_width(ui.available_width());

        ui.label(egui::RichText::new(self.t(TextKey::UrlLabel)).strong());
        let url_response = ui.add_sized(
            [ui.available_width(), 28.0],
            egui::TextEdit::singleline(&mut self.url),
        );
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

        let button_layout = match layout_mode {
            LayoutMode::Compact => egui::Layout::top_down(egui::Align::Min),
            LayoutMode::Medium | LayoutMode::Wide => {
                egui::Layout::left_to_right(egui::Align::Center)
            }
        };

        ui.with_layout(button_layout, |ui| {
            let paste_label = self.t(TextKey::PasteButton);
            let clear_label = self.t(TextKey::ClearButton);
            let find_assets_label = self.t(TextKey::FindReleaseAssetsButton);
            if ui.button(paste_label).clicked() {
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
            if ui.button(clear_label).clicked() {
                self.url.clear();
                self.clear_release_lookup_result();
            }
            if ui.button(find_assets_label).clicked() {
                self.start_release_lookup();
            }
            if self.release_lookup_thread.is_some() {
                ui.label(format!(
                    "⏳ {}",
                    self.t(TextKey::StatusResolvingReleaseAssets)
                ));
            } else if !self.release_status.is_empty() {
                ui.label(egui::RichText::new(&self.release_status).strong());
            }
        });

        ui.separator();

        ui.horizontal_wrapped(|ui| {
            if ui.button(self.t(TextKey::DownloadButton)).clicked() {
                self.start_download();
            }
            if let Some(ctrl) = &self.control {
                if ctrl.is_paused() {
                    if ui.button(self.t(TextKey::ResumeButton)).clicked() {
                        ctrl.resume();
                    }
                } else if ui.button(self.t(TextKey::PauseButton)).clicked() {
                    ctrl.pause();
                }
                if ui.button(self.t(TextKey::CancelButton)).clicked() {
                    ctrl.cancel();
                    self.download_thread = None;
                    self.control = None;
                    self.status = self.t(TextKey::StatusCancelled).to_string();
                }
            }
        });

        if let Some(progress) = self.download_progress_projection() {
            let mut bar =
                egui::ProgressBar::new(progress.fraction).text(progress.primary_text.clone());
            if progress.indeterminate {
                bar = bar.animate(true);
            }
            ui.add_sized([ui.available_width(), 22.0], bar);
            ui.small(progress.detail_text);
        }
    }

    fn render_command_hint_card(&mut self, ui: &mut egui::Ui) {
        ui.group(|ui| {
            ui.set_min_width(ui.available_width());
            let url_is_empty = self.url.trim().is_empty();
            ui.label(
                egui::RichText::new(if url_is_empty {
                    self.t(TextKey::StatusEnterUrlFirst)
                } else {
                    self.t(TextKey::StatusReady)
                })
                .strong(),
            );

            if url_is_empty {
                ui.small(self.t(TextKey::ReleasePickerHint));
            } else if !self.release_status.is_empty() {
                ui.small(&self.release_status);
            } else {
                ui.small(self.t(TextKey::ReleasePickerHint));
            }

            if !self.status.is_empty() && self.status != self.release_status {
                ui.label(&self.status);
            }

            ui.separator();
            ui.small(format!(
                "{} {}",
                self.t(TextKey::SaveToLabel),
                self.save_dir.display()
            ));
            ui.small(format!(
                "{} {}",
                self.t(TextKey::ProxyLabel),
                if self.proxy.trim().is_empty() {
                    "auto-detect on action start"
                } else {
                    &self.proxy
                }
            ));
            ui.small(format!(
                "TLS: {}",
                if self.allow_invalid_certs {
                    "unsafe debugging mode"
                } else {
                    "strict verification"
                }
            ));
        });
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
        let source_trust_policy = backend_contract::source_trust_policy_config(&self.trust_policy);
        let evidence_dir = self.update_candidate_evidence_dir();
        let (tx, rx) = mpsc::channel::<UpdateCandidateCheckMessage>();
        self.update_candidate_status = self.t(TextKey::StatusCheckingCandidate).to_string();
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
        let source_trust_policy = backend_contract::source_trust_policy_config(&self.trust_policy);
        let evidence_dir = self.update_candidate_evidence_dir();
        let stage_root = self.update_candidate_stage_root();
        let (tx, rx) = mpsc::channel::<UpdateCandidateStageMessage>();
        self.update_stage_status = self.t(TextKey::StatusStagingCandidate).to_string();
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
        let intent = backend_contract::resolve_download_intent(&input);
        let backend_contract::IntentDTO::NeedsAssetPick { query, .. } = intent else {
            self.release = None;
            self.selected_release_asset = None;
            self.release_status = release_lookup_non_picker_status(&input, intent);
            self.status = self.release_status.clone();
            return;
        };

        let auto_proxy = self.fill_default_proxy_if_blank();
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let (tx, rx) = mpsc::channel::<ReleaseLookupMessage>();
        let kind_label = backend_contract::release_query_selector_label(&query);
        let mut status = format!(
            "Resolving {}/{} {kind_label} assets...",
            query.owner, query.repo
        );
        if let Some(proxy) = auto_proxy {
            status.push_str(&format!(" (system proxy: {proxy})"));
        }
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
            self.status = self.t(TextKey::StatusPublisherKeyImportRunning).to_string();
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
            self.status = self.t(TextKey::StatusNoPublisherKeyAsset).to_string();
            return;
        };

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let asset_url = asset.browser_download_url.clone();
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
        self.status = self.t(TextKey::StatusPublisherKeyImportRunning).to_string();
    }

    fn start_download(&mut self) {
        if self.url.trim().is_empty() {
            self.status = self.t(TextKey::StatusEnterUrlFirst).to_string();
            return;
        }
        if self.download_thread.is_some() {
            self.status = self.t(TextKey::StatusDownloadAlreadyInProgress).to_string();
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
                self.status = self.t(TextKey::StatusReleaseAssetLookupRunning).to_string();
                return;
            }
            if self.release.is_none() {
                self.start_release_lookup();
                self.status = self.t(TextKey::StatusResolvingReleaseAssets).to_string();
                return;
            }
            if !self.apply_selected_release_asset() {
                self.status = self.t(TextKey::StatusChooseReleaseAssetFirst).to_string();
                return;
            }
        }

        let auto_proxy = self.fill_default_proxy_if_blank();
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
        self.downloaded_bytes = 0;
        self.download_total_bytes = None;
        self.download_speed_kib_per_second = 0.0;
        self.download_elapsed_seconds = 0.0;
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
            .unwrap_or_else(|| self.t(TextKey::StatusStartingDownloadUnknown).to_string());
        if let Some(proxy) = auto_proxy {
            self.status.push_str(&format!(" (system proxy: {proxy})"));
        }

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
            locale: self.locale,
            allow_invalid_certs: self.allow_invalid_certs,
            trust_unknown_keep_file: self.trust_policy.unknown_keep_file,
            trust_unknown_allow_open: self.trust_policy.unknown_allow_open,
            trust_mismatch_file_policy: self.trust_policy.mismatch_file_policy,
            source_trust_require_signed: backend_contract::source_trust_requires_signed(
                &self.trust_policy,
            ),
            source_trust_publisher_key: backend_contract::trusted_publisher_key_text(
                &self.trust_policy,
            ),
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
                            self.status = backend_contract::apply_imported_publisher_key_pin(
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
                self.update_candidate_status =
                    backend_contract::update_candidate_check_status_summary(&report);
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
                    backend_contract::update_candidate_stage_status_summary(&report);
                self.status = self.update_stage_status.clone();

                // Record a Stage 3 apply plan evidence file (no mutation / no install).
                // The UI only triggers the backend contract; backend/core resolves the target exe and writes evidence.
                self.update_apply_plan_evidence_record = None;
                self.update_apply_bundle_evidence_record = None;
                self.update_apply_bundle_status.clear();
                self.update_apply_plan_evidence_record =
                    backend_contract::record_update_apply_plan_evidence_for_current_exe(&report)
                        .ok();
                self.update_stage_report = Some(report);
            }
        }

        // Process download progress
        let progress_rx = self.progress_rx.take();
        if let Some(rx) = progress_rx {
            let mut keep_progress_rx = true;
            while let Ok((downloaded, total, speed, elapsed)) = rx.try_recv() {
                self.downloaded_bytes = downloaded;
                self.download_total_bytes = (total > 0).then_some(total);
                self.download_speed_kib_per_second = speed;
                self.download_elapsed_seconds = elapsed;
                let is_complete = downloaded >= total && total > 0;
                if total > 0 {
                    self.progress = (downloaded as f32) / (total as f32);
                }
                if downloaded == 0 && total == 0 {
                    // Error state
                    self.status = self.t(TextKey::StatusDownloadFailed).to_string();
                    self.download_thread = None;
                    self.control = None;
                    keep_progress_rx = false;
                } else if downloaded >= total && total > 0 {
                    self.progress = 1.0;
                    self.status = self.t(TextKey::StatusDownloadCompleteVerifying).to_string();
                    self.speed_text.clear();
                    self.elapsed_text.clear();
                    keep_progress_rx = false;
                }
                if !is_complete {
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
                    self.status = format!("{}: {e}", self.t(TextKey::StatusDownloadFailed));
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.download_result_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = format!(
                        "{}: worker exited unexpectedly",
                        self.t(TextKey::StatusDownloadFailed)
                    );
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                }
            }
        }

        // Drag-drop handling is app-wide; rendering below stays a stable projection shell.
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if let Some(file) = dropped.first() {
                if let Some(path_str) = &file.path {
                    self.url = path_str.to_string_lossy().to_string();
                }
            }
        }

        egui::TopBottomPanel::top("proof_to_action_top_bar").show(ctx, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.heading(format!("🚀 {}", self.t(TextKey::AppTitle)));
                ui.small(self.t(TextKey::AppSubtitle));
                ui.separator();
                let switch_key = if self.locale == UiLocale::En {
                    TextKey::SwitchToChinese
                } else {
                    TextKey::SwitchToEnglish
                };
                if ui.button(self.t(switch_key)).clicked() {
                    self.toggle_locale();
                }
                ui.separator();
                ui.label(egui::RichText::new(&self.status).color(status_color(&self.status)));
            });
        });

        egui::TopBottomPanel::top("proof_to_action_command_panel").show(ctx, |ui| {
            self.render_command_panel(ui);
        });

        // Draw UI body. Scroll is a fallback safety net after responsive layout projection.
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .id_salt("proof_to_action_main_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(2.0);
            if let Some(release) = self.release.clone() {
                ui.group(|ui| {
                    let release_name = release
                        .name
                        .as_ref()
                        .filter(|name| !name.trim().is_empty())
                        .map(|name| format!(" - {name}"))
                        .unwrap_or_default();
                    ui.label(format!(
                        "{} {}/{} @ {}{}",
                        self.t(TextKey::ReleaseLabel),
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
                        ui.label(self.t(TextKey::StatusNoAssetsFound));
                    } else {
                        if self
                            .selected_release_asset
                            .map(|idx| idx >= release.assets.len())
                            .unwrap_or(true)
                        {
                            self.selected_release_asset = Some(0);
                        }
                        let selected_idx = self.selected_release_asset.unwrap_or(0);
                        let selected_text =
                            backend_contract::release_asset_picker_label(&release.assets[selected_idx]);

                        ui.horizontal(|ui| {
                            ui.label(self.t(TextKey::AssetLabel));
                            egui::ComboBox::from_id_salt("release_asset_select")
                                .selected_text(selected_text)
                                .show_ui(ui, |ui| {
                                    for (idx, asset) in release.assets.iter().enumerate() {
                                        if ui
                                            .selectable_label(
                                                self.selected_release_asset == Some(idx),
                                                backend_contract::release_asset_picker_label(asset),
                                            )
                                            .clicked()
                                        {
                                            self.selected_release_asset = Some(idx);
                                        }
                                    }
                                });
                            if ui.button(self.t(TextKey::UseSelectedAssetButton)).clicked() {
                                self.apply_selected_release_asset();
                            }
                            if ui.button(self.t(TextKey::OpenReleaseButton)).clicked() {
                                let _ = open::that(&release.html_url);
                            }
                        });

                        if let Some(asset) = release.assets.get(selected_idx) {
                            let content_type = asset
                                .content_type
                                .as_deref()
                                .unwrap_or("unknown content type");
                            ui.label(format!(
                                "{} · {}",
                                backend_contract::release_asset_picker_label(asset),
                                content_type
                            ));
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
                    if ui.button(self.t(TextKey::RetestButton)).clicked() {
                        self.retest_mirrors();
                    }
                });

                // Speed test progress
                if self.speed_test_thread.is_some() || self.speed_test_completed > 0 {
                    ui.separator();
                    if self.speed_test_thread.is_some() {
                        ui.label(format!("⏳ {}", self.t(TextKey::StatusTestingMirrors)));
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
                ui.label(self.t(TextKey::SaveToLabel));
                ui.label(self.save_dir.to_string_lossy().to_string());
                if ui.button(self.t(TextKey::BrowseButton)).clicked() {
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
                ui.label(self.t(TextKey::ProxyLabel));
                ui.text_edit_singleline(&mut self.proxy);
                if ui.button(self.t(TextKey::ClearProxyButton)).clicked() {
                    self.proxy.clear();
                }
            });
            ui.horizontal(|ui| {
                let allow_invalid_certs_label = self.t(TextKey::AllowInvalidTlsCertificates);
                ui.checkbox(&mut self.allow_invalid_certs, allow_invalid_certs_label);
                if self.allow_invalid_certs {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 180, 0),
                        self.t(TextKey::UnsafeTlsHint),
                    );
                }
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new(self.t(TextKey::NetworkPolicyTitle)).strong());
                ui.small("Outbound HTTP(S) requests are restricted to GitHub official artifact hosts (https only).");
                let hosts = backend_contract::official_github_artifact_hosts();
                ui.horizontal(|ui| {
                    if ui.button(self.t(TextKey::CopyAllowlistButton)).clicked() {
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
                ui.collapsing(self.t(TextKey::ShowAllowlist), |ui| {
                    for host in hosts {
                        ui.monospace(*host);
                    }
                });
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new(self.t(TextKey::TrustPolicyTitle)).strong());
                let keep_unknown_downloads_label = self.t(TextKey::KeepUnknownDownloads);
                ui.checkbox(
                    &mut self.trust_policy.unknown_keep_file,
                    keep_unknown_downloads_label,
                );
                if !self.trust_policy.unknown_keep_file {
                    self.trust_policy.unknown_allow_open = false;
                }
                let allow_open_unknown_downloads_label =
                    self.t(TextKey::AllowOpenUnknownDownloads);
                ui.add_enabled_ui(self.trust_policy.unknown_keep_file, |ui| {
                    ui.checkbox(
                        &mut self.trust_policy.unknown_allow_open,
                        allow_open_unknown_downloads_label,
                    );
                });
                ui.horizontal(|ui| {
                    ui.label(self.t(TextKey::MismatchFileActionLabel));
                    let quarantine_option_label = self.t(TextKey::QuarantineOption);
                    let delete_option_label = self.t(TextKey::DeleteOption);
                    egui::ComboBox::from_id_salt("mismatch_file_policy")
                        .selected_text(self.trust_policy.mismatch_file_policy.as_str())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.trust_policy.mismatch_file_policy,
                                MismatchFilePolicy::Quarantine,
                                quarantine_option_label,
                            );
                            ui.selectable_value(
                                &mut self.trust_policy.mismatch_file_policy,
                                MismatchFilePolicy::Delete,
                                delete_option_label,
                            );
                        });
                });
                ui.separator();
                ui.label(egui::RichText::new(self.t(TextKey::VerificationSourceTrustTitle)).strong());
                let mut require_trusted_source =
                    backend_contract::source_trust_requires_signed(&self.trust_policy);
                if ui
                    .checkbox(
                        &mut require_trusted_source,
                        self.t(TextKey::RequireSignedChecksumSource),
                    )
                    .changed()
                {
                    backend_contract::set_source_trust_requires_signed(
                        &mut self.trust_policy,
                        require_trusted_source,
                    );
                }
                ui.horizontal(|ui| {
                    ui.label(self.t(TextKey::PinnedPublisherKeyLabel));
                    let mut trusted_publisher_key =
                        backend_contract::trusted_publisher_key_text(&self.trust_policy);
                    if ui.text_edit_singleline(&mut trusted_publisher_key).changed()
                    {
                        backend_contract::set_trusted_publisher_key_from_manual_input(
                            &mut self.trust_policy,
                            &mut self.publisher_key_source,
                            trusted_publisher_key,
                        );
                    }
                });
                ui.horizontal(|ui| {
                    if ui.button(self.t(TextKey::ImportPublicKey)).clicked() {
                        if let Some(path) = FileDialog::new()
                            .add_filter("Public key", &["pub", "txt"])
                            .pick_file()
                        {
                            match import_publisher_key_pin_from_path(&path) {
                                Ok(pin) => {
                                    self.status = backend_contract::set_trusted_publisher_key_pin(
                                        &mut self.trust_policy,
                                        &mut self.publisher_key_source,
                                        pin,
                                        format!("local file {}", path.display()),
                                    );
                                }
                                Err(e) => {
                                    self.status =
                                        format!("❌ Public key import failed: {e}");
                                }
                            }
                        }
                    }
                    if ui.button(self.t(TextKey::NormalizeKey)).clicked() {
                        match backend_contract::normalize_trusted_publisher_key(
                            &mut self.trust_policy,
                            &mut self.publisher_key_source,
                        ) {
                            Ok(status) => self.status = status,
                            Err(e) => {
                                self.status = format!("❌ Publisher key is invalid: {e}");
                            }
                        }
                    }
                    if ui.button(self.t(TextKey::ClearKey)).clicked() {
                        backend_contract::clear_trusted_publisher_key(
                            &mut self.trust_policy,
                            &mut self.publisher_key_source,
                        );
                    }
                });
                if let Some(fingerprint) =
                    backend_contract::trusted_publisher_key_fingerprint(&self.trust_policy)
                {
                    ui.small(format!("Pinned key SHA256 fingerprint: {fingerprint}"));
                    ui.small(format!(
                        "Pinned key source: {}",
                        backend_contract::publisher_key_source_label_for_policy(
                            &self.trust_policy,
                            &self.publisher_key_source
                        )
                    ));
                } else if backend_contract::source_trust_requires_signed(&self.trust_policy) {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 70, 70),
                        "Required policy needs a pinned Ed25519 public key and .sig source assets.",
                    );
                } else {
                    ui.small("No key pinned: hash verification still works, but source authenticity is not checked.");
                }
                ui.horizontal(|ui| {
                    ui.label(self.t(TextKey::HistoryPathLabel));
                    ui.text_edit_singleline(&mut self.history_path);
                    if ui.button(self.t(TextKey::DefaultButton)).clicked() {
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
                ui.label(egui::RichText::new(self.t(TextKey::Stage1Title)).strong());
                ui.small("Checks the public latest release and only reports candidate / no-update / refused.");
                ui.horizontal(|ui| {
                    let running = self.update_candidate_thread.is_some();
                    if ui
                        .add_enabled(
                            !running,
                            egui::Button::new(self.t(TextKey::CheckLatestCandidateButton)),
                        )
                        .clicked()
                    {
                        self.start_update_candidate_check();
                    }
                    if running {
                        ui.label(format!("⏳ {}", self.t(TextKey::StatusCheckingCandidate)));
                    } else if !self.update_candidate_status.is_empty() {
                        ui.label(&self.update_candidate_status);
                    }
                });
                if let Some(report) = &self.update_candidate_report {
                    render_update_candidate_check(ui, report);
                }
            });

            ui.group(|ui| {
                ui.label(egui::RichText::new(self.t(TextKey::Stage2Title)).strong());
                ui.small("Stages a verified candidate to a local folder (still no install).");
                ui.horizontal(|ui| {
                    let running = self.update_stage_thread.is_some();
                    if ui
                        .add_enabled(
                            !running,
                            egui::Button::new(self.t(TextKey::StageLatestCandidateButton)),
                        )
                        .clicked()
                    {
                        self.start_update_candidate_stage();
                    }
                    if running {
                        ui.label(format!("⏳ {}", self.t(TextKey::StatusStagingCandidate)));
                    } else if !self.update_stage_status.is_empty() {
                        ui.label(&self.update_stage_status);
                    }
                });
                if let Some(report) = self.update_stage_report.clone() {
                    render_update_candidate_stage(ui, &report);
                    ui.separator();
                    if let Some(record) = &self.update_apply_plan_evidence_record {
                        render_update_apply_plan_preview(ui, &record.plan, Some(record));
                    } else {
                        match backend_contract::current_exe_update_apply_plan_for_stage2(&report) {
                            Ok(plan) => {
                                render_update_apply_plan_preview(ui, &plan, None);
                            }
                            Err(e) => {
                                ui.small(format!("Update apply plan preview unavailable ({e})"));
                            }
                        }
                    }
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(self.t(TextKey::PrepareHelperBundleButton))
                            .clicked()
                        {
                            match backend_contract::record_update_apply_bundle_evidence_for_current_exe(&report) {
                                Ok(record) => {
                                    self.update_apply_bundle_status =
                                        "Controlled helper bundle prepared; helper execution is not launched by the UI."
                                            .to_string();
                                    self.update_apply_bundle_evidence_record = Some(record);
                                }
                                Err(e) => {
                                    self.update_apply_bundle_status =
                                        format!("Controlled helper bundle unavailable: {e}");
                                    self.update_apply_bundle_evidence_record = None;
                                }
                            }
                        }
                        if !self.update_apply_bundle_status.is_empty() {
                            ui.label(&self.update_apply_bundle_status);
                        }
                    });
                    if let Some(record) = &self.update_apply_bundle_evidence_record {
                        render_update_apply_bundle_preview(ui, record);
                    }
                }
            });

            if let Some(snapshot) = self.last_trust_center_snapshot.clone() {
                ui.horizontal(|ui| {
                    if let Some(notice) = backend_contract::last_download_status_notice(&snapshot) {
                        ui.colored_label(backend_notice_color(notice.level), notice.message);
                        if let Some(retry_label) = notice.retry_label {
                            if self.download_thread.is_none()
                                && ui.button(retry_label).clicked()
                            {
                                self.start_download();
                            }
                        }
                    }

                    if let Some(action) = backend_contract::last_download_evidence_action(
                        self.last_verification_evidence_path.as_deref(),
                    ) {
                        render_backend_path_action(ui, action);
                    }
                    if let (Some(download_path), Some(disposition)) =
                        (&self.last_download_path, &self.last_file_disposition)
                    {
                        if let Some(action) = backend_contract::last_download_open_location_action(
                            &snapshot,
                            disposition,
                            &self.trust_policy,
                            download_path,
                            &self.save_dir,
                        ) {
                            render_backend_path_action(ui, action);
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

                });
        });
    }
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn archive_tag_url_gets_release_picker_suggestion() {
        let release_url = release_picker_url_from_archive_input(
            "https://github.com/mindfold-ai/Trellis/archive/refs/tags/v0.6.0-beta.8.zip",
        );

        assert_eq!(
            release_url.as_deref(),
            Some("https://github.com/mindfold-ai/Trellis/releases/tag/v0.6.0-beta.8")
        );
    }

    #[test]
    fn find_assets_message_explains_direct_archive_download() {
        let input = "https://github.com/mindfold-ai/Trellis/archive/refs/tags/v0.6.0-beta.8.zip";
        let status = release_lookup_non_picker_status(
            input,
            backend_contract::resolve_download_intent(input),
        );

        assert!(status.contains("Direct GitHub download detected"));
        assert!(status.contains("Click Download to download this URL"));
        assert!(
            status.contains("https://github.com/mindfold-ai/Trellis/releases/tag/v0.6.0-beta.8")
        );
    }

    #[test]
    fn windows_proxy_server_value_defaults_to_http_proxy_url() {
        assert_eq!(
            proxy_url_from_windows_proxy_server("127.0.0.1:7897").as_deref(),
            Some("http://127.0.0.1:7897")
        );
        assert_eq!(
            proxy_url_from_windows_proxy_server(
                "http=127.0.0.1:7897;https=127.0.0.1:7897;socks=127.0.0.1:7898"
            )
            .as_deref(),
            Some("http://127.0.0.1:7897")
        );
        assert_eq!(
            proxy_url_from_windows_proxy_server("socks=127.0.0.1:7898").as_deref(),
            Some("socks5://127.0.0.1:7898")
        );
    }

    #[test]
    fn registry_proxy_enable_parser_accepts_hex_enabled() {
        assert!(reg_dword_enabled("0x1"));
        assert!(reg_dword_enabled("1"));
        assert!(!reg_dword_enabled("0x0"));
    }
}
