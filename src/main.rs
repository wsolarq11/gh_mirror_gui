mod bench;
mod download;
mod history;
mod releases;
mod verification;

#[cfg(test)]
use bench::parse_bench_config;
use bench::{choose_history_backed_strategy, run_bench_download};
use directories::UserDirs;
use download::{
    build_client, build_effective_url, download_with_strategy, extract_filename, format_speed,
    probe_download, DownloadControl, DownloadProbe,
};
#[cfg(test)]
use download::{
    download_segmented, download_single, SegmentedDownloadConfig, SEGMENT_CONCURRENCY, SEGMENT_SIZE,
};
use eframe::egui;
use eframe::Storage;
#[cfg(test)]
use history::BenchHistoryEntry;
use history::{append_download_history, default_history_path, load_bench_history};
use notify_rust::Notification;
use releases::{
    asset_picker_label, is_github_release_asset_download_url, parse_release_query,
    resolve_release_assets, ResolvedRelease,
};
use reqwest::blocking::Client;
use rfd::FileDialog;
use std::env;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};
use verification::{
    verification_plan_for_selected_asset, verification_source_summary, verify_downloaded_file,
    DownloadVerificationPlan, VerificationReport, VerificationStatus,
};

fn log_error(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("download_error.log")
    {
        use std::io::Write;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}

fn format_download_completion_status(report: &VerificationReport) -> String {
    let short_hash = report.file_sha256.chars().take(12).collect::<String>();
    match report.status {
        VerificationStatus::Verified => format!(
            "✅ Download complete · VERIFIED SHA256={} via {}",
            short_hash,
            report.source.as_deref().unwrap_or("verification asset")
        ),
        VerificationStatus::Mismatch => format!(
            "❌ Download complete · MISMATCH SHA256={} expected {} via {}",
            short_hash,
            report
                .expected_sha256
                .as_deref()
                .map(|hash| hash.chars().take(12).collect::<String>())
                .unwrap_or_else(|| "unknown".to_string()),
            report.source.as_deref().unwrap_or("verification asset")
        ),
        VerificationStatus::Unknown => format!(
            "⚠ Download complete · UNKNOWN verification · SHA256={} · {}",
            short_hash, report.detail
        ),
    }
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
type DownloadResultMessage = Result<DownloadCompletion, String>;

struct DownloadCompletion {
    path: PathBuf,
    verification: VerificationReport,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedState {
    selected_mirror: usize,
    save_dir: String,
    proxy: String,
    #[serde(default)]
    allow_invalid_certs: bool,
}

struct GhMirrorGui {
    url: String,
    save_dir: PathBuf,
    proxy: String,
    allow_invalid_certs: bool,
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
    // Persisted state
    download_complete_notified: bool,
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
        if let Some(storage) = storage {
            if let Some(json) = storage.get_string("app_settings") {
                if let Ok(state) = serde_json::from_str::<SavedState>(&json) {
                    selected_mirror = state.selected_mirror;
                    if !state.save_dir.is_empty() {
                        save_dir = state.save_dir;
                    }
                    proxy = state.proxy;
                    allow_invalid_certs = state.allow_invalid_certs;
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
            download_complete_notified: false,
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

    fn clear_release_lookup_result(&mut self) {
        self.release = None;
        self.selected_release_asset = None;
        self.release_status.clear();
        self.release_lookup_input = None;
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
            let result = match build_client(&proxy, 30, allow_invalid_certs) {
                Ok(client) => resolve_release_assets(&client, &query),
                Err(e) => Err(format!("Release resolver client error: {e}")),
            };
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
        let control = DownloadControl::new();
        let ctrl = control.clone();
        let effective_url = build_effective_url(&self.mirror_urls[self.selected_mirror], &self.url);
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
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
            let client = match build_client(&proxy, 3600, allow_invalid_certs) {
                Ok(c) => c,
                Err(e) => {
                    log_error(&format!("build_client error: {}", e));
                    let _ = progress_tx.send((0, 0, 0.0, 0.0));
                    let _ = result_tx.send(Err(format!("Client build error: {e}")));
                    return;
                }
            };

            let history_path = default_history_path();
            let probe = match probe_download(&client, &effective_url) {
                Ok(probe) => probe,
                Err(e) => {
                    log_error(&format!("probe_download error: {}", e));
                    DownloadProbe {
                        total: 0,
                        range_supported: false,
                        etag: None,
                        last_modified: None,
                    }
                }
            };
            let total = probe.total;
            let history = load_bench_history(&Some(history_path.clone()), &effective_url, &probe);
            let strategy = choose_history_backed_strategy(&probe, &history);
            let save_path_str = save_path.to_string_lossy().to_string();
            let download_start = Instant::now();

            match download_with_strategy(
                &client,
                &effective_url,
                &save_path_str,
                &probe,
                &strategy,
                &ctrl,
                &progress_tx,
            ) {
                Ok(()) => {
                    let verification = match verify_downloaded_file(
                        &client,
                        &save_path,
                        &asset_name,
                        verification_plan.as_ref(),
                    ) {
                        Ok(report) => report,
                        Err(e) => {
                            log_error(&format!("verify_downloaded_file error: {}", e));
                            let _ = result_tx.send(Err(format!(
                                "Download completed but SHA256 verification failed: {e}"
                            )));
                            return;
                        }
                    };
                    if let Err(e) = append_download_history(
                        &Some(history_path),
                        &effective_url,
                        &save_path,
                        &probe,
                        &strategy,
                        download_start.elapsed(),
                        Some(&verification),
                    ) {
                        log_error(&format!("append_download_history error: {}", e));
                    }
                    let _ = progress_tx.send((total, total, 0.0, 0.0));
                    let _ = result_tx.send(Ok(DownloadCompletion {
                        path: save_path,
                        verification,
                    }));
                }
                Err(e) => {
                    log_error(&format!("download_file error: {}", e));
                    let _ = progress_tx.send((0, 0, 0.0, 0.0));
                    let _ = result_tx.send(Err(e));
                }
            }
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
                    self.status = format_download_completion_status(&completion.verification);
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                    if !self.download_complete_notified {
                        self.download_complete_notified = true;
                        let save_path_str = completion.path.to_string_lossy().to_string();
                        let status = completion.verification.status.as_str().to_string();
                        thread::spawn(move || {
                            let _ = Notification::new()
                                .summary("gh_mirror_gui")
                                .body(&format!(
                                    "Download complete ({status})\nSaved to: {save_path_str}"
                                ))
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
                // Open downloaded file folder
                if self.status.contains("Download complete")
                    && ui.button("📂 Open Folder").clicked()
                    && self.save_dir.exists()
                {
                    let _ = open::that(&self.save_dir);
                }
            });

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

fn main() -> Result<(), eframe::Error> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().map(|s| s.as_str()) == Some("--bench-download") {
        if let Err(e) = run_bench_download(&args[1..]) {
            eprintln!("benchmark failed: {e}");
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
                verification_source: None,
                expected_sha256: None,
                verification_detail: None,
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
                verification_source: None,
                expected_sha256: None,
                verification_detail: None,
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
