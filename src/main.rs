use directories::{ProjectDirs, UserDirs};
use eframe::egui;
use eframe::Storage;
use notify_rust::Notification;
use reqwest::blocking::Client;
use rfd::FileDialog;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::env;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

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

// ---------------------------------------------------------------------------
// Data structures and constants
// ---------------------------------------------------------------------------

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;
const SPEED_TEST_TIMEOUT_SECS: u64 = 5;
const DOWNLOAD_BUFFER_SIZE: usize = 256 * 1024;
const PROGRESS_INTERVAL_MS: u128 = 200;
const SEGMENTED_MIN_SIZE: u64 = 8 * 1024 * 1024;
const SEGMENT_SIZE: u64 = 4 * 1024 * 1024;
const SEGMENT_CONCURRENCY: usize = 4;
const ADAPTIVE_TOTAL_SAMPLE_SIZE: u64 = 4 * 1024 * 1024;

/// Known mirror sites.  First entry must be "Direct (no mirror)"
const MIRRORS: &[(&str, &str)] = &[("Direct (no mirror)", "")];

struct DownloadControl {
    cancel_flag: AtomicBool,
    pause_flag: AtomicBool,
    pause_mutex: Mutex<()>,
    pause_condvar: Condvar,
}

#[derive(Clone)]
struct CachedClient {
    proxy: String,
    timeout_secs: u64,
    allow_invalid_certs: bool,
    client: Client,
}

impl DownloadControl {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel_flag: AtomicBool::new(false),
            pause_flag: AtomicBool::new(false),
            pause_mutex: Mutex::new(()),
            pause_condvar: Condvar::new(),
        })
    }

    fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
        self.pause_condvar.notify_all();
    }

    fn pause(&self) {
        self.pause_flag.store(true, Ordering::Relaxed);
    }

    fn resume(&self) {
        self.pause_flag.store(false, Ordering::Relaxed);
        self.pause_condvar.notify_all();
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SavedState {
    selected_mirror: usize,
    save_dir: String,
    proxy: String,
    #[serde(default)]
    allow_invalid_certs: bool,
}

#[derive(Clone, Debug)]
struct DownloadProbe {
    total: u64,
    range_supported: bool,
    etag: Option<String>,
    last_modified: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SegmentState {
    start: u64,
    end: u64,
    done: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct SegmentedDownloadMeta {
    url: String,
    total: u64,
    etag: Option<String>,
    last_modified: Option<String>,
    segments: Vec<SegmentState>,
}

#[derive(Clone, Copy, Debug)]
struct SegmentedDownloadConfig {
    segment_size: u64,
    concurrency: usize,
}

#[derive(Debug)]
struct BenchConfig {
    url: String,
    out: PathBuf,
    json: Option<PathBuf>,
    history: Option<PathBuf>,
    proxy: String,
    allow_invalid_certs: bool,
    mode: BenchMode,
    segment_size: Option<u64>,
    concurrency: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BenchMode {
    Auto,
    Single,
    Segmented,
    Adaptive,
}

#[derive(Clone, Debug)]
struct BenchCandidate {
    variant: String,
    segment_size: Option<u64>,
    concurrency: Option<usize>,
}

#[derive(Clone, Debug)]
struct SelectedDownloadStrategy {
    variant: String,
    config: Option<SegmentedDownloadConfig>,
    history_matches: usize,
}

#[derive(Clone, Debug, serde::Serialize)]
struct AdaptiveSample {
    variant: String,
    mode: String,
    segment_size: Option<u64>,
    concurrency: Option<usize>,
    sample_bytes: u64,
    sample_ms: u128,
    avg_mib_s: f64,
    history_avg_mib_s: Option<f64>,
    score_mib_s: f64,
    status: String,
    error: Option<String>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct BenchHistoryEntry {
    schema_version: u32,
    url: String,
    variant: String,
    mode: String,
    total_bytes: u64,
    segment_size: Option<u64>,
    concurrency: Option<usize>,
    download_ms: u128,
    avg_mib_s: f64,
    sha256: String,
    etag: Option<String>,
    last_modified: Option<String>,
    recorded_at_epoch_secs: u64,
}

#[derive(serde::Serialize)]
struct BenchResult {
    schema_version: u32,
    status: String,
    url: String,
    output: String,
    mode: String,
    selected_variant: Option<String>,
    history_path: Option<String>,
    history_matches: usize,
    total_bytes: u64,
    file_bytes: u64,
    range_supported: bool,
    segment_size: Option<u64>,
    concurrency: Option<usize>,
    segment_count: Option<usize>,
    probe_ms: u128,
    download_ms: u128,
    total_ms: u128,
    avg_mib_s: f64,
    peak_mib_s: f64,
    progress_events: usize,
    adaptive_samples: Option<Vec<AdaptiveSample>>,
    sha256: String,
    etag: Option<String>,
    last_modified: Option<String>,
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
            mirrors: names,
            mirror_urls: urls,
            selected_mirror,
            speed_test_status: String::from("Testing mirrors..."),
            speed_test_thread: Some(handle),
            speed_test_rx: Some(final_rx),
            speed_test_progress_rx: Some(progress_rx),
            speed_test_results: vec![None; MIRRORS.len()],
            speed_test_completed: 0,
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

    fn start_download(&mut self) {
        if self.url.trim().is_empty() {
            self.status = String::from("Please enter a URL first");
            return;
        }
        if self.download_thread.is_some() {
            self.status = String::from("Download already in progress");
            return;
        }

        let save_path = match self.choose_save_path() {
            Some(p) => p,
            None => return,
        };

        self.download_complete_notified = false;
        let control = DownloadControl::new();
        let ctrl = control.clone();
        let effective_url = build_effective_url(&self.mirror_urls[self.selected_mirror], &self.url);
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let (progress_tx, progress_rx) = mpsc::channel();
        self.progress_rx = Some(progress_rx);

        self.progress = 0.0;
        self.speed_text.clear();
        self.elapsed_text.clear();
        self.status = String::from("Starting download...");

        self.download_thread = Some(thread::spawn(move || {
            let client = match build_client(&proxy, 3600, allow_invalid_certs) {
                Ok(c) => c,
                Err(e) => {
                    log_error(&format!("build_client error: {}", e));
                    let _ = progress_tx.send((0, 0, 0.0, 0.0));
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
                    if let Err(e) = append_download_history(
                        &Some(history_path),
                        &effective_url,
                        &save_path,
                        &probe,
                        &strategy,
                        download_start.elapsed(),
                    ) {
                        log_error(&format!("append_download_history error: {}", e));
                    }
                    let _ = progress_tx.send((total, total, 0.0, 0.0));
                }
                Err(e) => {
                    log_error(&format!("download_file error: {}", e));
                    let _ = progress_tx.send((0, 0, 0.0, 0.0));
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

        // Process download progress
        let progress_rx = self.progress_rx.take();
        if let Some(rx) = progress_rx {
            while let Ok((downloaded, total, speed, elapsed)) = rx.try_recv() {
                if total > 0 {
                    self.progress = (downloaded as f32) / (total as f32);
                }
                if downloaded == 0 && total == 0 {
                    // Error state
                    self.status = String::from("❌ Download failed");
                    self.download_thread = None;
                    self.control = None;
                } else if downloaded >= total && total > 0 {
                    self.progress = 1.0;
                    self.status = String::from("✅ Download complete!");
                    self.speed_text.clear();
                    self.elapsed_text.clear();
                    self.download_thread = None;
                    self.control = None;
                    // Desktop notification
                    if !self.download_complete_notified {
                        self.download_complete_notified = true;
                        let save_path_str = self.save_dir.to_string_lossy().to_string();
                        thread::spawn(move || {
                            let _ = Notification::new()
                                .summary("gh_mirror_gui")
                                .body(&format!("Download complete!\nSaved to: {}", save_path_str))
                                .show();
                        });
                    }
                } else {
                    self.speed_text = format_speed(speed);
                    let total_min = elapsed / 60.0;
                    let total_sec = elapsed % 60.0;
                    self.elapsed_text = format!("{:02.0}:{:04.1}", total_min, total_sec);
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
                ui.text_edit_singleline(&mut self.url);
                if ui.button("📋 Paste").clicked() {
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        if let Ok(text) = clipboard.get_text() {
                            self.url = text;
                        }
                    }
                }
                if ui.button("🗑 Clear").clicked() {
                    self.url.clear();
                }
            });

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
                    if ctrl.pause_flag.load(Ordering::Relaxed) {
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
                if self.status.contains("✅")
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
            ui.label(egui::RichText::new(&self.status).color(egui::Color32::from_rgb(0, 180, 0)));
        });
    }
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

fn extract_filename(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(2, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() {
        return Some(parts[0].to_string());
    }
    None
}

fn build_effective_url(mirror_url: &str, raw_url: &str) -> String {
    if mirror_url.is_empty() {
        raw_url.to_string()
    } else {
        format!("{}{}", mirror_url, raw_url)
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

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn build_client(
    proxy: &str,
    timeout_secs: u64,
    allow_invalid_certs: bool,
) -> Result<Client, String> {
    static GLOBAL_CLIENT: OnceLock<Mutex<Option<CachedClient>>> = OnceLock::new();
    let cell = GLOBAL_CLIENT.get_or_init(|| Mutex::new(None));
    let mut guard = cell.lock().unwrap();
    if let Some(ref cached) = *guard {
        if cached.proxy == proxy
            && cached.timeout_secs == timeout_secs
            && cached.allow_invalid_certs == allow_invalid_certs
        {
            return Ok(cached.client.clone());
        }
    }
    let mut builder = reqwest::blocking::Client::builder()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.clamp(1, 30)));
    if allow_invalid_certs {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if !proxy.is_empty() {
        builder = builder
            .proxy(reqwest::Proxy::all(proxy).map_err(|e| format!("Invalid proxy URL: {}", e))?);
    }
    let client = builder
        .build()
        .map_err(|e| format!("Client build error: {}", e))?;
    *guard = Some(CachedClient {
        proxy: proxy.to_string(),
        timeout_secs,
        allow_invalid_certs,
        client: client.clone(),
    });
    Ok(client)
}

fn header_string(resp: &reqwest::blocking::Response, name: &str) -> Option<String> {
    resp.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn content_length(resp: &reqwest::blocking::Response) -> u64 {
    resp.headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

fn parse_content_range_total(value: &str) -> Option<u64> {
    let (_, total) = value.rsplit_once('/')?;
    if total == "*" {
        None
    } else {
        total.parse().ok()
    }
}

fn probe_download(client: &Client, url: &str) -> Result<DownloadProbe, String> {
    let mut total = 0;
    let mut etag = None;
    let mut last_modified = None;

    if let Ok(resp) = client.head(url).send() {
        if resp.status().is_success() {
            total = content_length(&resp);
            etag = header_string(&resp, "etag");
            last_modified = header_string(&resp, "last-modified");
        }
    }

    let range_resp = client
        .get(url)
        .header("Range", "bytes=0-0")
        .send()
        .map_err(|e| format!("Range probe request failed: {}", e))?;
    let status = range_resp.status();

    if status.as_u16() == 206 {
        if let Some(value) = header_string(&range_resp, "content-range") {
            if let Some(parsed_total) = parse_content_range_total(&value) {
                total = parsed_total;
            }
        }
        if etag.is_none() {
            etag = header_string(&range_resp, "etag");
        }
        if last_modified.is_none() {
            last_modified = header_string(&range_resp, "last-modified");
        }
        return Ok(DownloadProbe {
            total,
            range_supported: total > 0,
            etag,
            last_modified,
        });
    }

    if total == 0 && status.is_success() {
        total = content_length(&range_resp);
    }

    if total == 0 {
        return Err(format!(
            "Unable to determine download size; probe returned {status}"
        ));
    }

    Ok(DownloadProbe {
        total,
        range_supported: false,
        etag,
        last_modified,
    })
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

fn download_with_strategy(
    client: &Client,
    url: &str,
    save_path: &str,
    probe: &DownloadProbe,
    strategy: &SelectedDownloadStrategy,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<(u64, u64, f64, f64)>,
) -> Result<(), String> {
    if let Some(config) = strategy.config {
        download_segmented(client, url, save_path, probe, config, ctrl, progress_tx)
    } else {
        download_single(client, url, save_path, probe.total, ctrl, progress_tx)
    }
}

fn segmented_config_for(total: u64) -> SegmentedDownloadConfig {
    let segment_size = if total < 64 * 1024 * 1024 {
        SEGMENT_SIZE
    } else if total < 512 * 1024 * 1024 {
        4 * 1024 * 1024
    } else {
        8 * 1024 * 1024
    };
    let segment_count = total.div_ceil(segment_size).max(1) as usize;

    SegmentedDownloadConfig {
        segment_size,
        concurrency: SEGMENT_CONCURRENCY.min(segment_count).max(1),
    }
}

fn segment_size_label(segment_size: u64) -> String {
    let mib = 1024 * 1024;
    if segment_size.is_multiple_of(mib) {
        format!("{}m", segment_size / mib)
    } else {
        segment_size.to_string()
    }
}

fn segmented_variant_name(config: SegmentedDownloadConfig) -> String {
    format!(
        "seg-c{}-s{}",
        config.concurrency,
        segment_size_label(config.segment_size)
    )
}

fn default_history_path() -> PathBuf {
    ProjectDirs::from("com", "gh_mirror_gui", "gh_mirror_gui")
        .map(|dirs| dirs.data_local_dir().join("bench-history.jsonl"))
        .unwrap_or_else(|| PathBuf::from("target").join("bench-history.jsonl"))
}

fn config_for_candidate(total: u64, candidate: &BenchCandidate) -> Option<SegmentedDownloadConfig> {
    if candidate.segment_size.is_some() {
        apply_segmented_overrides(total, candidate.segment_size, candidate.concurrency).ok()
    } else {
        None
    }
}

fn choose_history_backed_strategy(
    probe: &DownloadProbe,
    history: &[BenchHistoryEntry],
) -> SelectedDownloadStrategy {
    if !probe.range_supported || probe.total < SEGMENTED_MIN_SIZE {
        return SelectedDownloadStrategy {
            variant: "single".to_string(),
            config: None,
            history_matches: history.len(),
        };
    }

    if let Some((candidate, _history_avg)) = adaptive_candidates()
        .into_iter()
        .filter_map(|candidate| {
            history_avg_for_variant(history, &candidate.variant)
                .map(|history_avg| (candidate, history_avg))
        })
        .max_by(|(_, a), (_, b)| a.total_cmp(b))
    {
        if let Some(config) = config_for_candidate(probe.total, &candidate) {
            return SelectedDownloadStrategy {
                variant: segmented_variant_name(config),
                config: Some(config),
                history_matches: history.len(),
            };
        }
    }

    let config = segmented_config_for(probe.total);
    SelectedDownloadStrategy {
        variant: segmented_variant_name(config),
        config: Some(config),
        history_matches: history.len(),
    }
}

fn apply_segmented_overrides(
    total: u64,
    segment_size: Option<u64>,
    concurrency: Option<usize>,
) -> Result<SegmentedDownloadConfig, String> {
    let mut config = segmented_config_for(total);
    if let Some(segment_size) = segment_size {
        if segment_size == 0 {
            return Err("--segment-size must be greater than 0".to_string());
        }
        config.segment_size = segment_size;
    }
    let segment_count = total.div_ceil(config.segment_size).max(1) as usize;
    if let Some(concurrency) = concurrency {
        if concurrency == 0 {
            return Err("--concurrency must be greater than 0".to_string());
        }
        config.concurrency = concurrency.min(segment_count).max(1);
    } else {
        config.concurrency = config.concurrency.min(segment_count).max(1);
    }
    Ok(config)
}

fn wait_for_download_turn(ctrl: &Arc<DownloadControl>) -> Result<(), String> {
    if ctrl.cancel_flag.load(Ordering::Relaxed) {
        return Err("Cancelled".into());
    }

    let mut guard = ctrl.pause_mutex.lock().unwrap();
    while ctrl.pause_flag.load(Ordering::Relaxed) && !ctrl.cancel_flag.load(Ordering::Relaxed) {
        guard = ctrl.pause_condvar.wait(guard).unwrap();
    }

    if ctrl.cancel_flag.load(Ordering::Relaxed) {
        Err("Cancelled".into())
    } else {
        Ok(())
    }
}

fn report_progress(
    progress_tx: &mpsc::Sender<(u64, u64, f64, f64)>,
    report_state: &Arc<Mutex<Instant>>,
    downloaded: u64,
    total: u64,
    start_time: Instant,
    force: bool,
) {
    let elapsed = start_time.elapsed().as_secs_f64();
    let speed = if elapsed > 0.0 {
        (downloaded as f64) / (elapsed * 1024.0)
    } else {
        0.0
    };

    let mut last_report = report_state.lock().unwrap();
    if force
        || last_report.elapsed().as_millis() >= PROGRESS_INTERVAL_MS
        || downloaded >= total && total > 0
    {
        *last_report = Instant::now();
        let _ = progress_tx.send((downloaded, total, speed, elapsed));
    }
}

fn segment_len(segment: &SegmentState) -> u64 {
    segment.end - segment.start + 1
}

fn plan_segments(total: u64, segment_size: u64) -> Vec<SegmentState> {
    let mut segments = Vec::new();
    let mut start = 0;
    while start < total {
        let end = (start + segment_size - 1).min(total - 1);
        segments.push(SegmentState {
            start,
            end,
            done: false,
        });
        start = end + 1;
    }
    segments
}

fn meta_matches(meta: &SegmentedDownloadMeta, url: &str, probe: &DownloadProbe) -> bool {
    meta.url == url
        && meta.total == probe.total
        && meta.etag == probe.etag
        && meta.last_modified == probe.last_modified
        && !meta.segments.is_empty()
}

fn load_segment_meta(
    path: &str,
    url: &str,
    probe: &DownloadProbe,
) -> Option<SegmentedDownloadMeta> {
    let bytes = fs::read(path).ok()?;
    let meta = serde_json::from_slice::<SegmentedDownloadMeta>(&bytes).ok()?;
    if meta_matches(&meta, url, probe) {
        Some(meta)
    } else {
        None
    }
}

fn save_segment_meta(path: &str, meta: &SegmentedDownloadMeta) -> Result<(), String> {
    let json =
        serde_json::to_vec_pretty(meta).map_err(|e| format!("Segment meta encode error: {e}"))?;
    fs::write(path, json).map_err(|e| format!("Segment meta write error: {e}"))
}

fn download_segmented(
    client: &Client,
    url: &str,
    save_path: &str,
    probe: &DownloadProbe,
    config: SegmentedDownloadConfig,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<(u64, u64, f64, f64)>,
) -> Result<(), String> {
    let tmp_path = format!("{}.part", save_path);
    let meta_path = format!("{}.json", tmp_path);
    let start_time = Instant::now();

    let meta = if let Some(meta) = load_segment_meta(&meta_path, url, probe) {
        meta
    } else {
        let _ = fs::remove_file(&tmp_path);
        SegmentedDownloadMeta {
            url: url.to_string(),
            total: probe.total,
            etag: probe.etag.clone(),
            last_modified: probe.last_modified.clone(),
            segments: plan_segments(probe.total, config.segment_size),
        }
    };

    save_segment_meta(&meta_path, &meta)?;

    let already_done: u64 = meta
        .segments
        .iter()
        .filter(|s| s.done)
        .map(segment_len)
        .sum();
    if already_done >= probe.total {
        fs::rename(&tmp_path, save_path).map_err(|e| format!("Failed to rename temp file: {e}"))?;
        let _ = fs::remove_file(&meta_path);
        return Ok(());
    }

    let file = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&tmp_path)
        .map_err(|e| format!("Open segmented temp file error: {e}"))?;
    file.set_len(probe.total)
        .map_err(|e| format!("Preallocate temp file error: {e}"))?;

    let queue = Arc::new(Mutex::new(VecDeque::from(
        meta.segments
            .iter()
            .filter(|s| !s.done)
            .cloned()
            .collect::<Vec<_>>(),
    )));
    let shared_meta = Arc::new(Mutex::new(meta));
    let shared_file = Arc::new(Mutex::new(file));
    let completed = Arc::new(AtomicU64::new(already_done));
    let failed = Arc::new(AtomicBool::new(false));
    let errors = Arc::new(Mutex::new(Vec::<String>::new()));
    let report_state = Arc::new(Mutex::new(Instant::now()));
    let worker_count = config
        .concurrency
        .max(1)
        .min(queue.lock().unwrap().len().max(1));

    let mut workers = Vec::new();
    for _ in 0..worker_count {
        let worker_client = client.clone();
        let worker_url = url.to_string();
        let worker_queue = queue.clone();
        let worker_meta = shared_meta.clone();
        let worker_file = shared_file.clone();
        let worker_completed = completed.clone();
        let worker_failed = failed.clone();
        let worker_errors = errors.clone();
        let worker_ctrl = ctrl.clone();
        let worker_tx = progress_tx.clone();
        let worker_report_state = report_state.clone();
        let worker_meta_path = meta_path.clone();
        let worker_total = probe.total;

        workers.push(thread::spawn(move || 'worker_loop: loop {
            if worker_failed.load(Ordering::Relaxed)
                || worker_ctrl.cancel_flag.load(Ordering::Relaxed)
            {
                return;
            }

            let segment = {
                let mut queue = worker_queue.lock().unwrap();
                queue.pop_front()
            };

            let Some(segment) = segment else {
                return;
            };

            let mut last_err = None;
            for attempt in 0..=MAX_RETRIES {
                if attempt > 0 {
                    thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
                }

                match download_segment(
                    &worker_client,
                    &worker_url,
                    &segment,
                    &worker_file,
                    &worker_ctrl,
                ) {
                    Ok(()) => {
                        let downloaded = worker_completed
                            .fetch_add(segment_len(&segment), Ordering::Relaxed)
                            + segment_len(&segment);
                        {
                            let mut meta = worker_meta.lock().unwrap();
                            if let Some(found) = meta
                                .segments
                                .iter_mut()
                                .find(|s| s.start == segment.start && s.end == segment.end)
                            {
                                found.done = true;
                            }
                            if let Err(e) = save_segment_meta(&worker_meta_path, &meta) {
                                worker_failed.store(true, Ordering::Relaxed);
                                worker_errors.lock().unwrap().push(e);
                                return;
                            }
                        }
                        report_progress(
                            &worker_tx,
                            &worker_report_state,
                            downloaded,
                            worker_total,
                            start_time,
                            false,
                        );
                        continue 'worker_loop;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        if worker_ctrl.cancel_flag.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }

            worker_failed.store(true, Ordering::Relaxed);
            if let Some(e) = last_err {
                worker_errors.lock().unwrap().push(e);
            }
            return;
        }));
    }

    for worker in workers {
        if worker.join().is_err() {
            failed.store(true, Ordering::Relaxed);
            errors
                .lock()
                .unwrap()
                .push("Segment worker panicked".to_string());
        }
    }

    if ctrl.cancel_flag.load(Ordering::Relaxed) {
        let _ = fs::remove_file(&tmp_path);
        let _ = fs::remove_file(&meta_path);
        return Err("Cancelled".into());
    }

    if failed.load(Ordering::Relaxed) {
        let joined = errors.lock().unwrap().join("; ");
        return Err(if joined.is_empty() {
            "Segmented download failed".to_string()
        } else {
            joined
        });
    }

    drop(shared_file);

    let final_size = fs::metadata(&tmp_path)
        .map_err(|e| format!("Temp file stat error: {e}"))?
        .len();
    if final_size != probe.total {
        return Err(format!(
            "Segmented download size mismatch: expected {}, got {}",
            probe.total, final_size
        ));
    }

    fs::rename(&tmp_path, save_path).map_err(|e| format!("Failed to rename temp file: {e}"))?;
    let _ = fs::remove_file(&meta_path);
    report_progress(
        progress_tx,
        &report_state,
        probe.total,
        probe.total,
        start_time,
        true,
    );
    Ok(())
}

fn download_segment(
    client: &Client,
    url: &str,
    segment: &SegmentState,
    file: &Arc<Mutex<fs::File>>,
    ctrl: &Arc<DownloadControl>,
) -> Result<(), String> {
    let mut resp = client
        .get(url)
        .header("Range", format!("bytes={}-{}", segment.start, segment.end))
        .send()
        .map_err(|e| format!("Segment request failed: {e}"))?;

    if resp.status().as_u16() != 206 {
        return Err(format!(
            "Segment request returned {}, expected 206",
            resp.status()
        ));
    }

    let mut offset = segment.start;
    let expected_end = segment.end + 1;
    let mut buf = vec![0u8; DOWNLOAD_BUFFER_SIZE];

    loop {
        wait_for_download_turn(ctrl)?;

        let n = resp
            .read(&mut buf)
            .map_err(|e| format!("Segment read error: {e}"))?;
        if n == 0 {
            break;
        }

        if offset + n as u64 > expected_end {
            return Err("Segment exceeded planned range".into());
        }

        {
            let mut file = file.lock().unwrap();
            file.seek(SeekFrom::Start(offset))
                .map_err(|e| format!("Segment seek error: {e}"))?;
            file.write_all(&buf[..n])
                .map_err(|e| format!("Segment write error: {e}"))?;
        }
        offset += n as u64;
    }

    if offset != expected_end {
        return Err(format!(
            "Segment incomplete: expected end {}, got {}",
            expected_end, offset
        ));
    }

    Ok(())
}

fn download_single(
    client: &Client,
    url: &str,
    save_path: &str,
    total: u64,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<(u64, u64, f64, f64)>,
) -> Result<(), String> {
    let tmp_path = format!("{}.part", save_path);
    let start_time = Instant::now();
    let report_state = Arc::new(Mutex::new(Instant::now()));
    let mut downloaded: u64 = 0;

    if let Ok(meta) = fs::metadata(&tmp_path) {
        downloaded = meta.len();
        if total > 0 && downloaded >= total {
            fs::rename(&tmp_path, save_path)
                .map_err(|e| format!("Failed to rename temp file: {}", e))?;
            return Ok(());
        }
    }

    for attempt in 0..=MAX_RETRIES {
        if attempt > 0 {
            thread::sleep(Duration::from_millis(RETRY_DELAY_MS));
        }

        let mut req_builder = client.get(url);
        if downloaded > 0 {
            req_builder = req_builder.header("Range", format!("bytes={}-", downloaded));
        }

        let mut resp = req_builder
            .send()
            .map_err(|e| format!("Download request failed: {}", e))?;

        let status = resp.status();
        if status == 416 {
            fs::rename(&tmp_path, save_path)
                .map_err(|e| format!("Failed to rename temp file: {}", e))?;
            return Ok(());
        }
        if downloaded > 0 && status.as_u16() == 200 {
            downloaded = 0;
        }
        if downloaded > 0 && status.as_u16() != 206 {
            if attempt == MAX_RETRIES {
                return Err(format!(
                    "Server did not honor Range resume request; returned {}",
                    status
                ));
            }
            continue;
        }
        if !status.is_success() && status != 206 {
            if attempt == MAX_RETRIES {
                return Err(format!("Server returned {}", status));
            }
            continue;
        }

        let mut file = if downloaded == 0 {
            fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| format!("Open temp file error: {}", e))?
        } else {
            fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&tmp_path)
                .map_err(|e| format!("Open temp file error: {}", e))?
        };

        let mut buf = vec![0u8; DOWNLOAD_BUFFER_SIZE];

        loop {
            wait_for_download_turn(ctrl).inspect_err(|_| {
                let _ = fs::remove_file(&tmp_path);
            })?;

            let n = resp
                .read(&mut buf)
                .map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .map_err(|e| format!("Write error: {}", e))?;
            downloaded += n as u64;

            report_progress(
                progress_tx,
                &report_state,
                downloaded,
                total,
                start_time,
                false,
            );
        }

        if total > 0 && downloaded >= total {
            break;
        }
    }

    fs::rename(&tmp_path, save_path).map_err(|e| format!("Failed to rename temp file: {}", e))?;
    report_progress(
        progress_tx,
        &report_state,
        downloaded,
        total,
        start_time,
        true,
    );
    Ok(())
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

fn parse_bench_config(args: &[String]) -> Result<BenchConfig, String> {
    let mut url = None;
    let mut out = None;
    let mut json = None;
    let mut history = None;
    let mut proxy = String::new();
    let mut allow_invalid_certs = false;
    let mut mode = BenchMode::Auto;
    let mut segment_size = None;
    let mut concurrency = None;
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--url" => {
                i += 1;
                url = args.get(i).cloned();
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--json" => {
                i += 1;
                json = args.get(i).map(PathBuf::from);
            }
            "--history" => {
                i += 1;
                history = args.get(i).map(PathBuf::from);
            }
            "--proxy" => {
                i += 1;
                proxy = args.get(i).cloned().unwrap_or_default();
            }
            "--allow-invalid-certs" => {
                allow_invalid_certs = true;
            }
            "--mode" => {
                i += 1;
                mode = match args.get(i).map(|s| s.as_str()) {
                    Some("auto") => BenchMode::Auto,
                    Some("single") => BenchMode::Single,
                    Some("segmented") => BenchMode::Segmented,
                    Some("adaptive") => BenchMode::Adaptive,
                    Some(other) => {
                        return Err(format!(
                            "Invalid --mode value: {other}; expected auto|single|segmented|adaptive"
                        ))
                    }
                    None => return Err("--mode requires a value".to_string()),
                };
            }
            "--segment-size" => {
                i += 1;
                segment_size = Some(
                    args.get(i)
                        .ok_or_else(|| "--segment-size requires a value".to_string())?
                        .parse::<u64>()
                        .map_err(|e| format!("Invalid --segment-size: {e}"))?,
                );
            }
            "--concurrency" => {
                i += 1;
                concurrency = Some(
                    args.get(i)
                        .ok_or_else(|| "--concurrency requires a value".to_string())?
                        .parse::<usize>()
                        .map_err(|e| format!("Invalid --concurrency: {e}"))?,
                );
            }
            "--help" | "-h" => {
                return Err(
                    "Usage: gh_mirror_gui.exe --bench-download --url <URL> --out <PATH> [--json <PATH>] [--history <PATH>] [--proxy <URL>] [--allow-invalid-certs] [--mode auto|single|segmented|adaptive] [--segment-size BYTES] [--concurrency N]"
                        .to_string(),
                );
            }
            other => {
                return Err(format!("Unknown benchmark argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(BenchConfig {
        url: url.ok_or_else(|| "--url is required".to_string())?,
        out: out.ok_or_else(|| "--out is required".to_string())?,
        json,
        history,
        proxy,
        allow_invalid_certs,
        mode,
        segment_size,
        concurrency,
    })
}

fn sha256_file(path: &PathBuf) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("Open hash input error: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; DOWNLOAD_BUFFER_SIZE];

    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("Hash read error: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:X}", hasher.finalize()))
}

fn write_bench_json(path: &Option<PathBuf>, result: &BenchResult) -> Result<(), String> {
    if let Some(path) = path {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Create benchmark json dir error: {e}"))?;
        }
        let json = serde_json::to_vec_pretty(result)
            .map_err(|e| format!("Encode benchmark json error: {e}"))?;
        fs::write(path, json).map_err(|e| format!("Write benchmark json error: {e}"))?;
    }
    Ok(())
}

fn unix_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn load_bench_history(
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

fn history_avg_for_variant(history: &[BenchHistoryEntry], variant: &str) -> Option<f64> {
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

fn append_bench_history(path: &Option<PathBuf>, result: &BenchResult) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Create benchmark history dir error: {e}"))?;
    }

    let entry = BenchHistoryEntry {
        schema_version: 1,
        url: result.url.clone(),
        variant: result
            .selected_variant
            .clone()
            .unwrap_or_else(|| result.mode.clone()),
        mode: result.mode.clone(),
        total_bytes: result.total_bytes,
        segment_size: result.segment_size,
        concurrency: result.concurrency,
        download_ms: result.download_ms,
        avg_mib_s: result.avg_mib_s,
        sha256: result.sha256.clone(),
        etag: result.etag.clone(),
        last_modified: result.last_modified.clone(),
        recorded_at_epoch_secs: unix_epoch_secs(),
    };
    let line = serde_json::to_string(&entry)
        .map_err(|e| format!("Encode benchmark history entry error: {e}"))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Open benchmark history error: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("Write benchmark history error: {e}"))
}

fn append_download_history(
    path: &Option<PathBuf>,
    url: &str,
    output: &PathBuf,
    probe: &DownloadProbe,
    strategy: &SelectedDownloadStrategy,
    download_elapsed: Duration,
) -> Result<(), String> {
    let output_string = output.to_string_lossy().to_string();
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
    let result = BenchResult {
        schema_version: 1,
        status: "PASS".to_string(),
        url: url.to_string(),
        output: output_string,
        mode: if strategy.config.is_some() {
            "adaptive".to_string()
        } else {
            "single".to_string()
        },
        selected_variant: Some(strategy.variant.clone()),
        history_path: path.as_ref().map(|path| path.to_string_lossy().to_string()),
        history_matches: strategy.history_matches,
        total_bytes: probe.total,
        file_bytes,
        range_supported: probe.range_supported,
        segment_size: strategy.config.map(|config| config.segment_size),
        concurrency: strategy.config.map(|config| config.concurrency),
        segment_count: strategy
            .config
            .map(|config| probe.total.div_ceil(config.segment_size) as usize),
        probe_ms: 0,
        download_ms,
        total_ms: download_ms,
        avg_mib_s,
        peak_mib_s: 0.0,
        progress_events: 0,
        adaptive_samples: None,
        sha256,
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
    };
    append_bench_history(path, &result)
}

fn adaptive_candidates() -> Vec<BenchCandidate> {
    vec![
        BenchCandidate {
            variant: "single".to_string(),
            segment_size: None,
            concurrency: None,
        },
        BenchCandidate {
            variant: "seg-c4-s4m".to_string(),
            segment_size: Some(4 * 1024 * 1024),
            concurrency: Some(4),
        },
        BenchCandidate {
            variant: "seg-c8-s4m".to_string(),
            segment_size: Some(4 * 1024 * 1024),
            concurrency: Some(8),
        },
        BenchCandidate {
            variant: "seg-c16-s2m".to_string(),
            segment_size: Some(2 * 1024 * 1024),
            concurrency: Some(16),
        },
    ]
}

fn read_range_discard(client: &Client, url: &str, start: u64, end: u64) -> Result<u64, String> {
    let mut resp = client
        .get(url)
        .header("Range", format!("bytes={start}-{end}"))
        .send()
        .map_err(|e| format!("Adaptive sample request failed: {e}"))?;
    if resp.status().as_u16() != 206 {
        return Err(format!(
            "Adaptive sample expected 206, got {}",
            resp.status()
        ));
    }

    let mut total = 0;
    let mut buf = vec![0u8; DOWNLOAD_BUFFER_SIZE];
    loop {
        let n = resp
            .read(&mut buf)
            .map_err(|e| format!("Adaptive sample read failed: {e}"))?;
        if n == 0 {
            break;
        }
        total += n as u64;
    }
    Ok(total)
}

fn sample_candidate(
    client: &Client,
    url: &str,
    total: u64,
    candidate: &BenchCandidate,
    history: &[BenchHistoryEntry],
) -> AdaptiveSample {
    let start_time = Instant::now();
    let mut sample_bytes = 0;
    let target_sample_bytes = ADAPTIVE_TOTAL_SAMPLE_SIZE.min(total);
    let result = if let (Some(segment_size), Some(concurrency)) =
        (candidate.segment_size, candidate.concurrency)
    {
        let mut handles = Vec::new();
        let worker_count = concurrency
            .max(1)
            .min(target_sample_bytes.max(1) as usize)
            .min(total.div_ceil(segment_size).max(1) as usize);
        let chunk_size = target_sample_bytes.div_ceil(worker_count as u64).max(1);
        for i in 0..worker_count {
            let start = (i as u64).saturating_mul(segment_size);
            if start >= total {
                break;
            }
            let end = (start + chunk_size - 1).min(total - 1);
            let worker_client = client.clone();
            let worker_url = url.to_string();
            handles.push(thread::spawn(move || {
                read_range_discard(&worker_client, &worker_url, start, end)
            }));
        }

        let mut errors = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(Ok(bytes)) => sample_bytes += bytes,
                Ok(Err(e)) => errors.push(e),
                Err(_) => errors.push("Adaptive sample worker panicked".to_string()),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    } else {
        let end = (target_sample_bytes - 1).min(total - 1);
        read_range_discard(client, url, 0, end).map(|bytes| {
            sample_bytes = bytes;
        })
    };

    let sample_ms = start_time.elapsed().as_millis();
    let avg_mib_s = if sample_ms > 0 {
        (sample_bytes as f64) / (sample_ms as f64 / 1000.0) / (1024.0 * 1024.0)
    } else {
        0.0
    };
    let history_avg_mib_s = history_avg_for_variant(history, &candidate.variant);
    let score_mib_s = if let Some(history_avg_mib_s) = history_avg_mib_s {
        avg_mib_s * 0.65 + history_avg_mib_s * 0.35
    } else {
        avg_mib_s
    };

    AdaptiveSample {
        variant: candidate.variant.clone(),
        mode: if candidate.segment_size.is_some() {
            "segmented".to_string()
        } else {
            "single".to_string()
        },
        segment_size: candidate.segment_size,
        concurrency: candidate.concurrency,
        sample_bytes,
        sample_ms,
        avg_mib_s,
        history_avg_mib_s,
        score_mib_s,
        status: if result.is_ok() { "PASS" } else { "FAIL" }.to_string(),
        error: result.err(),
    }
}

fn choose_adaptive_candidate(
    client: &Client,
    url: &str,
    probe: &DownloadProbe,
    history: &[BenchHistoryEntry],
) -> Result<(BenchCandidate, Vec<AdaptiveSample>), String> {
    if !probe.range_supported || probe.total == 0 {
        let candidate = BenchCandidate {
            variant: "single".to_string(),
            segment_size: None,
            concurrency: None,
        };
        return Ok((candidate, Vec::new()));
    }

    let candidates = adaptive_candidates();
    let samples = candidates
        .iter()
        .map(|candidate| sample_candidate(client, url, probe.total, candidate, history))
        .collect::<Vec<_>>();
    let winner = samples
        .iter()
        .filter(|sample| sample.status == "PASS" && sample.sample_bytes > 0)
        .max_by(|a, b| a.score_mib_s.total_cmp(&b.score_mib_s))
        .ok_or_else(|| "Adaptive sampling produced no successful candidate".to_string())?;
    let candidate = candidates
        .into_iter()
        .find(|candidate| candidate.variant == winner.variant)
        .ok_or_else(|| "Adaptive winner was not found in candidate list".to_string())?;

    Ok((candidate, samples))
}

fn run_bench_download(args: &[String]) -> Result<(), String> {
    let config = parse_bench_config(args)?;
    if let Some(parent) = config.out.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Create benchmark output dir error: {e}"))?;
    }

    let out_str = config.out.to_string_lossy().to_string();
    let part_path = format!("{out_str}.part");
    let meta_path = format!("{part_path}.json");
    let _ = fs::remove_file(&config.out);
    let _ = fs::remove_file(&part_path);
    let _ = fs::remove_file(&meta_path);

    let total_start = Instant::now();
    let client = build_client(&config.proxy, 3600, config.allow_invalid_certs)?;
    let probe_start = Instant::now();
    let probe = probe_download(&client, &config.url)?;
    let probe_ms = probe_start.elapsed().as_millis();
    let history = load_bench_history(&config.history, &config.url, &probe);

    let selected_variant;
    let adaptive_samples;
    let segmented_config = match config.mode {
        BenchMode::Auto => {
            selected_variant = Some(
                if probe.range_supported && probe.total >= SEGMENTED_MIN_SIZE {
                    "auto-segmented".to_string()
                } else {
                    "auto-single".to_string()
                },
            );
            adaptive_samples = None;
            if probe.range_supported && probe.total >= SEGMENTED_MIN_SIZE {
                Some(apply_segmented_overrides(
                    probe.total,
                    config.segment_size,
                    config.concurrency,
                )?)
            } else {
                None
            }
        }
        BenchMode::Single => {
            selected_variant = Some("single".to_string());
            adaptive_samples = None;
            None
        }
        BenchMode::Segmented => {
            if !probe.range_supported {
                return Err(
                    "--mode segmented requested but server does not support Range".to_string(),
                );
            }
            let segmented_config =
                apply_segmented_overrides(probe.total, config.segment_size, config.concurrency)?;
            selected_variant = Some(segmented_variant_name(segmented_config));
            adaptive_samples = None;
            Some(segmented_config)
        }
        BenchMode::Adaptive => {
            let (candidate, samples) =
                choose_adaptive_candidate(&client, &config.url, &probe, &history)?;
            selected_variant = Some(candidate.variant);
            adaptive_samples = Some(samples);
            if candidate.segment_size.is_some() {
                Some(apply_segmented_overrides(
                    probe.total,
                    candidate.segment_size,
                    candidate.concurrency,
                )?)
            } else {
                None
            }
        }
    };
    let segmented = segmented_config.is_some();
    let (tx, rx) = mpsc::channel();
    let ctrl = DownloadControl::new();
    let download_start = Instant::now();

    if let Some(segmented_config) = segmented_config {
        download_segmented(
            &client,
            &config.url,
            &out_str,
            &probe,
            segmented_config,
            &ctrl,
            &tx,
        )?;
    } else {
        download_single(&client, &config.url, &out_str, probe.total, &ctrl, &tx)?;
    }

    let download_ms = download_start.elapsed().as_millis();
    let total_ms = total_start.elapsed().as_millis();
    let file_bytes = fs::metadata(&config.out)
        .map_err(|e| format!("Benchmark output stat error: {e}"))?
        .len();
    if probe.total > 0 && file_bytes != probe.total {
        return Err(format!(
            "Benchmark size mismatch: expected {}, got {}",
            probe.total, file_bytes
        ));
    }

    let progress = rx.try_iter().collect::<Vec<_>>();
    let peak_mib_s = progress
        .iter()
        .map(|(_, _, speed_kib_s, _)| speed_kib_s / 1024.0)
        .fold(0.0, f64::max);
    let avg_mib_s = if download_ms > 0 {
        (file_bytes as f64) / (download_ms as f64 / 1000.0) / (1024.0 * 1024.0)
    } else {
        0.0
    };
    let sha256 = sha256_file(&config.out)?;
    let segment_count = segmented_config.map(|c| probe.total.div_ceil(c.segment_size) as usize);

    let result = BenchResult {
        schema_version: 1,
        status: "PASS".to_string(),
        url: config.url,
        output: out_str,
        mode: match config.mode {
            BenchMode::Adaptive => "adaptive".to_string(),
            _ if segmented => "segmented".to_string(),
            _ => "single".to_string(),
        },
        selected_variant,
        history_path: config
            .history
            .as_ref()
            .map(|path| path.to_string_lossy().to_string()),
        history_matches: history.len(),
        total_bytes: probe.total,
        file_bytes,
        range_supported: probe.range_supported,
        segment_size: segmented_config.map(|c| c.segment_size),
        concurrency: segmented_config.map(|c| c.concurrency),
        segment_count,
        probe_ms,
        download_ms,
        total_ms,
        avg_mib_s,
        peak_mib_s,
        progress_events: progress.len(),
        adaptive_samples,
        sha256,
        etag: probe.etag,
        last_modified: probe.last_modified,
    };

    append_bench_history(&config.history, &result)?;
    write_bench_json(&config.json, &result)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&result)
            .map_err(|e| format!("Encode benchmark stdout error: {e}"))?
    );
    Ok(())
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
