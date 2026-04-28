use eframe::egui;
use eframe::Storage;
use notify_rust::Notification;
use reqwest::blocking::Client;
use rfd::FileDialog;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use directories::UserDirs;

// ---------------------------------------------------------------------------
// Data structures and constants
// ---------------------------------------------------------------------------

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;
const SPEED_TEST_TIMEOUT_SECS: u64 = 5;

/// Known mirror sites.  First entry must be "Direct (no mirror)"
const MIRRORS: &[(&str, &str)] = &[
    ("Direct (no mirror)", ""),
    ("ghproxy.com", "https://ghproxy.com/"),
    ("mirror.ghproxy.com", "https://mirror.ghproxy.com/"),
    ("gh.api.99988866.xyz", "https://gh.api.99988866.xyz/"),
    ("gh-proxy.com", "https://gh-proxy.com/"),
    ("gh.con.sh", "https://gh.con.sh/"),
];

struct DownloadControl {
    cancel_flag: AtomicBool,
    pause_flag: AtomicBool,
    pause_mutex: Mutex<()>,
    pause_condvar: Condvar,
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
}

struct GhMirrorGui {
    url: String,
    save_dir: PathBuf,
    proxy: String,
    status: String,
    progress: f32,
    speed_text: String,
    elapsed_text: String,
    download_thread: Option<thread::JoinHandle<()>>,
    control: Option<Arc<DownloadControl>>,
    progress_rx: Option<mpsc::Receiver<(u64, u64, f64, f64)>>,
    // Mirror-related fields
    mirrors: Vec<String>,          // human-readable names
    mirror_urls: Vec<String>,      // actual URL prefixes
    selected_mirror: usize,        // index
    speed_test_status: String,
    speed_test_thread: Option<thread::JoinHandle<()>>,
    speed_test_rx: Option<mpsc::Receiver<usize>>,
    speed_test_progress_rx: Option<mpsc::Receiver<(usize, Option<Duration>)>>,
    speed_test_results: Vec<Option<Duration>>,
    speed_test_completed: usize,   // how many mirrors have been tested
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
        if let Some(storage) = storage {
            if let Some(json) = storage.get_string("app_settings") {
                if let Ok(state) = serde_json::from_str::<SavedState>(&json) {
                    selected_mirror = state.selected_mirror;
                    if !state.save_dir.is_empty() {
                        save_dir = state.save_dir;
                    }
                    proxy = state.proxy;
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
            download_complete_notified: false,        }
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
        let (progress_tx, progress_rx) = mpsc::channel();
        self.progress_rx = Some(progress_rx);

        self.progress = 0.0;
        self.speed_text.clear();
        self.elapsed_text.clear();
        self.status = String::from("Starting download...");

        self.download_thread = Some(thread::spawn(move || {
            let client = match build_client(&proxy, 30) {
                Ok(c) => c,
                Err(_e) => {
                    let _ = progress_tx.send((0, 0, 0.0, 0.0));
                    return;
                }
            };

            let total = head_info(&client, &effective_url).unwrap_or(0);

            match download_file(
                &client,
                &effective_url,
                save_path.to_str().unwrap(),
                total,
                &ctrl,
                &progress_tx,
            ) {
                Ok(()) => {
                    let _ = progress_tx.send((total, total, 0.0, 0.0));
                }
                Err(_e) => {
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
                    ui.add(egui::ProgressBar::new(pct).text(format!("{}/{}", tested, self.mirrors.len())));
                }
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .show(ui, |ui| {
                        for (i, name) in self.mirrors.iter().enumerate() {
                            match &self.speed_test_results[i] {
                                Some(dur) => {
                                    let ms = dur.as_secs_f64() * 1000.0;
                                    let color = latency_color(ms);
                                    let mark = if self.selected_mirror == i && self.speed_test_thread.is_none() {
                                        "⭐"
                                    } else {
                                        "  "
                                    };
                                    ui.label(
                                        egui::RichText::new(format!("{} {} {:.0} ms", mark, name, ms))
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
                    if let Some(dir) = FileDialog::new().set_directory(&self.save_dir).pick_folder() {
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
                if self.status.contains("✅") {
                    if ui.button("📂 Open Folder").clicked() {
                        if self.save_dir.exists() {
                            let _ = open::that(&self.save_dir);
                        }
                    }
                }
            });

            // Progress bar and info — always visible during download
            if self.download_thread.is_some() || self.progress > 0.0 || !self.speed_text.is_empty() {
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
        egui::Color32::from_rgb(0, 200, 0)       // green
    } else if ms < 500.0 {
        egui::Color32::from_rgb(255, 200, 0)      // yellow/orange
    } else {
        egui::Color32::from_rgb(255, 80, 80)      // red
    }
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn build_client(proxy: &str, timeout_secs: u64) -> Result<Client, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .tcp_nodelay(true)
        .pool_max_idle_per_host(10)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs));
    if !proxy.is_empty() {
        builder = builder.proxy(reqwest::Proxy::all(proxy)
            .map_err(|e| format!("Invalid proxy URL: {}", e))?);
    }
    builder.build().map_err(|e| format!("Client build error: {}", e))
}

fn head_info(client: &Client, url: &str) -> Result<u64, String> {
    let resp = client
        .head(url)
        .send()
        .map_err(|e| format!("HEAD request failed: {}", e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("Server returned {}", status));
    }

    let length: u64 = resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if length > 0 {
        return Ok(length);
    }

    let get_resp = client
        .get(url)
        .send()
        .map_err(|e| format!("GET request for Content-Length failed: {}", e))?;
    let get_status = get_resp.status();
    if !get_status.is_success() {
        return Err(format!("GET returned {}", get_status));
    }

    let get_length: u64 = get_resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    Ok(get_length)
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

fn download_file(
    client: &Client,
    url: &str,
    save_path: &str,
    total: u64,
    ctrl: &Arc<DownloadControl>,
    progress_tx: &mpsc::Sender<(u64, u64, f64, f64)>,
) -> Result<(), String> {
    download_single(client, url, save_path, total, ctrl, progress_tx)
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
        if !status.is_success() && status != 206 {
            if attempt == MAX_RETRIES {
                return Err(format!("Server returned {}", status));
            }
            continue;
        }

        let mut file = if downloaded == 0 {
            fs::OpenOptions::new()
                .create(true)
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

        let mut buf = [0u8; 8192];

        loop {
            if ctrl.cancel_flag.load(Ordering::Relaxed) {
                let _ = fs::remove_file(&tmp_path);
                return Err("Cancelled".into());
            }

            {
                let guard = ctrl.pause_mutex.lock().unwrap();
                if ctrl.pause_flag.load(Ordering::Relaxed) {
                    drop(ctrl.pause_condvar.wait(guard));
                    continue;
                }
            }

            let n = resp
                .read(&mut buf)
                .map_err(|e| format!("Read error: {}", e))?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])
                .map_err(|e| format!("Write error: {}", e))?;
            downloaded += n as u64;

            let elapsed = start_time.elapsed().as_secs_f64();
            let speed = if elapsed > 0.0 {
                (downloaded as f64) / (elapsed * 1024.0)
            } else {
                0.0
            };
            let _ = progress_tx.send((downloaded, total, speed, elapsed));
        }

        if total > 0 && downloaded >= total {
            break;
        }
    }

    fs::rename(&tmp_path, save_path)
        .map_err(|e| format!("Failed to rename temp file: {}", e))?;
    Ok(())
}

fn run_speed_test(mirror_urls: &[String], progress_tx: &mpsc::Sender<(usize, Option<Duration>)>) -> usize {
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
}fn main() -> Result<(), eframe::Error> {
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