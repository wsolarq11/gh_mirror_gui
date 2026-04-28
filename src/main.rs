use eframe::egui;
use eframe::Storage;
use reqwest::blocking::Client;
use rfd::FileDialog;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

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
}

impl GhMirrorGui {
    fn new() -> Self {
        let names: Vec<String> = MIRRORS.iter().map(|(name, _)| name.to_string()).collect();
        let urls: Vec<String> = MIRRORS.iter().map(|(_, url)| url.to_string()).collect();

        let (final_tx, final_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();

        let test_urls = urls.clone();
        let handle = thread::spawn(move || {
            let best = run_speed_test(&test_urls, &progress_tx);
            let _ = final_tx.send(best);
        });

        Self {
            url: String::new(),
            save_dir: PathBuf::from("."),
            proxy: String::new(),
            status: "Ready".to_string(),
            progress: 0.0,
            speed_text: String::new(),
            elapsed_text: String::new(),
            download_thread: None,
            control: None,
            progress_rx: None,
            mirrors: names,
            mirror_urls: urls,
            selected_mirror: 0,
            speed_test_status: "Testing mirrors...".to_string(),
            speed_test_thread: Some(handle),
            speed_test_rx: Some(final_rx),
            speed_test_progress_rx: Some(progress_rx),
            speed_test_results: vec![None; MIRRORS.len()],
            speed_test_completed: 0,
        }
    }
}

impl eframe::App for GhMirrorGui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // --- Check speed test progress ---
        if let Some(rx) = &self.speed_test_progress_rx {
            while let Ok((i, maybe_dur)) = rx.try_recv() {
                self.speed_test_results[i] = maybe_dur;
                self.speed_test_completed += 1;
                ctx.request_repaint();
            }
        }

        // --- Check speed test final result ---
        if let Some(rx) = &self.speed_test_rx {
            if let Ok(best_idx) = rx.try_recv() {
                self.selected_mirror = best_idx;
                self.speed_test_status = format!("Selected: {} (fastest)", self.mirrors[best_idx]);
                self.speed_test_rx = None;
                self.speed_test_progress_rx = None;
                self.speed_test_thread = None;
                ctx.request_repaint();
            }
        }

        // --- Pump download progress ---
        if let Some(rx) = &self.progress_rx {
            while let Ok((downloaded, total, speed, elapsed)) = rx.try_recv() {
                if total > 0 {
                    self.progress = downloaded as f32 / total as f32;
                } else {
                    // Unknown total: animate indeterminate bar
                    self.progress = (self.progress + 0.02) % 1.0;
                }
                self.speed_text = format_speed(speed);
                if speed > 0.0 {
                    self.elapsed_text = format!("{:.0}s elapsed", elapsed);
                } else {
                    self.elapsed_text = String::new();
                }
                ctx.request_repaint();
            }
        }

        // --- UI ---
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("GitHub Mirror Downloader");

            // Mirror selection row
            ui.horizontal(|ui| {
                ui.label("Mirror:");
                let prev = self.selected_mirror;
                egui::ComboBox::from_id_salt("mirror_select")
                    .selected_text(&self.mirrors[self.selected_mirror])
                    .show_ui(ui, |ui| {
                        for (i, name) in self.mirrors.iter().enumerate() {
                            ui.selectable_value(&mut self.selected_mirror, i, name);
                        }
                    });
                if self.selected_mirror != prev {
                    // User manually changed
                    self.speed_test_status = format!("Manual: {}", self.mirrors[self.selected_mirror]);
                }
                if ui.button("Retest").clicked() {
                    self.retest_mirrors();
                }
                ui.label(&self.speed_test_status);
            });

            // Show per-mirror latency testing progress and results
            let results = &self.speed_test_results;
            let total = self.mirrors.len();
            // Always show this group if we are testing or have results, to provide visual feedback
            if self.speed_test_progress_rx.is_some() || results.iter().any(|r| r.is_some()) {
                ui.group(|ui| {
                    ui.label("Latency (ms) -- lower is faster:");
                    // Overall progress bar
                    let done = self.speed_test_completed;
                    let progress_ratio = if total > 0 { done as f32 / total as f32 } else { 0.0 };
                    ui.add(egui::ProgressBar::new(progress_ratio).text(format!("{}/{}", done, total)));
                    // Per-mirror status
                    for (i, name) in self.mirrors.iter().enumerate() {
                        let text = match results[i] {
                            Some(d) => {
                                if i == self.selected_mirror && self.speed_test_status.contains("fastest") {
                                    format!("[FASTEST] {} -- {:.0} ms", name, d.as_secs_f64() * 1000.0)
                                } else {
                                    format!("   {} -- {:.0} ms", name, d.as_secs_f64() * 1000.0)
                                }
                            }
                            None => {
                                if self.speed_test_progress_rx.is_some() {
                                    format!("... {} -- testing...", name)
                                } else {
                                    format!("   {} -- not tested", name)
                                }
                            }
                        };
                        ui.label(&text);
                    }
                });
            }

            // URL row with paste and clear
            ui.horizontal(|ui| {
                ui.label("URL:");
                let url_response = ui.text_edit_singleline(&mut self.url);
                if ui.button("Paste").on_hover_text("Paste from clipboard").clicked() {
                    if let Ok(mut clipboard) = arboard::Clipboard::new() {
                        if let Ok(text) = clipboard.get_text() {
                            self.url = text.trim().to_string();
                            url_response.request_focus();
                        }
                    }
                }
                if ui.button("Clear").on_hover_text("Clear URL").clicked() {
                    self.url.clear();
                }
            });

            // Save to
            ui.horizontal(|ui| {
                ui.label("Save to:");
                ui.label(self.save_dir.display().to_string());
                if ui.button("Browse...").clicked() {
                    if let Some(dir) = FileDialog::new().pick_folder() {
                        self.save_dir = dir;
                    }
                }
            });

            // Proxy
            ui.horizontal(|ui| {
                ui.label("Proxy (optional):");
                ui.text_edit_singleline(&mut self.proxy);
            });

            ui.separator();

            let can_download = !self.url.is_empty()
                && self.download_thread.is_none()
                && self.control.is_none()
                && self.speed_test_rx.is_none(); // also block download while testing

            ui.horizontal(|ui| {
                if ui
                    .add_enabled(can_download, egui::Button::new("Download"))
                    .clicked()
                {
                    self.start_download();
                }

                if let Some(ctrl) = &self.control {
                    if ctrl.pause_flag.load(Ordering::Relaxed) {
                        if ui.button("Resume").clicked() {
                            ctrl.resume();
                        }
                    } else {
                        if ui.button("Pause").clicked() {
                            ctrl.pause();
                        }
                    }
                    if ui.button("Cancel").clicked() {
                        ctrl.cancel();
                    }
                }
            });

            ui.separator();

            if self.download_thread.is_some() || self.control.is_some() {
                if self.progress_rx.is_some() {
                    let bar = egui::ProgressBar::new(self.progress)
                        .show_percentage()
                        .animate(true);
                    ui.add(bar);
                } else {
                    ui.add(egui::ProgressBar::new(self.progress).show_percentage());
                }

                if !self.speed_text.is_empty() {
                    ui.label(&self.speed_text);
                }
                if !self.elapsed_text.is_empty() {
                    ui.label(&self.elapsed_text);
                }
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Center), |ui| {
                ui.label(&self.status);
            });
        });
    }

    fn save(&mut self, _storage: &mut dyn Storage) {}
}

impl GhMirrorGui {
    fn retest_mirrors(&mut self) {
        let (final_tx, final_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let test_urls = self.mirror_urls.clone();
        self.speed_test_status = "Testing mirrors...".to_string();
        self.speed_test_results = vec![None; self.mirrors.len()];
        self.speed_test_completed = 0;
        self.speed_test_thread = Some(thread::spawn(move || {
            let best = run_speed_test(&test_urls, &progress_tx);
            let _ = final_tx.send(best);
        }));
        self.speed_test_rx = Some(final_rx);
        self.speed_test_progress_rx = Some(progress_rx);
    }

    fn start_download(&mut self) {
        if self.url.is_empty() {
            self.status = "Please enter a URL".to_string();
            return;
        }

        let original_url = self.url.clone();
        // Build effective URL using selected mirror
        let effective_url = if self.selected_mirror > 0 && self.selected_mirror < self.mirror_urls.len() {
            format!("{}{}", self.mirror_urls[self.selected_mirror], original_url)
        } else {
            original_url.clone()
        };

        let save_path = self
            .save_dir
            .join(original_url.rsplit('/').next().unwrap_or("download.bin"));
        let proxy = self.proxy.clone();
        let control = DownloadControl::new();
        let ctrl = control.clone();
        let (progress_tx, progress_rx) = mpsc::channel();
        self.progress_rx = Some(progress_rx);

        self.progress = 0.0;
        self.speed_text.clear();
        self.elapsed_text.clear();
        self.status = "Starting download...".to_string();

        self.download_thread = Some(thread::spawn(move || {
            let client = match build_client(&proxy, 30) {
                Ok(c) => c,
                Err(_e) => {
                    let _ = progress_tx.send((0, 0, 0.0, 0.0));
                    return;
                }
            };

            // Fetch total size asynchronously in the thread - non-blocking to UI
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
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

#[allow(dead_code)]
fn extract_filename(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(2, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() {
        return Some(parts[0].to_string());
    }
    None
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

fn build_client(proxy: &str, timeout_secs: u64) -> Result<Client, String> {
    let mut builder = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs));
    if !proxy.is_empty() {
        builder = builder.proxy(reqwest::Proxy::all(proxy)
            .map_err(|e| format!("Invalid proxy URL: {}", e))?);
    }
    builder.build().map_err(|e| format!("Client build error: {}", e))
}

#[allow(dead_code)]
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

    // Fallback: GET request to obtain Content-Length
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
    ctrl: &DownloadControl,
    progress_tx: &mpsc::Sender<(u64, u64, f64, f64)>,
) -> Result<(), String> {
    let tmp_path = format!("{}.part", save_path);
    let start_time = Instant::now();
    let mut downloaded: u64 = 0;

    // Check for existing partial file
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
            // Range not satisfiable
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

        if total == 0 && downloaded == 0 {
            // File created, we'll write from scratch
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

    // Rename tmp file to final
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
        Err(_) => return 0, // default to direct
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
        let elapsed_opt = match result {
            Ok(resp) => {
                let status = resp.status();
                if status.is_success() || status.is_redirection() {
                    let elapsed = start.elapsed();
                    if elapsed < best_time {
                        best_time = elapsed;
                        best_idx = i;
                    }
                    Some(elapsed)
                } else {
                    None
                }
            }
            Err(_) => None,
        };
        let _ = progress_tx.send((i, elapsed_opt));
    }

    best_idx
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "GitHub Mirror Downloader",
        options,
        Box::new(|_cc| Ok(Box::new(GhMirrorGui::new()))),
    )
}