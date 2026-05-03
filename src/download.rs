use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const MAX_RETRIES: u32 = 3;
const RETRY_DELAY_MS: u64 = 1000;
pub(crate) const DOWNLOAD_BUFFER_SIZE: usize = 256 * 1024;
const PROGRESS_INTERVAL_MS: u128 = 200;
pub(crate) const SEGMENTED_MIN_SIZE: u64 = 8 * 1024 * 1024;
pub(crate) const SEGMENT_SIZE: u64 = 4 * 1024 * 1024;
pub(crate) const SEGMENT_CONCURRENCY: usize = 4;

pub(crate) struct DownloadControl {
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
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            cancel_flag: AtomicBool::new(false),
            pause_flag: AtomicBool::new(false),
            pause_mutex: Mutex::new(()),
            pause_condvar: Condvar::new(),
        })
    }

    pub(crate) fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
        self.pause_condvar.notify_all();
    }

    pub(crate) fn pause(&self) {
        self.pause_flag.store(true, Ordering::Relaxed);
    }

    pub(crate) fn resume(&self) {
        self.pause_flag.store(false, Ordering::Relaxed);
        self.pause_condvar.notify_all();
    }

    pub(crate) fn is_paused(&self) -> bool {
        self.pause_flag.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct DownloadProbe {
    pub(crate) total: u64,
    pub(crate) range_supported: bool,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
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
pub(crate) struct SegmentedDownloadConfig {
    pub(crate) segment_size: u64,
    pub(crate) concurrency: usize,
}

#[derive(Clone, Debug)]
pub(crate) struct SelectedDownloadStrategy {
    pub(crate) variant: String,
    pub(crate) config: Option<SegmentedDownloadConfig>,
    pub(crate) history_matches: usize,
}

pub(crate) fn extract_filename(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(2, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() {
        return Some(parts[0].to_string());
    }
    None
}

pub(crate) fn build_effective_url(mirror_url: &str, raw_url: &str) -> String {
    if mirror_url.is_empty() {
        raw_url.to_string()
    } else {
        format!("{}{}", mirror_url, raw_url)
    }
}

pub(crate) fn build_client(
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

pub(crate) fn probe_download(client: &Client, url: &str) -> Result<DownloadProbe, String> {
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

pub(crate) fn format_speed(speed_kbps: f64) -> String {
    if speed_kbps > 1024.0 {
        format!("{:.1} MB/s", speed_kbps / 1024.0)
    } else if speed_kbps > 1.0 {
        format!("{:.0} KB/s", speed_kbps)
    } else {
        format!("{:.1} B/s", speed_kbps * 1024.0)
    }
}

pub(crate) fn download_with_strategy(
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

pub(crate) fn segmented_config_for(total: u64) -> SegmentedDownloadConfig {
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

pub(crate) fn segmented_variant_name(config: SegmentedDownloadConfig) -> String {
    format!(
        "seg-c{}-s{}",
        config.concurrency,
        segment_size_label(config.segment_size)
    )
}

pub(crate) fn apply_segmented_overrides(
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

pub(crate) fn download_segmented(
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

pub(crate) fn download_single(
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

pub(crate) fn sha256_file(path: &PathBuf) -> Result<String, String> {
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
