use crate::download::{
    apply_segmented_overrides, build_client, download_segmented, download_single, probe_download,
    segmented_config_for, segmented_variant_name, sha256_file, DownloadControl, DownloadProbe,
    SegmentedDownloadConfig, SelectedDownloadStrategy, DOWNLOAD_BUFFER_SIZE, SEGMENTED_MIN_SIZE,
};
use crate::history::{
    append_bench_history_entry, history_avg_for_variant, load_bench_history, unix_epoch_secs,
    BenchHistoryEntry,
};
use reqwest::blocking::Client;
use std::fs;
use std::io::Read;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

const ADAPTIVE_TOTAL_SAMPLE_SIZE: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
pub(crate) struct BenchConfig {
    pub(crate) url: String,
    pub(crate) out: PathBuf,
    pub(crate) json: Option<PathBuf>,
    pub(crate) history: Option<PathBuf>,
    pub(crate) proxy: String,
    pub(crate) allow_invalid_certs: bool,
    pub(crate) mode: BenchMode,
    pub(crate) segment_size: Option<u64>,
    pub(crate) concurrency: Option<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BenchMode {
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

fn config_for_candidate(total: u64, candidate: &BenchCandidate) -> Option<SegmentedDownloadConfig> {
    if candidate.segment_size.is_some() {
        apply_segmented_overrides(total, candidate.segment_size, candidate.concurrency).ok()
    } else {
        None
    }
}

pub(crate) fn choose_history_backed_strategy(
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

pub(crate) fn parse_bench_config(args: &[String]) -> Result<BenchConfig, String> {
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

fn append_bench_history(path: &Option<PathBuf>, result: &BenchResult) -> Result<(), String> {
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
    append_bench_history_entry(path, &entry)
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

pub(crate) fn run_bench_download(args: &[String]) -> Result<(), String> {
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
