use crate::download::{sha256_file, DownloadProbe, SelectedDownloadStrategy};
use directories::ProjectDirs;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct BenchHistoryEntry {
    pub(crate) schema_version: u32,
    pub(crate) url: String,
    pub(crate) variant: String,
    pub(crate) mode: String,
    pub(crate) total_bytes: u64,
    pub(crate) segment_size: Option<u64>,
    pub(crate) concurrency: Option<usize>,
    pub(crate) download_ms: u128,
    pub(crate) avg_mib_s: f64,
    pub(crate) sha256: String,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
    pub(crate) recorded_at_epoch_secs: u64,
}

pub(crate) fn default_history_path() -> PathBuf {
    ProjectDirs::from("com", "gh_mirror_gui", "gh_mirror_gui")
        .map(|dirs| dirs.data_local_dir().join("bench-history.jsonl"))
        .unwrap_or_else(|| PathBuf::from("target").join("bench-history.jsonl"))
}

pub(crate) fn load_bench_history(
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

pub(crate) fn history_avg_for_variant(history: &[BenchHistoryEntry], variant: &str) -> Option<f64> {
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

pub(crate) fn unix_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(crate) fn append_bench_history_entry(
    path: &Option<PathBuf>,
    entry: &BenchHistoryEntry,
) -> Result<(), String> {
    let Some(path) = path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Create benchmark history dir error: {e}"))?;
    }

    let line = serde_json::to_string(entry)
        .map_err(|e| format!("Encode benchmark history entry error: {e}"))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| format!("Open benchmark history error: {e}"))?;
    writeln!(file, "{line}").map_err(|e| format!("Write benchmark history error: {e}"))
}

pub(crate) fn append_download_history(
    path: &Option<PathBuf>,
    url: &str,
    output: &PathBuf,
    probe: &DownloadProbe,
    strategy: &SelectedDownloadStrategy,
    download_elapsed: Duration,
) -> Result<(), String> {
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
    let _history_matches = strategy.history_matches;
    let entry = BenchHistoryEntry {
        schema_version: 1,
        url: url.to_string(),
        variant: strategy.variant.clone(),
        mode: if strategy.config.is_some() {
            "adaptive".to_string()
        } else {
            "single".to_string()
        },
        total_bytes: probe.total,
        segment_size: strategy.config.map(|config| config.segment_size),
        concurrency: strategy.config.map(|config| config.concurrency),
        download_ms,
        avg_mib_s,
        sha256,
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
        recorded_at_epoch_secs: unix_epoch_secs(),
    };
    append_bench_history_entry(path, &entry)
}
