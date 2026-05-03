use crate::download::{sha256_file, DownloadProbe, SelectedDownloadStrategy};
use crate::verification::VerificationReport;
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) verification_detail: Option<String>,
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
    verification: Option<&VerificationReport>,
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
        verification_status: verification.map(|report| report.status.as_str().to_string()),
        verification_source: verification.and_then(|report| report.source.clone()),
        expected_sha256: verification.and_then(|report| report.expected_sha256.clone()),
        verification_detail: verification.map(|report| report.detail.clone()),
        etag: probe.etag.clone(),
        last_modified: probe.last_modified.clone(),
        recorded_at_epoch_secs: unix_epoch_secs(),
    };
    append_bench_history_entry(path, &entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::SelectedDownloadStrategy;
    use crate::verification::{VerificationReport, VerificationStatus};

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_history_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    #[test]
    fn append_download_history_records_verification_status() {
        let output = unique_test_path("app.exe");
        let history = unique_test_path("bench-history.jsonl");
        fs::write(&output, b"history payload").unwrap();
        let probe = DownloadProbe {
            total: fs::metadata(&output).unwrap().len(),
            range_supported: false,
            etag: Some("\"etag\"".to_string()),
            last_modified: None,
        };
        let strategy = SelectedDownloadStrategy {
            variant: "single".to_string(),
            config: None,
            history_matches: 0,
        };
        let report = VerificationReport {
            status: VerificationStatus::Verified,
            asset_name: "app.exe".to_string(),
            file_sha256: sha256_file(&output).unwrap(),
            expected_sha256: Some(sha256_file(&output).unwrap()),
            source: Some("SHA256SUMS.txt".to_string()),
            detail: "SHA256 matched SHA256SUMS.txt".to_string(),
        };

        append_download_history(
            &Some(history.clone()),
            "https://example.test/app.exe",
            &output,
            &probe,
            &strategy,
            Duration::from_millis(10),
            Some(&report),
        )
        .unwrap();
        let line = fs::read_to_string(&history).unwrap();
        let entry = serde_json::from_str::<BenchHistoryEntry>(line.trim()).unwrap();

        assert_eq!(entry.verification_status.as_deref(), Some("VERIFIED"));
        assert_eq!(entry.verification_source.as_deref(), Some("SHA256SUMS.txt"));
        assert_eq!(entry.expected_sha256, report.expected_sha256);
        let _ = fs::remove_file(output);
        let _ = fs::remove_file(history);
    }
}
