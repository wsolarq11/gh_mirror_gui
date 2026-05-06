use eframe::egui;
use gh_mirror_gui::backend_contract;
use reqwest::blocking::Client;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub(crate) fn history_path_from_setting(value: &str) -> PathBuf {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        backend_contract::default_history_path()
    } else {
        PathBuf::from(trimmed)
    }
}

pub(crate) fn extract_filename(url: &str) -> Option<String> {
    let parts: Vec<&str> = url.rsplitn(2, '/').collect();
    if parts.len() >= 2 && !parts[0].is_empty() {
        Some(parts[0].to_string())
    } else {
        None
    }
}

pub(crate) fn build_effective_url(mirror_url: &str, raw_url: &str) -> String {
    if mirror_url.is_empty() {
        raw_url.to_string()
    } else {
        format!("{}{}", mirror_url, raw_url)
    }
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

pub(crate) fn latency_color(ms: f64) -> egui::Color32 {
    if ms < 200.0 {
        egui::Color32::from_rgb(0, 200, 0) // green
    } else if ms < 500.0 {
        egui::Color32::from_rgb(255, 200, 0) // yellow/orange
    } else {
        egui::Color32::from_rgb(255, 80, 80) // red
    }
}

pub(crate) fn run_speed_test(
    mirror_urls: &[String],
    timeout_secs: u64,
    progress_tx: &mpsc::Sender<(usize, Option<Duration>)>,
) -> usize {
    let client = match Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
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
