use serde::Serialize;
use std::fs;
use std::io::Write;
use std::path::Path;

/// Evidence ledger seam (Phase 5: Artifact Trust Broker / future storage backends).
///
/// Today we write evidence to the local filesystem (JSON + JSONL). This trait is the
/// stable internal seam that lets us evolve toward alternative ledgers (SQLite, remote
/// audit export, enterprise policy stores) without rewriting the core pipeline.
pub(crate) trait EvidenceLedger {
    fn write_text(&self, path: &Path, text: &str) -> Result<(), String>;
    fn append_line(&self, path: &Path, line: &str) -> Result<(), String>;
}

pub(crate) struct FileSystemEvidenceLedger;

impl EvidenceLedger for FileSystemEvidenceLedger {
    fn write_text(&self, path: &Path, text: &str) -> Result<(), String> {
        ensure_parent_dir(path)?;
        fs::write(path, text.as_bytes()).map_err(|e| format!("Write {}: {e}", path.display()))
    }

    fn append_line(&self, path: &Path, line: &str) -> Result<(), String> {
        ensure_parent_dir(path)?;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| format!("Open {}: {e}", path.display()))?;
        writeln!(file, "{line}").map_err(|e| format!("Append {}: {e}", path.display()))
    }
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|e| format!("Create parent dir {}: {e}", parent.display()))
}

pub(crate) fn write_json_pretty<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let pretty = serde_json::to_string_pretty(value).map_err(|e| format!("Serialize JSON: {e}"))?;
    FileSystemEvidenceLedger.write_text(path, &format!("{pretty}\n"))
}

pub(crate) fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let line = serde_json::to_string(value).map_err(|e| format!("Serialize JSONL: {e}"))?;
    FileSystemEvidenceLedger.append_line(path, &line)
}
