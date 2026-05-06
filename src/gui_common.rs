use eframe::egui;
use gh_mirror_gui::backend_contract;
use gh_mirror_gui::backend_contract::{ImportedPublisherKeyPin, TrustPolicyConfig};
use std::path::Path;

pub(crate) fn import_publisher_key_pin_from_path(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Read publisher public key {}: {e}", path.display()))?;
    backend_contract::normalize_public_key_pin(&text)
}

pub(crate) fn apply_imported_publisher_key_pin(
    trust_policy: &mut TrustPolicyConfig,
    publisher_key_source: &mut String,
    imported: ImportedPublisherKeyPin,
    source_label: impl Into<String>,
) -> String {
    trust_policy.source_trust.trusted_publisher_key = imported.public_key;
    let source_label = source_label.into();
    *publisher_key_source = source_label.clone();
    let short_fingerprint = imported
        .fingerprint_sha256
        .chars()
        .take(12)
        .collect::<String>();
    format!(
        "Imported Ed25519 publisher key from {} · fingerprint {}…",
        source_label, short_fingerprint
    )
}

pub(crate) fn status_color(status: &str) -> egui::Color32 {
    if status.contains('❌') {
        egui::Color32::from_rgb(220, 70, 70)
    } else if status.contains('⚠') {
        egui::Color32::from_rgb(220, 160, 0)
    } else {
        egui::Color32::from_rgb(0, 180, 0)
    }
}
