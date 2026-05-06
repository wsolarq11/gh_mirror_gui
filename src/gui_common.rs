use eframe::egui;
use gh_mirror_gui::backend_contract;
use std::path::Path;

pub(crate) fn import_publisher_key_pin_from_path(path: &Path) -> Result<String, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("Read publisher public key {}: {e}", path.display()))?;
    backend_contract::normalize_public_key_pin(&text)
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
