use eframe::egui;
use gh_mirror_gui::backend_contract;
use std::path::Path;

pub(crate) fn import_publisher_key_pin_from_path(path: &Path) -> Result<String, String> {
    backend_contract::import_publisher_key_pin_from_path(path)
}

pub(crate) fn render_backend_path_action(
    ui: &mut egui::Ui,
    action: backend_contract::BackendPathAction,
) {
    let path = Path::new(&action.path);
    let path_ready = match action.kind {
        backend_contract::BackendPathActionKind::File => path.is_file(),
        backend_contract::BackendPathActionKind::Directory => path.is_dir(),
    };
    if path_ready {
        if ui.button(action.label).clicked() {
            let _ = open::that(path);
        }
    } else {
        ui.add_enabled(false, egui::Button::new(action.label));
        ui.small(action.missing_message);
    }
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
