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
        if ui
            .add(egui::Button::new(action.label).rounding(complete_control_rounding()))
            .clicked()
        {
            let _ = open::that(path);
        }
    } else {
        ui.add_enabled(
            false,
            egui::Button::new(action.label).rounding(complete_control_rounding()),
        );
        ui.small(action.missing_message);
    }
}

fn complete_control_rounding() -> egui::Rounding {
    egui::Rounding {
        nw: 8.0,
        ne: 8.0,
        sw: 8.0,
        se: 8.0,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_path_action_buttons_use_complete_four_corner_rounding() {
        let rounding = complete_control_rounding();

        assert!(rounding.nw > 0.0);
        assert_eq!(rounding.nw, rounding.ne);
        assert_eq!(rounding.nw, rounding.sw);
        assert_eq!(rounding.nw, rounding.se);
    }
}
