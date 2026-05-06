use eframe::egui;
use gh_mirror_gui::backend_contract::{UpdateCandidateCheckReport, UpdateCandidateStageReport};
use std::path::Path;

pub(crate) fn render_update_candidate_check(
    ui: &mut egui::Ui,
    report: &UpdateCandidateCheckReport,
) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Trust Center · Self-update Stage 1").strong());
        ui.small(
            "Backend/core verdict only: no install, no exe replacement, no system persistence.",
        );
        egui::Grid::new("trust_center_update_candidate")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Status");
                ui.label(report.status_display());
                ui.end_row();

                ui.label("Release");
                ui.label(format!("{} @ {}", report.repo, report.release_tag));
                ui.end_row();

                ui.label("Asset");
                ui.label(&report.asset_name);
                ui.end_row();

                ui.label("Reason");
                ui.label(&report.evaluation.reason);
                ui.end_row();

                ui.label("refusal_reason");
                ui.label(report.refusal_reason().unwrap_or("none"));
                ui.end_row();

                ui.label("Publisher fingerprint");
                ui.label(
                    report
                        .publisher_key_fingerprint_sha256()
                        .unwrap_or("not available"),
                );
                ui.end_row();

                ui.label("Evidence path");
                ui.label(
                    report
                        .evaluation
                        .evidence_path
                        .as_deref()
                        .unwrap_or("not recorded"),
                );
                ui.end_row();

                ui.label("No mutation");
                ui.label(report.evaluation.no_mutation.to_string());
                ui.end_row();
            });

        if let Some(error) = &report.evidence_write_error {
            ui.colored_label(
                egui::Color32::from_rgb(220, 160, 0),
                format!("Evidence write warning: {error}"),
            );
        }
        if let Some(path) = report.evaluation.evidence_path.as_deref() {
            let evidence_path = Path::new(path);
            if evidence_path.is_file() {
                if ui.button("📄 Open Update Evidence").clicked() {
                    let _ = open::that(evidence_path);
                }
            } else {
                ui.small("Update evidence path is recorded but not present on disk.");
            }
        }
    });
}

pub(crate) fn render_update_candidate_stage(
    ui: &mut egui::Ui,
    report: &UpdateCandidateStageReport,
) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Self-update Stage 2 (staging)").strong());
        ui.small("No install: stages a verified candidate to a local folder and records evidence.");

        egui::Grid::new("trust_center_update_stage")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Status");
                ui.label(format!("{:?}", report.status).to_lowercase());
                ui.end_row();

                ui.label("Release");
                ui.label(format!("{} @ {}", report.repo, report.release_tag));
                ui.end_row();

                ui.label("Reason");
                ui.label(&report.reason);
                ui.end_row();

                ui.label("Publisher fingerprint");
                ui.label(
                    report
                        .publisher_key_fingerprint_sha256
                        .as_deref()
                        .unwrap_or("not available"),
                );
                ui.end_row();

                ui.label("Stage dir");
                ui.label(report.stage_dir.as_deref().unwrap_or("not staged"));
                ui.end_row();

                ui.label("Staged asset");
                ui.label(report.staged_asset_path.as_deref().unwrap_or("none"));
                ui.end_row();

                ui.label("Expected SHA256");
                ui.label(report.expected_sha256.as_deref().unwrap_or("unknown"));
                ui.end_row();

                ui.label("Staged SHA256");
                ui.label(report.staged_sha256.as_deref().unwrap_or("unknown"));
                ui.end_row();

                ui.label("Evidence path");
                ui.label(report.evidence_path.as_deref().unwrap_or("not recorded"));
                ui.end_row();
            });

        if let Some(error) = &report.evidence_write_error {
            ui.colored_label(
                egui::Color32::from_rgb(220, 160, 0),
                format!("Evidence write warning: {error}"),
            );
        }

        if let Some(dir) = report.stage_dir.as_deref() {
            let stage_dir = Path::new(dir);
            if stage_dir.is_dir() && ui.button("📁 Open stage folder").clicked() {
                let _ = open::that(stage_dir);
            }
        }
        if let Some(path) = report.evidence_path.as_deref() {
            let evidence_path = Path::new(path);
            if evidence_path.is_file() && ui.button("📄 Open stage evidence").clicked() {
                let _ = open::that(evidence_path);
            }
        }
    });
}
