use eframe::egui;
use gh_mirror_gui::backend_contract::{
    self, UpdateApplyPlan, UpdateApplyPlanEvidenceRecord, UpdateCandidateCheckReport,
    UpdateCandidateStageReport,
};
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
                for row in backend_contract::update_candidate_check_rows(report) {
                    ui.label(row.label);
                    ui.label(row.value);
                    ui.end_row();
                }
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
                for row in backend_contract::update_candidate_stage_rows(report) {
                    ui.label(row.label);
                    ui.label(row.value);
                    ui.end_row();
                }
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

pub(crate) fn render_update_apply_plan_preview(
    ui: &mut egui::Ui,
    plan: &UpdateApplyPlan,
    evidence: Option<&UpdateApplyPlanEvidenceRecord>,
) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Self-update Stage 3 (apply plan preview)").strong());
        ui.small(
            "Pure backend plan only: no mutation, no install, no exe replacement; preview is reversible.",
        );

        egui::Grid::new("trust_center_update_apply_plan")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                for row in backend_contract::update_apply_plan_summary_rows(plan, evidence) {
                    ui.label(row.label);
                    ui.label(row.value);
                    ui.end_row();
                }
            });

        if let Some(record) = evidence {
            if let Some(error) = record.write_error.as_deref() {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 0),
                    format!("Evidence write warning: {error}"),
                );
            }
            if let Some(path) = record.evidence_path.as_deref() {
                let evidence_path = Path::new(path);
                if evidence_path.is_file() {
                    if ui.button("📄 Open apply plan evidence").clicked() {
                        let _ = open::that(evidence_path);
                    }
                } else {
                    ui.small("Apply plan evidence path is recorded but not present on disk.");
                }
            }
        } else {
            ui.small("Apply plan evidence is not recorded for this preview.");
        }

        for (idx, step) in plan.steps.iter().enumerate() {
            ui.small(format!(
                "{}: {}",
                idx + 1,
                backend_contract::describe_update_apply_step(step)
            ));
        }
    });
}
