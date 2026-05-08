use crate::gui_common::render_backend_path_action;
use eframe::egui;
use gh_mirror_gui::backend_contract::{
    self, UpdateApplyPlan, UpdateApplyPlanEvidenceRecord, UpdateCandidateCheckReport,
    UpdateCandidateStageReport,
};

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

        if let Some(warning) = backend_contract::update_candidate_check_evidence_warning(report) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }
        if let Some(action) = backend_contract::update_candidate_check_evidence_action(report) {
            render_backend_path_action(ui, action);
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

        if let Some(warning) = backend_contract::update_candidate_stage_evidence_warning(report) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }

        if let Some(action) = backend_contract::update_candidate_stage_folder_action(report) {
            render_backend_path_action(ui, action);
        }
        if let Some(action) = backend_contract::update_candidate_stage_evidence_action(report) {
            render_backend_path_action(ui, action);
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

        if let Some(warning) = backend_contract::update_apply_plan_evidence_warning(evidence) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }
        if let Some(action) = backend_contract::update_apply_plan_evidence_action(evidence) {
            render_backend_path_action(ui, action);
        }
        if let Some(message) = backend_contract::update_apply_plan_missing_evidence_message(evidence)
        {
            ui.small(message);
        }

        for step_row in backend_contract::update_apply_plan_step_rows(plan) {
            ui.small(step_row);
        }
    });
}
