use crate::gui_common::render_backend_path_action;
use eframe::egui;
use gh_mirror_gui::backend_contract::{
    self, ArtifactDecision, UpdateApplyBundleEvidenceRecord, UpdateApplyPlan,
    UpdateApplyPlanEvidenceRecord, UpdateCandidateCheckReport, UpdateCandidateStageReport,
};

fn render_artifact_decision(ui: &mut egui::Ui, grid_id: &'static str, decision: &ArtifactDecision) {
    egui::Grid::new(grid_id)
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            for row in backend_contract::artifact_decision_rows(decision) {
                ui.label(row.label);
                ui.label(row.value);
                ui.end_row();
            }
        });

    if let Some(action) = backend_contract::artifact_decision_action_path(decision) {
        render_backend_path_action(ui, action);
    }
    if let Some(action) = backend_contract::artifact_decision_evidence_action(decision) {
        render_backend_path_action(ui, action);
    }
    for step_row in backend_contract::artifact_decision_step_rows(decision) {
        ui.small(step_row);
    }
}

pub(crate) fn render_update_candidate_check(
    ui: &mut egui::Ui,
    report: &UpdateCandidateCheckReport,
) {
    ui.group(|ui| {
        let decision = backend_contract::artifact_decision_from_update_candidate_check(report);
        ui.label(egui::RichText::new("Trust Center · Self-update Stage 1").strong());
        ui.small(
            "Backend/core verdict only: no install, no exe replacement, no system persistence.",
        );
        render_artifact_decision(ui, "trust_center_update_candidate", &decision);

        if let Some(warning) = backend_contract::update_candidate_check_evidence_warning(report) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }
    });
}

pub(crate) fn render_update_candidate_stage(
    ui: &mut egui::Ui,
    report: &UpdateCandidateStageReport,
) {
    ui.group(|ui| {
        let decision = backend_contract::artifact_decision_from_update_candidate_stage(report);
        ui.label(egui::RichText::new("Self-update Stage 2 (staging)").strong());
        ui.small("No install: stages a verified candidate to a local folder and records evidence.");

        render_artifact_decision(ui, "trust_center_update_stage", &decision);

        if let Some(warning) = backend_contract::update_candidate_stage_evidence_warning(report) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }
    });
}

pub(crate) fn render_update_apply_plan_preview(
    ui: &mut egui::Ui,
    plan: &UpdateApplyPlan,
    evidence: Option<&UpdateApplyPlanEvidenceRecord>,
) {
    ui.group(|ui| {
        let decision =
            backend_contract::artifact_decision_from_update_apply_plan_evidence(plan, evidence);
        ui.label(egui::RichText::new("Self-update Stage 3 (apply plan preview)").strong());
        ui.small(
            "Pure backend plan only: no mutation, no install, no exe replacement; preview is reversible.",
        );

        render_artifact_decision(ui, "trust_center_update_apply_plan", &decision);

        if let Some(warning) = backend_contract::update_apply_plan_evidence_warning(evidence) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }
        if let Some(message) = backend_contract::update_apply_plan_missing_evidence_message(evidence)
        {
            ui.small(message);
        }
    });
}

pub(crate) fn render_update_apply_bundle_preview(
    ui: &mut egui::Ui,
    record: &UpdateApplyBundleEvidenceRecord,
) {
    ui.group(|ui| {
        let decision = backend_contract::artifact_decision_from_update_apply_bundle_evidence(record);
        ui.label(egui::RichText::new("Self-update Stage 4 (controlled helper bundle)").strong());
        ui.small(
            "Backend/core prepared bundle only: no install launched here; helper execution remains explicit and receipt-bound.",
        );

        render_artifact_decision(ui, "trust_center_update_apply_bundle", &decision);
        egui::Grid::new("trust_center_update_apply_bundle_summary")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                for row in backend_contract::update_apply_bundle_summary_rows(record) {
                    ui.label(row.label);
                    ui.label(row.value);
                    ui.end_row();
                }
            });

        if let Some(warning) = backend_contract::update_apply_bundle_evidence_warning(record) {
            ui.colored_label(egui::Color32::from_rgb(220, 160, 0), warning);
        }
        if let Some(action) = backend_contract::update_apply_bundle_evidence_action(record) {
            render_backend_path_action(ui, action);
        }
    });
}
