use eframe::egui;
use gh_mirror_gui::backend_contract::{
    UpdateApplyPlan, UpdateApplyPlanEvidenceRecord, UpdateApplyStep, UpdateCandidateCheckReport,
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

fn describe_update_apply_step(step: &UpdateApplyStep) -> String {
    match step {
        UpdateApplyStep::VerifyStagedCandidateSha256 {
            path,
            expected_sha256,
        } => format!("Verify staged candidate SHA256 at {path} == {expected_sha256}"),
        UpdateApplyStep::BackupCurrentExecutable { from, to } => {
            format!("Backup current executable {from} -> {to}")
        }
        UpdateApplyStep::ReplaceExecutableFromStage { from, to } => {
            format!("Replace executable from staged asset {from} -> {to}")
        }
        UpdateApplyStep::VerifyInstalledExecutableSha256 {
            path,
            expected_sha256,
        } => format!("Verify installed executable SHA256 at {path} == {expected_sha256}"),
        UpdateApplyStep::RollbackByRestoringBackup {
            from_backup,
            to_target,
        } => format!("Rollback by restoring backup {from_backup} -> {to_target}"),
    }
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
                ui.label("Status");
                ui.label(format!("{:?}", plan.status).to_lowercase());
                ui.end_row();

                ui.label("Reason");
                ui.label(&plan.reason);
                ui.end_row();

                ui.label("Release");
                ui.label(format!("{} @ {}", plan.repo, plan.release_tag));
                ui.end_row();

                ui.label("Target exe");
                ui.label(plan.target_exe_path.as_deref().unwrap_or("not recorded"));
                ui.end_row();

                ui.label("Backup exe");
                ui.label(plan.backup_exe_path.as_deref().unwrap_or("not planned"));
                ui.end_row();

                ui.label("Reversible");
                ui.label(plan.reversible.to_string());
                ui.end_row();

                ui.label("No mutation");
                ui.label(plan.no_mutation.to_string());
                ui.end_row();

                ui.label("Evidence path");
                ui.label(
                    evidence
                        .and_then(|record| record.evidence_path.as_deref())
                        .unwrap_or("not recorded"),
                );
                ui.end_row();

                ui.label("Steps");
                ui.label(plan.steps.len().to_string());
                ui.end_row();
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
            ui.small(format!("{}: {}", idx + 1, describe_update_apply_step(step)));
        }
    });
}
