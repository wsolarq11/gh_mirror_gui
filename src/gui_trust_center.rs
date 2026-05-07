use eframe::egui;
use gh_mirror_gui::backend_contract::{self, AppliedFileDisposition, TrustCenterSnapshot};

pub(crate) fn format_download_completion_status(
    snapshot: &TrustCenterSnapshot,
    disposition: &AppliedFileDisposition,
) -> String {
    backend_contract::download_completion_status(snapshot, disposition)
}

pub(crate) fn format_download_notification_status(snapshot: &TrustCenterSnapshot) -> String {
    backend_contract::download_notification_status(snapshot)
}

pub(crate) fn source_trust_status_summary(snapshot: &TrustCenterSnapshot) -> String {
    backend_contract::source_trust_status_summary(snapshot)
}

pub(crate) fn render_trust_center_snapshot(ui: &mut egui::Ui, snapshot: &TrustCenterSnapshot) {
    ui.group(|ui| {
        ui.label(egui::RichText::new("Trust Center").strong());
        egui::Grid::new("trust_center_last_download")
            .num_columns(2)
            .striped(true)
            .show(ui, |ui| {
                ui.label("Downloaded asset");
                ui.label(&snapshot.downloaded_asset);
                ui.end_row();

                ui.label("Hash status");
                ui.label(&snapshot.hash_status);
                ui.end_row();

                ui.label("File SHA256");
                ui.label(&snapshot.file_sha256);
                ui.end_row();

                ui.label("Expected SHA256");
                ui.label(&snapshot.expected_sha256);
                ui.end_row();

                ui.label("Source authenticity");
                ui.label(&snapshot.source_authenticity);
                ui.end_row();

                ui.label("Source trust detail");
                ui.label(&snapshot.source_trust_detail);
                ui.end_row();

                ui.label("Verification source");
                ui.label(&snapshot.source_asset);
                ui.end_row();

                ui.label("Signature asset");
                ui.label(&snapshot.signature_asset);
                ui.end_row();

                ui.label("Publisher key fingerprint");
                ui.label(&snapshot.publisher_key_fingerprint);
                ui.end_row();

                ui.label("Publisher key source");
                ui.label(&snapshot.publisher_key_source);
                ui.end_row();

                ui.label("Policy verdict");
                ui.label(&snapshot.policy_verdict);
                ui.end_row();

                ui.label("Policy at decision");
                ui.label(&snapshot.policy_at_decision);
                ui.end_row();

                ui.label("Evidence path");
                ui.label(&snapshot.evidence_path);
                ui.end_row();

                ui.label("Evidence access");
                ui.label(&snapshot.evidence_access);
                ui.end_row();

                ui.label("File disposition");
                ui.label(&snapshot.file_disposition);
                ui.end_row();

                ui.label("Final path");
                ui.label(&snapshot.final_path);
                ui.end_row();
            });
    });
}
