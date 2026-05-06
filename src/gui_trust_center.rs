use eframe::egui;
use gh_mirror_gui::backend_contract::{self, AppliedFileDisposition, TrustCenterSnapshot};

pub(crate) fn format_download_completion_status(
    snapshot: &TrustCenterSnapshot,
    disposition: &AppliedFileDisposition,
) -> String {
    let short_hash = snapshot.file_sha256.chars().take(12).collect::<String>();
    let disposition_summary = backend_contract::file_disposition_summary(disposition);
    let source_trust = source_trust_status_summary(snapshot);
    match (snapshot.hash_status.as_str(), snapshot.policy_verdict.as_str()) {
        ("VERIFIED", "BLOCK") => format!(
            "❌ Verification BLOCKED · SHA256 matched {} but source authenticity is {} · {} · {}",
            snapshot.source_asset.as_str(),
            source_trust,
            disposition_summary,
            "retry or open evidence before trusting this file"
        ),
        ("VERIFIED", _) => format!(
            "✅ Download complete · VERIFIED SHA256={} via {} · source {} · {}",
            short_hash,
            snapshot.source_asset.as_str(),
            source_trust,
            disposition_summary
        ),
        ("MISMATCH", _) => format!(
            "❌ Verification BLOCKED · MISMATCH SHA256={} expected {} via {} · {} · retry or open evidence before trusting this file",
            short_hash,
            snapshot
                .expected_sha256
                .as_str()
                .chars()
                .take(12)
                .collect::<String>(),
            snapshot.source_asset.as_str(),
            disposition_summary
        ),
        ("UNKNOWN", _) => format!(
            "⚠ Verification UNKNOWN risk · SHA256={} · {} · {}",
            short_hash,
            "no matching checksum/provenance could verify this file",
            disposition_summary
        ),
        (other, decision) => format!(
            "⚠ Verification {} ({}) · SHA256={} · {}",
            other, decision, short_hash, disposition_summary
        ),
    }
}

pub(crate) fn format_download_notification_status(snapshot: &TrustCenterSnapshot) -> String {
    match (
        snapshot.hash_status.as_str(),
        snapshot.policy_verdict.as_str(),
    ) {
        ("VERIFIED", "BLOCK") => "Download blocked (UNTRUSTED SOURCE)".to_string(),
        ("VERIFIED", _) => "Download complete (VERIFIED)".to_string(),
        ("MISMATCH", _) => "Download blocked (MISMATCH)".to_string(),
        ("UNKNOWN", _) => "Download saved with UNKNOWN verification risk".to_string(),
        _ => "Download completed with UNKNOWN verification risk".to_string(),
    }
}

pub(crate) fn source_trust_status_summary(snapshot: &TrustCenterSnapshot) -> String {
    let signature = if snapshot.signature_asset != "none" {
        format!(" via {}", snapshot.signature_asset)
    } else {
        String::new()
    };
    let pin = if snapshot.publisher_key_fingerprint != "not pinned" {
        let short = snapshot
            .publisher_key_fingerprint
            .chars()
            .take(12)
            .collect::<String>();
        format!(" key={short}")
    } else {
        String::new()
    };
    format!(
        "{} decision={}{}{}",
        snapshot.source_authenticity, snapshot.policy_verdict, signature, pin
    )
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
