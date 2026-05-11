use eframe::egui;
use std::env;
#[cfg(test)]
use std::fs;
#[cfg(test)]
use std::path::PathBuf;

mod cli;

mod gui_common;
#[cfg(test)]
use gui_common::import_publisher_key_pin_from_path;

mod gui_helpers;
#[cfg(test)]
use gui_helpers::build_effective_url;
#[cfg(test)]
use gui_helpers::extract_filename;
#[cfg(test)]
use gui_helpers::format_speed;
#[cfg(test)]
use gui_helpers::history_path_from_setting;

mod gui_mirrors;
#[cfg(test)]
use gui_mirrors::normalize_mirror_index;
#[cfg(test)]
use gui_mirrors::MIRRORS;

mod gui_trust_center;
#[cfg(test)]
use gui_trust_center::format_download_completion_status;
#[cfg(test)]
use gui_trust_center::format_download_notification_status;

mod gui_update_candidate;

#[cfg(test)]
use backend_contract::{
    AppliedFileDisposition, ImportedPublisherKeyPin, MismatchFilePolicy, TrustCenterSnapshot,
    TrustPolicyConfig,
};
#[cfg(test)]
use gh_mirror_gui::backend_contract;
#[cfg(test)]
use gh_mirror_gui::ui_projection::UiLocale;

const RELEASE_PRIVATE_KEY_ENV: &str = "RELEASE_ED25519_PRIVATE_KEY_HEX";
const LEGACY_RELEASE_PRIVATE_KEY_ENV: &str = "GH_MIRROR_GUI_ED25519_PRIVATE_KEY_HEX";
const RELEASE_PUBLIC_KEY_ASSET: &str = "publisher-key.ed25519.pub";
const SHA256SUMS_ASSET: &str = "SHA256SUMS.txt";
const SHA256SUMS_SIGNATURE_ASSET: &str = "SHA256SUMS.txt.sig";
const PROVENANCE_ASSET: &str = "release-provenance.json";
const PROVENANCE_SIGNATURE_ASSET: &str = "release-provenance.json.sig";
const SIGNATURE_FORMAT: &str = "ed25519-detached-hex";

// ---------------------------------------------------------------------------
// App state and UI constants
// ---------------------------------------------------------------------------
mod gui_app;
use gui_app::GhMirrorGui;
#[cfg(test)]
use gui_app::SavedState;
fn main() -> Result<(), eframe::Error> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if cli::dispatch_cli(&args) {
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1366.0, 860.0])
            .with_min_inner_size([720.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Trusted Release Downloader",
        options,
        Box::new(|cc| {
            gui_app::configure_egui_context(&cc.egui_ctx);
            Ok(Box::new(GhMirrorGui::new(cc.storage)))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use backend_contract::FileDispositionAction;

    fn unique_test_path(name: &str) -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "gh_mirror_gui_{}_{}_{}",
            std::process::id(),
            nonce,
            name
        ))
    }

    #[test]
    fn verify_verification_source_cli_accepts_publisher_key_file() {
        let source = unique_test_path("signed-source.txt");
        let signature_path = unique_test_path("signed-source.txt.sig");
        let public_key_path = unique_test_path("publisher-key.ed25519.pub");
        let json_path = unique_test_path("verify-source.json");
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let source_bytes = b"release verification source bytes";
        fs::write(&source, source_bytes).unwrap();
        let signature = backend_contract::sign_ed25519_detached(source_bytes, private_key).unwrap();
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
        fs::write(&signature_path, format!("{signature}\n")).unwrap();
        fs::write(&public_key_path, format!("ed25519:{public_key}\n")).unwrap();

        cli::run_verify_verification_source(&[
            "--source".to_string(),
            source.display().to_string(),
            "--signature".to_string(),
            signature_path.display().to_string(),
            "--public-key-file".to_string(),
            public_key_path.display().to_string(),
            "--json".to_string(),
            json_path.display().to_string(),
        ])
        .unwrap();

        let report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&json_path).unwrap()).unwrap();
        assert_eq!(report["ok"], true);
        assert_eq!(report["signature"]["verified"], true);
        assert_eq!(
            report["public_key"]["fingerprint_sha256"]
                .as_str()
                .unwrap()
                .len(),
            64
        );

        let _ = fs::remove_file(source);
        let _ = fs::remove_file(signature_path);
        let _ = fs::remove_file(public_key_path);
        let _ = fs::remove_file(json_path);
    }

    #[test]
    fn verify_verification_source_cli_rejects_bad_signature() {
        let source = unique_test_path("bad-signed-source.txt");
        let signature_path = unique_test_path("bad-signed-source.txt.sig");
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let source_bytes = b"release verification source bytes";
        fs::write(&source, source_bytes).unwrap();
        let mut signature =
            backend_contract::sign_ed25519_detached(source_bytes, private_key).unwrap();
        signature.replace_range(0..2, "00");
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
        fs::write(&signature_path, format!("{signature}\n")).unwrap();

        let err = cli::run_verify_verification_source(&[
            "--source".to_string(),
            source.display().to_string(),
            "--signature".to_string(),
            signature_path.display().to_string(),
            "--public-key".to_string(),
            public_key,
        ])
        .unwrap_err();
        assert!(err.contains("invalid Ed25519 signature"));

        let _ = fs::remove_file(source);
        let _ = fs::remove_file(signature_path);
    }

    #[test]
    fn verify_verification_source_cli_rejects_missing_public_key_source() {
        let err = cli::run_verify_verification_source(&[
            "--source".to_string(),
            "source.txt".to_string(),
            "--signature".to_string(),
            "source.txt.sig".to_string(),
        ])
        .unwrap_err();

        assert_eq!(
            err,
            "provide exactly one of --public-key or --public-key-file"
        );
    }

    #[test]
    fn verify_verification_source_cli_rejects_multiple_public_key_sources() {
        let err = cli::run_verify_verification_source(&[
            "--source".to_string(),
            "source.txt".to_string(),
            "--signature".to_string(),
            "source.txt.sig".to_string(),
            "--public-key".to_string(),
            "ed25519:abc".to_string(),
            "--public-key-file".to_string(),
            "publisher-key.ed25519.pub".to_string(),
        ])
        .unwrap_err();

        assert_eq!(
            err,
            "provide exactly one of --public-key or --public-key-file"
        );
    }

    #[test]
    fn url_helpers_cover_direct_and_mirror_cases() {
        assert_eq!(
            extract_filename("https://github.com/owner/repo/releases/download/v1/app.tar.gz"),
            Some("app.tar.gz".to_string())
        );
        assert_eq!(extract_filename("https://github.com/owner/repo/"), None);
        assert_eq!(
            build_effective_url("", "https://github.com/owner/repo"),
            "https://github.com/owner/repo"
        );
        assert_eq!(
            build_effective_url("https://mirror.example/", "https://github.com/owner/repo"),
            "https://mirror.example/https://github.com/owner/repo"
        );
    }

    #[test]
    fn normalize_mirror_index_resets_out_of_range_to_direct() {
        assert_eq!(normalize_mirror_index(0), 0);
        if MIRRORS.len() > 1 {
            assert_eq!(normalize_mirror_index(1), 1);
        }
        assert_eq!(normalize_mirror_index(MIRRORS.len()), 0);
        assert_eq!(normalize_mirror_index(usize::MAX), 0);
    }

    #[test]
    fn speed_formatting_covers_bytes_kb_and_mb() {
        assert_eq!(format_speed(0.5), "512.0 B/s");
        assert_eq!(format_speed(512.0), "512 KB/s");
        assert_eq!(format_speed(2048.0), "2.0 MB/s");
    }

    #[test]
    fn saved_state_defaults_to_safe_tls() {
        let state: SavedState =
            serde_json::from_str(r#"{"selected_mirror":0,"save_dir":"","proxy":""}"#).unwrap();
        assert!(!state.allow_invalid_certs);
        assert!(state.trust_unknown_keep_file);
        assert!(!state.trust_unknown_allow_open);
        assert_eq!(
            state.trust_mismatch_file_policy,
            MismatchFilePolicy::Quarantine
        );
        assert!(!state.source_trust_require_signed);
        assert!(state.source_trust_publisher_key.is_empty());
        assert!(state.source_trust_publisher_key_source.is_empty());
        assert!(state.history_path.is_empty());
        assert_eq!(state.locale, UiLocale::En);
    }

    #[test]
    fn saved_state_persists_trust_policy_and_history_path() {
        let state: SavedState = serde_json::from_str(
            r#"{"selected_mirror":0,"save_dir":"C:\\Downloads","proxy":"","locale":"zh","allow_invalid_certs":false,"trust_unknown_keep_file":false,"trust_unknown_allow_open":false,"trust_mismatch_file_policy":"DELETE","source_trust_require_signed":true,"source_trust_publisher_key":"D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A","source_trust_publisher_key_source":"GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub","history_path":"C:\\Evidence\\bench-history.jsonl"}"#,
        )
        .unwrap();

        assert!(!state.trust_unknown_keep_file);
        assert!(!state.trust_unknown_allow_open);
        assert_eq!(state.trust_mismatch_file_policy, MismatchFilePolicy::Delete);
        assert!(state.source_trust_require_signed);
        assert_eq!(
            state.source_trust_publisher_key,
            "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A"
        );
        assert_eq!(
            state.source_trust_publisher_key_source,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub"
        );
        assert_eq!(state.history_path, r"C:\Evidence\bench-history.jsonl");
        assert_eq!(state.locale, UiLocale::Zh);
    }

    #[test]
    fn publisher_key_import_accepts_release_public_key_asset() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
        let path = unique_test_path("publisher-key.ed25519.pub");
        fs::write(&path, format!("ed25519:{public_key}\r\n")).unwrap();

        let imported_pin = import_publisher_key_pin_from_path(&path).unwrap();

        assert_eq!(imported_pin, public_key);
        assert!(backend_contract::trusted_key_fingerprint(&imported_pin).is_some());

        let _ = fs::remove_file(path);
    }

    #[test]
    fn publisher_key_import_result_updates_trust_policy_pin_and_status() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let public_key = backend_contract::public_key_from_private_seed(private_key).unwrap();
        let fingerprint = backend_contract::trusted_key_fingerprint(&public_key).unwrap();
        let imported = ImportedPublisherKeyPin {
            public_key: public_key.clone(),
            fingerprint_sha256: fingerprint.clone(),
            asset_name: "publisher-key.ed25519.pub".to_string(),
        };
        let mut policy = TrustPolicyConfig::default();
        let mut publisher_key_source = String::new();

        let status = backend_contract::apply_imported_publisher_key_pin(
            &mut policy,
            &mut publisher_key_source,
            imported,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub",
        );

        assert_eq!(policy.source_trust.trusted_publisher_key, public_key);
        assert!(status.contains("publisher-key.ed25519.pub"));
        assert!(status.contains(&fingerprint[..12]));
        assert_eq!(
            publisher_key_source,
            "GitHub Release wsolarq11/gh_mirror_gui@v0.1.2 asset publisher-key.ed25519.pub"
        );
    }

    #[test]
    fn history_path_setting_uses_default_when_blank_and_custom_when_set() {
        assert_eq!(
            history_path_from_setting("  "),
            backend_contract::default_history_path()
        );
        assert_eq!(
            history_path_from_setting(r"C:\Evidence\bench-history.jsonl"),
            PathBuf::from(r"C:\Evidence\bench-history.jsonl")
        );
    }

    #[test]
    fn completion_status_makes_mismatch_blocking_and_unknown_risky() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";

        fn mk_snapshot(
            hash: &str,
            hash_status: &str,
            policy_verdict: &str,
            expected_sha256: &str,
            source_authenticity: &str,
        ) -> TrustCenterSnapshot {
            TrustCenterSnapshot {
                downloaded_asset: "app.exe".to_string(),
                hash_status: hash_status.to_string(),
                file_sha256: hash.to_string(),
                expected_sha256: expected_sha256.to_string(),
                source_authenticity: source_authenticity.to_string(),
                source_trust_detail: "n/a".to_string(),
                source_asset: "SHA256SUMS.txt".to_string(),
                signature_asset: "none".to_string(),
                publisher_key_fingerprint: "not pinned".to_string(),
                publisher_key_source: "not recorded".to_string(),
                policy_verdict: policy_verdict.to_string(),
                policy_at_decision: "n/a".to_string(),
                evidence_path: "not recorded".to_string(),
                evidence_access: "not recorded".to_string(),
                file_disposition: "n/a".to_string(),
                final_path: "n/a".to_string(),
            }
        }

        let verified = mk_snapshot(hash, "VERIFIED", "TRUSTED", hash, "NOT_APPLICABLE");
        let mismatch = mk_snapshot(
            hash,
            "MISMATCH",
            "BLOCK",
            "B9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC",
            "NOT_APPLICABLE",
        );
        let unknown = mk_snapshot(hash, "UNKNOWN", "RISK", "not available", "NOT_APPLICABLE");
        let kept = AppliedFileDisposition {
            action: FileDispositionAction::Keep,
            original_path: PathBuf::from("app.exe"),
            final_path: Some(PathBuf::from("app.exe")),
        };
        let quarantined = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: PathBuf::from("app.exe"),
            final_path: Some(PathBuf::from(".gh_mirror_gui-quarantine/app.exe")),
        };

        assert!(format_download_completion_status(&verified, &kept).contains("Download complete"));
        let mismatch_status = format_download_completion_status(&mismatch, &quarantined);
        assert!(mismatch_status.contains("Verification BLOCKED"));
        assert!(!mismatch_status.contains("Download complete"));
        assert!(mismatch_status.contains("file quarantined"));
        assert!(mismatch_status.contains("retry or open evidence"));
        let unknown_status = format_download_completion_status(&unknown, &kept);
        assert!(unknown_status.contains("Verification UNKNOWN risk"));
        assert!(!unknown_status.contains("✅"));
        assert_eq!(
            format_download_notification_status(&mismatch),
            "Download blocked (MISMATCH)"
        );
    }

    #[test]
    fn completion_status_blocks_untrusted_signed_source() {
        let hash = "A9BDB5AE91B153ED8E04513CA9322B4445A91D3BE8DD2695A8F1C206C9937CCC";
        let report = TrustCenterSnapshot {
            downloaded_asset: "app.exe".to_string(),
            hash_status: "VERIFIED".to_string(),
            file_sha256: hash.to_string(),
            expected_sha256: hash.to_string(),
            source_authenticity: "BAD_SIGNATURE".to_string(),
            source_trust_detail: "bad signature".to_string(),
            source_asset: "SHA256SUMS.txt".to_string(),
            signature_asset: "SHA256SUMS.txt.sig".to_string(),
            publisher_key_fingerprint: "ABCDEF".to_string(),
            publisher_key_source: "n/a".to_string(),
            policy_verdict: "BLOCK".to_string(),
            policy_at_decision: "n/a".to_string(),
            evidence_path: "not recorded".to_string(),
            evidence_access: "not recorded".to_string(),
            file_disposition: "n/a".to_string(),
            final_path: "n/a".to_string(),
        };
        let quarantined = AppliedFileDisposition {
            action: FileDispositionAction::Quarantine,
            original_path: PathBuf::from("app.exe"),
            final_path: Some(PathBuf::from(".gh_mirror_gui-quarantine/app.exe")),
        };

        let status = format_download_completion_status(&report, &quarantined);

        assert!(status.contains("Verification BLOCKED"));
        assert!(status.contains("source authenticity"));
        assert!(status.contains("BAD_SIGNATURE"));
        assert_eq!(
            format_download_notification_status(&report),
            "Download blocked (UNTRUSTED SOURCE)"
        );
    }
}
