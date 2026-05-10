use gh_mirror_gui::backend_contract;
use std::env;
use std::path::{Path, PathBuf};

fn load_release_private_key_seed() -> Result<(String, &'static str), String> {
    for env_name in [
        crate::RELEASE_PRIVATE_KEY_ENV,
        crate::LEGACY_RELEASE_PRIVATE_KEY_ENV,
    ] {
        if let Ok(value) = env::var(env_name) {
            if !value.trim().is_empty() {
                return Ok((value, env_name));
            }
        }
    }

    Err(format!(
        "{} is required (32-byte Ed25519 seed encoded as 64 hex characters)",
        crate::RELEASE_PRIVATE_KEY_ENV
    ))
}

fn write_text_file(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create dir error: {e}"))?;
    }
    std::fs::write(path, text).map_err(|e| format!("Write {} error: {e}", path.display()))
}

fn release_signing_required_assets() -> [&'static str; 6] {
    [
        "gh_mirror_gui.exe",
        crate::SHA256SUMS_ASSET,
        crate::SHA256SUMS_SIGNATURE_ASSET,
        crate::PROVENANCE_ASSET,
        crate::PROVENANCE_SIGNATURE_ASSET,
        crate::RELEASE_PUBLIC_KEY_ASSET,
    ]
}

fn sha256_file(path: &PathBuf) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    const HASH_BUFFER_SIZE: usize = 256 * 1024;

    let mut file = std::fs::File::open(path).map_err(|e| format!("Open hash input error: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; HASH_BUFFER_SIZE];

    loop {
        let n = std::io::Read::read(&mut file, &mut buf)
            .map_err(|e| format!("Hash read error: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:X}", hasher.finalize()))
}

pub(crate) fn run_release_signing_doctor(args: &[String]) -> Result<(), String> {
    let mut fixture_dir = PathBuf::from("target/release-signing-fixture");
    let mut json_out = None;
    let mut public_key_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--fixture-dir" => {
                i += 1;
                fixture_dir = args
                    .get(i)
                    .map(PathBuf::from)
                    .ok_or_else(|| "--fixture-dir requires a path".to_string())?;
            }
            "--json" => {
                i += 1;
                json_out = Some(
                    args.get(i)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--json requires a path".to_string())?,
                );
            }
            "--public-key-out" => {
                i += 1;
                public_key_out = Some(
                    args.get(i)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--public-key-out requires a path".to_string())?,
                );
            }
            other => return Err(format!("unknown --release-signing-doctor option: {other}")),
        }
        i += 1;
    }

    let (private_key, private_key_env) = load_release_private_key_seed()?;
    let public_key = backend_contract::public_key_from_private_seed(&private_key)?;
    let fingerprint = backend_contract::trusted_key_fingerprint(&public_key)
        .ok_or_else(|| "derived Ed25519 public key fingerprint failed".to_string())?;

    std::fs::create_dir_all(&fixture_dir).map_err(|e| format!("Create fixture dir error: {e}"))?;
    let source_path = fixture_dir.join(crate::SHA256SUMS_ASSET);
    let signature_path = fixture_dir.join(crate::SHA256SUMS_SIGNATURE_ASSET);
    let public_key_path =
        public_key_out.unwrap_or_else(|| fixture_dir.join(crate::RELEASE_PUBLIC_KEY_ASSET));
    let fixture_text = concat!(
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "  gh_mirror_gui.exe\n"
    );
    write_text_file(&source_path, fixture_text)?;
    let signature = backend_contract::sign_ed25519_detached(fixture_text.as_bytes(), &private_key)?;
    write_text_file(&signature_path, &format!("{signature}\n"))?;
    write_text_file(&public_key_path, &format!("{public_key}\n"))?;
    backend_contract::verify_ed25519_detached(fixture_text.as_bytes(), &signature, &public_key)?;

    let report = serde_json::json!({
        "schema_version": 1,
        "ok": true,
        "private_key_env": private_key_env,
        "required_repository_secret": crate::RELEASE_PRIVATE_KEY_ENV,
        "private_key_material": "not_recorded",
        "signature_format": crate::SIGNATURE_FORMAT,
        "public_key": {
            "asset_name": crate::RELEASE_PUBLIC_KEY_ASSET,
            "path": public_key_path,
            "value": public_key,
            "fingerprint_sha256": fingerprint,
        },
        "fixture": {
            "source_asset_name": crate::SHA256SUMS_ASSET,
            "signature_asset_name": crate::SHA256SUMS_SIGNATURE_ASSET,
            "source_path": source_path,
            "signature_path": signature_path,
            "source_bytes_signed": true,
            "signature_hex_chars": signature.len(),
            "verified": true,
        },
        "next_release_required_assets": release_signing_required_assets(),
        "workflow_contract": {
            "refuses_unsigned_release": true,
            "uploads_public_key_pin_asset": crate::RELEASE_PUBLIC_KEY_ASSET,
            "uploads_signature_assets": [
                crate::SHA256SUMS_SIGNATURE_ASSET,
                crate::PROVENANCE_SIGNATURE_ASSET,
            ],
        },
    });
    let pretty_report =
        serde_json::to_string_pretty(&report).map_err(|e| format!("Serialize doctor JSON: {e}"))?;
    if let Some(json_path) = json_out {
        write_text_file(&json_path, &format!("{pretty_report}\n"))?;
    }
    println!("{pretty_report}");
    Ok(())
}

pub(crate) fn run_sign_verification_source(args: &[String]) -> Result<(), String> {
    let mut source = None;
    let mut out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                i += 1;
                source = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --sign-verification-source option: {other}"
                ))
            }
        }
        i += 1;
    }

    let source = source.ok_or_else(|| "--source is required".to_string())?;
    let out = out.ok_or_else(|| "--out is required".to_string())?;
    let (private_key, _) = load_release_private_key_seed()?;
    let source_bytes =
        std::fs::read(&source).map_err(|e| format!("Read source asset error: {e}"))?;
    let signature = backend_contract::sign_ed25519_detached(&source_bytes, &private_key)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("Create signature dir error: {e}"))?;
    }
    std::fs::write(&out, format!("{signature}\n"))
        .map_err(|e| format!("Write signature asset error: {e}"))?;
    println!(
        "signed verification source {} -> {}",
        source.display(),
        out.display()
    );
    Ok(())
}

pub(crate) fn run_verify_verification_source(args: &[String]) -> Result<(), String> {
    let mut source = None;
    let mut signature = None;
    let mut public_key = None;
    let mut public_key_file = None;
    let mut json_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                i += 1;
                source = args.get(i).map(PathBuf::from);
            }
            "--signature" => {
                i += 1;
                signature = args.get(i).map(PathBuf::from);
            }
            "--public-key" => {
                i += 1;
                public_key = args.get(i).cloned();
            }
            "--public-key-file" => {
                i += 1;
                public_key_file = args.get(i).map(PathBuf::from);
            }
            "--json" => {
                i += 1;
                json_out = args.get(i).map(PathBuf::from);
            }
            other => {
                return Err(format!(
                    "unknown --verify-verification-source option: {other}"
                ))
            }
        }
        i += 1;
    }

    let source = source.ok_or_else(|| "--source is required".to_string())?;
    let signature = signature.ok_or_else(|| "--signature is required".to_string())?;
    if public_key.is_some() == public_key_file.is_some() {
        return Err("provide exactly one of --public-key or --public-key-file".to_string());
    }

    let source_bytes =
        std::fs::read(&source).map_err(|e| format!("Read source asset error: {e}"))?;
    let signature_text = std::fs::read_to_string(&signature)
        .map_err(|e| format!("Read signature asset error: {e}"))?;
    let (public_key_text, public_key_source) = match (public_key, public_key_file) {
        (Some(public_key), None) => (public_key, "--public-key".to_string()),
        (None, Some(path)) => (
            std::fs::read_to_string(&path)
                .map_err(|e| format!("Read public key asset error: {e}"))?,
            path.display().to_string(),
        ),
        _ => {
            return Err("provide exactly one of --public-key or --public-key-file".to_string());
        }
    };
    let public_key = backend_contract::normalize_public_key_pin(&public_key_text)?;
    backend_contract::verify_ed25519_detached(&source_bytes, signature_text.trim(), &public_key)?;
    let fingerprint = backend_contract::trusted_key_fingerprint(&public_key)
        .ok_or_else(|| "publisher key fingerprint failed".to_string())?;
    let source_sha256 = sha256_file(&source)?;

    let report = serde_json::json!({
        "schema_version": 1,
        "ok": true,
        "signature_format": crate::SIGNATURE_FORMAT,
        "source": {
            "path": source,
            "size": source_bytes.len(),
            "sha256": source_sha256,
        },
        "signature": {
            "path": signature,
            "hex_chars": signature_text.trim().len(),
            "verified": true,
        },
        "public_key": {
            "source": public_key_source,
            "fingerprint_sha256": fingerprint,
        },
    });
    let pretty_report =
        serde_json::to_string_pretty(&report).map_err(|e| format!("Serialize verify JSON: {e}"))?;
    if let Some(json_path) = json_out {
        write_text_file(&json_path, &format!("{pretty_report}\n"))?;
    }
    println!("{pretty_report}");
    Ok(())
}

pub(crate) fn run_resolve_download_intent(args: &[String]) -> Result<(), String> {
    let mut input = None;
    let mut json_out = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" => {
                i += 1;
                input = args.get(i).cloned();
            }
            "--json" => {
                i += 1;
                json_out = Some(
                    args.get(i)
                        .map(PathBuf::from)
                        .ok_or_else(|| "--json requires a path".to_string())?,
                );
            }
            other if input.is_none() && !other.starts_with("--") => {
                input = Some(other.to_string());
            }
            other => return Err(format!("unknown --resolve-download-intent option: {other}")),
        }
        i += 1;
    }

    let input = input.ok_or_else(|| "--input is required".to_string())?;
    let intent = backend_contract::resolve_download_intent(&input);
    let pretty = serde_json::to_string_pretty(&intent)
        .map_err(|e| format!("Serialize intent JSON error: {e}"))?;
    if let Some(path) = json_out {
        write_text_file(&path, &format!("{pretty}\n"))?;
    }
    println!("{pretty}");
    Ok(())
}

pub(crate) fn dispatch_cli(args: &[String]) -> bool {
    if args.first().map(|s| s.as_str()) == Some("--release-signing-doctor") {
        if let Err(e) = run_release_signing_doctor(&args[1..]) {
            eprintln!("release signing doctor failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--sign-verification-source") {
        if let Err(e) = run_sign_verification_source(&args[1..]) {
            eprintln!("sign verification source failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--resolve-download-intent") {
        if let Err(e) = run_resolve_download_intent(&args[1..]) {
            eprintln!("resolve download intent failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--verify-verification-source") {
        if let Err(e) = run_verify_verification_source(&args[1..]) {
            eprintln!("verify verification source failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--bench-download") {
        if let Err(e) = backend_contract::run_bench_download(&args[1..]) {
            eprintln!("benchmark failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--staged-release-download-selftest") {
        if let Err(e) = backend_contract::run_staged_release_download_selftest(&args[1..]) {
            eprintln!("staged release download selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-contract-selftest") {
        if let Err(e) = backend_contract::run_update_candidate_contract_selftest(&args[1..]) {
            eprintln!("update candidate contract selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-latest-selftest") {
        if let Err(e) = backend_contract::run_update_candidate_latest_selftest(&args[1..]) {
            eprintln!("update candidate latest selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--update-candidate-stage-selftest") {
        if let Err(e) = backend_contract::run_update_candidate_stage_selftest(&args[1..]) {
            eprintln!("update candidate stage selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--update-apply-plan-contract-selftest") {
        if let Err(e) = backend_contract::run_update_apply_plan_contract_selftest(&args[1..]) {
            eprintln!("update apply plan contract selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--update-apply-readiness-contract-selftest") {
        if let Err(e) = backend_contract::run_update_apply_readiness_contract_selftest(&args[1..]) {
            eprintln!("update apply readiness contract selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    if args.first().map(|s| s.as_str()) == Some("--update-apply-fixture-contract-selftest") {
        if let Err(e) = backend_contract::run_update_apply_fixture_contract_selftest(&args[1..]) {
            eprintln!("update apply fixture contract selftest failed: {e}");
            std::process::exit(2);
        }
        return true;
    }

    false
}
