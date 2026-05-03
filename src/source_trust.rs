use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

const SOURCE_TRUST_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SourceTrustPolicyConfig {
    pub(crate) require_trusted_source: bool,
    pub(crate) trusted_publisher_key: String,
}

impl SourceTrustPolicyConfig {
    pub(crate) fn has_trusted_key(&self) -> bool {
        !self.trusted_publisher_key.trim().is_empty()
    }

    pub(crate) fn snapshot(&self) -> SourceTrustPolicySnapshot {
        SourceTrustPolicySnapshot {
            schema_version: SOURCE_TRUST_SCHEMA_VERSION,
            require_trusted_source: self.require_trusted_source,
            trusted_publisher_key_fingerprint_sha256: trusted_key_fingerprint(
                &self.trusted_publisher_key,
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SourceTrustPolicySnapshot {
    pub(crate) schema_version: u32,
    pub(crate) require_trusted_source: bool,
    pub(crate) trusted_publisher_key_fingerprint_sha256: Option<String>,
}

impl Default for SourceTrustPolicySnapshot {
    fn default() -> Self {
        Self {
            schema_version: SOURCE_TRUST_SCHEMA_VERSION,
            require_trusted_source: false,
            trusted_publisher_key_fingerprint_sha256: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SourceAuthenticityStatus {
    TrustedSignature,
    Unsigned,
    MissingSignature,
    BadSignature,
    NoTrustedKey,
    NotApplicable,
}

impl SourceAuthenticityStatus {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::TrustedSignature => "TRUSTED_SIGNATURE",
            Self::Unsigned => "UNSIGNED",
            Self::MissingSignature => "MISSING_SIGNATURE",
            Self::BadSignature => "BAD_SIGNATURE",
            Self::NoTrustedKey => "NO_TRUSTED_KEY",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum SourceTrustDecision {
    Trusted,
    AllowUnsigned,
    Block,
    NotApplicable,
}

impl SourceTrustDecision {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Trusted => "TRUSTED",
            Self::AllowUnsigned => "ALLOW_UNSIGNED",
            Self::Block => "BLOCK",
            Self::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct SourceTrustEvidence {
    pub(crate) schema_version: u32,
    pub(crate) status: SourceAuthenticityStatus,
    pub(crate) decision: SourceTrustDecision,
    pub(crate) required: bool,
    pub(crate) source_asset_name: Option<String>,
    pub(crate) signature_asset_name: Option<String>,
    pub(crate) trusted_publisher_key_fingerprint_sha256: Option<String>,
    pub(crate) detail: String,
}

impl SourceTrustEvidence {
    pub(crate) fn is_blocking(&self) -> bool {
        self.decision == SourceTrustDecision::Block
    }

    pub(crate) fn status_label(&self) -> &'static str {
        self.status.as_str()
    }

    pub(crate) fn decision_label(&self) -> &'static str {
        self.decision.as_str()
    }
}

pub(crate) fn not_applicable_source_trust(
    policy: &SourceTrustPolicyConfig,
    detail: impl Into<String>,
) -> SourceTrustEvidence {
    SourceTrustEvidence {
        schema_version: SOURCE_TRUST_SCHEMA_VERSION,
        status: SourceAuthenticityStatus::NotApplicable,
        decision: SourceTrustDecision::NotApplicable,
        required: policy.require_trusted_source,
        source_asset_name: None,
        signature_asset_name: None,
        trusted_publisher_key_fingerprint_sha256: trusted_key_fingerprint(
            &policy.trusted_publisher_key,
        ),
        detail: detail.into(),
    }
}

pub(crate) fn evaluate_source_trust(
    source_bytes: &[u8],
    source_asset_name: &str,
    signature_asset_name: Option<&str>,
    signature_text: Option<&str>,
    policy: &SourceTrustPolicyConfig,
) -> SourceTrustEvidence {
    let trusted_key_fingerprint = trusted_key_fingerprint(&policy.trusted_publisher_key);
    if !policy.has_trusted_key() {
        let decision = if policy.require_trusted_source {
            SourceTrustDecision::Block
        } else {
            SourceTrustDecision::AllowUnsigned
        };
        return SourceTrustEvidence {
            schema_version: SOURCE_TRUST_SCHEMA_VERSION,
            status: SourceAuthenticityStatus::NoTrustedKey,
            decision,
            required: policy.require_trusted_source,
            source_asset_name: Some(source_asset_name.to_string()),
            signature_asset_name: signature_asset_name.map(ToString::to_string),
            trusted_publisher_key_fingerprint_sha256: None,
            detail: if policy.require_trusted_source {
                "trusted verification source is required, but no publisher key is pinned"
                    .to_string()
            } else {
                "no publisher key is pinned; source authenticity was not checked".to_string()
            },
        };
    }

    let Some(signature_text) = signature_text else {
        let status = if policy.require_trusted_source {
            SourceAuthenticityStatus::MissingSignature
        } else {
            SourceAuthenticityStatus::Unsigned
        };
        let decision = if policy.require_trusted_source {
            SourceTrustDecision::Block
        } else {
            SourceTrustDecision::AllowUnsigned
        };
        return SourceTrustEvidence {
            schema_version: SOURCE_TRUST_SCHEMA_VERSION,
            status,
            decision,
            required: policy.require_trusted_source,
            source_asset_name: Some(source_asset_name.to_string()),
            signature_asset_name: signature_asset_name.map(ToString::to_string),
            trusted_publisher_key_fingerprint_sha256: trusted_key_fingerprint,
            detail: if policy.require_trusted_source {
                format!("{source_asset_name} has no detached signature asset")
            } else {
                format!("{source_asset_name} is unsigned; policy allows unsigned sources")
            },
        };
    };

    match verify_ed25519_detached(source_bytes, signature_text, &policy.trusted_publisher_key) {
        Ok(()) => SourceTrustEvidence {
            schema_version: SOURCE_TRUST_SCHEMA_VERSION,
            status: SourceAuthenticityStatus::TrustedSignature,
            decision: SourceTrustDecision::Trusted,
            required: policy.require_trusted_source,
            source_asset_name: Some(source_asset_name.to_string()),
            signature_asset_name: signature_asset_name.map(ToString::to_string),
            trusted_publisher_key_fingerprint_sha256: trusted_key_fingerprint,
            detail: format!(
                "{source_asset_name} signature verified with pinned Ed25519 publisher key"
            ),
        },
        Err(e) => SourceTrustEvidence {
            schema_version: SOURCE_TRUST_SCHEMA_VERSION,
            status: SourceAuthenticityStatus::BadSignature,
            decision: SourceTrustDecision::Block,
            required: policy.require_trusted_source,
            source_asset_name: Some(source_asset_name.to_string()),
            signature_asset_name: signature_asset_name.map(ToString::to_string),
            trusted_publisher_key_fingerprint_sha256: trusted_key_fingerprint,
            detail: format!("{source_asset_name} detached signature did not verify: {e}"),
        },
    }
}

pub(crate) fn verify_ed25519_detached(
    message: &[u8],
    signature_text: &str,
    public_key_text: &str,
) -> Result<(), String> {
    let public_key = decode_hex_array::<32>(public_key_text, "Ed25519 public key")?;
    let signature = decode_hex_array::<64>(signature_text, "Ed25519 signature")?;
    let verifying_key = VerifyingKey::from_bytes(&public_key)
        .map_err(|e| format!("invalid Ed25519 public key: {e}"))?;
    let signature = Signature::from_bytes(&signature);
    verifying_key
        .verify(message, &signature)
        .map_err(|e| format!("invalid Ed25519 signature: {e}"))
}

pub(crate) fn sign_ed25519_detached(
    message: &[u8],
    private_key_text: &str,
) -> Result<String, String> {
    let private_key = decode_hex_array::<32>(private_key_text, "Ed25519 private key seed")?;
    let signing_key = SigningKey::from_bytes(&private_key);
    let signature = signing_key.sign(message);
    Ok(hex_encode_upper(&signature.to_bytes()))
}

pub(crate) fn trusted_key_fingerprint(public_key_text: &str) -> Option<String> {
    let public_key = decode_hex_array::<32>(public_key_text, "Ed25519 public key").ok()?;
    let digest = Sha256::digest(public_key);
    Some(hex_encode_upper(&digest))
}

pub(crate) fn normalize_public_key_pin(public_key_text: &str) -> Result<String, String> {
    let public_key = decode_hex_array::<32>(public_key_text, "Ed25519 public key")?;
    Ok(hex_encode_upper(&public_key))
}

#[cfg(test)]
pub(crate) fn hex_encode_for_test(bytes: &[u8]) -> String {
    hex_encode_upper(bytes)
}

fn decode_hex_array<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = decode_hex(value).map_err(|e| format!("{label}: {e}"))?;
    decoded
        .try_into()
        .map_err(|decoded: Vec<u8>| format!("{label} must be {} bytes, got {}", N, decoded.len()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let compact = value
        .trim()
        .trim_start_matches("ed25519:")
        .trim_start_matches("ED25519:")
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != ':' && *ch != '-')
        .collect::<String>();
    if compact.len() % 2 != 0 {
        return Err("hex value has odd length".to_string());
    }
    if compact.is_empty() {
        return Err("hex value is empty".to_string());
    }

    (0..compact.len())
        .step_by(2)
        .map(|idx| {
            u8::from_str_radix(&compact[idx..idx + 2], 16)
                .map_err(|_| "hex value contains non-hex characters".to_string())
        })
        .collect()
}

fn hex_encode_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC8032_EMPTY_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const RFC8032_EMPTY_SIGNATURE: &str = concat!(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155",
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );

    #[test]
    fn source_trust_verifies_good_and_bad_ed25519_signature() {
        verify_ed25519_detached(b"", RFC8032_EMPTY_SIGNATURE, RFC8032_EMPTY_PUBLIC_KEY).unwrap();

        let mut bad_signature = RFC8032_EMPTY_SIGNATURE.to_string();
        bad_signature.replace_range(0..2, "00");
        assert!(
            verify_ed25519_detached(b"", &bad_signature, RFC8032_EMPTY_PUBLIC_KEY).is_err(),
            "mutated signature must not verify"
        );
    }

    #[test]
    fn source_trust_signs_detached_signature_that_verifier_accepts() {
        let private_key = "1111111111111111111111111111111111111111111111111111111111111111";
        let message = b"SHA256SUMS.txt contents";
        let signature = sign_ed25519_detached(message, private_key).unwrap();
        let signing_key = SigningKey::from_bytes(&[0x11u8; 32]);
        let public_key = hex_encode_upper(&signing_key.verifying_key().to_bytes());

        verify_ed25519_detached(message, &signature, &public_key).unwrap();
    }

    #[test]
    fn source_trust_missing_signature_blocks_only_when_required() {
        let optional = SourceTrustPolicyConfig {
            require_trusted_source: false,
            trusted_publisher_key: RFC8032_EMPTY_PUBLIC_KEY.to_string(),
        };
        let required = SourceTrustPolicyConfig {
            require_trusted_source: true,
            trusted_publisher_key: RFC8032_EMPTY_PUBLIC_KEY.to_string(),
        };

        let optional_evidence =
            evaluate_source_trust(b"source", "SHA256SUMS.txt", None, None, &optional);
        assert_eq!(optional_evidence.status, SourceAuthenticityStatus::Unsigned);
        assert_eq!(
            optional_evidence.decision,
            SourceTrustDecision::AllowUnsigned
        );
        assert!(!optional_evidence.is_blocking());

        let required_evidence =
            evaluate_source_trust(b"source", "SHA256SUMS.txt", None, None, &required);
        assert_eq!(
            required_evidence.status,
            SourceAuthenticityStatus::MissingSignature
        );
        assert_eq!(required_evidence.decision, SourceTrustDecision::Block);
        assert!(required_evidence.is_blocking());
    }

    #[test]
    fn source_trust_no_key_blocks_required_policy() {
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: true,
            trusted_publisher_key: String::new(),
        };

        let evidence = evaluate_source_trust(
            b"source",
            "release-provenance.json",
            Some("release-provenance.json.sig"),
            Some(RFC8032_EMPTY_SIGNATURE),
            &policy,
        );

        assert_eq!(evidence.status, SourceAuthenticityStatus::NoTrustedKey);
        assert_eq!(evidence.decision, SourceTrustDecision::Block);
        assert!(evidence.is_blocking());
    }

    #[test]
    fn source_trust_snapshot_records_key_fingerprint_not_raw_key() {
        let policy = SourceTrustPolicyConfig {
            require_trusted_source: true,
            trusted_publisher_key: RFC8032_EMPTY_PUBLIC_KEY.to_string(),
        };

        let snapshot = policy.snapshot();

        assert_eq!(snapshot.schema_version, 1);
        assert!(snapshot.require_trusted_source);
        assert!(snapshot.trusted_publisher_key_fingerprint_sha256.is_some());
        assert_ne!(
            snapshot.trusted_publisher_key_fingerprint_sha256.as_deref(),
            Some(RFC8032_EMPTY_PUBLIC_KEY)
        );
        assert_eq!(
            normalize_public_key_pin(&format!("ed25519:{RFC8032_EMPTY_PUBLIC_KEY}")).unwrap(),
            RFC8032_EMPTY_PUBLIC_KEY.to_ascii_uppercase()
        );
    }
}
