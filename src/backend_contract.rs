use crate::download::build_client;
use crate::releases::ReleaseAsset;
use crate::releases::{resolve_release_assets, ReleaseQuery, ResolvedRelease};
use crate::source_trust::SourceTrustPolicyConfig;
use crate::source_trust::{import_publisher_key_pin_from_release_asset, ImportedPublisherKeyPin};
use crate::update_candidate::{
    check_latest_update_candidate, refused_update_candidate_check_report,
    refused_update_candidate_stage_report, stage_latest_update_candidate,
};
use crate::update_candidate::{UpdateCandidateCheckReport, UpdateCandidateStageReport};
use std::path::Path;

pub(crate) struct BackendClientSettings {
    pub(crate) proxy: String,
    pub(crate) allow_invalid_certs: bool,
}

impl BackendClientSettings {
    pub(crate) fn new(proxy: String, allow_invalid_certs: bool) -> Self {
        Self {
            proxy,
            allow_invalid_certs,
        }
    }

    fn client(&self, timeout_secs: u64) -> Result<reqwest::blocking::Client, String> {
        build_client(&self.proxy, timeout_secs, self.allow_invalid_certs)
    }
}

pub(crate) fn resolve_release_assets_for_query(
    settings: &BackendClientSettings,
    query: &ReleaseQuery,
) -> Result<ResolvedRelease, String> {
    let client = settings
        .client(30)
        .map_err(|e| format!("Release resolver client error: {e}"))?;
    resolve_release_assets(&client, query)
}

pub(crate) fn import_publisher_key_from_release_asset(
    settings: &BackendClientSettings,
    asset: &ReleaseAsset,
) -> Result<ImportedPublisherKeyPin, String> {
    let client = settings
        .client(30)
        .map_err(|e| format!("Publisher key import client error: {e}"))?;
    import_publisher_key_pin_from_release_asset(&client, asset)
}

pub(crate) fn run_update_candidate_check(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
) -> UpdateCandidateCheckReport {
    match settings.client(60) {
        Ok(client) => check_latest_update_candidate(
            &client,
            crate::update_candidate::UpdateCandidateCheckConfig {
                current_version,
                source_trust_policy,
                evidence_dir,
                api_base: None,
            },
        ),
        Err(e) => refused_update_candidate_check_report(
            current_version,
            format!("self-update client build failed: {e}"),
            evidence_dir,
        ),
    }
}

pub(crate) fn run_update_candidate_stage(
    settings: &BackendClientSettings,
    current_version: &str,
    source_trust_policy: &SourceTrustPolicyConfig,
    evidence_dir: &Path,
    stage_root: &Path,
) -> UpdateCandidateStageReport {
    match settings.client(60) {
        Ok(client) => stage_latest_update_candidate(
            &client,
            crate::update_candidate::UpdateCandidateStageConfig {
                current_version,
                source_trust_policy,
                evidence_dir,
                stage_root,
                api_base: None,
            },
        ),
        Err(e) => refused_update_candidate_stage_report(
            current_version,
            format!("self-update client build failed: {e}"),
            evidence_dir,
        ),
    }
}
