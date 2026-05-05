use crate::releases::{ReleaseQuery, ResolvedRelease};
use crate::source_adapter::{GitHubReleaseAdapter, SourceAdapter};
use crate::source_trust::SourceTrustPolicyConfig;
use crate::verification::{DownloadVerificationPlan, VerificationReport};
use crate::verifier_adapter::{GitHubReleaseVerifierAdapter, VerifierAdapter};
use reqwest::blocking::Client;
use std::path::Path;

/// Core runtime orchestrator.
///
/// This is an internal "composition point" that wires together the stable Phase 5 seams.
///
/// Long-term direction:
/// - `backend_contract` stays a small, stable front door (DTOs + a few use-cases)
/// - this runtime becomes the internal pipeline entrypoint
/// - adapters evolve behind seams to grow from "GitHub Release" toward an Artifact Trust Broker
pub(crate) struct CoreRuntime {
    source_adapter: GitHubReleaseAdapter,
    verifier_adapter: GitHubReleaseVerifierAdapter,
}

impl Default for CoreRuntime {
    fn default() -> Self {
        Self {
            source_adapter: GitHubReleaseAdapter,
            verifier_adapter: GitHubReleaseVerifierAdapter,
        }
    }
}

impl CoreRuntime {
    pub(crate) fn resolve_release_assets(
        &self,
        client: &Client,
        api_base: Option<&str>,
        query: &ReleaseQuery,
    ) -> Result<ResolvedRelease, String> {
        self.source_adapter
            .resolve_release_assets(client, api_base, query)
    }

    pub(crate) fn verification_plan_for_selected_asset(
        &self,
        release: &ResolvedRelease,
        asset_index: usize,
    ) -> Option<DownloadVerificationPlan> {
        self.verifier_adapter
            .verification_plan_for_selected_asset(release, asset_index)
    }

    pub(crate) fn verify_downloaded_file(
        &self,
        client: &Client,
        path: &Path,
        asset_name: &str,
        plan: Option<&DownloadVerificationPlan>,
        source_trust_policy: &SourceTrustPolicyConfig,
    ) -> Result<VerificationReport, String> {
        self.verifier_adapter.verify_downloaded_file(
            client,
            path,
            asset_name,
            plan,
            source_trust_policy,
        )
    }
}
