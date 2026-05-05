use crate::releases::ResolvedRelease;
use crate::source_trust::SourceTrustPolicyConfig;
use crate::verification::{DownloadVerificationPlan, VerificationReport};
use reqwest::blocking::Client;
use std::path::Path;

/// Verification adapter (Phase 5: Artifact Trust Broker).
///
/// Today we only ship the GitHub Release verifier, but this trait is the stable
/// internal seam that lets us add future verification sources without rewriting
/// the backend contract, policy, evidence, and UI pipeline.
pub(crate) trait VerifierAdapter {
    fn verification_plan_for_selected_asset(
        &self,
        release: &ResolvedRelease,
        asset_index: usize,
    ) -> Option<DownloadVerificationPlan>;

    fn verify_downloaded_file(
        &self,
        client: &Client,
        path: &Path,
        asset_name: &str,
        plan: Option<&DownloadVerificationPlan>,
        source_trust_policy: &SourceTrustPolicyConfig,
    ) -> Result<VerificationReport, String>;
}

pub(crate) struct GitHubReleaseVerifierAdapter;

impl VerifierAdapter for GitHubReleaseVerifierAdapter {
    fn verification_plan_for_selected_asset(
        &self,
        release: &ResolvedRelease,
        asset_index: usize,
    ) -> Option<DownloadVerificationPlan> {
        crate::verification::verification_plan_for_selected_asset(release, asset_index)
    }

    fn verify_downloaded_file(
        &self,
        client: &Client,
        path: &Path,
        asset_name: &str,
        plan: Option<&DownloadVerificationPlan>,
        source_trust_policy: &SourceTrustPolicyConfig,
    ) -> Result<VerificationReport, String> {
        crate::verification::verify_downloaded_file(
            client,
            path,
            asset_name,
            plan,
            source_trust_policy,
        )
    }
}
