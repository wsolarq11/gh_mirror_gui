use crate::releases::{ReleaseQuery, ResolvedRelease};
use reqwest::blocking::Client;

/// Artifact source adapter (Phase 5: Artifact Trust Broker).
///
/// Today we only ship the GitHub Release adapter, but this trait is the stable
/// internal seam that lets us add future adapters without rewriting the trust,
/// verification, policy, and evidence pipeline.
pub(crate) trait SourceAdapter {
    fn resolve_release_assets(
        &self,
        client: &Client,
        api_base: Option<&str>,
        query: &ReleaseQuery,
    ) -> Result<ResolvedRelease, String>;
}

pub(crate) struct GitHubReleaseAdapter;

impl SourceAdapter for GitHubReleaseAdapter {
    fn resolve_release_assets(
        &self,
        client: &Client,
        api_base: Option<&str>,
        query: &ReleaseQuery,
    ) -> Result<ResolvedRelease, String> {
        match api_base {
            Some(base) => crate::releases::resolve_release_assets_with_base(client, base, query),
            None => crate::releases::resolve_release_assets(client, query),
        }
    }
}
