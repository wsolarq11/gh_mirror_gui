use crate::releases::{ReleaseQuery, ReleaseQueryKind, ResolvedRelease};
use crate::source_spec::SourceSpec;
use reqwest::blocking::Client;
use reqwest::Url;

/// Artifact source adapter for the Artifact Trust Broker route.
///
/// Today we only ship the GitHub Release adapter, but this trait is the stable
/// internal seam that lets us add future adapters without rewriting the trust,
/// verification, policy, and evidence pipeline.
pub(crate) trait SourceAdapter {
    fn resolve_release_assets(
        &self,
        client: &Client,
        api_base: Option<&str>,
        spec: &SourceSpec,
    ) -> Result<ResolvedRelease, String>;
}

pub(crate) struct GitHubReleaseAdapter;

impl SourceAdapter for GitHubReleaseAdapter {
    fn resolve_release_assets(
        &self,
        client: &Client,
        api_base: Option<&str>,
        spec: &SourceSpec,
    ) -> Result<ResolvedRelease, String> {
        let query = match spec {
            SourceSpec::GitHubRelease { query } => query.clone(),
            SourceSpec::GitHubReleaseAssetUrl { url } => release_query_from_release_asset_url(url)?,
        };
        match api_base {
            Some(base) => crate::releases::resolve_release_assets_with_base(client, base, &query),
            None => crate::releases::resolve_release_assets(client, &query),
        }
    }
}

fn release_query_from_release_asset_url(input: &str) -> Result<ReleaseQuery, String> {
    let url = Url::parse(input).map_err(|e| format!("Invalid GitHub release asset URL: {e}"))?;
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim()
        .trim_start_matches("www.");
    if host != "github.com" {
        return Err(format!("Unsupported host for release asset URL: {host}"));
    }
    if url.scheme() != "https" {
        return Err(format!(
            "Unsupported scheme for release asset URL: {}",
            url.scheme()
        ));
    }

    let segments = url
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(|segment| segment.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if segments.len() < 5 {
        return Err("GitHub release asset URL must include owner/repo/releases/...".to_string());
    }

    let owner = segments[0].clone();
    let repo = segments[1].trim().trim_end_matches(".git").to_string();

    match segments.as_slice() {
        [_, _, releases, download, tag, ..] if releases == "releases" && download == "download" => {
            Ok(ReleaseQuery {
                owner,
                repo,
                kind: ReleaseQueryKind::Tag(tag.clone()),
            })
        }
        [_, _, releases, latest, download, ..]
            if releases == "releases" && latest == "latest" && download == "download" =>
        {
            Ok(ReleaseQuery {
                owner,
                repo,
                kind: ReleaseQueryKind::Latest,
            })
        }
        _ => Err("Unsupported GitHub release asset URL path".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_release_asset_url_maps_to_tag_query() {
        let query = release_query_from_release_asset_url(
            "https://github.com/owner/repo/releases/download/v1.2.3/app.zip",
        )
        .unwrap();
        assert_eq!(query.owner, "owner");
        assert_eq!(query.repo, "repo");
        assert_eq!(query.kind, ReleaseQueryKind::Tag("v1.2.3".to_string()));
    }

    #[test]
    fn github_latest_release_asset_url_maps_to_latest_query() {
        let query = release_query_from_release_asset_url(
            "https://github.com/owner/repo/releases/latest/download/app.zip",
        )
        .unwrap();
        assert_eq!(query.kind, ReleaseQueryKind::Latest);
    }

    #[test]
    fn github_release_asset_url_rejects_non_https() {
        let err = release_query_from_release_asset_url(
            "http://github.com/owner/repo/releases/download/v1.2.3/app.zip",
        )
        .unwrap_err();
        assert!(err.contains("scheme"));
    }
}
