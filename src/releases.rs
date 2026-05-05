use reqwest::blocking::Client;
use reqwest::header::{ACCEPT, USER_AGENT};
use reqwest::Url;
use std::time::Duration;

const DEFAULT_GITHUB_API_BASE: &str = "https://api.github.com";
const RELEASE_RESOLVER_USER_AGENT: &str = "gh_mirror_gui-release-resolver";
const RELEASE_LOOKUP_MAX_RETRIES: u32 = 3;
const RELEASE_LOOKUP_RETRY_DELAY_MS: u64 = 800;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ReleaseQueryKind {
    Latest,
    Tag(String),
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReleaseQuery {
    pub owner: String,
    pub repo: String,
    pub kind: ReleaseQueryKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseAsset {
    pub name: String,
    pub size: u64,
    pub browser_download_url: String,
    pub content_type: Option<String>,
    pub api_url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedRelease {
    pub owner: String,
    pub repo: String,
    pub tag_name: String,
    pub name: Option<String>,
    pub html_url: String,
    pub assets: Vec<ReleaseAsset>,
}

#[derive(serde::Deserialize)]
struct GitHubReleaseResponse {
    tag_name: String,
    name: Option<String>,
    html_url: String,
    assets: Vec<GitHubAssetResponse>,
}

#[derive(serde::Deserialize)]
struct GitHubAssetResponse {
    url: Option<String>,
    name: String,
    size: u64,
    browser_download_url: String,
    content_type: Option<String>,
}

impl ReleaseQuery {
    pub(crate) fn repo_slug(&self) -> String {
        format!("{}/{}", self.owner, self.repo)
    }

    pub(crate) fn selector_label(&self) -> String {
        match &self.kind {
            ReleaseQueryKind::Latest => "latest".to_string(),
            ReleaseQueryKind::Tag(tag) => format!("tag {tag}"),
        }
    }
}

#[cfg(test)]
pub(crate) fn parse_release_query(input: &str) -> Result<ReleaseQuery, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("Enter a GitHub repository or release URL first".to_string());
    }

    if looks_like_github_url(trimmed) {
        let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            trimmed.to_string()
        } else {
            format!("https://{trimmed}")
        };
        return parse_github_url(&normalized);
    }

    parse_repo_slug(trimmed)
}

#[cfg(test)]
pub(crate) fn is_github_release_asset_download_url(input: &str) -> bool {
    let trimmed = input.trim();
    if !looks_like_github_url(trimmed) {
        return false;
    }
    let normalized = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    let Ok(url) = Url::parse(&normalized) else {
        return false;
    };
    if !is_github_host(url.host_str()) {
        return false;
    }
    let segments = url_segments(&url);
    segments.len() >= 6 && segments[2] == "releases" && segments[3] == "download"
}

pub(crate) fn resolve_release_assets(
    client: &Client,
    query: &ReleaseQuery,
) -> Result<ResolvedRelease, String> {
    resolve_release_assets_with_base(client, DEFAULT_GITHUB_API_BASE, query)
}

pub(crate) fn resolve_release_assets_with_base(
    client: &Client,
    api_base: &str,
    query: &ReleaseQuery,
) -> Result<ResolvedRelease, String> {
    let endpoint = github_release_api_url(api_base, query)?;
    let token = std::env::var("GITHUB_TOKEN")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());

    let mut last_retryable_error = None;
    for attempt in 0..=RELEASE_LOOKUP_MAX_RETRIES {
        if attempt > 0 {
            std::thread::sleep(Duration::from_millis(
                RELEASE_LOOKUP_RETRY_DELAY_MS * attempt as u64,
            ));
        }

        let mut request = client
            .get(endpoint.clone())
            .header(USER_AGENT, RELEASE_RESOLVER_USER_AGENT)
            .header(ACCEPT, "application/vnd.github+json");
        if let Some(token) = token.as_deref() {
            request = request.bearer_auth(token);
        }

        let response = match request.send() {
            Ok(response) => response,
            Err(e) => {
                last_retryable_error = Some(format!("GitHub release lookup request failed: {e}"));
                continue;
            }
        };

        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            let detail = compact_error_body(&body);
            let error = format!(
                "GitHub release lookup failed for {} {}: HTTP {}{}",
                query.repo_slug(),
                query.selector_label(),
                status.as_u16(),
                detail
            );

            if is_retryable_release_lookup_status(status) && attempt < RELEASE_LOOKUP_MAX_RETRIES {
                last_retryable_error = Some(error);
                continue;
            }

            return Err(error);
        }

        let body = response
            .text()
            .map_err(|e| format!("GitHub release response body could not be read: {e}"))?;
        let release = serde_json::from_str::<GitHubReleaseResponse>(&body)
            .map_err(|e| format!("GitHub release response was not valid JSON: {e}"))?;
        return Ok(ResolvedRelease {
            owner: query.owner.clone(),
            repo: query.repo.clone(),
            tag_name: release.tag_name,
            name: release.name,
            html_url: release.html_url,
            assets: release
                .assets
                .into_iter()
                .map(|asset| ReleaseAsset {
                    name: asset.name,
                    size: asset.size,
                    browser_download_url: asset.browser_download_url,
                    content_type: asset.content_type,
                    api_url: asset.url,
                })
                .collect(),
        });
    }

    Err(format!(
        "GitHub release lookup failed after {} attempts: {}",
        RELEASE_LOOKUP_MAX_RETRIES + 1,
        last_retryable_error.unwrap_or_else(|| "unknown transient error".to_string())
    ))
}

fn is_retryable_release_lookup_status(status: reqwest::StatusCode) -> bool {
    status.is_server_error() || status.as_u16() == 429
}

fn github_release_api_url(api_base: &str, query: &ReleaseQuery) -> Result<Url, String> {
    let mut url = Url::parse(api_base).map_err(|e| format!("Invalid GitHub API base URL: {e}"))?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| "GitHub API base URL cannot be used as a base".to_string())?;
        segments.clear();
        segments.push("repos");
        segments.push(&query.owner);
        segments.push(&query.repo);
        segments.push("releases");
        match &query.kind {
            ReleaseQueryKind::Latest => {
                segments.push("latest");
            }
            ReleaseQueryKind::Tag(tag) => {
                segments.push("tags");
                segments.push(tag);
            }
        }
    }
    Ok(url)
}

#[cfg(test)]
fn parse_repo_slug(input: &str) -> Result<ReleaseQuery, String> {
    let trimmed = input.trim().trim_matches('/');
    let parts = trimmed.split('/').collect::<Vec<_>>();
    if parts.len() != 2 {
        return Err(
            "Use owner/repo or a GitHub release URL such as https://github.com/owner/repo/releases/latest"
                .to_string(),
        );
    }
    let owner = clean_repo_part(parts[0])?;
    let repo = clean_repo_part(parts[1])?;
    Ok(ReleaseQuery {
        owner,
        repo,
        kind: ReleaseQueryKind::Latest,
    })
}

#[cfg(test)]
fn parse_github_url(input: &str) -> Result<ReleaseQuery, String> {
    let url = Url::parse(input).map_err(|e| format!("Invalid GitHub URL: {e}"))?;
    if !is_github_host(url.host_str()) {
        return Err("Only github.com repository and release URLs are supported".to_string());
    }

    let segments = url_segments(&url);
    if segments.len() < 2 {
        return Err("GitHub URL must include owner and repository".to_string());
    }

    let owner = clean_repo_part(&segments[0])?;
    let repo = clean_repo_part(&segments[1])?;

    let kind = match segments.as_slice() {
        [_, _] => ReleaseQueryKind::Latest,
        [_, _, tail] if tail == "releases" => ReleaseQueryKind::Latest,
        [_, _, releases, latest] if releases == "releases" && latest == "latest" => {
            ReleaseQueryKind::Latest
        }
        [_, _, releases, tag_label, tag @ ..] if releases == "releases" && tag_label == "tag" => {
            release_tag_from_segments(tag)?
        }
        [_, _, releases, download_label, tag, ..]
            if releases == "releases" && download_label == "download" =>
        {
            ReleaseQueryKind::Tag(tag.to_string())
        }
        _ => {
            return Err(
                "Use a GitHub repo URL, /releases, /releases/latest, or /releases/tag/<tag>"
                    .to_string(),
            )
        }
    };

    Ok(ReleaseQuery { owner, repo, kind })
}

#[cfg(test)]
fn release_tag_from_segments(segments: &[String]) -> Result<ReleaseQueryKind, String> {
    if segments.is_empty() {
        return Err("GitHub release tag URL is missing the tag name".to_string());
    }
    Ok(ReleaseQueryKind::Tag(segments.join("/")))
}

#[cfg(test)]
fn clean_repo_part(part: &str) -> Result<String, String> {
    let value = part.trim().trim_end_matches(".git");
    if value.is_empty()
        || value.contains('\\')
        || value == "."
        || value == ".."
        || value.contains(char::is_whitespace)
    {
        return Err(format!("Invalid GitHub repository component: {part}"));
    }
    Ok(value.to_string())
}

#[cfg(test)]
fn looks_like_github_url(input: &str) -> bool {
    input.starts_with("http://")
        || input.starts_with("https://")
        || input.starts_with("github.com/")
        || input.starts_with("www.github.com/")
}

#[cfg(test)]
fn is_github_host(host: Option<&str>) -> bool {
    matches!(
        host.map(|h| h.trim_start_matches("www.")),
        Some("github.com")
    )
}

#[cfg(test)]
fn url_segments(url: &Url) -> Vec<String> {
    url.path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.is_empty())
                .map(|segment| segment.to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn compact_error_body(body: &str) -> String {
    let compact = body
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(240)
        .collect::<String>();
    if compact.is_empty() {
        String::new()
    } else {
        format!(": {compact}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    fn serve_api_once(
        body: &'static str,
        status: &'static str,
    ) -> (String, thread::JoinHandle<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]).to_string();
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(header.as_bytes()).unwrap();
            stream.write_all(body.as_bytes()).unwrap();
            request
        });

        (format!("http://{addr}"), handle)
    }

    #[test]
    fn parser_accepts_repo_release_latest_and_tag_inputs() {
        assert_eq!(
            parse_release_query("owner/repo").unwrap(),
            ReleaseQuery {
                owner: "owner".to_string(),
                repo: "repo".to_string(),
                kind: ReleaseQueryKind::Latest
            }
        );
        assert_eq!(
            parse_release_query("https://github.com/owner/repo/releases")
                .unwrap()
                .kind,
            ReleaseQueryKind::Latest
        );
        assert_eq!(
            parse_release_query("github.com/owner/repo/releases/latest")
                .unwrap()
                .kind,
            ReleaseQueryKind::Latest
        );
        assert_eq!(
            parse_release_query("https://github.com/owner/repo/releases/tag/v1.2.3")
                .unwrap()
                .kind,
            ReleaseQueryKind::Tag("v1.2.3".to_string())
        );
    }

    #[test]
    fn parser_maps_direct_download_url_back_to_its_release_tag() {
        let query = parse_release_query(
            "https://github.com/owner/repo/releases/download/v1.2.3/app.tar.gz",
        )
        .unwrap();

        assert_eq!(query.owner, "owner");
        assert_eq!(query.repo, "repo");
        assert_eq!(query.kind, ReleaseQueryKind::Tag("v1.2.3".to_string()));
        assert!(is_github_release_asset_download_url(
            "https://github.com/owner/repo/releases/download/v1.2.3/app.tar.gz"
        ));
    }

    #[test]
    fn parser_rejects_unsupported_hosts_and_incomplete_paths() {
        assert!(parse_release_query("https://example.com/owner/repo").is_err());
        assert!(parse_release_query("https://github.com/owner").is_err());
        assert!(parse_release_query("owner/repo/extra").is_err());
    }

    #[test]
    fn resolver_fetches_release_assets_from_api() {
        let body = r#"{
          "tag_name":"v1.2.3",
          "name":"Release v1.2.3",
          "html_url":"https://github.com/owner/repo/releases/tag/v1.2.3",
          "assets":[
            {
              "name":"app.zip",
              "size":1048576,
              "browser_download_url":"https://github.com/owner/repo/releases/download/v1.2.3/app.zip",
              "content_type":"application/zip"
            }
          ]
        }"#;
        let (api_base, server) = serve_api_once(body, "200 OK");
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let query =
            parse_release_query("https://github.com/owner/repo/releases/tag/v1.2.3").unwrap();

        let release = resolve_release_assets_with_base(&client, &api_base, &query).unwrap();
        let request = server.join().unwrap();

        assert!(request.starts_with("GET /repos/owner/repo/releases/tags/v1.2.3 HTTP/1.1"));
        assert!(request.contains("user-agent: gh_mirror_gui-release-resolver"));
        assert_eq!(release.tag_name, "v1.2.3");
        assert_eq!(release.assets.len(), 1);
        assert_eq!(release.assets[0].name, "app.zip");
        assert_eq!(release.assets[0].size, 1_048_576);
    }

    #[test]
    fn resolver_surfaces_http_errors_with_status_code() {
        let (api_base, server) = serve_api_once(r#"{"message":"Not Found"}"#, "404 Not Found");
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let query = parse_release_query("owner/repo").unwrap();

        let err = resolve_release_assets_with_base(&client, &api_base, &query).unwrap_err();
        let _ = server.join().unwrap();

        assert!(err.contains("HTTP 404"));
        assert!(err.contains("owner/repo latest"));
    }
}
