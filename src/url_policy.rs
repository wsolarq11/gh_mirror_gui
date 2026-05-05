use reqwest::Url;
use std::sync::atomic::{AtomicBool, Ordering};

static ALLOW_LOOPBACK_ASSET_HOSTS: AtomicBool = AtomicBool::new(false);

pub(crate) fn enable_loopback_for_selftests() {
    ALLOW_LOOPBACK_ASSET_HOSTS.store(true, Ordering::Relaxed);
}

fn allow_loopback_hosts() -> bool {
    ALLOW_LOOPBACK_ASSET_HOSTS.load(Ordering::Relaxed)
}

const OFFICIAL_GITHUB_ARTIFACT_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "objects-origin.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

pub(crate) fn official_github_artifact_hosts() -> &'static [&'static str] {
    OFFICIAL_GITHUB_ARTIFACT_HOSTS
}

fn normalize_host(host: &str) -> &str {
    host.trim().strip_prefix("www.").unwrap_or(host.trim())
}

pub(crate) fn is_github_official_artifact_host(host: &str) -> bool {
    let host = normalize_host(host);
    OFFICIAL_GITHUB_ARTIFACT_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

pub(crate) fn validate_https_github_official_url(url: &Url, context: &str) -> Result<(), String> {
    let host = url
        .host_str()
        .ok_or_else(|| format!("{context}: URL is missing a host"))?;

    if url.scheme() != "https" {
        if url.scheme() == "http"
            && is_loopback_host(host)
            && (cfg!(test) || allow_loopback_hosts())
        {
            return Ok(());
        }
        return Err(format!("{context}: only https:// URLs are supported"));
    }
    if !is_github_official_artifact_host(host) {
        if is_loopback_host(host) && (cfg!(test) || allow_loopback_hosts()) {
            return Ok(());
        }
        return Err(format!("{context}: unsupported host: {host}"));
    }
    Ok(())
}

pub(crate) fn parse_and_validate_https_github_official_url(
    url: &str,
    context: &str,
) -> Result<Url, String> {
    let parsed = Url::parse(url).map_err(|e| format!("{context}: invalid URL: {e}"))?;
    validate_https_github_official_url(&parsed, context)?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_official_host_allowlist_accepts_known_hosts() {
        for host in OFFICIAL_GITHUB_ARTIFACT_HOSTS {
            assert!(is_github_official_artifact_host(host));
            assert!(is_github_official_artifact_host(&host.to_uppercase()));
            assert!(is_github_official_artifact_host(&format!("www.{host}")));
        }
    }

    #[test]
    fn github_official_host_allowlist_rejects_unknown_hosts() {
        assert!(!is_github_official_artifact_host("example.com"));
        assert!(!is_github_official_artifact_host("github.example.com"));
    }

    #[test]
    fn validate_rejects_non_https() {
        let url = Url::parse("http://github.com/owner/repo/releases/latest").unwrap();
        let err = validate_https_github_official_url(&url, "test").unwrap_err();
        assert!(err.contains("only https"));
    }

    #[test]
    fn validate_allows_local_http_in_tests() {
        let url = Url::parse("http://127.0.0.1:1234/file.bin").unwrap();
        assert!(validate_https_github_official_url(&url, "test").is_ok());
    }
}
