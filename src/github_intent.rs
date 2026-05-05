use reqwest::Url;

use crate::releases::{ReleaseQuery, ReleaseQueryKind};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ParsedGithubIntent {
    DirectDownload {
        url: String,
        filename: Option<String>,
        label: String,
    },
    ReleaseQuery {
        query: ReleaseQuery,
        picker_hint: Option<String>,
    },
    Unsupported {
        reason: String,
        suggested_examples: Vec<String>,
    },
}

pub(crate) fn parse_github_intent(input: &str) -> ParsedGithubIntent {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return ParsedGithubIntent::Unsupported {
            reason: "Enter a GitHub URL first".to_string(),
            suggested_examples: default_suggested_examples(),
        };
    }

    if looks_like_url(trimmed) {
        let normalized = ensure_https_scheme(trimmed);
        match Url::parse(&normalized) {
            Ok(url) => parse_github_url(&url),
            Err(e) => ParsedGithubIntent::Unsupported {
                reason: format!("Invalid URL: {e}"),
                suggested_examples: default_suggested_examples(),
            },
        }
    } else if looks_like_repo_slug(trimmed) {
        let normalized = format!("https://github.com/{}", trimmed.trim().trim_matches('/'));
        match Url::parse(&normalized) {
            Ok(url) => parse_github_url(&url),
            Err(e) => ParsedGithubIntent::Unsupported {
                reason: format!("Invalid GitHub repo slug: {e}"),
                suggested_examples: default_suggested_examples(),
            },
        }
    } else {
        ParsedGithubIntent::Unsupported {
            reason: "Unsupported input; paste a GitHub URL such as https://github.com/owner/repo/releases/latest".to_string(),
            suggested_examples: default_suggested_examples(),
        }
    }
}

fn parse_github_url(url: &Url) -> ParsedGithubIntent {
    let host = url
        .host_str()
        .unwrap_or_default()
        .trim()
        .trim_start_matches("www.");

    match host {
        "github.com" => parse_github_com_url(url),
        "raw.githubusercontent.com" => parse_raw_githubusercontent_url(url),
        _ => ParsedGithubIntent::Unsupported {
            reason: format!("Unsupported host: {host}"),
            suggested_examples: default_suggested_examples(),
        },
    }
}

fn parse_github_com_url(url: &Url) -> ParsedGithubIntent {
    let segments = url_segments(url);
    if segments.len() < 2 {
        return ParsedGithubIntent::Unsupported {
            reason: "GitHub URL must include owner and repo".to_string(),
            suggested_examples: default_suggested_examples(),
        };
    }

    let owner = segments[0].clone();
    let repo = clean_repo_part(&segments[1]);
    if repo.is_empty() {
        return ParsedGithubIntent::Unsupported {
            reason: "GitHub URL repository component is empty".to_string(),
            suggested_examples: default_suggested_examples(),
        };
    }

    match segments.as_slice() {
        // https://github.com/owner/repo
        [_, _] => ParsedGithubIntent::ReleaseQuery {
            query: ReleaseQuery {
                owner,
                repo,
                kind: ReleaseQueryKind::Latest,
            },
            picker_hint: None,
        },
        // https://github.com/owner/repo/releases
        [_, _, tail] if tail == "releases" => ParsedGithubIntent::ReleaseQuery {
            query: ReleaseQuery {
                owner,
                repo,
                kind: ReleaseQueryKind::Latest,
            },
            picker_hint: None,
        },
        // https://github.com/owner/repo/releases/latest
        [_, _, releases, latest] if releases == "releases" && latest == "latest" => {
            ParsedGithubIntent::ReleaseQuery {
                query: ReleaseQuery {
                    owner,
                    repo,
                    kind: ReleaseQueryKind::Latest,
                },
                picker_hint: None,
            }
        }
        // https://github.com/owner/repo/releases/tag/<tag...>
        [_, _, releases, tag_label, tag @ ..] if releases == "releases" && tag_label == "tag" => {
            let tag = tag.join("/");
            if tag.is_empty() {
                return ParsedGithubIntent::Unsupported {
                    reason: "GitHub release tag URL is missing the tag name".to_string(),
                    suggested_examples: default_suggested_examples(),
                };
            }
            ParsedGithubIntent::ReleaseQuery {
                query: ReleaseQuery {
                    owner,
                    repo,
                    kind: ReleaseQueryKind::Tag(tag),
                },
                picker_hint: None,
            }
        }
        // https://github.com/owner/repo/releases/download/<tag>/<asset...>
        [_, _, releases, download, tag, asset @ ..]
            if releases == "releases" && download == "download" =>
        {
            let asset_name = asset.join("/");
            ParsedGithubIntent::DirectDownload {
                url: url.as_str().to_string(),
                filename: if asset_name.is_empty() {
                    None
                } else {
                    Some(asset_name.clone())
                },
                label: format!("release asset: {owner}/{repo}@{tag}/{asset_name}"),
            }
        }
        // https://github.com/owner/repo/releases/latest/download/<asset...>
        [_, _, releases, latest, download, asset @ ..]
            if releases == "releases" && latest == "latest" && download == "download" =>
        {
            let asset_name = asset.join("/");
            ParsedGithubIntent::DirectDownload {
                url: url.as_str().to_string(),
                filename: if asset_name.is_empty() {
                    None
                } else {
                    Some(asset_name.clone())
                },
                label: format!("latest release asset: {owner}/{repo}/{asset_name}"),
            }
        }
        // https://github.com/owner/repo/archive/refs/tags/<tag...>.zip
        // https://github.com/owner/repo/archive/refs/heads/<branch...>.zip
        // https://github.com/owner/repo/archive/<ref...>.zip (legacy)
        [_, _, archive, rest @ ..] if archive == "archive" => {
            let filename = rest.last().cloned().filter(|s| !s.is_empty());
            ParsedGithubIntent::DirectDownload {
                url: url.as_str().to_string(),
                filename,
                label: format!("repo archive: {owner}/{repo}"),
            }
        }
        // https://github.com/owner/repo/blob/<ref...>/<path...>
        [_, _, blob, rest @ ..] if blob == "blob" => parse_blob_url(owner, repo, rest),
        // https://github.com/owner/repo/raw/<ref...>/<path...>
        [_, _, raw, rest @ ..] if raw == "raw" => parse_blob_url(owner, repo, rest),
        _ => ParsedGithubIntent::Unsupported {
            reason: "Unsupported GitHub URL. Supported: releases/*, archive/*, blob/*, raw/*"
                .to_string(),
            suggested_examples: default_suggested_examples(),
        },
    }
}

fn parse_raw_githubusercontent_url(url: &Url) -> ParsedGithubIntent {
    let segments = url_segments(url);
    if segments.len() < 4 {
        return ParsedGithubIntent::Unsupported {
            reason: "raw.githubusercontent.com URL must include owner/repo/ref/path".to_string(),
            suggested_examples: default_suggested_examples(),
        };
    }
    let owner = segments[0].clone();
    let repo = clean_repo_part(&segments[1]);
    let _ref = segments[2].clone();
    let path = segments[3..].join("/");
    let filename = path.split('/').next_back().map(|s| s.to_string());
    ParsedGithubIntent::DirectDownload {
        url: url.as_str().to_string(),
        filename,
        label: format!("raw file: {owner}/{repo}@{_ref}/{path}"),
    }
}

fn parse_blob_url(owner: String, repo: String, rest: &[String]) -> ParsedGithubIntent {
    if rest.len() < 2 {
        return ParsedGithubIntent::Unsupported {
            reason: "GitHub blob/raw URL is missing ref or file path".to_string(),
            suggested_examples: default_suggested_examples(),
        };
    }
    let git_ref = rest[0].clone();
    let path = rest[1..].join("/");
    let filename = path.split('/').next_back().map(|s| s.to_string());
    let raw_url = format!("https://raw.githubusercontent.com/{owner}/{repo}/{git_ref}/{path}");
    ParsedGithubIntent::DirectDownload {
        url: raw_url,
        filename,
        label: format!("file: {owner}/{repo}@{git_ref}/{path}"),
    }
}

fn looks_like_url(input: &str) -> bool {
    input.starts_with("http://")
        || input.starts_with("https://")
        || input.starts_with("github.com/")
        || input.starts_with("www.github.com/")
        || input.starts_with("raw.githubusercontent.com/")
}

fn looks_like_repo_slug(input: &str) -> bool {
    let trimmed = input.trim().trim_matches('/');
    let parts = trimmed.split('/').collect::<Vec<_>>();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty()
}

fn ensure_https_scheme(input: &str) -> String {
    if input.starts_with("http://") || input.starts_with("https://") {
        input.to_string()
    } else {
        format!("https://{input}")
    }
}

fn clean_repo_part(part: &str) -> String {
    part.trim().trim_end_matches(".git").to_string()
}

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

fn default_suggested_examples() -> Vec<String> {
    vec![
        "https://github.com/owner/repo/releases/latest".to_string(),
        "https://github.com/owner/repo/releases/tag/v1.2.3".to_string(),
        "https://github.com/owner/repo/releases/download/v1.2.3/asset.zip".to_string(),
        "https://github.com/owner/repo/archive/refs/tags/v1.2.3.zip".to_string(),
        "https://github.com/owner/repo/blob/main/README.md".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn router_classifies_release_asset_download_url() {
        let intent = parse_github_intent(
            "https://github.com/octo-org/octo-repo/releases/download/v1.2.3/app.zip",
        );
        match intent {
            ParsedGithubIntent::DirectDownload { filename, .. } => {
                assert_eq!(filename, Some("app.zip".to_string()));
            }
            other => panic!("expected DirectDownload, got {other:?}"),
        }
    }

    #[test]
    fn router_classifies_release_page_urls() {
        let intent = parse_github_intent("https://github.com/octo-org/octo-repo/releases/latest");
        match intent {
            ParsedGithubIntent::ReleaseQuery { query, .. } => {
                assert_eq!(query.owner, "octo-org");
                assert_eq!(query.repo, "octo-repo");
                assert_eq!(query.kind, ReleaseQueryKind::Latest);
            }
            other => panic!("expected ReleaseQuery, got {other:?}"),
        }

        let intent = parse_github_intent("octo-org/octo-repo");
        match intent {
            ParsedGithubIntent::ReleaseQuery { query, .. } => {
                assert_eq!(query.kind, ReleaseQueryKind::Latest);
            }
            other => panic!("expected ReleaseQuery, got {other:?}"),
        }
    }

    #[test]
    fn router_maps_blob_to_raw_download_spec() {
        let intent =
            parse_github_intent("https://github.com/octo-org/octo-repo/blob/main/README.md");
        match intent {
            ParsedGithubIntent::DirectDownload { url, filename, .. } => {
                assert!(
                    url.starts_with("https://raw.githubusercontent.com/octo-org/octo-repo/main/")
                );
                assert_eq!(filename, Some("README.md".to_string()));
            }
            other => panic!("expected DirectDownload, got {other:?}"),
        }
    }

    #[test]
    fn router_accepts_raw_githubusercontent_urls() {
        let intent = parse_github_intent(
            "https://raw.githubusercontent.com/octo-org/octo-repo/main/path/to/file.txt",
        );
        match intent {
            ParsedGithubIntent::DirectDownload { filename, .. } => {
                assert_eq!(filename, Some("file.txt".to_string()));
            }
            other => panic!("expected DirectDownload, got {other:?}"),
        }
    }

    #[test]
    fn router_rejects_non_artifact_github_urls() {
        let intent = parse_github_intent("https://github.com/octo-org/octo-repo/issues/123");
        match intent {
            ParsedGithubIntent::Unsupported { .. } => {}
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }
}
