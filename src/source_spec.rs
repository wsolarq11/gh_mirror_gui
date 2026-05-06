use crate::releases::ReleaseQuery;

/// Artifact Trust Broker source specification (Phase 5).
///
/// Today we only support GitHub Release resolution, but the stable contract is a
/// tagged union so future adapters can plug in without rewriting the backend
/// contract, verification, policy, evidence, or UI shells.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub(crate) enum SourceSpec {
    GitHubRelease { query: ReleaseQuery },
}
