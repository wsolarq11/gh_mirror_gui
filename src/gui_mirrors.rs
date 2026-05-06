/// Mirror support is intentionally minimal.
///
/// Project guardrails: do not turn this project into a mirror-list aggregator.
/// This table is for local testing and controlled environments only.
pub(crate) const SPEED_TEST_TIMEOUT_SECS: u64 = 5;

/// Known mirror sites. First entry must be "Direct (no mirror)".
pub(crate) const MIRRORS: &[(&str, &str)] = &[("Direct (no mirror)", "")];

pub(crate) fn normalize_mirror_index(index: usize) -> usize {
    if index < MIRRORS.len() {
        index
    } else {
        0
    }
}
