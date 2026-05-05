use crate::download::DownloadControl;
use crate::download::DownloadProbe;
use crate::download::SelectedDownloadStrategy;
use crate::evidence_ledger::{EvidenceLedger, FileSystemEvidenceLedger};
use crate::releases::{ReleaseQuery, ResolvedRelease};
use crate::source_adapter::{GitHubReleaseAdapter, SourceAdapter};
use crate::source_trust::SourceTrustPolicyConfig;
use crate::verification::{DownloadVerificationPlan, VerificationReport};
use crate::verifier_adapter::{GitHubReleaseVerifierAdapter, VerifierAdapter};
use reqwest::blocking::Client;
use std::path::Path;
use std::path::PathBuf;
use std::sync::mpsc;
use std::sync::Arc;

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
    evidence_ledger: FileSystemEvidenceLedger,
}

pub(crate) struct DownloadWithStrategyContractInput<'a> {
    pub(crate) client: &'a Client,
    pub(crate) url: &'a str,
    pub(crate) save_path: &'a str,
    pub(crate) probe: &'a DownloadProbe,
    pub(crate) strategy: &'a SelectedDownloadStrategy,
    pub(crate) ctrl: &'a Arc<DownloadControl>,
    pub(crate) progress_tx: &'a mpsc::Sender<(u64, u64, f64, f64)>,
}

impl Default for CoreRuntime {
    fn default() -> Self {
        Self {
            source_adapter: GitHubReleaseAdapter,
            verifier_adapter: GitHubReleaseVerifierAdapter,
            evidence_ledger: FileSystemEvidenceLedger,
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

    pub(crate) fn verification_plan_from_download_context(
        &self,
        release: Option<&ResolvedRelease>,
        asset_index: Option<usize>,
    ) -> Result<Option<DownloadVerificationPlan>, String> {
        match (release, asset_index) {
            (None, None) => Ok(None),
            (Some(release), Some(idx)) => {
                if release.assets.get(idx).is_none() {
                    return Err(format!(
                        "Download verification context is invalid: asset index {idx} is out of range (assets={})",
                        release.assets.len()
                    ));
                }
                Ok(self.verification_plan_for_selected_asset(release, idx))
            }
            _ => Err(
                "Download verification context is inconsistent (release + asset index must be both set or both absent)"
                    .to_string(),
            ),
        }
    }

    pub(crate) fn probe_download_best_effort(
        &self,
        client: &Client,
        url: &str,
    ) -> (DownloadProbe, Option<String>) {
        match crate::download::probe_download(client, url) {
            Ok(probe) => (probe, None),
            Err(e) => (
                DownloadProbe {
                    total: 0,
                    range_supported: false,
                    etag: None,
                    last_modified: None,
                },
                Some(e),
            ),
        }
    }

    pub(crate) fn choose_download_strategy(
        &self,
        history_path: Option<&PathBuf>,
        url: &str,
        probe: &DownloadProbe,
    ) -> SelectedDownloadStrategy {
        let history_path = history_path.cloned();
        let history = crate::history::load_bench_history(&history_path, url, probe);
        crate::bench::choose_history_backed_strategy(probe, &history)
    }

    pub(crate) fn download_with_strategy_contract(
        &self,
        input: DownloadWithStrategyContractInput<'_>,
    ) -> Result<(), String> {
        let DownloadWithStrategyContractInput {
            client,
            url,
            save_path,
            probe,
            strategy,
            ctrl,
            progress_tx,
        } = input;
        if let Err(e) = crate::download::download_with_strategy(
            client,
            url,
            save_path,
            probe,
            strategy,
            ctrl,
            progress_tx,
        ) {
            let ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let _ = self.append_line(
                Path::new("download_error.log"),
                &format!("[{ts}] download_with_strategy error: {e}"),
            );
            let _ = progress_tx.send((0, 0, 0.0, 0.0));
            return Err(e);
        }

        // Ensure the UI sees a non-error completion progress event even when the probe could
        // not determine a total size (probe.total == 0). Otherwise the (0,0) sentinel would
        // be indistinguishable from failure.
        let downloaded_bytes = std::fs::metadata(save_path)
            .map(|meta| meta.len())
            .unwrap_or(0);
        let done_total = if downloaded_bytes > 0 {
            downloaded_bytes
        } else if probe.total > 0 {
            probe.total
        } else {
            1
        };
        let _ = progress_tx.send((done_total, done_total, 0.0, 0.0));

        Ok(())
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

    pub(crate) fn append_line(&self, path: &Path, line: &str) -> Result<(), String> {
        self.evidence_ledger.append_line(path, line)
    }
}
