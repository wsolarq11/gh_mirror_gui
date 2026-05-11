use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiLocale {
    #[default]
    En,
    Zh,
}

impl UiLocale {
    pub const fn toggle(self) -> Self {
        match self {
            Self::En => Self::Zh,
            Self::Zh => Self::En,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutMode {
    Wide,
    Medium,
    Compact,
}

impl LayoutMode {
    pub const fn is_wide(self) -> bool {
        matches!(self, Self::Wide)
    }

    pub const fn is_compact(self) -> bool {
        matches!(self, Self::Compact)
    }
}

pub fn layout_mode_for_width(width: f32) -> LayoutMode {
    if !width.is_finite() || width < 820.0 {
        LayoutMode::Compact
    } else if width < 1180.0 {
        LayoutMode::Medium
    } else {
        LayoutMode::Wide
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TextKey {
    AppTitle,
    AppSubtitle,
    SwitchToChinese,
    SwitchToEnglish,
    UrlLabel,
    PasteButton,
    ClearButton,
    FindReleaseAssetsButton,
    ReleasePickerHint,
    ReleaseLabel,
    AssetLabel,
    UseSelectedAssetButton,
    OpenReleaseButton,
    RetestButton,
    SaveToLabel,
    BrowseButton,
    ProxyLabel,
    ClearProxyButton,
    AllowInvalidTlsCertificates,
    UnsafeTlsHint,
    NetworkPolicyTitle,
    CopyAllowlistButton,
    ShowAllowlist,
    TrustPolicyTitle,
    KeepUnknownDownloads,
    AllowOpenUnknownDownloads,
    MismatchFileActionLabel,
    QuarantineOption,
    DeleteOption,
    VerificationSourceTrustTitle,
    RequireSignedChecksumSource,
    PinnedPublisherKeyLabel,
    ImportPublicKey,
    NormalizeKey,
    ClearKey,
    HistoryPathLabel,
    DefaultButton,
    Stage1Title,
    CheckLatestCandidateButton,
    Stage2Title,
    StageLatestCandidateButton,
    PrepareHelperBundleButton,
    DownloadButton,
    PauseButton,
    ResumeButton,
    CancelButton,
    ProgressWaitingForBytes,
    ProgressUnknownSize,
    StatusReady,
    StatusEnterUrlFirst,
    StatusTestingMirrors,
    StatusDirectNoMirror,
    StatusResolvingReleaseAssets,
    StatusDownloadAlreadyInProgress,
    StatusReleaseAssetLookupRunning,
    StatusStartingDownloadUnknown,
    StatusDownloadCompleteVerifying,
    StatusDownloadFailed,
    StatusCancelled,
    StatusChooseReleaseAssetFirst,
    StatusReleaseAssetsReady,
    StatusCheckingCandidate,
    StatusStagingCandidate,
    StatusPublisherKeyImportRunning,
    StatusNoPublisherKeyAsset,
    StatusNoAssetsFound,
}

pub const ALL_TEXT_KEYS: &[TextKey] = &[
    TextKey::AppTitle,
    TextKey::AppSubtitle,
    TextKey::SwitchToChinese,
    TextKey::SwitchToEnglish,
    TextKey::UrlLabel,
    TextKey::PasteButton,
    TextKey::ClearButton,
    TextKey::FindReleaseAssetsButton,
    TextKey::ReleasePickerHint,
    TextKey::ReleaseLabel,
    TextKey::AssetLabel,
    TextKey::UseSelectedAssetButton,
    TextKey::OpenReleaseButton,
    TextKey::RetestButton,
    TextKey::SaveToLabel,
    TextKey::BrowseButton,
    TextKey::ProxyLabel,
    TextKey::ClearProxyButton,
    TextKey::AllowInvalidTlsCertificates,
    TextKey::UnsafeTlsHint,
    TextKey::NetworkPolicyTitle,
    TextKey::CopyAllowlistButton,
    TextKey::ShowAllowlist,
    TextKey::TrustPolicyTitle,
    TextKey::KeepUnknownDownloads,
    TextKey::AllowOpenUnknownDownloads,
    TextKey::MismatchFileActionLabel,
    TextKey::QuarantineOption,
    TextKey::DeleteOption,
    TextKey::VerificationSourceTrustTitle,
    TextKey::RequireSignedChecksumSource,
    TextKey::PinnedPublisherKeyLabel,
    TextKey::ImportPublicKey,
    TextKey::NormalizeKey,
    TextKey::ClearKey,
    TextKey::HistoryPathLabel,
    TextKey::DefaultButton,
    TextKey::Stage1Title,
    TextKey::CheckLatestCandidateButton,
    TextKey::Stage2Title,
    TextKey::StageLatestCandidateButton,
    TextKey::PrepareHelperBundleButton,
    TextKey::DownloadButton,
    TextKey::PauseButton,
    TextKey::ResumeButton,
    TextKey::CancelButton,
    TextKey::ProgressWaitingForBytes,
    TextKey::ProgressUnknownSize,
    TextKey::StatusReady,
    TextKey::StatusEnterUrlFirst,
    TextKey::StatusTestingMirrors,
    TextKey::StatusDirectNoMirror,
    TextKey::StatusResolvingReleaseAssets,
    TextKey::StatusDownloadAlreadyInProgress,
    TextKey::StatusReleaseAssetLookupRunning,
    TextKey::StatusStartingDownloadUnknown,
    TextKey::StatusDownloadCompleteVerifying,
    TextKey::StatusDownloadFailed,
    TextKey::StatusCancelled,
    TextKey::StatusChooseReleaseAssetFirst,
    TextKey::StatusReleaseAssetsReady,
    TextKey::StatusCheckingCandidate,
    TextKey::StatusStagingCandidate,
    TextKey::StatusPublisherKeyImportRunning,
    TextKey::StatusNoPublisherKeyAsset,
    TextKey::StatusNoAssetsFound,
];

pub fn text(locale: UiLocale, key: TextKey) -> &'static str {
    match locale {
        UiLocale::En => match key {
            TextKey::AppTitle => "GitHub Mirror Downloader",
            TextKey::AppSubtitle => "Proof-to-Action UI Kernel",
            TextKey::SwitchToChinese => "中文",
            TextKey::SwitchToEnglish => "English",
            TextKey::UrlLabel => "URL:",
            TextKey::PasteButton => "📋 Paste",
            TextKey::ClearButton => "🗑 Clear",
            TextKey::FindReleaseAssetsButton => "🔎 Find release assets",
            TextKey::ReleasePickerHint => "Find release assets only works with repo/release pages.",
            TextKey::ReleaseLabel => "Release:",
            TextKey::AssetLabel => "Asset:",
            TextKey::UseSelectedAssetButton => "Use selected asset",
            TextKey::OpenReleaseButton => "Open release",
            TextKey::RetestButton => "🔄 Retest",
            TextKey::SaveToLabel => "Save to:",
            TextKey::BrowseButton => "📁 Browse...",
            TextKey::ProxyLabel => "Proxy:",
            TextKey::ClearProxyButton => "🗑 Clear",
            TextKey::AllowInvalidTlsCertificates => "Allow invalid TLS certificates (unsafe)",
            TextKey::UnsafeTlsHint => "Only use this for trusted debugging proxies.",
            TextKey::NetworkPolicyTitle => "Network policy",
            TextKey::CopyAllowlistButton => "Copy allowlist",
            TextKey::ShowAllowlist => "Show allowlist",
            TextKey::TrustPolicyTitle => "Trust policy",
            TextKey::KeepUnknownDownloads => "Keep UNKNOWN downloads",
            TextKey::AllowOpenUnknownDownloads => "Allow Open Folder for UNKNOWN downloads",
            TextKey::MismatchFileActionLabel => "MISMATCH file action:",
            TextKey::QuarantineOption => "QUARANTINE",
            TextKey::DeleteOption => "DELETE",
            TextKey::VerificationSourceTrustTitle => "Verification source trust",
            TextKey::RequireSignedChecksumSource => "Require signed checksum/provenance source",
            TextKey::PinnedPublisherKeyLabel => "Pinned Ed25519 publisher key:",
            TextKey::ImportPublicKey => "Import public key",
            TextKey::NormalizeKey => "Normalize key",
            TextKey::ClearKey => "Clear key",
            TextKey::HistoryPathLabel => "History/evidence path:",
            TextKey::DefaultButton => "Default",
            TextKey::Stage1Title => "Self-update Stage 1",
            TextKey::CheckLatestCandidateButton => "Check latest self-update candidate",
            TextKey::Stage2Title => "Self-update Stage 2",
            TextKey::StageLatestCandidateButton => "Stage latest candidate (no install)",
            TextKey::PrepareHelperBundleButton => "Prepare controlled helper bundle (no install)",
            TextKey::DownloadButton => "⬇ Download",
            TextKey::PauseButton => "⏸ Pause",
            TextKey::ResumeButton => "▶ Resume",
            TextKey::CancelButton => "❌ Cancel",
            TextKey::ProgressWaitingForBytes => "Connecting... waiting for first bytes",
            TextKey::ProgressUnknownSize => "size unknown",
            TextKey::StatusReady => "Ready",
            TextKey::StatusEnterUrlFirst => "Please enter a URL first",
            TextKey::StatusTestingMirrors => "Testing mirrors...",
            TextKey::StatusDirectNoMirror => "Direct (no mirror)",
            TextKey::StatusResolvingReleaseAssets => "Resolving release assets before download...",
            TextKey::StatusDownloadAlreadyInProgress => "Download already in progress",
            TextKey::StatusReleaseAssetLookupRunning => "Release asset lookup is still running...",
            TextKey::StatusStartingDownloadUnknown => {
                "Connecting... waiting for first bytes; verification will be UNKNOWN"
            }
            TextKey::StatusDownloadCompleteVerifying => "Download complete; verifying SHA256...",
            TextKey::StatusDownloadFailed => "❌ Download failed",
            TextKey::StatusCancelled => "Cancelled",
            TextKey::StatusChooseReleaseAssetFirst => "Choose a release asset first",
            TextKey::StatusReleaseAssetsReady => "Release asset selection ready",
            TextKey::StatusCheckingCandidate => {
                "Checking latest self-update candidate (no install)..."
            }
            TextKey::StatusStagingCandidate => {
                "Staging latest self-update candidate (no install)..."
            }
            TextKey::StatusPublisherKeyImportRunning => "Importing publisher key...",
            TextKey::StatusNoPublisherKeyAsset => {
                "No publisher-key.ed25519.pub asset was found in this release"
            }
            TextKey::StatusNoAssetsFound => "This release has no downloadable assets.",
        },
        UiLocale::Zh => match key {
            TextKey::AppTitle => "GitHub 镜像下载器",
            TextKey::AppSubtitle => "证据到动作 UI 内核",
            TextKey::SwitchToChinese => "中文",
            TextKey::SwitchToEnglish => "English",
            TextKey::UrlLabel => "URL：",
            TextKey::PasteButton => "📋 粘贴",
            TextKey::ClearButton => "🗑 清空",
            TextKey::FindReleaseAssetsButton => "🔎 查找 release 资源",
            TextKey::ReleasePickerHint => "查找 release 资源只适用于仓库 / release 页面。",
            TextKey::ReleaseLabel => "Release：",
            TextKey::AssetLabel => "资源：",
            TextKey::UseSelectedAssetButton => "使用选中资源",
            TextKey::OpenReleaseButton => "打开 release",
            TextKey::RetestButton => "🔄 重测",
            TextKey::SaveToLabel => "保存到：",
            TextKey::BrowseButton => "📁 浏览…",
            TextKey::ProxyLabel => "代理：",
            TextKey::ClearProxyButton => "🗑 清空",
            TextKey::AllowInvalidTlsCertificates => "允许无效 TLS 证书（不安全）",
            TextKey::UnsafeTlsHint => "仅在可信调试代理下使用。",
            TextKey::NetworkPolicyTitle => "网络策略",
            TextKey::CopyAllowlistButton => "复制允许列表",
            TextKey::ShowAllowlist => "显示允许列表",
            TextKey::TrustPolicyTitle => "信任策略",
            TextKey::KeepUnknownDownloads => "保留 UNKNOWN 下载",
            TextKey::AllowOpenUnknownDownloads => "允许对 UNKNOWN 下载打开文件夹",
            TextKey::MismatchFileActionLabel => "MISMATCH 文件动作：",
            TextKey::QuarantineOption => "隔离",
            TextKey::DeleteOption => "删除",
            TextKey::VerificationSourceTrustTitle => "验证来源信任",
            TextKey::RequireSignedChecksumSource => "要求签名的校验和 / 证明来源",
            TextKey::PinnedPublisherKeyLabel => "固定的 Ed25519 发布者公钥：",
            TextKey::ImportPublicKey => "导入公钥",
            TextKey::NormalizeKey => "规范化密钥",
            TextKey::ClearKey => "清除密钥",
            TextKey::HistoryPathLabel => "历史 / 证据路径：",
            TextKey::DefaultButton => "默认",
            TextKey::Stage1Title => "自更新阶段 1",
            TextKey::CheckLatestCandidateButton => "检查最新自更新候选",
            TextKey::Stage2Title => "自更新阶段 2",
            TextKey::StageLatestCandidateButton => "暂存最新候选（不安装）",
            TextKey::PrepareHelperBundleButton => "准备受控 helper bundle（不安装）",
            TextKey::DownloadButton => "⬇ 下载",
            TextKey::PauseButton => "⏸ 暂停",
            TextKey::ResumeButton => "▶ 继续",
            TextKey::CancelButton => "❌ 取消",
            TextKey::ProgressWaitingForBytes => "正在连接…等待首批数据",
            TextKey::ProgressUnknownSize => "大小未知",
            TextKey::StatusReady => "就绪",
            TextKey::StatusEnterUrlFirst => "请先输入 URL",
            TextKey::StatusTestingMirrors => "正在测试镜像…",
            TextKey::StatusDirectNoMirror => "直连（无镜像）",
            TextKey::StatusResolvingReleaseAssets => "下载前正在解析 release 资源…",
            TextKey::StatusDownloadAlreadyInProgress => "下载已在进行中",
            TextKey::StatusReleaseAssetLookupRunning => "release 资源查找仍在运行…",
            TextKey::StatusStartingDownloadUnknown => "正在连接…等待首批数据；验证将是 UNKNOWN",
            TextKey::StatusDownloadCompleteVerifying => "下载完成；正在验证 SHA256…",
            TextKey::StatusDownloadFailed => "❌ 下载失败",
            TextKey::StatusCancelled => "已取消",
            TextKey::StatusChooseReleaseAssetFirst => "请先选择一个 release 资源",
            TextKey::StatusReleaseAssetsReady => "release 资源选择已就绪",
            TextKey::StatusCheckingCandidate => "正在检查最新自更新候选（不安装）…",
            TextKey::StatusStagingCandidate => "正在暂存最新自更新候选（不安装）…",
            TextKey::StatusPublisherKeyImportRunning => "正在导入发布者公钥…",
            TextKey::StatusNoPublisherKeyAsset => {
                "此 release 中未找到 publisher-key.ed25519.pub 资源"
            }
            TextKey::StatusNoAssetsFound => "此 release 没有可下载资源。",
        },
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProgressInput {
    pub downloaded_bytes: u64,
    pub total_bytes: Option<u64>,
    pub speed_kib_per_second: f64,
    pub elapsed_seconds: f64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProgressProjection {
    pub indeterminate: bool,
    pub fraction: f32,
    pub primary_text: String,
    pub detail_text: String,
}

pub fn project_download_progress(locale: UiLocale, input: ProgressInput) -> ProgressProjection {
    let total_bytes = input.total_bytes.filter(|total| *total > 0);
    let speed_text = format_speed(input.speed_kib_per_second);
    let detail_text = format!("{} · {}", speed_text, format_elapsed(input.elapsed_seconds));

    if input.downloaded_bytes == 0 {
        let size_text = total_bytes
            .map(|total| match locale {
                UiLocale::En => format!("total {} MiB", format_mib(total)),
                UiLocale::Zh => format!("总大小 {} MiB", format_mib(total)),
            })
            .unwrap_or_else(|| text(locale, TextKey::ProgressUnknownSize).to_string());
        return ProgressProjection {
            indeterminate: true,
            fraction: 0.0,
            primary_text: format!(
                "{} · {}",
                text(locale, TextKey::ProgressWaitingForBytes),
                size_text
            ),
            detail_text,
        };
    }

    if let Some(total) = total_bytes {
        let fraction = if total == 0 {
            0.0
        } else {
            (input.downloaded_bytes as f64 / total as f64).clamp(0.0, 1.0) as f32
        };
        ProgressProjection {
            indeterminate: false,
            fraction,
            primary_text: format!(
                "{:.1}% · {} / {} MiB",
                fraction * 100.0,
                format_mib(input.downloaded_bytes),
                format_mib(total)
            ),
            detail_text,
        }
    } else {
        ProgressProjection {
            indeterminate: true,
            fraction: 0.0,
            primary_text: format!(
                "{} MiB · {}",
                format_mib(input.downloaded_bytes),
                text(locale, TextKey::ProgressUnknownSize)
            ),
            detail_text,
        }
    }
}

pub fn format_mib(bytes: u64) -> String {
    format!("{:.1}", bytes as f64 / 1024.0 / 1024.0)
}

pub fn format_speed(speed_kib_per_second: f64) -> String {
    if speed_kib_per_second > 1024.0 {
        format!("{:.1} MB/s", speed_kib_per_second / 1024.0)
    } else if speed_kib_per_second > 1.0 {
        format!("{:.0} KB/s", speed_kib_per_second)
    } else {
        format!("{:.1} B/s", speed_kib_per_second * 1024.0)
    }
}

pub fn format_elapsed(seconds: f64) -> String {
    let total_minutes = seconds / 60.0;
    let remaining_seconds = seconds % 60.0;
    format!("{:02.0}:{:04.1}", total_minutes, remaining_seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locale_toggle_round_trips() {
        assert_eq!(UiLocale::En.toggle(), UiLocale::Zh);
        assert_eq!(UiLocale::Zh.toggle(), UiLocale::En);
    }

    #[test]
    fn layout_policy_classifies_wide_medium_compact() {
        assert_eq!(layout_mode_for_width(0.0), LayoutMode::Compact);
        assert_eq!(layout_mode_for_width(819.9), LayoutMode::Compact);
        assert_eq!(layout_mode_for_width(820.0), LayoutMode::Medium);
        assert_eq!(layout_mode_for_width(1179.9), LayoutMode::Medium);
        assert_eq!(layout_mode_for_width(1180.0), LayoutMode::Wide);
    }

    #[test]
    fn locale_dictionary_covers_all_keys() {
        for &key in ALL_TEXT_KEYS {
            assert!(!text(UiLocale::En, key).trim().is_empty(), "{key:?} en");
            assert!(!text(UiLocale::Zh, key).trim().is_empty(), "{key:?} zh");
        }
    }

    #[test]
    fn progress_projection_known_total_is_determinate() {
        let projection = project_download_progress(
            UiLocale::En,
            ProgressInput {
                downloaded_bytes: 6 * 1024 * 1024,
                total_bytes: Some(24 * 1024 * 1024),
                speed_kib_per_second: 512.0,
                elapsed_seconds: 13.4,
            },
        );

        assert!(!projection.indeterminate);
        assert!((projection.fraction - 0.25).abs() < f32::EPSILON);
        assert_eq!(projection.primary_text, "25.0% · 6.0 / 24.0 MiB");
        assert_eq!(projection.detail_text, "512 KB/s · 00:13.4");
    }

    #[test]
    fn progress_projection_unknown_total_is_indeterminate() {
        let projection = project_download_progress(
            UiLocale::Zh,
            ProgressInput {
                downloaded_bytes: 3 * 1024 * 1024,
                total_bytes: None,
                speed_kib_per_second: 0.5,
                elapsed_seconds: 73.2,
            },
        );

        assert!(projection.indeterminate);
        assert_eq!(projection.fraction, 0.0);
        assert_eq!(projection.primary_text, "3.0 MiB · 大小未知");
        assert_eq!(projection.detail_text, "512.0 B/s · 01:13.2");
    }

    #[test]
    fn progress_projection_waiting_for_first_bytes_avoids_fake_zero_percent() {
        let projection = project_download_progress(
            UiLocale::En,
            ProgressInput {
                downloaded_bytes: 0,
                total_bytes: Some(24 * 1024 * 1024),
                speed_kib_per_second: 0.0,
                elapsed_seconds: 4.2,
            },
        );

        assert!(projection.indeterminate);
        assert_eq!(projection.fraction, 0.0);
        assert!(projection.primary_text.contains("waiting for first bytes"));
        assert!(!projection.primary_text.contains("0.0%"));
        assert!(!projection.primary_text.contains("0.0 /"));
        assert_eq!(projection.detail_text, "0.0 B/s · 00:04.2");
    }

    #[test]
    fn progress_projection_clamps_known_fraction() {
        let projection = project_download_progress(
            UiLocale::En,
            ProgressInput {
                downloaded_bytes: 120,
                total_bytes: Some(100),
                speed_kib_per_second: 1.5,
                elapsed_seconds: 1.0,
            },
        );

        assert_eq!(projection.fraction, 1.0);
        assert_eq!(projection.primary_text, "100.0% · 0.0 / 0.0 MiB");
    }
}
