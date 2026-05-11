use crate::gui_common::{
    import_publisher_key_pin_from_path, render_backend_path_action, status_color,
};
use crate::gui_helpers::{
    build_effective_url, extract_filename, format_speed, history_path_from_setting, latency_color,
    run_speed_test,
};
use crate::gui_mirrors::{normalize_mirror_index, MIRRORS, SPEED_TEST_TIMEOUT_SECS};
use crate::gui_trust_center::{
    format_download_completion_status, format_download_notification_status,
    render_trust_center_snapshot, source_trust_status_summary,
};
use crate::gui_update_candidate::{
    render_update_apply_bundle_preview, render_update_apply_plan_preview,
    render_update_candidate_check, render_update_candidate_stage,
};
use crate::RELEASE_PUBLIC_KEY_ASSET;
use backend_contract::{
    AppliedFileDisposition, DownloadControl, ImportedPublisherKeyPin, MismatchFilePolicy,
    ResolvedRelease, TrustCenterSnapshot, TrustPolicyConfig, UpdateApplyBundleEvidenceRecord,
    UpdateApplyPlanEvidenceRecord, UpdateCandidateCheckReport, UpdateCandidateStageReport,
};
use directories::UserDirs;
use eframe::egui;
use eframe::Storage;
use gh_mirror_gui::backend_contract;
use gh_mirror_gui::backend_contract::{BackendClientSettings, DownloadCompletion};
use gh_mirror_gui::ui_projection::{
    layout_mode_for_width, project_download_progress, text as ui_text, LayoutMode, ProgressInput,
    ProgressProjection, TextKey, UiLocale,
};
use notify_rust::Notification;
use rfd::FileDialog;
use std::path::PathBuf;
#[cfg(windows)]
use std::process::Command;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

type ReleaseLookupMessage = (String, Result<ResolvedRelease, String>);
type PublisherKeyImportMessage = (String, Result<ImportedPublisherKeyPin, String>);
type UpdateCandidateCheckMessage = UpdateCandidateCheckReport;
type UpdateCandidateStageMessage = UpdateCandidateStageReport;
type DownloadResultMessage = Result<DownloadCompletion, String>;

const GOLDEN_MAJOR: f32 = 0.618_034;
const GOLDEN_MINOR: f32 = 1.0 - GOLDEN_MAJOR;
const BODY_TWO_COLUMN_MIN_WIDTH: f32 = 820.0;
const BODY_THREE_COLUMN_MIN_WIDTH: f32 = 1120.0;
const BODY_THREE_COLUMN_SHORT_MIN_WIDTH: f32 = 1040.0;
const BODY_FILL_MIN_HEIGHT: f32 = 430.0;
const RESIZE_HYSTERESIS: f32 = 32.0;
const BODY_SCROLL_ENTER_MAX_HEIGHT: f32 = BODY_FILL_MIN_HEIGHT - RESIZE_HYSTERESIS;
const BODY_SCROLL_EXIT_MIN_HEIGHT: f32 = BODY_FILL_MIN_HEIGHT + RESIZE_HYSTERESIS;
const COMMAND_MEDIUM_MIN_WIDTH: f32 = 820.0;
const COMMAND_WIDE_MIN_WIDTH: f32 = 1180.0;
const RESIZE_CHANGE_EPSILON: f32 = 0.5;
const RESIZE_STABILIZE_WINDOW_MS: u64 = 180;
const RESIZE_REPAINT_FRAME_MS: u64 = 16;
const UI_PRESENTATION_HEARTBEAT_MS: u64 = 16;

fn app_background_color() -> egui::Color32 {
    egui::Color32::from_rgb(241, 244, 249)
}

fn app_chrome_color() -> egui::Color32 {
    egui::Color32::from_rgb(252, 253, 255)
}

fn app_surface_color() -> egui::Color32 {
    egui::Color32::from_rgb(255, 255, 255)
}

fn app_surface_alt_color() -> egui::Color32 {
    egui::Color32::from_rgb(247, 249, 253)
}

fn app_surface_stroke() -> egui::Stroke {
    egui::Stroke::new(1.0, egui::Color32::from_rgb(220, 226, 236))
}

fn app_text_color() -> egui::Color32 {
    egui::Color32::from_rgb(25, 31, 43)
}

fn app_muted_text_color() -> egui::Color32 {
    egui::Color32::from_rgb(93, 103, 120)
}

fn app_accent_color() -> egui::Color32 {
    egui::Color32::from_rgb(43, 100, 231)
}

fn app_accent_soft_color() -> egui::Color32 {
    egui::Color32::from_rgb(235, 242, 255)
}

fn app_accent_stroke() -> egui::Stroke {
    egui::Stroke::new(1.0, egui::Color32::from_rgb(167, 193, 247))
}

fn app_panel_rounding() -> egui::Rounding {
    complete_rounding(12.0)
}

fn app_control_rounding() -> egui::Rounding {
    complete_rounding(8.0)
}

fn app_focus_rounding() -> egui::Rounding {
    complete_rounding(10.0)
}

fn complete_rounding(radius: f32) -> egui::Rounding {
    egui::Rounding {
        nw: radius,
        ne: radius,
        sw: radius,
        se: radius,
    }
}

fn app_surface_shadow() -> egui::Shadow {
    egui::Shadow {
        offset: egui::vec2(0.0, 6.0),
        blur: 18.0,
        spread: -8.0,
        color: egui::Color32::from_black_alpha(22),
    }
}

fn app_clear_color() -> [f32; 4] {
    app_background_color().to_normalized_gamma_f32()
}

fn ui_presentation_heartbeat_duration() -> Duration {
    Duration::from_millis(UI_PRESENTATION_HEARTBEAT_MS)
}

fn chrome_panel_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(app_chrome_color())
        .rounding(app_panel_rounding())
        .inner_margin(egui::Margin::symmetric(10.0, 3.0))
}

fn body_panel_frame() -> egui::Frame {
    egui::Frame::none()
        .fill(app_background_color())
        .rounding(app_panel_rounding())
        .inner_margin(egui::Margin::symmetric(8.0, 6.0))
}

fn rounded_singleline_text_edit(text: &mut String) -> egui::TextEdit<'_> {
    egui::TextEdit::singleline(text).margin(egui::Margin::symmetric(8.0, 4.0))
}

fn add_sized_singleline_text_edit(
    ui: &mut egui::Ui,
    text: &mut String,
    size: [f32; 2],
) -> egui::Response {
    ui.add_sized(size, rounded_singleline_text_edit(text))
}

fn app_combo_box(
    id_salt: impl std::hash::Hash,
    selected_text: impl Into<egui::WidgetText>,
) -> egui::ComboBox {
    egui::ComboBox::from_id_salt(id_salt)
        .selected_text(selected_text)
        .height(220.0)
}

fn add_rounded_checkbox(
    ui: &mut egui::Ui,
    checked: &mut bool,
    text: impl Into<egui::WidgetText>,
) -> egui::Response {
    ui.checkbox(checked, text)
}

fn add_primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label.to_owned())
                .strong()
                .color(egui::Color32::WHITE),
        )
        .fill(app_accent_color())
        .stroke(egui::Stroke::new(1.0, app_accent_color()))
        .rounding(app_control_rounding()),
    )
}

fn add_tonal_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(
            egui::RichText::new(label.to_owned())
                .strong()
                .color(app_accent_color()),
        )
        .fill(app_accent_soft_color())
        .stroke(app_accent_stroke())
        .rounding(app_control_rounding()),
    )
}

fn add_subtle_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(rounded_subtle_button(label))
}

fn rounded_subtle_button(label: &str) -> egui::Button<'_> {
    egui::Button::new(egui::RichText::new(label.to_owned()).color(app_text_color()))
        .fill(app_surface_alt_color())
        .stroke(app_surface_stroke())
        .rounding(app_control_rounding())
}

fn add_enabled_tonal_button(ui: &mut egui::Ui, enabled: bool, label: &str) -> egui::Response {
    ui.add_enabled(
        enabled,
        egui::Button::new(
            egui::RichText::new(label.to_owned())
                .strong()
                .color(app_accent_color()),
        )
        .fill(app_accent_soft_color())
        .stroke(app_accent_stroke())
        .rounding(app_control_rounding()),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ViewportDensity {
    Dense,
    Regular,
    Spacious,
}

impl ViewportDensity {
    fn for_size(size: egui::Vec2) -> Self {
        if !size.x.is_finite() || !size.y.is_finite() || size.x < 900.0 || size.y < 620.0 {
            Self::Dense
        } else if size.x >= 1500.0 && size.y >= 900.0 {
            Self::Spacious
        } else {
            Self::Regular
        }
    }

    fn for_resized_size(current: Self, size: egui::Vec2) -> Self {
        if !size.x.is_finite() || !size.y.is_finite() {
            return current;
        }

        match current {
            Self::Dense => {
                if size.x >= 900.0 + RESIZE_HYSTERESIS && size.y >= 620.0 + RESIZE_HYSTERESIS {
                    Self::Regular
                } else {
                    Self::Dense
                }
            }
            Self::Regular => {
                if size.x < 900.0 - RESIZE_HYSTERESIS || size.y < 620.0 - RESIZE_HYSTERESIS {
                    Self::Dense
                } else if size.x >= 1500.0 + RESIZE_HYSTERESIS
                    && size.y >= 900.0 + RESIZE_HYSTERESIS
                {
                    Self::Spacious
                } else {
                    Self::Regular
                }
            }
            Self::Spacious => {
                if size.x < 1500.0 - RESIZE_HYSTERESIS || size.y < 900.0 - RESIZE_HYSTERESIS {
                    Self::Regular
                } else {
                    Self::Spacious
                }
            }
        }
    }

    const fn is_dense(self) -> bool {
        matches!(self, Self::Dense)
    }

    const fn advanced_default_open(self) -> bool {
        matches!(self, Self::Spacious)
    }

    fn panel_margin(self) -> egui::Margin {
        match self {
            Self::Dense => egui::Margin::symmetric(5.0, 3.0),
            Self::Regular => egui::Margin::symmetric(7.0, 5.0),
            Self::Spacious => egui::Margin::symmetric(8.0, 6.0),
        }
    }

    fn item_spacing(self) -> egui::Vec2 {
        match self {
            Self::Dense => egui::vec2(4.0, 3.0),
            Self::Regular => egui::vec2(6.0, 4.0),
            Self::Spacious => egui::vec2(8.0, 5.0),
        }
    }

    fn button_padding(self) -> egui::Vec2 {
        match self {
            Self::Dense => egui::vec2(6.0, 3.0),
            Self::Regular => egui::vec2(8.0, 4.0),
            Self::Spacious => egui::vec2(9.0, 4.0),
        }
    }

    const fn command_gap(self) -> f32 {
        match self {
            Self::Dense => 4.0,
            Self::Regular => 6.0,
            Self::Spacious => 8.0,
        }
    }

    const fn body_gap(self) -> f32 {
        match self {
            Self::Dense => 4.0,
            Self::Regular => 6.0,
            Self::Spacious => 8.0,
        }
    }

    const fn card_gap(self) -> f32 {
        match self {
            Self::Dense => 0.0,
            Self::Regular => 1.0,
            Self::Spacious => 2.0,
        }
    }

    const fn input_height(self) -> f32 {
        match self {
            Self::Dense => 22.0,
            Self::Regular => 24.0,
            Self::Spacious => 26.0,
        }
    }

    const fn progress_height(self) -> f32 {
        match self {
            Self::Dense => 16.0,
            Self::Regular => 18.0,
            Self::Spacious => 20.0,
        }
    }

    const fn top_bar_height(self) -> f32 {
        match self {
            Self::Dense => 30.0,
            Self::Regular => 32.0,
            Self::Spacious => 34.0,
        }
    }

    const fn command_panel_height(self, layout_mode: LayoutMode) -> f32 {
        match (self, layout_mode) {
            (Self::Dense, LayoutMode::Compact) => 174.0,
            (Self::Regular, LayoutMode::Compact) => 184.0,
            (Self::Spacious, LayoutMode::Compact) => 192.0,
            (Self::Dense, LayoutMode::Medium | LayoutMode::Wide) => 110.0,
            (Self::Regular, LayoutMode::Medium | LayoutMode::Wide) => 118.0,
            (Self::Spacious, LayoutMode::Medium | LayoutMode::Wide) => 126.0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyLayout {
    Single,
    GoldenTwo,
    GoldenThree,
}

fn body_layout_for_viewport(total_width: f32, body_height: f32) -> BodyLayout {
    if total_width < BODY_TWO_COLUMN_MIN_WIDTH {
        BodyLayout::Single
    } else if total_width >= BODY_THREE_COLUMN_MIN_WIDTH
        || (body_height < 620.0 && total_width >= BODY_THREE_COLUMN_SHORT_MIN_WIDTH)
    {
        BodyLayout::GoldenThree
    } else {
        BodyLayout::GoldenTwo
    }
}

fn body_layout_for_resized_viewport(
    current: BodyLayout,
    total_width: f32,
    body_height: f32,
) -> BodyLayout {
    if !total_width.is_finite() || !body_height.is_finite() {
        return current;
    }

    match current {
        BodyLayout::Single => {
            if total_width >= BODY_TWO_COLUMN_MIN_WIDTH + RESIZE_HYSTERESIS {
                body_layout_for_viewport(total_width, body_height)
            } else {
                BodyLayout::Single
            }
        }
        BodyLayout::GoldenTwo => {
            if total_width < BODY_TWO_COLUMN_MIN_WIDTH - RESIZE_HYSTERESIS {
                BodyLayout::Single
            } else if total_width >= BODY_THREE_COLUMN_MIN_WIDTH + RESIZE_HYSTERESIS
                || (body_height < 620.0 - RESIZE_HYSTERESIS
                    && total_width >= BODY_THREE_COLUMN_SHORT_MIN_WIDTH + RESIZE_HYSTERESIS)
            {
                BodyLayout::GoldenThree
            } else {
                BodyLayout::GoldenTwo
            }
        }
        BodyLayout::GoldenThree => {
            if total_width < BODY_TWO_COLUMN_MIN_WIDTH - RESIZE_HYSTERESIS {
                BodyLayout::Single
            } else if total_width < BODY_THREE_COLUMN_MIN_WIDTH - RESIZE_HYSTERESIS
                && !(body_height < 620.0 + RESIZE_HYSTERESIS
                    && total_width >= BODY_THREE_COLUMN_SHORT_MIN_WIDTH - RESIZE_HYSTERESIS)
            {
                BodyLayout::GoldenTwo
            } else {
                BodyLayout::GoldenThree
            }
        }
    }
}

fn layout_mode_for_resized_width(current: LayoutMode, width: f32) -> LayoutMode {
    if !width.is_finite() {
        return current;
    }

    match current {
        LayoutMode::Compact => {
            if width >= COMMAND_MEDIUM_MIN_WIDTH + RESIZE_HYSTERESIS {
                layout_mode_for_width(width)
            } else {
                LayoutMode::Compact
            }
        }
        LayoutMode::Medium => {
            if width < COMMAND_MEDIUM_MIN_WIDTH - RESIZE_HYSTERESIS {
                LayoutMode::Compact
            } else if width >= COMMAND_WIDE_MIN_WIDTH + RESIZE_HYSTERESIS {
                LayoutMode::Wide
            } else {
                LayoutMode::Medium
            }
        }
        LayoutMode::Wide => {
            if width < COMMAND_WIDE_MIN_WIDTH - RESIZE_HYSTERESIS {
                layout_mode_for_width(width)
            } else {
                LayoutMode::Wide
            }
        }
    }
}

fn viewport_size_changed_enough(previous: egui::Vec2, next: egui::Vec2) -> bool {
    (previous.x - next.x).abs() > RESIZE_CHANGE_EPSILON
        || (previous.y - next.y).abs() > RESIZE_CHANGE_EPSILON
}

fn golden_two_column_widths(total_width: f32, gap: f32) -> (f32, f32) {
    let usable_width = (total_width - gap).max(0.0);
    let major_width = usable_width * GOLDEN_MAJOR;
    (major_width, (usable_width - major_width).max(0.0))
}

fn golden_three_column_widths(total_width: f32, gap: f32) -> (f32, f32, f32) {
    let usable_width = (total_width - gap * 2.0).max(0.0);
    let primary_weight = 1.0;
    let policy_weight = GOLDEN_MAJOR;
    let update_weight = GOLDEN_MINOR;
    let total_weight = primary_weight + policy_weight + update_weight;
    let primary_width = usable_width * primary_weight / total_weight;
    let policy_width = primary_width * GOLDEN_MAJOR;
    let update_width = (usable_width - primary_width - policy_width).max(0.0);

    (primary_width, policy_width, update_width)
}

fn body_fill_height(total_height: f32) -> Option<f32> {
    if total_height.is_finite() && total_height >= BODY_FILL_MIN_HEIGHT {
        Some(total_height)
    } else {
        None
    }
}

#[cfg(test)]
fn body_scroll_fallback_for_viewport(total_width: f32, body_height: f32) -> bool {
    body_fill_height(body_height).is_none()
        || matches!(
            body_layout_for_viewport(total_width, body_height),
            BodyLayout::Single
        )
}

fn body_scroll_fallback_for_resized_viewport(
    current: bool,
    layout: BodyLayout,
    body_height: f32,
) -> bool {
    if matches!(layout, BodyLayout::Single) {
        return true;
    }

    if current {
        body_height < BODY_SCROLL_EXIT_MIN_HEIGHT
    } else {
        body_height < BODY_SCROLL_ENTER_MAX_HEIGHT
    }
}

fn weighted_stack_heights(total_height: f32, gap: f32, weights: &[f32]) -> Vec<f32> {
    if weights.is_empty() {
        return Vec::new();
    }

    let usable_height = (total_height - gap * weights.len().saturating_sub(1) as f32).max(0.0);
    let total_weight = weights
        .iter()
        .copied()
        .filter(|weight| *weight > 0.0)
        .sum::<f32>();
    if total_weight <= f32::EPSILON {
        return vec![0.0; weights.len()];
    }

    weights
        .iter()
        .map(|weight| usable_height * weight.max(0.0) / total_weight)
        .collect()
}

fn golden_stack_heights(total_height: f32, gap: f32, count: usize) -> Vec<f32> {
    if count == 0 {
        return Vec::new();
    }

    let mut weights = Vec::with_capacity(count);
    let mut weight = 1.0;
    for _ in 0..count {
        weights.push(weight);
        weight *= GOLDEN_MAJOR;
    }

    weighted_stack_heights(total_height, gap, &weights)
}

fn primary_column_height_weights(has_release_picker: bool, has_last_download: bool) -> Vec<f32> {
    let mut weights =
        Vec::with_capacity(2 + usize::from(has_release_picker) + usize::from(has_last_download));
    weights.push(GOLDEN_MINOR);
    if has_release_picker {
        weights.push(1.0);
    }
    weights.push(if has_release_picker {
        GOLDEN_MAJOR
    } else {
        1.0
    });
    if has_last_download {
        weights.push(GOLDEN_MAJOR);
    }
    weights
}

fn height_at(heights: &[f32], index: &mut usize) -> Option<f32> {
    let value = heights.get(*index).copied();
    *index += 1;
    value
}

pub(crate) fn configure_egui_context(ctx: &egui::Context) {
    configure_system_fonts(ctx);
    configure_comfortable_app_style(ctx);
}

fn configure_system_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    if let Some(font_bytes) = read_first_existing_font(&[
        r"C:\Windows\Fonts\segoeui.ttf",
        r"C:\Windows\Fonts\SegoeUI.ttf",
    ]) {
        let name = "windows_segoe_ui".to_string();
        fonts.font_data.insert(
            name.clone(),
            Arc::new(egui::FontData::from_owned(font_bytes)),
        );
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            family.insert(0, name);
        }
    }

    if let Some(font_bytes) = read_first_existing_font(&[
        r"C:\Windows\Fonts\msyh.ttc",
        r"C:\Windows\Fonts\msyh.ttf",
        r"C:\Windows\Fonts\simhei.ttf",
        r"C:\Windows\Fonts\simsun.ttc",
    ]) {
        let name = "windows_cjk_fallback".to_string();
        fonts.font_data.insert(
            name.clone(),
            Arc::new(egui::FontData::from_owned(font_bytes)),
        );
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
            family.push(name.clone());
        }
        if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
            family.push(name);
        }
    }

    ctx.set_fonts(fonts);
}

fn read_first_existing_font(candidates: &[&str]) -> Option<Vec<u8>> {
    candidates.iter().find_map(|path| std::fs::read(path).ok())
}

fn configure_comfortable_app_style(ctx: &egui::Context) {
    ctx.style_mut(|style| {
        style.visuals = egui::Visuals::light();
        style.visuals.override_text_color = Some(app_text_color());
        style.visuals.panel_fill = app_background_color();
        style.visuals.window_fill = app_surface_color();
        style.visuals.extreme_bg_color = egui::Color32::from_rgb(255, 255, 255);
        style.visuals.faint_bg_color = app_surface_alt_color();
        style.visuals.collapsing_header_frame = true;
        style.visuals.window_rounding = app_panel_rounding();
        style.visuals.menu_rounding = app_control_rounding();
        style.visuals.window_shadow = app_surface_shadow();
        style.visuals.popup_shadow = app_surface_shadow();
        style.visuals.widgets.noninteractive.bg_fill = app_surface_color();
        style.visuals.widgets.noninteractive.weak_bg_fill = app_surface_color();
        style.visuals.widgets.noninteractive.bg_stroke = app_surface_stroke();
        style.visuals.widgets.noninteractive.rounding = app_panel_rounding();
        style.visuals.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, app_text_color());
        style.visuals.widgets.inactive.bg_fill = egui::Color32::from_rgb(242, 245, 249);
        style.visuals.widgets.inactive.weak_bg_fill = app_surface_alt_color();
        style.visuals.widgets.inactive.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(211, 219, 231));
        style.visuals.widgets.inactive.rounding = app_control_rounding();
        style.visuals.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, app_text_color());
        style.visuals.widgets.hovered.bg_fill = app_accent_soft_color();
        style.visuals.widgets.hovered.weak_bg_fill = egui::Color32::from_rgb(241, 246, 255);
        style.visuals.widgets.hovered.bg_stroke = app_accent_stroke();
        style.visuals.widgets.hovered.rounding = app_control_rounding();
        style.visuals.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, app_text_color());
        style.visuals.widgets.active.bg_fill = egui::Color32::from_rgb(219, 232, 255);
        style.visuals.widgets.active.bg_stroke =
            egui::Stroke::new(1.0, egui::Color32::from_rgb(130, 169, 242));
        style.visuals.widgets.active.rounding = app_control_rounding();
        style.visuals.widgets.active.fg_stroke = egui::Stroke::new(2.0, app_text_color());
        style.visuals.widgets.open.bg_fill = app_surface_color();
        style.visuals.widgets.open.bg_stroke = app_accent_stroke();
        style.visuals.widgets.open.rounding = app_control_rounding();
        style.visuals.widgets.open.fg_stroke = egui::Stroke::new(1.0, app_text_color());
        style.visuals.hyperlink_color = app_accent_color();
        style.visuals.selection.bg_fill = egui::Color32::from_rgb(210, 229, 255);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, app_accent_color());
        style.text_styles.insert(
            egui::TextStyle::Heading,
            egui::FontId::new(18.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Body,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            egui::FontId::new(14.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Small,
            egui::FontId::new(12.0, egui::FontFamily::Proportional),
        );
        style.text_styles.insert(
            egui::TextStyle::Monospace,
            egui::FontId::new(13.0, egui::FontFamily::Monospace),
        );
        style.spacing.item_spacing = egui::vec2(6.0, 4.0);
        style.spacing.button_padding = egui::vec2(8.0, 4.0);
        style.spacing.indent = 12.0;
        style.spacing.window_margin = egui::Margin::symmetric(8.0, 6.0);
    });
}

fn backend_notice_color(level: backend_contract::BackendStatusNoticeLevel) -> egui::Color32 {
    match level {
        backend_contract::BackendStatusNoticeLevel::Good => egui::Color32::from_rgb(0, 180, 0),
        backend_contract::BackendStatusNoticeLevel::Warning => egui::Color32::from_rgb(220, 160, 0),
        backend_contract::BackendStatusNoticeLevel::Error => egui::Color32::from_rgb(220, 70, 70),
    }
}

fn release_lookup_non_picker_status(input: &str, intent: backend_contract::IntentDTO) -> String {
    match intent {
        backend_contract::IntentDTO::DirectDownload {
            human_readable_label,
            ..
        } => {
            let mut message = format!(
                "ℹ Direct GitHub download detected ({human_readable_label}). Click Download to download this URL; Find release assets only works with repo/release pages."
            );
            if let Some(release_url) = release_picker_url_from_archive_input(input) {
                message.push_str(&format!(
                    " To pick release assets for this tag, use {release_url}."
                ));
            }
            message
        }
        backend_contract::IntentDTO::Unsupported { reason, .. } => format!("❌ {reason}"),
        backend_contract::IntentDTO::NeedsAssetPick { .. } => {
            "Release asset picker input is ready".to_string()
        }
    }
}

fn release_picker_url_from_archive_input(input: &str) -> Option<String> {
    let normalized = if input.starts_with("https://") || input.starts_with("http://") {
        input.to_string()
    } else if input.starts_with("github.com/") || input.starts_with("www.github.com/") {
        format!("https://{input}")
    } else {
        return None;
    };
    let url = reqwest::Url::parse(&normalized).ok()?;
    let host = url.host_str()?.trim_start_matches("www.");
    if host != "github.com" {
        return None;
    }
    let segments = url
        .path_segments()?
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    let [owner, repo, archive, refs, tags, tag_parts @ ..] = segments.as_slice() else {
        return None;
    };
    if *archive != "archive" || *refs != "refs" || *tags != "tags" || tag_parts.is_empty() {
        return None;
    }
    let tag = tag_parts.join("/");
    let tag = tag
        .strip_suffix(".tar.gz")
        .or_else(|| tag.strip_suffix(".tar.bz2"))
        .or_else(|| tag.strip_suffix(".zip"))
        .unwrap_or(&tag);
    if tag.is_empty() {
        return None;
    }
    Some(format!(
        "https://github.com/{owner}/{repo}/releases/tag/{tag}"
    ))
}

fn default_proxy_from_environment_or_system() -> Option<String> {
    for name in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
        if let Ok(value) = std::env::var(name) {
            if let Some(proxy) = normalize_proxy_url(&value, "http") {
                return Some(proxy);
            }
        }
    }
    detect_windows_user_proxy_url()
}

#[cfg(windows)]
fn detect_windows_user_proxy_url() -> Option<String> {
    let key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";
    let enabled_output = Command::new("reg")
        .args(["query", key, "/v", "ProxyEnable"])
        .output()
        .ok()?;
    if !enabled_output.status.success() {
        return None;
    }
    let enabled_stdout = String::from_utf8_lossy(&enabled_output.stdout);
    if !reg_dword_enabled(&reg_query_value(&enabled_stdout, "ProxyEnable")?) {
        return None;
    }

    let server_output = Command::new("reg")
        .args(["query", key, "/v", "ProxyServer"])
        .output()
        .ok()?;
    if !server_output.status.success() {
        return None;
    }
    let server_stdout = String::from_utf8_lossy(&server_output.stdout);
    proxy_url_from_windows_proxy_server(&reg_query_value(&server_stdout, "ProxyServer")?)
}

#[cfg(not(windows))]
fn detect_windows_user_proxy_url() -> Option<String> {
    None
}

fn reg_query_value(stdout: &str, name: &str) -> Option<String> {
    stdout.lines().find_map(|line| {
        let trimmed = line.trim();
        if !trimmed.starts_with(name) {
            return None;
        }
        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 3 {
            return None;
        }
        Some(parts[2..].join(" "))
    })
}

fn reg_dword_enabled(value: &str) -> bool {
    let value = value.trim();
    value.eq_ignore_ascii_case("0x1") || value == "1"
}

fn proxy_url_from_windows_proxy_server(value: &str) -> Option<String> {
    let entries = value.split(';').filter_map(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }
        if let Some((kind, address)) = entry.split_once('=') {
            Some((kind.trim().to_ascii_lowercase(), address.trim()))
        } else {
            Some(("http".to_string(), entry))
        }
    });

    let mut fallback = None;
    let mut http = None;
    let mut https = None;
    let mut socks = None;
    for (kind, address) in entries {
        match kind.as_str() {
            "https" => https = normalize_proxy_url(address, "http"),
            "http" => http = normalize_proxy_url(address, "http"),
            "socks" | "socks5" => socks = normalize_proxy_url(address, "socks5"),
            _ if fallback.is_none() => fallback = normalize_proxy_url(address, "http"),
            _ => {}
        }
    }

    https.or(http).or(socks).or(fallback)
}

fn normalize_proxy_url(value: &str, default_scheme: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if value.contains("://") {
        Some(value.to_string())
    } else {
        Some(format!("{default_scheme}://{value}"))
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct SavedState {
    pub(crate) selected_mirror: usize,
    pub(crate) save_dir: String,
    pub(crate) proxy: String,
    #[serde(default)]
    pub(crate) locale: UiLocale,
    #[serde(default)]
    pub(crate) allow_invalid_certs: bool,
    #[serde(default = "default_unknown_keep_file")]
    pub(crate) trust_unknown_keep_file: bool,
    #[serde(default)]
    pub(crate) trust_unknown_allow_open: bool,
    #[serde(default)]
    pub(crate) trust_mismatch_file_policy: MismatchFilePolicy,
    #[serde(default)]
    pub(crate) source_trust_require_signed: bool,
    #[serde(default)]
    pub(crate) source_trust_publisher_key: String,
    #[serde(default)]
    pub(crate) source_trust_publisher_key_source: String,
    #[serde(default)]
    pub(crate) history_path: String,
}

fn default_unknown_keep_file() -> bool {
    true
}

pub(crate) struct GhMirrorGui {
    url: String,
    last_viewport_size: egui::Vec2,
    viewport_density: ViewportDensity,
    applied_density: Option<ViewportDensity>,
    command_layout_mode: LayoutMode,
    body_layout: BodyLayout,
    body_scroll_fallback: bool,
    resize_stabilize_until: Option<Instant>,
    save_dir: PathBuf,
    proxy: String,
    locale: UiLocale,
    allow_invalid_certs: bool,
    trust_policy: TrustPolicyConfig,
    publisher_key_source: String,
    history_path: String,
    status: String,
    progress: f32,
    downloaded_bytes: u64,
    download_total_bytes: Option<u64>,
    download_speed_kib_per_second: f64,
    download_elapsed_seconds: f64,
    download_started_at: Option<Instant>,
    speed_text: String,
    elapsed_text: String,
    download_thread: Option<thread::JoinHandle<()>>,
    control: Option<Arc<DownloadControl>>,
    progress_rx: Option<mpsc::Receiver<(u64, u64, f64, f64)>>,
    download_result_rx: Option<mpsc::Receiver<DownloadResultMessage>>,
    // Mirror-related fields
    mirrors: Vec<String>,     // human-readable names
    mirror_urls: Vec<String>, // actual URL prefixes
    selected_mirror: usize,   // index
    speed_test_status: String,
    speed_test_thread: Option<thread::JoinHandle<()>>,
    speed_test_rx: Option<mpsc::Receiver<usize>>,
    speed_test_progress_rx: Option<mpsc::Receiver<(usize, Option<Duration>)>>,
    speed_test_results: Vec<Option<Duration>>,
    speed_test_completed: usize, // how many mirrors have been tested
    // GitHub release discovery
    release_status: String,
    release: Option<ResolvedRelease>,
    selected_release_asset: Option<usize>,
    release_lookup_thread: Option<thread::JoinHandle<()>>,
    release_lookup_rx: Option<mpsc::Receiver<ReleaseLookupMessage>>,
    release_lookup_input: Option<String>,
    publisher_key_import_thread: Option<thread::JoinHandle<()>>,
    publisher_key_import_rx: Option<mpsc::Receiver<PublisherKeyImportMessage>>,
    publisher_key_import_asset_url: Option<String>,
    publisher_key_import_source_label: Option<String>,
    update_candidate_status: String,
    update_candidate_report: Option<UpdateCandidateCheckReport>,
    update_candidate_thread: Option<thread::JoinHandle<()>>,
    update_candidate_rx: Option<mpsc::Receiver<UpdateCandidateCheckMessage>>,
    update_stage_status: String,
    update_stage_report: Option<UpdateCandidateStageReport>,
    update_stage_thread: Option<thread::JoinHandle<()>>,
    update_stage_rx: Option<mpsc::Receiver<UpdateCandidateStageMessage>>,
    update_apply_plan_evidence_record: Option<UpdateApplyPlanEvidenceRecord>,
    update_apply_bundle_evidence_record: Option<UpdateApplyBundleEvidenceRecord>,
    update_apply_bundle_status: String,
    // Persisted state
    download_complete_notified: bool,
    last_download_path: Option<PathBuf>,
    last_trust_center_snapshot: Option<TrustCenterSnapshot>,
    last_verification_evidence_path: Option<PathBuf>,
    last_file_disposition: Option<AppliedFileDisposition>,
}

impl GhMirrorGui {
    pub(crate) fn new(storage: Option<&dyn Storage>) -> Self {
        let names: Vec<String> = MIRRORS.iter().map(|(name, _)| name.to_string()).collect();
        let urls: Vec<String> = MIRRORS.iter().map(|(_, url)| url.to_string()).collect();

        // Load persisted state
        let mut selected_mirror = 0usize;
        let mut save_dir = UserDirs::new()
            .and_then(|d| d.download_dir().map(|p| p.to_string_lossy().to_string()))
            .unwrap_or_else(|| ".".to_string());
        let mut proxy = String::new();
        let mut locale = UiLocale::default();
        let mut allow_invalid_certs = false;
        let mut trust_policy = TrustPolicyConfig::default();
        let mut publisher_key_source = String::new();
        let mut history_path = String::new();
        if let Some(storage) = storage {
            if let Some(json) = storage.get_string("app_settings") {
                if let Ok(state) = serde_json::from_str::<SavedState>(&json) {
                    selected_mirror = state.selected_mirror;
                    if !state.save_dir.is_empty() {
                        save_dir = state.save_dir;
                    }
                    proxy = state.proxy;
                    locale = state.locale;
                    allow_invalid_certs = state.allow_invalid_certs;
                    trust_policy = backend_contract::trust_policy_from_settings(
                        state.trust_unknown_keep_file,
                        state.trust_unknown_allow_open,
                        state.trust_mismatch_file_policy,
                        state.source_trust_require_signed,
                        state.source_trust_publisher_key,
                    );
                    publisher_key_source = state.source_trust_publisher_key_source;
                    history_path = state.history_path;
                }
            }
        }

        // Persisted states from older versions might point to a mirror index that no longer exists.
        // Prefer resetting to "Direct (no mirror)" instead of crashing (index out of range).
        selected_mirror = normalize_mirror_index(selected_mirror);
        let detected_proxy = if proxy.trim().is_empty() {
            default_proxy_from_environment_or_system()
        } else {
            None
        };
        if let Some(default_proxy) = detected_proxy.as_ref() {
            proxy = default_proxy.clone();
        }
        let status = detected_proxy
            .as_ref()
            .map(|proxy| {
                format!(
                    "{} (system proxy detected: {proxy})",
                    ui_text(locale, TextKey::StatusReady)
                )
            })
            .unwrap_or_else(|| ui_text(locale, TextKey::StatusReady).to_string());

        let (
            speed_test_status,
            speed_test_thread,
            speed_test_rx,
            speed_test_progress_rx,
            speed_test_results,
            speed_test_completed,
        ) = if MIRRORS.len() <= 1 {
            (
                ui_text(locale, TextKey::StatusDirectNoMirror).to_string(),
                None,
                None,
                None,
                vec![None; MIRRORS.len()],
                MIRRORS.len(),
            )
        } else {
            let (final_tx, final_rx) = mpsc::channel();
            let (progress_tx, progress_rx) = mpsc::channel();
            let test_urls = urls.clone();
            let handle = thread::spawn(move || {
                let best = run_speed_test(&test_urls, SPEED_TEST_TIMEOUT_SECS, &progress_tx);
                let _ = final_tx.send(best);
            });

            (
                ui_text(locale, TextKey::StatusTestingMirrors).to_string(),
                Some(handle),
                Some(final_rx),
                Some(progress_rx),
                vec![None; MIRRORS.len()],
                0,
            )
        };

        Self {
            url: String::new(),
            last_viewport_size: egui::vec2(1366.0, 860.0),
            viewport_density: ViewportDensity::for_size(egui::vec2(1366.0, 860.0)),
            applied_density: None,
            command_layout_mode: layout_mode_for_width(1366.0),
            body_layout: BodyLayout::GoldenThree,
            body_scroll_fallback: false,
            resize_stabilize_until: None,
            save_dir: PathBuf::from(&save_dir),
            proxy,
            locale,
            allow_invalid_certs,
            trust_policy,
            publisher_key_source,
            history_path,
            status,
            progress: 0.0,
            downloaded_bytes: 0,
            download_total_bytes: None,
            download_speed_kib_per_second: 0.0,
            download_elapsed_seconds: 0.0,
            download_started_at: None,
            speed_text: String::new(),
            elapsed_text: String::new(),
            download_thread: None,
            control: None,
            progress_rx: None,
            download_result_rx: None,
            mirrors: names,
            mirror_urls: urls,
            selected_mirror,
            speed_test_status,
            speed_test_thread,
            speed_test_rx,
            speed_test_progress_rx,
            speed_test_results,
            speed_test_completed,
            release_status: String::new(),
            release: None,
            selected_release_asset: None,
            release_lookup_thread: None,
            release_lookup_rx: None,
            release_lookup_input: None,
            publisher_key_import_thread: None,
            publisher_key_import_rx: None,
            publisher_key_import_asset_url: None,
            publisher_key_import_source_label: None,
            update_candidate_status: String::new(),
            update_candidate_report: None,
            update_candidate_thread: None,
            update_candidate_rx: None,
            update_stage_status: String::new(),
            update_stage_report: None,
            update_stage_thread: None,
            update_stage_rx: None,
            update_apply_plan_evidence_record: None,
            update_apply_bundle_evidence_record: None,
            update_apply_bundle_status: String::new(),
            download_complete_notified: false,
            last_download_path: None,
            last_trust_center_snapshot: None,
            last_verification_evidence_path: None,
            last_file_disposition: None,
        }
    }

    fn retest_mirrors(&mut self) {
        if self.speed_test_thread.is_some() {
            return;
        }
        if MIRRORS.len() <= 1 {
            // No mirrors to test. Keep the UI stable and avoid unnecessary network calls.
            self.selected_mirror = 0;
            self.speed_test_status = self.t(TextKey::StatusDirectNoMirror).to_string();
            self.speed_test_thread = None;
            self.speed_test_rx = None;
            self.speed_test_progress_rx = None;
            self.speed_test_results = vec![None; MIRRORS.len()];
            self.speed_test_completed = MIRRORS.len();
            return;
        }
        let (final_tx, final_rx) = mpsc::channel();
        let (progress_tx, progress_rx) = mpsc::channel();
        let test_urls = self.mirror_urls.clone();
        let handle = thread::spawn(move || {
            let best = run_speed_test(&test_urls, SPEED_TEST_TIMEOUT_SECS, &progress_tx);
            let _ = final_tx.send(best);
        });
        self.speed_test_status = self.t(TextKey::StatusTestingMirrors).to_string();
        self.speed_test_thread = Some(handle);
        self.speed_test_rx = Some(final_rx);
        self.speed_test_progress_rx = Some(progress_rx);
        self.speed_test_results = vec![None; MIRRORS.len()];
        self.speed_test_completed = 0;
    }

    fn effective_history_path(&self) -> PathBuf {
        history_path_from_setting(&self.history_path)
    }

    fn t(&self, key: TextKey) -> &'static str {
        ui_text(self.locale, key)
    }

    fn current_density(&self) -> ViewportDensity {
        self.viewport_density
    }

    fn update_viewport_density(&mut self, viewport_size: egui::Vec2) {
        let now = Instant::now();
        let previous_viewport_size = self.last_viewport_size;
        self.last_viewport_size = viewport_size;
        if viewport_size_changed_enough(previous_viewport_size, viewport_size) {
            self.resize_stabilize_until =
                Some(now + Duration::from_millis(RESIZE_STABILIZE_WINDOW_MS));
            return;
        }

        if let Some(until) = self.resize_stabilize_until {
            if now < until {
                return;
            }
            self.resize_stabilize_until = None;
        }

        self.viewport_density =
            ViewportDensity::for_resized_size(self.viewport_density, viewport_size);
        self.command_layout_mode =
            layout_mode_for_resized_width(self.command_layout_mode, viewport_size.x);
    }

    fn apply_adaptive_style(&mut self, ctx: &egui::Context) {
        let density = self.current_density();
        if self.applied_density == Some(density) {
            return;
        }
        ctx.style_mut(|style| {
            style.spacing.item_spacing = density.item_spacing();
            style.spacing.button_padding = density.button_padding();
            style.spacing.window_margin = density.panel_margin();
        });
        self.applied_density = Some(density);
    }

    fn add_card_gap(&self, ui: &mut egui::Ui) {
        ui.add_space(self.current_density().card_gap());
    }

    fn tr(&self, en: &'static str, zh: &'static str) -> &'static str {
        match self.locale {
            UiLocale::En => en,
            UiLocale::Zh => zh,
        }
    }

    fn toggle_locale(&mut self) {
        self.locale = self.locale.toggle();
    }

    fn download_progress_projection(&self) -> Option<ProgressProjection> {
        if self.download_thread.is_none() && self.download_result_rx.is_none() {
            return None;
        }

        Some(project_download_progress(
            self.locale,
            ProgressInput {
                downloaded_bytes: self.downloaded_bytes,
                total_bytes: self.download_total_bytes,
                speed_kib_per_second: self.download_speed_kib_per_second,
                elapsed_seconds: self.download_elapsed_seconds,
            },
        ))
    }

    fn fill_default_proxy_if_blank(&mut self) -> Option<String> {
        if !self.proxy.trim().is_empty() {
            return None;
        }

        let proxy = default_proxy_from_environment_or_system()?;
        self.proxy = proxy.clone();
        Some(proxy)
    }

    fn gallery_panel<R>(
        ui: &mut egui::Ui,
        density: ViewportDensity,
        add_contents: impl FnOnce(&mut egui::Ui) -> R,
    ) -> R {
        egui::Frame::none()
            .fill(app_surface_color())
            .stroke(app_surface_stroke())
            .rounding(app_panel_rounding())
            .shadow(app_surface_shadow())
            .outer_margin(egui::Margin::same(1.0))
            .inner_margin(density.panel_margin())
            .show(ui, add_contents)
            .inner
    }

    fn render_command_panel(&mut self, ui: &mut egui::Ui) {
        let density = self.current_density();
        Self::gallery_panel(ui, density, |ui| {
            ui.set_min_width(ui.available_width());
            ui.set_min_height(ui.available_height());
            let layout_mode = self.command_layout_mode;
            let wide_layout = matches!(layout_mode, LayoutMode::Medium | LayoutMode::Wide);

            if wide_layout {
                let total_width = ui.available_width();
                let gap = density.command_gap();
                let (left_width, right_width) = golden_two_column_widths(total_width, gap);

                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(left_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_command_primary_stack(ui, layout_mode, density);
                        },
                    );
                    ui.add_space(gap);
                    ui.allocate_ui_with_layout(
                        egui::vec2(right_width, 0.0),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_command_hint_content(ui);
                        },
                    );
                });
            } else {
                self.render_command_primary_stack(ui, layout_mode, density);
                ui.separator();
                self.render_command_hint_content(ui);
            }
        });
    }

    fn render_command_primary_stack(
        &mut self,
        ui: &mut egui::Ui,
        layout_mode: LayoutMode,
        density: ViewportDensity,
    ) {
        ui.set_min_width(ui.available_width());

        ui.label(egui::RichText::new(self.t(TextKey::UrlLabel)).strong());
        let url_response = add_sized_singleline_text_edit(
            ui,
            &mut self.url,
            [ui.available_width(), density.input_height()],
        );
        if url_response.changed() {
            self.clear_release_lookup_result();
        }
        if url_response.lost_focus()
            && ui.input(|i| i.key_pressed(egui::Key::Enter))
            && matches!(
                backend_contract::resolve_download_intent(&self.url),
                backend_contract::IntentDTO::NeedsAssetPick { .. }
            )
        {
            self.start_release_lookup();
        }

        let button_layout = match layout_mode {
            LayoutMode::Compact => egui::Layout::top_down(egui::Align::Min),
            LayoutMode::Medium | LayoutMode::Wide => {
                egui::Layout::left_to_right(egui::Align::Center)
            }
        };

        ui.with_layout(button_layout, |ui| {
            let paste_label = self.t(TextKey::PasteButton);
            let clear_label = self.t(TextKey::ClearButton);
            let find_assets_label = self.t(TextKey::FindReleaseAssetsButton);
            if add_subtle_button(ui, paste_label).clicked() {
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    if let Ok(text) = clipboard.get_text() {
                        self.url = text;
                        self.clear_release_lookup_result();
                        if matches!(
                            backend_contract::resolve_download_intent(&self.url),
                            backend_contract::IntentDTO::NeedsAssetPick { .. }
                        ) {
                            self.start_release_lookup();
                        }
                    }
                }
            }
            if add_subtle_button(ui, clear_label).clicked() {
                self.url.clear();
                self.clear_release_lookup_result();
            }
            if add_tonal_button(ui, find_assets_label).clicked() {
                self.start_release_lookup();
            }
            if self.release_lookup_thread.is_some() {
                ui.label(format!(
                    "⏳ {}",
                    self.t(TextKey::StatusResolvingReleaseAssets)
                ));
            } else if !self.release_status.is_empty() {
                ui.label(egui::RichText::new(&self.release_status).strong());
            }
        });

        ui.separator();

        ui.horizontal_wrapped(|ui| {
            if add_primary_button(ui, self.t(TextKey::DownloadButton)).clicked() {
                self.start_download();
            }
            if let Some(ctrl) = &self.control {
                if ctrl.is_paused() {
                    if add_subtle_button(ui, self.t(TextKey::ResumeButton)).clicked() {
                        ctrl.resume();
                    }
                } else if add_subtle_button(ui, self.t(TextKey::PauseButton)).clicked() {
                    ctrl.pause();
                }
                if add_subtle_button(ui, self.t(TextKey::CancelButton)).clicked() {
                    ctrl.cancel();
                    self.download_thread = None;
                    self.control = None;
                    self.download_started_at = None;
                    self.status = self.t(TextKey::StatusCancelled).to_string();
                }
            }
        });

        self.render_download_progress(ui, density);
    }

    fn render_download_progress(&self, ui: &mut egui::Ui, density: ViewportDensity) {
        let Some(progress) = self.download_progress_projection() else {
            return;
        };

        if progress.indeterminate {
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Spinner::new());
                ui.label(egui::RichText::new(progress.primary_text.clone()).strong());
            });
        } else {
            ui.add_sized(
                [ui.available_width(), density.progress_height()],
                egui::ProgressBar::new(progress.fraction)
                    .text(progress.primary_text.clone())
                    .rounding(app_focus_rounding()),
            );
        }
        ui.small(progress.detail_text);
    }

    fn render_command_hint_content(&mut self, ui: &mut egui::Ui) {
        let url_is_empty = self.url.trim().is_empty();
        ui.vertical(|ui| {
            ui.set_min_width(ui.available_width());
            ui.label(
                egui::RichText::new(if url_is_empty {
                    self.t(TextKey::StatusEnterUrlFirst)
                } else {
                    self.t(TextKey::StatusReady)
                })
                .strong(),
            );

            if url_is_empty {
                ui.small(self.t(TextKey::ReleasePickerHint));
            } else if !self.release_status.is_empty() {
                ui.small(&self.release_status);
            } else {
                ui.small(self.t(TextKey::ReleasePickerHint));
            }

            if !self.status.is_empty() && self.status != self.release_status {
                ui.label(&self.status);
            }

            ui.add_space(2.0);
            egui::Grid::new("command_summary_grid")
                .num_columns(2)
                .spacing(egui::vec2(10.0, 3.0))
                .striped(false)
                .show(ui, |ui| {
                    ui.label(self.t(TextKey::SaveToLabel));
                    ui.monospace(self.save_dir.display().to_string());
                    ui.end_row();

                    ui.label(self.t(TextKey::ProxyLabel));
                    ui.label(if self.proxy.trim().is_empty() {
                        "auto-detect on action start"
                    } else {
                        &self.proxy
                    });
                    ui.end_row();

                    ui.label("TLS");
                    ui.label(if self.allow_invalid_certs {
                        "unsafe debugging mode"
                    } else {
                        "strict verification"
                    });
                    ui.end_row();
                });
        });
    }

    fn render_body(&mut self, ui: &mut egui::Ui) {
        let density = self.current_density();
        let body_height = ui.available_height();
        let total_width = ui.available_width();
        if self.resize_stabilize_until.is_none() {
            let layout =
                body_layout_for_resized_viewport(self.body_layout, total_width, body_height);
            self.body_layout = layout;
            self.body_scroll_fallback = body_scroll_fallback_for_resized_viewport(
                self.body_scroll_fallback,
                layout,
                body_height,
            );
        }

        if self.body_scroll_fallback {
            egui::ScrollArea::vertical()
                .id_salt("proof_to_action_main_scroll")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add_space(density.card_gap());
                    let total_width = ui.available_width();
                    self.render_body_layout(ui, self.body_layout, total_width, body_height, None);
                });
        } else {
            ui.add_space(density.card_gap());
            let fill_height = body_fill_height((body_height - density.card_gap()).max(0.0));
            self.render_body_layout(ui, self.body_layout, total_width, body_height, fill_height);
        }
    }

    fn render_body_layout(
        &mut self,
        ui: &mut egui::Ui,
        layout: BodyLayout,
        total_width: f32,
        body_height: f32,
        fill_height: Option<f32>,
    ) {
        let density = self.current_density();
        match layout {
            BodyLayout::Single => {
                self.render_body_primary_column(ui, None);
                self.render_body_secondary_column(ui, None);
            }
            BodyLayout::GoldenThree => {
                let gap = density.body_gap();
                let (primary_width, policy_width, update_width) =
                    golden_three_column_widths(total_width, gap);

                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(primary_width, body_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_body_primary_column(ui, fill_height);
                        },
                    );
                    ui.add_space(gap);
                    ui.allocate_ui_with_layout(
                        egui::vec2(policy_width, body_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_body_policy_column(ui, fill_height);
                        },
                    );
                    ui.add_space(gap);
                    ui.allocate_ui_with_layout(
                        egui::vec2(update_width, body_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_body_update_column(ui, fill_height);
                        },
                    );
                });
            }
            BodyLayout::GoldenTwo => {
                let gap = density.body_gap();
                let (left_width, right_width) = golden_two_column_widths(total_width, gap);

                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(
                        egui::vec2(left_width, body_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_body_primary_column(ui, fill_height);
                        },
                    );
                    ui.add_space(gap);
                    ui.allocate_ui_with_layout(
                        egui::vec2(right_width, body_height),
                        egui::Layout::top_down(egui::Align::Min),
                        |ui| {
                            self.render_body_secondary_column(ui, fill_height);
                        },
                    );
                });
            }
        }
    }

    fn render_body_primary_column(&mut self, ui: &mut egui::Ui, target_height: Option<f32>) {
        let density = self.current_density();
        let weights = primary_column_height_weights(
            self.release.is_some(),
            self.last_trust_center_snapshot.is_some(),
        );
        let heights = target_height
            .map(|height| weighted_stack_heights(height, density.card_gap(), &weights))
            .unwrap_or_default();
        let mut height_index = 0;

        self.render_workspace_summary_card(ui, height_at(&heights, &mut height_index));
        let release_height = self
            .release
            .is_some()
            .then(|| height_at(&heights, &mut height_index))
            .flatten();
        self.render_release_picker_card(ui, release_height);
        self.render_transfer_settings_card(ui, height_at(&heights, &mut height_index));
        let last_download_height = self
            .last_trust_center_snapshot
            .is_some()
            .then(|| height_at(&heights, &mut height_index))
            .flatten();
        self.render_last_download_card(ui, last_download_height);
    }

    fn render_body_secondary_column(&mut self, ui: &mut egui::Ui, target_height: Option<f32>) {
        let density = self.current_density();
        let heights = target_height
            .map(|height| golden_stack_heights(height, density.card_gap(), 2))
            .unwrap_or_default();
        let mut height_index = 0;

        self.render_body_policy_column(ui, height_at(&heights, &mut height_index));
        self.render_body_update_column(ui, height_at(&heights, &mut height_index));
    }

    fn render_body_policy_column(&mut self, ui: &mut egui::Ui, target_height: Option<f32>) {
        self.render_trust_policy_card(ui, target_height);
    }

    fn render_body_update_column(&mut self, ui: &mut egui::Ui, target_height: Option<f32>) {
        self.render_update_card(ui, target_height);
    }

    fn render_workspace_summary_card(&mut self, ui: &mut egui::Ui, min_height: Option<f32>) {
        let density = self.current_density();
        Self::gallery_panel(ui, density, |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(min_height) = min_height {
                ui.set_min_height(min_height);
            }
            ui.label(egui::RichText::new(self.tr("Workspace", "工作区")).strong());

            let intent_summary = if self.url.trim().is_empty() {
                self.tr("Waiting for URL", "等待 URL").to_string()
            } else {
                match backend_contract::resolve_download_intent(&self.url) {
                    backend_contract::IntentDTO::NeedsAssetPick { .. } => self
                        .tr("Release asset picker", "Release 资源选择")
                        .to_string(),
                    backend_contract::IntentDTO::DirectDownload {
                        human_readable_label,
                        ..
                    } => format!("{} · {human_readable_label}", self.tr("Direct", "直连")),
                    backend_contract::IntentDTO::Unsupported { reason, .. } => {
                        format!("{} · {reason}", self.tr("Unsupported", "不支持"))
                    }
                }
            };

            let download_summary = if let Some(progress) = self.download_progress_projection() {
                progress.primary_text
            } else if self.last_download_path.is_some() {
                self.tr("Last download evidence is available", "已有上次下载证据")
                    .to_string()
            } else {
                self.tr("Idle", "空闲").to_string()
            };

            let evidence_summary = self
                .last_trust_center_snapshot
                .as_ref()
                .map(source_trust_status_summary)
                .unwrap_or_else(|| {
                    self.tr("No completed download yet", "尚无已完成下载")
                        .to_string()
                });

            let policy_summary =
                if backend_contract::source_trust_requires_signed(&self.trust_policy) {
                    self.tr("Signed source required", "要求签名来源")
                } else {
                    self.tr("Hash/provenance evidence accepted", "接受哈希 / 来源证据")
                };

            egui::Grid::new("workspace_summary_grid")
                .num_columns(2)
                .spacing(egui::vec2(8.0, 3.0))
                .striped(false)
                .show(ui, |ui| {
                    ui.label(self.tr("Intent", "意图"));
                    ui.label(intent_summary);
                    ui.end_row();

                    ui.label(self.tr("Download", "下载"));
                    ui.label(download_summary);
                    ui.end_row();

                    ui.label(self.tr("Evidence", "证据"));
                    ui.label(evidence_summary);
                    ui.end_row();

                    ui.label(self.tr("Policy", "策略"));
                    ui.label(policy_summary);
                    ui.end_row();
                });

            if !density.is_dense() {
                ui.separator();
                self.render_decision_chain(ui);
            }
            if min_height.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.small(self.tr(
                        "One workspace, one backend contract, one evidence trail.",
                        "一个工作区，一个后端契约，一条证据链。",
                    ));
                });
            }
        });
        self.add_card_gap(ui);
    }

    fn render_decision_chain(&self, ui: &mut egui::Ui) {
        ui.small(self.tr("Decision flow", "决策流"));
        ui.horizontal_wrapped(|ui| {
            for (idx, label) in [
                self.tr("Source", "来源"),
                self.tr("Intent", "意图"),
                self.tr("Policy", "策略"),
                self.tr("Evidence", "证据"),
                self.tr("Verdict", "裁决"),
                self.tr("Action", "动作"),
            ]
            .iter()
            .enumerate()
            {
                if idx > 0 {
                    ui.small("→");
                }
                ui.label(egui::RichText::new(*label).small().strong());
            }
        });
    }

    fn render_release_picker_card(&mut self, ui: &mut egui::Ui, min_height: Option<f32>) {
        let Some(release) = self.release.clone() else {
            return;
        };

        Self::gallery_panel(ui, self.current_density(), |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(min_height) = min_height {
                ui.set_min_height(min_height);
            }
            let release_name = release
                .name
                .as_ref()
                .filter(|name| !name.trim().is_empty())
                .map(|name| format!(" - {name}"))
                .unwrap_or_default();
            ui.label(format!(
                "{} {}/{} @ {}{}",
                self.t(TextKey::ReleaseLabel),
                release.owner,
                release.repo,
                release.tag_name,
                release_name
            ));

            if let Some(publisher_key_asset) = release
                .assets
                .iter()
                .find(|asset| asset.name == RELEASE_PUBLIC_KEY_ASSET)
            {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!("Publisher key: {}", publisher_key_asset.name));
                    let importing = self.publisher_key_import_thread.is_some();
                    if add_enabled_tonal_button(ui, !importing, "Pin publisher key from release")
                        .clicked()
                    {
                        self.start_import_publisher_key_from_selected_release();
                    }
                    if importing {
                        ui.label("⏳ Importing...");
                    }
                });
            } else {
                ui.small("No publisher-key.ed25519.pub asset detected for one-click pinning.");
            }

            if release.assets.is_empty() {
                ui.label(self.t(TextKey::StatusNoAssetsFound));
            } else {
                if self
                    .selected_release_asset
                    .map(|idx| idx >= release.assets.len())
                    .unwrap_or(true)
                {
                    self.selected_release_asset = Some(0);
                }
                let selected_idx = self.selected_release_asset.unwrap_or(0);
                let selected_text =
                    backend_contract::release_asset_picker_label(&release.assets[selected_idx]);

                ui.horizontal_wrapped(|ui| {
                    ui.label(self.t(TextKey::AssetLabel));
                    app_combo_box("release_asset_select", selected_text).show_ui(ui, |ui| {
                        for (idx, asset) in release.assets.iter().enumerate() {
                            if ui
                                .selectable_label(
                                    self.selected_release_asset == Some(idx),
                                    backend_contract::release_asset_picker_label(asset),
                                )
                                .clicked()
                            {
                                self.selected_release_asset = Some(idx);
                            }
                        }
                    });
                    if add_tonal_button(ui, self.t(TextKey::UseSelectedAssetButton)).clicked() {
                        self.apply_selected_release_asset();
                    }
                    if add_subtle_button(ui, self.t(TextKey::OpenReleaseButton)).clicked() {
                        let _ = open::that(&release.html_url);
                    }
                });

                if let Some(asset) = release.assets.get(selected_idx) {
                    let content_type = asset
                        .content_type
                        .as_deref()
                        .unwrap_or("unknown content type");
                    ui.label(format!(
                        "{} · {}",
                        backend_contract::release_asset_picker_label(asset),
                        content_type
                    ));
                    ui.label(
                        backend_contract::verification_source_summary_for_release_asset(
                            &release,
                            selected_idx,
                        ),
                    );
                    ui.monospace(&asset.browser_download_url);
                }
            }
            if min_height.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.small(self.tr(
                        "Asset choice stays local until Download.",
                        "资源选择保持本地，直到点击下载。",
                    ));
                });
            }
        });
        self.add_card_gap(ui);
    }

    fn render_transfer_settings_card(&mut self, ui: &mut egui::Ui, min_height: Option<f32>) {
        let density = self.current_density();
        Self::gallery_panel(ui, density, |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(min_height) = min_height {
                ui.set_min_height(min_height);
            }

            // Route guardrail: this project is not a mirror-list aggregator.
            // Today we ship "Direct (no mirror)" only. Keep the mirror UX hidden unless
            // we intentionally introduce multiple entries again under the same guardrails.
            if self.mirrors.len() > 1 {
                ui.horizontal_wrapped(|ui| {
                    ui.label("Mirror:");
                    app_combo_box("mirror_select", &self.mirrors[self.selected_mirror]).show_ui(
                        ui,
                        |ui| {
                            for (i, name) in self.mirrors.iter().enumerate() {
                                if ui.selectable_label(false, name).clicked() {
                                    self.selected_mirror = i;
                                }
                            }
                        },
                    );
                    if add_subtle_button(ui, self.t(TextKey::RetestButton)).clicked() {
                        self.retest_mirrors();
                    }
                });

                if self.speed_test_thread.is_some() || self.speed_test_completed > 0 {
                    ui.separator();
                    if self.speed_test_thread.is_some() {
                        ui.label(format!("⏳ {}", self.t(TextKey::StatusTestingMirrors)));
                    } else {
                        ui.label(egui::RichText::new(&self.speed_test_status).strong());
                    }
                    let tested = self.speed_test_completed.min(self.mirrors.len());
                    if tested > 0 {
                        let pct = (tested as f32) / (self.mirrors.len() as f32);
                        ui.add(
                            egui::ProgressBar::new(pct)
                                .text(format!("{}/{}", tested, self.mirrors.len()))
                                .rounding(app_focus_rounding()),
                        );
                    }
                    egui::ScrollArea::vertical()
                        .max_height(120.0)
                        .show(ui, |ui| {
                            for (i, name) in self.mirrors.iter().enumerate() {
                                match &self.speed_test_results[i] {
                                    Some(dur) => {
                                        let ms = dur.as_secs_f64() * 1000.0;
                                        let color = latency_color(ms);
                                        let mark = if self.selected_mirror == i
                                            && self.speed_test_thread.is_none()
                                        {
                                            "⭐"
                                        } else {
                                            "  "
                                        };
                                        ui.label(
                                            egui::RichText::new(format!(
                                                "{} {} {:.0} ms",
                                                mark, name, ms
                                            ))
                                            .color(color),
                                        );
                                    }
                                    None => {
                                        if i < self.speed_test_completed {
                                            ui.label(format!("  {} ❌ timeout", name));
                                        } else {
                                            ui.label(format!("  {} ⏳", name));
                                        }
                                    }
                                }
                            }
                        });
                }
                ui.separator();
            }

            ui.horizontal_wrapped(|ui| {
                ui.label(self.t(TextKey::SaveToLabel));
                ui.label(self.save_dir.to_string_lossy().to_string());
                if add_subtle_button(ui, self.t(TextKey::BrowseButton)).clicked() {
                    if let Some(dir) = FileDialog::new()
                        .set_directory(&self.save_dir)
                        .pick_folder()
                    {
                        self.save_dir = dir;
                    }
                }
            });

            ui.horizontal_wrapped(|ui| {
                ui.label(self.t(TextKey::ProxyLabel));
                let clear_width = 84.0;
                let edit_width = (ui.available_width() - clear_width).max(180.0);
                add_sized_singleline_text_edit(
                    ui,
                    &mut self.proxy,
                    [edit_width, density.input_height()],
                );
                if add_subtle_button(ui, self.t(TextKey::ClearProxyButton)).clicked() {
                    self.proxy.clear();
                }
            });

            ui.horizontal_wrapped(|ui| {
                let allow_invalid_certs_label = self.t(TextKey::AllowInvalidTlsCertificates);
                add_rounded_checkbox(ui, &mut self.allow_invalid_certs, allow_invalid_certs_label);
                if self.allow_invalid_certs {
                    ui.colored_label(
                        egui::Color32::from_rgb(255, 180, 0),
                        self.t(TextKey::UnsafeTlsHint),
                    );
                }
            });

            ui.separator();
            egui::CollapsingHeader::new(self.t(TextKey::NetworkPolicyTitle))
                .default_open(min_height.is_some() || density.advanced_default_open())
                .show(ui, |ui| {
                    ui.small(
                        "Outbound HTTP(S) requests are restricted to GitHub official artifact hosts (https only).",
                    );
                    let hosts = backend_contract::official_github_artifact_hosts();
                    ui.horizontal_wrapped(|ui| {
                        if add_subtle_button(ui, self.t(TextKey::CopyAllowlistButton)).clicked() {
                            let mut text = String::new();
                            for (i, host) in hosts.iter().enumerate() {
                                if i > 0 {
                                    text.push('\n');
                                }
                                text.push_str(host);
                            }
                            ui.ctx().copy_text(text);
                            self.status =
                                "Copied official artifact host allowlist to clipboard".to_string();
                        }
                        ui.small(format!("{} hosts", hosts.len()));
                    });
                    ui.collapsing(self.t(TextKey::ShowAllowlist), |ui| {
                        for host in hosts {
                            ui.monospace(*host);
                        }
                    });
                });
            if min_height.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.small(self.tr(
                        "Transfer settings affect acquisition only; trust verdict stays backend-owned.",
                        "传输设置只影响获取；信任裁决仍由后端负责。",
                    ));
                });
            }
        });
        self.add_card_gap(ui);
    }

    fn render_trust_policy_card(&mut self, ui: &mut egui::Ui, min_height: Option<f32>) {
        let density = self.current_density();
        Self::gallery_panel(ui, density, |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(min_height) = min_height {
                ui.set_min_height(min_height);
            }
            ui.label(egui::RichText::new(self.t(TextKey::TrustPolicyTitle)).strong());
            let keep_unknown_downloads_label = self.t(TextKey::KeepUnknownDownloads);
            add_rounded_checkbox(
                ui,
                &mut self.trust_policy.unknown_keep_file,
                keep_unknown_downloads_label,
            );
            if !self.trust_policy.unknown_keep_file {
                self.trust_policy.unknown_allow_open = false;
            }
            let allow_open_unknown_downloads_label = self.t(TextKey::AllowOpenUnknownDownloads);
            ui.add_enabled_ui(self.trust_policy.unknown_keep_file, |ui| {
                add_rounded_checkbox(
                    ui,
                    &mut self.trust_policy.unknown_allow_open,
                    allow_open_unknown_downloads_label,
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(self.t(TextKey::MismatchFileActionLabel));
                let quarantine_option_label = self.t(TextKey::QuarantineOption);
                let delete_option_label = self.t(TextKey::DeleteOption);
                app_combo_box(
                    "mismatch_file_policy",
                    self.trust_policy.mismatch_file_policy.as_str(),
                )
                .show_ui(ui, |ui| {
                    ui.selectable_value(
                        &mut self.trust_policy.mismatch_file_policy,
                        MismatchFilePolicy::Quarantine,
                        quarantine_option_label,
                    );
                    ui.selectable_value(
                        &mut self.trust_policy.mismatch_file_policy,
                        MismatchFilePolicy::Delete,
                        delete_option_label,
                    );
                });
            });
            let mut require_trusted_source =
                backend_contract::source_trust_requires_signed(&self.trust_policy);
            let has_pinned_key =
                backend_contract::trusted_publisher_key_fingerprint(&self.trust_policy).is_some();
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                if add_rounded_checkbox(
                    ui,
                    &mut require_trusted_source,
                    self.t(TextKey::RequireSignedChecksumSource),
                )
                .changed()
                {
                    backend_contract::set_source_trust_requires_signed(
                        &mut self.trust_policy,
                        require_trusted_source,
                    );
                }

                if require_trusted_source && !has_pinned_key {
                    ui.colored_label(
                        egui::Color32::from_rgb(220, 70, 70),
                        self.tr("publisher key required", "需要发布者公钥"),
                    );
                } else if has_pinned_key {
                    ui.small(self.tr("publisher key pinned", "已固定发布者公钥"));
                } else {
                    ui.small(self.tr("hash evidence only", "仅哈希证据"));
                }
            });
            let open_advanced = min_height.is_some()
                || density.advanced_default_open()
                || require_trusted_source
                || has_pinned_key;
            egui::CollapsingHeader::new(self.t(TextKey::VerificationSourceTrustTitle))
                .default_open(open_advanced)
                .show(ui, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(self.t(TextKey::PinnedPublisherKeyLabel));
                        let mut trusted_publisher_key =
                            backend_contract::trusted_publisher_key_text(&self.trust_policy);
                        let edit_width = ui.available_width().max(180.0);
                        if ui
                            .add_sized(
                                [edit_width, density.input_height()],
                                rounded_singleline_text_edit(&mut trusted_publisher_key),
                            )
                            .changed()
                        {
                            backend_contract::set_trusted_publisher_key_from_manual_input(
                                &mut self.trust_policy,
                                &mut self.publisher_key_source,
                                trusted_publisher_key,
                            );
                        }
                    });
                    ui.horizontal_wrapped(|ui| {
                        if add_subtle_button(ui, self.t(TextKey::ImportPublicKey)).clicked() {
                            if let Some(path) = FileDialog::new()
                                .add_filter("Public key", &["pub", "txt"])
                                .pick_file()
                            {
                                match import_publisher_key_pin_from_path(&path) {
                                    Ok(pin) => {
                                        self.status =
                                            backend_contract::set_trusted_publisher_key_pin(
                                                &mut self.trust_policy,
                                                &mut self.publisher_key_source,
                                                pin,
                                                format!("local file {}", path.display()),
                                            );
                                    }
                                    Err(e) => {
                                        self.status = format!("❌ Public key import failed: {e}");
                                    }
                                }
                            }
                        }
                        if add_subtle_button(ui, self.t(TextKey::NormalizeKey)).clicked() {
                            match backend_contract::normalize_trusted_publisher_key(
                                &mut self.trust_policy,
                                &mut self.publisher_key_source,
                            ) {
                                Ok(status) => self.status = status,
                                Err(e) => {
                                    self.status = format!("❌ Publisher key is invalid: {e}");
                                }
                            }
                        }
                        if add_subtle_button(ui, self.t(TextKey::ClearKey)).clicked() {
                            backend_contract::clear_trusted_publisher_key(
                                &mut self.trust_policy,
                                &mut self.publisher_key_source,
                            );
                        }
                    });
                    if let Some(fingerprint) =
                        backend_contract::trusted_publisher_key_fingerprint(&self.trust_policy)
                    {
                        ui.small(format!("Pinned key SHA256 fingerprint: {fingerprint}"));
                        ui.small(format!(
                            "Pinned key source: {}",
                            backend_contract::publisher_key_source_label_for_policy(
                                &self.trust_policy,
                                &self.publisher_key_source
                            )
                        ));
                    } else if backend_contract::source_trust_requires_signed(&self.trust_policy) {
                        ui.colored_label(
                            egui::Color32::from_rgb(220, 70, 70),
                            "Required policy needs a pinned Ed25519 public key and .sig source assets.",
                        );
                    } else {
                        ui.small("No key pinned: hash verification still works, but source authenticity is not checked.");
                    }
                    ui.horizontal_wrapped(|ui| {
                        ui.label(self.t(TextKey::HistoryPathLabel));
                        let default_width = 80.0;
                        let edit_width = (ui.available_width() - default_width).max(180.0);
                        add_sized_singleline_text_edit(
                            ui,
                            &mut self.history_path,
                            [edit_width, density.input_height()],
                        );
                        if add_subtle_button(ui, self.t(TextKey::DefaultButton)).clicked() {
                            self.history_path.clear();
                        }
                    });
                    ui.small(format!(
                        "Effective history: {}",
                        self.effective_history_path().display()
                    ));
                    ui.small(
                        "Open Evidence uses the exact JSON evidence path recorded for the completed download.",
                    );
                });
            if min_height.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.small(self.tr(
                        "Policy is applied at decision time and recorded with evidence.",
                        "策略在决策时应用，并随证据记录。",
                    ));
                });
            }
        });
        self.add_card_gap(ui);
    }

    fn render_update_card(&mut self, ui: &mut egui::Ui, min_height: Option<f32>) {
        let density = self.current_density();
        Self::gallery_panel(ui, density, |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(min_height) = min_height {
                ui.set_min_height(min_height);
            }
            ui.label(egui::RichText::new(self.t(TextKey::Stage1Title)).strong());
            ui.small("Checks the public latest release and only reports candidate / no-update / refused.");
            ui.horizontal_wrapped(|ui| {
                let running = self.update_candidate_thread.is_some();
                if add_enabled_tonal_button(
                    ui,
                    !running,
                    self.t(TextKey::CheckLatestCandidateButton),
                )
                .clicked()
                {
                    self.start_update_candidate_check();
                }
                if running {
                    ui.label(format!("⏳ {}", self.t(TextKey::StatusCheckingCandidate)));
                } else if !self.update_candidate_status.is_empty() {
                    ui.label(&self.update_candidate_status);
                }
            });
            if let Some(report) = &self.update_candidate_report {
                render_update_candidate_check(ui, report);
            }

            ui.separator();
            let stage2_open = density.advanced_default_open()
                || min_height.is_some()
                || self.update_stage_thread.is_some()
                || self.update_stage_report.is_some()
                || self.update_apply_bundle_evidence_record.is_some()
                || !self.update_stage_status.is_empty()
                || !self.update_apply_bundle_status.is_empty();
            egui::CollapsingHeader::new(self.t(TextKey::Stage2Title))
                .default_open(stage2_open)
                .show(ui, |ui| {
                    ui.small("Stages a verified candidate to a local folder (still no install).");
                    ui.horizontal_wrapped(|ui| {
                        let running = self.update_stage_thread.is_some();
                        if add_enabled_tonal_button(
                            ui,
                            !running,
                            self.t(TextKey::StageLatestCandidateButton),
                        )
                        .clicked()
                        {
                            self.start_update_candidate_stage();
                        }
                        if running {
                            ui.label(format!("⏳ {}", self.t(TextKey::StatusStagingCandidate)));
                        } else if !self.update_stage_status.is_empty() {
                            ui.label(&self.update_stage_status);
                        }
                    });
                    if let Some(report) = self.update_stage_report.clone() {
                        render_update_candidate_stage(ui, &report);
                        ui.separator();
                        if let Some(record) = &self.update_apply_plan_evidence_record {
                            render_update_apply_plan_preview(ui, &record.plan, Some(record));
                        } else {
                            match backend_contract::current_exe_update_apply_plan_for_stage2(
                                &report,
                            ) {
                                Ok(plan) => {
                                    render_update_apply_plan_preview(ui, &plan, None);
                                }
                                Err(e) => {
                                    ui.small(format!(
                                        "Update apply plan preview unavailable ({e})"
                                    ));
                                }
                            }
                        }
                        ui.separator();
                        ui.horizontal_wrapped(|ui| {
                            if add_subtle_button(ui, self.t(TextKey::PrepareHelperBundleButton))
                                .clicked()
                            {
                                match backend_contract::record_update_apply_bundle_evidence_for_current_exe(
                                    &report,
                                ) {
                                    Ok(record) => {
                                        self.update_apply_bundle_status =
                                            "Controlled helper bundle prepared; helper execution is not launched by the UI."
                                                .to_string();
                                        self.update_apply_bundle_evidence_record = Some(record);
                                    }
                                    Err(e) => {
                                        self.update_apply_bundle_status =
                                            format!("Controlled helper bundle unavailable: {e}");
                                        self.update_apply_bundle_evidence_record = None;
                                    }
                                }
                            }
                            if !self.update_apply_bundle_status.is_empty() {
                                ui.label(&self.update_apply_bundle_status);
                            }
                        });
                        if let Some(record) = &self.update_apply_bundle_evidence_record {
                            render_update_apply_bundle_preview(ui, record);
                        }
                    }
                });
            if min_height.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.small(self.tr(
                        "Update flow is check/stage only here; no install is launched.",
                        "此处自更新仅检查 / 暂存；不会启动安装。",
                    ));
                });
            }
        });
        self.add_card_gap(ui);
    }

    fn render_last_download_card(&mut self, ui: &mut egui::Ui, min_height: Option<f32>) {
        let Some(snapshot) = self.last_trust_center_snapshot.clone() else {
            return;
        };

        Self::gallery_panel(ui, self.current_density(), |ui| {
            ui.set_min_width(ui.available_width());
            if let Some(min_height) = min_height {
                ui.set_min_height(min_height);
            }
            ui.horizontal_wrapped(|ui| {
                if let Some(notice) = backend_contract::last_download_status_notice(&snapshot) {
                    ui.colored_label(backend_notice_color(notice.level), notice.message);
                    if let Some(retry_label) = notice.retry_label {
                        if self.download_thread.is_none()
                            && add_tonal_button(ui, retry_label).clicked()
                        {
                            self.start_download();
                        }
                    }
                }

                if let Some(action) = backend_contract::last_download_evidence_action(
                    self.last_verification_evidence_path.as_deref(),
                ) {
                    render_backend_path_action(ui, action);
                }
                if let (Some(download_path), Some(disposition)) =
                    (&self.last_download_path, &self.last_file_disposition)
                {
                    if let Some(action) = backend_contract::last_download_open_location_action(
                        &snapshot,
                        disposition,
                        &self.trust_policy,
                        download_path,
                        &self.save_dir,
                    ) {
                        render_backend_path_action(ui, action);
                    }
                }
            });
            ui.small(format!(
                "Source authenticity: {}",
                source_trust_status_summary(&snapshot)
            ));
            if let Some(disposition) = &self.last_file_disposition {
                ui.small(backend_contract::file_disposition_summary(disposition));
                render_trust_center_snapshot(ui, &snapshot);
            }
            if min_height.is_some() {
                ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                    ui.small(self.tr(
                        "Last result is rendered from backend evidence, not UI opinion.",
                        "上次结果来自后端证据渲染，不是 UI 自行判断。",
                    ));
                });
            }
        });
        self.add_card_gap(ui);
    }

    fn update_candidate_evidence_dir(&self) -> PathBuf {
        self.effective_history_path()
            .parent()
            .map(|path| path.join("update-candidate-evidence"))
            .unwrap_or_else(|| PathBuf::from("update-candidate-evidence"))
    }

    fn update_candidate_stage_root(&self) -> PathBuf {
        self.effective_history_path()
            .parent()
            .map(|path| path.join("update-candidate-staging"))
            .unwrap_or_else(|| PathBuf::from("update-candidate-staging"))
    }

    fn clear_release_lookup_result(&mut self) {
        self.release = None;
        self.selected_release_asset = None;
        self.release_status.clear();
        self.release_lookup_input = None;
        self.publisher_key_import_thread = None;
        self.publisher_key_import_rx = None;
        self.publisher_key_import_asset_url = None;
        self.publisher_key_import_source_label = None;
    }

    fn start_update_candidate_check(&mut self) {
        if self.update_candidate_thread.is_some() {
            self.update_candidate_status =
                "Self-update candidate check is already running...".to_string();
            return;
        }

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let source_trust_policy = backend_contract::source_trust_policy_config(&self.trust_policy);
        let evidence_dir = self.update_candidate_evidence_dir();
        let (tx, rx) = mpsc::channel::<UpdateCandidateCheckMessage>();
        self.update_candidate_status = self.t(TextKey::StatusCheckingCandidate).to_string();
        self.update_candidate_rx = Some(rx);
        self.update_candidate_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let report = backend_contract::run_update_candidate_check(
                &settings,
                env!("CARGO_PKG_VERSION"),
                &source_trust_policy,
                &evidence_dir,
            );
            let _ = tx.send(report);
        }));
    }

    fn start_update_candidate_stage(&mut self) {
        if self.update_stage_thread.is_some() {
            self.update_stage_status = "Update candidate staging is already running...".to_string();
            return;
        }

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let source_trust_policy = backend_contract::source_trust_policy_config(&self.trust_policy);
        let evidence_dir = self.update_candidate_evidence_dir();
        let stage_root = self.update_candidate_stage_root();
        let (tx, rx) = mpsc::channel::<UpdateCandidateStageMessage>();
        self.update_stage_status = self.t(TextKey::StatusStagingCandidate).to_string();
        self.update_stage_rx = Some(rx);
        self.update_stage_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let report = backend_contract::run_update_candidate_stage(
                &settings,
                env!("CARGO_PKG_VERSION"),
                &source_trust_policy,
                &evidence_dir,
                &stage_root,
            );
            let _ = tx.send(report);
        }));
    }

    fn start_release_lookup(&mut self) {
        if self.release_lookup_thread.is_some() {
            self.release_lookup_thread = None;
            self.release_lookup_rx = None;
            self.release_lookup_input = None;
        }

        let input = self.url.trim().to_string();
        let intent = backend_contract::resolve_download_intent(&input);
        let backend_contract::IntentDTO::NeedsAssetPick { query, .. } = intent else {
            self.release = None;
            self.selected_release_asset = None;
            self.release_status = release_lookup_non_picker_status(&input, intent);
            self.status = self.release_status.clone();
            return;
        };

        let auto_proxy = self.fill_default_proxy_if_blank();
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let (tx, rx) = mpsc::channel::<ReleaseLookupMessage>();
        let kind_label = backend_contract::release_query_selector_label(&query);
        let mut status = format!(
            "Resolving {}/{} {kind_label} assets...",
            query.owner, query.repo
        );
        if let Some(proxy) = auto_proxy {
            status.push_str(&format!(" (system proxy: {proxy})"));
        }
        self.release_status = status.clone();
        self.status = status;
        self.release = None;
        self.selected_release_asset = None;
        self.release_lookup_input = Some(input.clone());
        self.release_lookup_rx = Some(rx);
        self.release_lookup_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result = backend_contract::resolve_release_assets_for_query(&settings, &query);
            let _ = tx.send((input, result));
        }));
    }

    fn input_requires_release_asset_choice(&self) -> bool {
        matches!(
            backend_contract::resolve_download_intent(&self.url),
            backend_contract::IntentDTO::NeedsAssetPick { .. }
        )
    }

    fn apply_selected_release_asset(&mut self) -> bool {
        let selected = self
            .release
            .as_ref()
            .and_then(|release| {
                self.selected_release_asset
                    .and_then(|idx| release.assets.get(idx))
            })
            .map(|asset| (asset.name.clone(), asset.browser_download_url.clone()));

        if let Some((name, url)) = selected {
            self.url = url;
            self.status = format!("Selected release asset: {name}");
            true
        } else {
            false
        }
    }

    fn start_import_publisher_key_from_selected_release(&mut self) {
        if self.publisher_key_import_thread.is_some() {
            self.status = self.t(TextKey::StatusPublisherKeyImportRunning).to_string();
            return;
        }

        let Some((asset, source_label)) = self.release.as_ref().and_then(|release| {
            release
                .assets
                .iter()
                .find(|asset| asset.name == RELEASE_PUBLIC_KEY_ASSET)
                .cloned()
                .map(|asset| {
                    let source_label = format!(
                        "GitHub Release {}/{}@{} asset {}",
                        release.owner, release.repo, release.tag_name, asset.name
                    );
                    (asset, source_label)
                })
        }) else {
            self.status = self.t(TextKey::StatusNoPublisherKeyAsset).to_string();
            return;
        };

        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let asset_url = asset.browser_download_url.clone();
        let (tx, rx) = mpsc::channel::<PublisherKeyImportMessage>();
        self.publisher_key_import_asset_url = Some(asset_url.clone());
        self.publisher_key_import_source_label = Some(source_label);
        self.publisher_key_import_rx = Some(rx);
        self.publisher_key_import_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result =
                backend_contract::import_publisher_key_from_release_asset(&settings, &asset);
            let _ = tx.send((asset_url, result));
        }));
        self.status = self.t(TextKey::StatusPublisherKeyImportRunning).to_string();
    }

    fn start_download(&mut self) {
        if self.url.trim().is_empty() {
            self.status = self.t(TextKey::StatusEnterUrlFirst).to_string();
            return;
        }
        if self.download_thread.is_some() {
            self.status = self.t(TextKey::StatusDownloadAlreadyInProgress).to_string();
            return;
        }

        match backend_contract::resolve_download_intent(&self.url) {
            backend_contract::IntentDTO::DirectDownload { spec, .. } => {
                if spec.url != self.url {
                    self.url = spec.url;
                }
            }
            backend_contract::IntentDTO::NeedsAssetPick { .. } => {}
            backend_contract::IntentDTO::Unsupported { reason, .. } => {
                self.status = format!("❌ {reason}");
                return;
            }
        }
        if self.input_requires_release_asset_choice() {
            if self.release_lookup_thread.is_some() {
                self.status = self.t(TextKey::StatusReleaseAssetLookupRunning).to_string();
                return;
            }
            if self.release.is_none() {
                self.start_release_lookup();
                self.status = self.t(TextKey::StatusResolvingReleaseAssets).to_string();
                return;
            }
            if !self.apply_selected_release_asset() {
                self.status = self.t(TextKey::StatusChooseReleaseAssetFirst).to_string();
                return;
            }
        }

        let auto_proxy = self.fill_default_proxy_if_blank();
        let save_path = match self.choose_save_path() {
            Some(p) => p,
            None => return,
        };

        let (verification_release, verification_asset_index) =
            match (self.release.clone(), self.selected_release_asset) {
                (Some(release), Some(idx))
                    if release
                        .assets
                        .get(idx)
                        .is_some_and(|asset| asset.browser_download_url == self.url) =>
                {
                    (Some(release), Some(idx))
                }
                _ => (None, None),
            };

        let asset_name = verification_release
            .as_ref()
            .and_then(|release| {
                verification_asset_index
                    .and_then(|idx| release.assets.get(idx).map(|asset| asset.name.clone()))
            })
            .or_else(|| extract_filename(&self.url))
            .unwrap_or_else(|| String::from("download"));

        self.download_complete_notified = false;
        self.last_download_path = None;
        self.last_trust_center_snapshot = None;
        self.last_verification_evidence_path = None;
        self.last_file_disposition = None;
        let control = DownloadControl::new();
        let ctrl = control.clone();
        let effective_url = build_effective_url(&self.mirror_urls[self.selected_mirror], &self.url);
        let proxy = self.proxy.clone();
        let allow_invalid_certs = self.allow_invalid_certs;
        let trust_policy = self.trust_policy.clone();
        let publisher_key_source_at_decision =
            backend_contract::publisher_key_source_label_for_policy(
                &trust_policy,
                &self.publisher_key_source,
            );
        let history_path = self.effective_history_path();
        let (progress_tx, progress_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel::<DownloadResultMessage>();
        self.progress_rx = Some(progress_rx);
        self.download_result_rx = Some(result_rx);

        self.progress = 0.0;
        self.downloaded_bytes = 0;
        self.download_total_bytes = None;
        self.download_speed_kib_per_second = 0.0;
        self.download_elapsed_seconds = 0.0;
        self.download_started_at = Some(Instant::now());
        self.speed_text.clear();
        self.elapsed_text.clear();
        self.status = verification_release
            .as_ref()
            .and_then(|release| {
                verification_asset_index.map(|idx| {
                    backend_contract::verification_source_summary_for_release_asset(release, idx)
                })
            })
            .map(|summary| format!("{}; {summary}", self.t(TextKey::ProgressWaitingForBytes)))
            .unwrap_or_else(|| self.t(TextKey::StatusStartingDownloadUnknown).to_string());
        if let Some(proxy) = auto_proxy {
            self.status.push_str(&format!(" (system proxy: {proxy})"));
        }

        self.download_thread = Some(thread::spawn(move || {
            let settings = BackendClientSettings::new(proxy, allow_invalid_certs);
            let result = backend_contract::run_download_contract(
                &settings,
                backend_contract::DownloadContractInput {
                    effective_url,
                    save_path,
                    asset_name,
                    verification_release,
                    verification_asset_index,
                    trust_policy,
                    publisher_key_source_at_decision,
                    history_path,
                },
                &ctrl,
                &progress_tx,
            );

            let _ = result_tx.send(result);
        }));

        self.control = Some(control);
    }

    fn choose_save_path(&mut self) -> Option<PathBuf> {
        let default_name = extract_filename(&self.url).unwrap_or_else(|| String::from("download"));
        let file = FileDialog::new()
            .set_directory(&self.save_dir)
            .set_file_name(&default_name)
            .save_file();
        if let Some(path) = file {
            self.save_dir = path.parent().unwrap_or(&self.save_dir).to_path_buf();
            Some(path)
        } else {
            None
        }
    }
}

impl eframe::App for GhMirrorGui {
    fn clear_color(&self, _visuals: &egui::Visuals) -> [f32; 4] {
        app_clear_color()
    }

    fn save(&mut self, storage: &mut dyn Storage) {
        let state = SavedState {
            selected_mirror: self.selected_mirror,
            save_dir: self.save_dir.to_string_lossy().to_string(),
            proxy: self.proxy.clone(),
            locale: self.locale,
            allow_invalid_certs: self.allow_invalid_certs,
            trust_unknown_keep_file: self.trust_policy.unknown_keep_file,
            trust_unknown_allow_open: self.trust_policy.unknown_allow_open,
            trust_mismatch_file_policy: self.trust_policy.mismatch_file_policy,
            source_trust_require_signed: backend_contract::source_trust_requires_signed(
                &self.trust_policy,
            ),
            source_trust_publisher_key: backend_contract::trusted_publisher_key_text(
                &self.trust_policy,
            ),
            source_trust_publisher_key_source: self.publisher_key_source.clone(),
            history_path: self.history_path.clone(),
        };
        if let Ok(json) = serde_json::to_string(&state) {
            storage.set_string("app_settings", json);
        }
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.update_viewport_density(ctx.screen_rect().size());
        self.apply_adaptive_style(ctx);
        ctx.request_repaint_after(ui_presentation_heartbeat_duration());
        if self.resize_stabilize_until.is_some() {
            ctx.request_repaint();
        }

        // Check for speed test completion
        if let Some(rx) = &self.speed_test_rx {
            if let Ok(best_idx) = rx.try_recv() {
                self.selected_mirror = best_idx;
                self.speed_test_status = if best_idx > 0 {
                    let best_name = &self.mirrors[best_idx];
                    let best_time = self.speed_test_results[best_idx]
                        .map(|d| format!("{:.0}ms", d.as_secs_f64() * 1000.0))
                        .unwrap_or_else(|| String::from("N/A"));
                    format!("✅ Best: {} ({})", best_name, best_time)
                } else {
                    String::from("⚠ Direct is fastest (no mirror)")
                };
                self.speed_test_thread = None;
                self.speed_test_rx = None;
            }
        }

        // Process per-mirror progress
        if let Some(rx) = &self.speed_test_progress_rx {
            while let Ok((idx, duration_opt)) = rx.try_recv() {
                self.speed_test_results[idx] = duration_opt;
                self.speed_test_completed += 1;
                if self.speed_test_completed >= self.mirrors.len() {
                    self.speed_test_status = String::from("✅ All mirrors tested");
                }
            }
        }

        // Process GitHub release discovery result
        if let Some(rx) = &self.release_lookup_rx {
            if let Ok((input, result)) = rx.try_recv() {
                let is_current = self.release_lookup_input.as_deref() == Some(input.as_str());
                self.release_lookup_thread = None;
                self.release_lookup_rx = None;
                self.release_lookup_input = None;

                if is_current {
                    match result {
                        Ok(release) => {
                            let asset_count = release.assets.len();
                            self.selected_release_asset =
                                if asset_count > 0 { Some(0) } else { None };
                            self.release_status = if asset_count > 0 {
                                format!(
                                    "✅ {} assets found for {}/{}@{}",
                                    asset_count, release.owner, release.repo, release.tag_name
                                )
                            } else {
                                format!(
                                    "⚠ No assets found for {}/{}@{}",
                                    release.owner, release.repo, release.tag_name
                                )
                            };
                            self.status = self.release_status.clone();
                            self.release = Some(release);
                        }
                        Err(e) => {
                            self.release = None;
                            self.selected_release_asset = None;
                            self.release_status = format!("❌ {e}");
                            self.status = self.release_status.clone();
                        }
                    }
                }
            }
        }

        // Process selected-release publisher key import result.
        if let Some(rx) = &self.publisher_key_import_rx {
            if let Ok((asset_url, result)) = rx.try_recv() {
                let is_current =
                    self.publisher_key_import_asset_url.as_deref() == Some(asset_url.as_str());
                self.publisher_key_import_thread = None;
                self.publisher_key_import_rx = None;
                self.publisher_key_import_asset_url = None;
                let source_label = self
                    .publisher_key_import_source_label
                    .take()
                    .unwrap_or_else(|| format!("GitHub Release asset {asset_url}"));

                if is_current {
                    match result {
                        Ok(imported) => {
                            self.status = backend_contract::apply_imported_publisher_key_pin(
                                &mut self.trust_policy,
                                &mut self.publisher_key_source,
                                imported,
                                source_label,
                            );
                        }
                        Err(e) => {
                            self.status = format!("❌ Publisher key import failed: {e}");
                        }
                    }
                }
            }
        }

        // Process latest self-update candidate check result. This is no-mutation:
        // backend/core reports candidate/no-update/refused only; UI just displays it.
        if let Some(rx) = &self.update_candidate_rx {
            if let Ok(report) = rx.try_recv() {
                self.update_candidate_thread = None;
                self.update_candidate_rx = None;
                self.update_candidate_status =
                    backend_contract::update_candidate_check_status_summary(&report);
                self.status = self.update_candidate_status.clone();
                self.update_candidate_report = Some(report);
            }
        }

        // Process self-update Stage 2 staging result. This stage still performs no install:
        // it only stages a verified candidate to a local directory and records evidence.
        if let Some(rx) = &self.update_stage_rx {
            if let Ok(report) = rx.try_recv() {
                self.update_stage_thread = None;
                self.update_stage_rx = None;
                self.update_stage_status =
                    backend_contract::update_candidate_stage_status_summary(&report);
                self.status = self.update_stage_status.clone();

                // Record a Stage 3 apply plan evidence file (no mutation / no install).
                // The UI only triggers the backend contract; backend/core resolves the target exe and writes evidence.
                self.update_apply_plan_evidence_record = None;
                self.update_apply_bundle_evidence_record = None;
                self.update_apply_bundle_status.clear();
                self.update_apply_plan_evidence_record =
                    backend_contract::record_update_apply_plan_evidence_for_current_exe(&report)
                        .ok();
                self.update_stage_report = Some(report);
            }
        }

        // Process download progress
        let progress_rx = self.progress_rx.take();
        if let Some(rx) = progress_rx {
            let mut keep_progress_rx = true;
            while let Ok((downloaded, total, speed, elapsed)) = rx.try_recv() {
                self.downloaded_bytes = downloaded;
                self.download_total_bytes = (total > 0).then_some(total);
                self.download_speed_kib_per_second = speed;
                self.download_elapsed_seconds = elapsed;
                let is_complete = downloaded >= total && total > 0;
                if total > 0 {
                    self.progress = (downloaded as f32) / (total as f32);
                }
                if downloaded == 0 && total == 0 {
                    // Error state
                    self.status = self.t(TextKey::StatusDownloadFailed).to_string();
                    self.download_thread = None;
                    self.control = None;
                    self.download_started_at = None;
                    keep_progress_rx = false;
                } else if downloaded >= total && total > 0 {
                    self.progress = 1.0;
                    self.status = self.t(TextKey::StatusDownloadCompleteVerifying).to_string();
                    self.speed_text.clear();
                    self.elapsed_text.clear();
                    self.download_started_at = None;
                    keep_progress_rx = false;
                }
                if !is_complete {
                    self.speed_text = format_speed(speed);
                    let total_min = elapsed / 60.0;
                    let total_sec = elapsed % 60.0;
                    self.elapsed_text = format!("{:02.0}:{:04.1}", total_min, total_sec);
                }
            }
            if keep_progress_rx && self.download_thread.is_some() {
                self.progress_rx = Some(rx);
            }
        }

        // Process final download result including checksum/provenance verification.
        let download_result_rx = self.download_result_rx.take();
        if let Some(rx) = download_result_rx {
            match rx.try_recv() {
                Ok(Ok(completion)) => {
                    self.status = format_download_completion_status(
                        &completion.trust_center,
                        &completion.file_disposition,
                    );
                    self.last_download_path = completion.file_disposition.final_path.clone();
                    self.last_trust_center_snapshot = Some(completion.trust_center.clone());
                    self.last_verification_evidence_path = completion.evidence_path.clone();
                    self.last_file_disposition = Some(completion.file_disposition.clone());
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                    self.download_started_at = None;
                    if !self.download_complete_notified {
                        self.download_complete_notified = true;
                        let save_path_str = completion
                            .file_disposition
                            .final_path
                            .as_ref()
                            .unwrap_or(&completion.original_path)
                            .to_string_lossy()
                            .to_string();
                        let status = format_download_notification_status(&completion.trust_center);
                        thread::spawn(move || {
                            let _ = Notification::new()
                                .summary("gh_mirror_gui")
                                .body(&format!("{status}\nSaved to: {save_path_str}"))
                                .show();
                        });
                    }
                }
                Ok(Err(e)) => {
                    self.status = format!("{}: {e}", self.t(TextKey::StatusDownloadFailed));
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                    self.download_started_at = None;
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.download_result_rx = Some(rx);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = format!(
                        "{}: worker exited unexpectedly",
                        self.t(TextKey::StatusDownloadFailed)
                    );
                    self.download_thread = None;
                    self.control = None;
                    self.progress_rx = None;
                    self.download_started_at = None;
                }
            }
        }

        if self.download_thread.is_some() {
            if let Some(started_at) = self.download_started_at {
                self.download_elapsed_seconds = self
                    .download_elapsed_seconds
                    .max(started_at.elapsed().as_secs_f64());
            }
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        if let Some(until) = self.resize_stabilize_until {
            if Instant::now() < until {
                ctx.request_repaint_after(Duration::from_millis(RESIZE_REPAINT_FRAME_MS));
            } else {
                self.resize_stabilize_until = None;
            }
        }

        // Drag-drop handling is app-wide; rendering below stays a stable projection shell.
        if !ctx.input(|i| i.raw.dropped_files.is_empty()) {
            let dropped = ctx.input(|i| i.raw.dropped_files.clone());
            if let Some(file) = dropped.first() {
                if let Some(path_str) = &file.path {
                    self.url = path_str.to_string_lossy().to_string();
                }
            }
        }

        let density = self.current_density();
        egui::TopBottomPanel::top("proof_to_action_top_bar")
            .exact_height(density.top_bar_height())
            .resizable(false)
            .show_separator_line(false)
            .frame(chrome_panel_frame())
            .show(ctx, |ui| {
                let status_text = self.status.clone();
                let status_tone = status_color(&status_text);
                ui.horizontal_centered(|ui| {
                    ui.label(
                        egui::RichText::new(self.t(TextKey::AppTitle))
                            .size(16.0)
                            .strong()
                            .color(app_text_color()),
                    );
                    ui.add_space(8.0);
                    ui.label(
                        egui::RichText::new(self.t(TextKey::AppSubtitle))
                            .small()
                            .color(app_muted_text_color()),
                    );
                    let switch_key = if self.locale == UiLocale::En {
                        TextKey::SwitchToChinese
                    } else {
                        TextKey::SwitchToEnglish
                    };
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if add_subtle_button(ui, self.t(switch_key)).clicked() {
                            self.toggle_locale();
                        }
                        ui.add_space(8.0);
                        ui.label(
                            egui::RichText::new(status_text)
                                .small()
                                .strong()
                                .color(status_tone),
                        );
                    });
                });
            });

        egui::TopBottomPanel::top("proof_to_action_command_panel")
            .exact_height(density.command_panel_height(self.command_layout_mode))
            .resizable(false)
            .show_separator_line(false)
            .frame(chrome_panel_frame())
            .show(ctx, |ui| {
                self.render_command_panel(ui);
            });

        // Draw UI body. Scroll is a fallback safety net after responsive layout projection.
        egui::CentralPanel::default()
            .frame(body_panel_frame())
            .show(ctx, |ui| {
                self.render_body(ui);
            });
    }
}

// ---------------------------------------------------------------------------
// UI helpers
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_two_column_widths_fill_available_width() {
        let gap = 6.0;
        let (major, minor) = golden_two_column_widths(1000.0, gap);

        assert!((major + minor + gap - 1000.0).abs() < 0.01);
        assert!((major / (major + minor) - GOLDEN_MAJOR).abs() < 0.001);
    }

    #[test]
    fn golden_three_column_widths_use_golden_sequence_and_fill_width() {
        let gap = 6.0;
        let (primary, policy, update) = golden_three_column_widths(1200.0, gap);

        assert!((primary + policy + update + gap * 2.0 - 1200.0).abs() < 0.01);
        assert!((policy / primary - GOLDEN_MAJOR).abs() < 0.001);
        assert!((update / policy - GOLDEN_MAJOR).abs() < 0.001);
    }

    #[test]
    fn golden_stack_heights_fill_height_with_golden_decay() {
        let gap = 6.0;
        let heights = golden_stack_heights(900.0, gap, 3);

        assert_eq!(heights.len(), 3);
        assert!((heights.iter().sum::<f32>() + gap * 2.0 - 900.0).abs() < 0.01);
        assert!((heights[1] / heights[0] - GOLDEN_MAJOR).abs() < 0.001);
        assert!((heights[2] / heights[1] - GOLDEN_MAJOR).abs() < 0.001);
    }

    #[test]
    fn weighted_stack_heights_fill_height_by_control_weight() {
        let gap = 4.0;
        let heights = weighted_stack_heights(640.0, gap, &[GOLDEN_MINOR, 1.0]);

        assert_eq!(heights.len(), 2);
        assert!((heights.iter().sum::<f32>() + gap - 640.0).abs() < 0.01);
        assert!(heights[1] > heights[0]);
    }

    #[test]
    fn body_fill_height_only_activates_for_large_viewports() {
        assert_eq!(body_fill_height(360.0), None);
        assert_eq!(body_fill_height(430.0), Some(430.0));
    }

    #[test]
    fn body_scroll_is_only_fallback_for_compact_or_short_viewports() {
        assert!(body_scroll_fallback_for_viewport(760.0, 700.0));
        assert!(body_scroll_fallback_for_viewport(1200.0, 360.0));
        assert!(!body_scroll_fallback_for_viewport(1200.0, 700.0));
    }

    #[test]
    fn body_scroll_fallback_uses_hysteresis_during_resize() {
        assert!(body_scroll_fallback_for_resized_viewport(
            true,
            BodyLayout::GoldenTwo,
            420.0
        ));
        assert!(!body_scroll_fallback_for_resized_viewport(
            true,
            BodyLayout::GoldenTwo,
            470.0
        ));
        assert!(body_scroll_fallback_for_resized_viewport(
            false,
            BodyLayout::GoldenTwo,
            390.0
        ));
        assert!(!body_scroll_fallback_for_resized_viewport(
            false,
            BodyLayout::GoldenTwo,
            450.0
        ));
    }

    #[test]
    fn body_layout_uses_hysteresis_to_reduce_resize_thrashing() {
        assert_eq!(
            body_layout_for_resized_viewport(BodyLayout::Single, 819.0, 700.0),
            BodyLayout::Single
        );
        assert_eq!(
            body_layout_for_resized_viewport(BodyLayout::Single, 852.0, 700.0),
            BodyLayout::GoldenTwo
        );
        assert_eq!(
            body_layout_for_resized_viewport(BodyLayout::GoldenThree, 1100.0, 700.0),
            BodyLayout::GoldenThree
        );
        assert_eq!(
            body_layout_for_resized_viewport(BodyLayout::GoldenThree, 1070.0, 700.0),
            BodyLayout::GoldenTwo
        );
    }

    #[test]
    fn command_layout_uses_hysteresis_to_reduce_resize_thrashing() {
        assert_eq!(
            layout_mode_for_resized_width(LayoutMode::Compact, 819.0),
            LayoutMode::Compact
        );
        assert_eq!(
            layout_mode_for_resized_width(LayoutMode::Compact, 853.0),
            LayoutMode::Medium
        );
        assert_eq!(
            layout_mode_for_resized_width(LayoutMode::Medium, 1160.0),
            LayoutMode::Medium
        );
        assert_eq!(
            layout_mode_for_resized_width(LayoutMode::Medium, 1213.0),
            LayoutMode::Wide
        );
        assert_eq!(
            layout_mode_for_resized_width(LayoutMode::Wide, 1160.0),
            LayoutMode::Wide
        );
        assert_eq!(
            layout_mode_for_resized_width(LayoutMode::Wide, 1140.0),
            LayoutMode::Medium
        );
    }

    #[test]
    fn fixed_chrome_heights_prevent_resize_wrap_height_feedback() {
        assert!(ViewportDensity::Regular.top_bar_height() > 0.0);
        assert!(
            ViewportDensity::Regular.command_panel_height(LayoutMode::Compact)
                > ViewportDensity::Regular.command_panel_height(LayoutMode::Wide)
        );
    }

    #[test]
    fn app_palette_avoids_black_resize_clear_and_empty_bars() {
        assert_ne!(app_background_color(), egui::Color32::BLACK);
        assert_ne!(app_chrome_color(), egui::Color32::BLACK);
        assert_ne!(app_surface_color(), egui::Color32::BLACK);
        let clear = app_clear_color();
        assert!(clear[0] > 0.9);
        assert!(clear[1] > 0.9);
        assert!(clear[2] > 0.9);
        assert_eq!(clear[3], 1.0);
    }

    #[test]
    fn app_palette_keeps_soft_light_hierarchy() {
        assert!(app_background_color().r() < app_surface_color().r());
        assert!(app_chrome_color().r() >= app_background_color().r());
        assert!(app_muted_text_color().r() > app_text_color().r());
        assert_ne!(app_accent_color(), app_text_color());
        assert!(app_surface_shadow().color.a() > 0);
        assert!(app_panel_rounding().nw > app_control_rounding().nw);
    }

    #[test]
    fn app_rounding_presets_keep_all_four_corners_complete() {
        for rounding in [
            app_panel_rounding(),
            app_focus_rounding(),
            app_control_rounding(),
        ] {
            assert!(rounding.nw > 0.0);
            assert_eq!(rounding.nw, rounding.ne);
            assert_eq!(rounding.nw, rounding.sw);
            assert_eq!(rounding.nw, rounding.se);
        }
    }

    #[test]
    fn comfortable_style_applies_complete_rounding_to_all_widget_states() {
        let ctx = egui::Context::default();
        configure_comfortable_app_style(&ctx);
        let style = ctx.style();

        for rounding in [
            style.visuals.window_rounding,
            style.visuals.menu_rounding,
            style.visuals.widgets.noninteractive.rounding,
            style.visuals.widgets.inactive.rounding,
            style.visuals.widgets.hovered.rounding,
            style.visuals.widgets.active.rounding,
            style.visuals.widgets.open.rounding,
        ] {
            assert!(rounding.nw > 0.0);
            assert_eq!(rounding.nw, rounding.ne);
            assert_eq!(rounding.nw, rounding.sw);
            assert_eq!(rounding.nw, rounding.se);
        }
        assert!(
            style.visuals.collapsing_header_frame,
            "Collapsible controls must paint a rounded header frame instead of a naked square-edge row"
        );
    }

    #[test]
    fn visible_control_constructors_stay_behind_rounded_entrypoints() {
        let source = include_str!("gui_app.rs");
        let frame_ctor = concat!("egui::Frame", "::none()");
        let panel_rounding = concat!(".rounding(", "app_panel_rounding())");
        let progress_ctor = concat!("egui::ProgressBar", "::new(");
        let focus_rounding = concat!(".rounding(", "app_focus_rounding())");

        assert_eq!(
            source.matches(frame_ctor).count(),
            source.matches(panel_rounding).count(),
            "Every visible Frame surface must explicitly apply complete panel rounding"
        );
        assert_eq!(
            source
                .matches(concat!("egui::TextEdit", "::singleline("))
                .count(),
            1,
            "Raw TextEdit construction must stay centralized in rounded_singleline_text_edit"
        );
        assert_eq!(
            source
                .matches(concat!("egui::ComboBox", "::from_id_salt("))
                .count(),
            1,
            "Raw ComboBox construction must stay centralized in app_combo_box"
        );
        assert_eq!(
            source.matches(concat!("ui", ".checkbox(")).count(),
            1,
            "Raw checkbox construction must stay centralized in add_rounded_checkbox"
        );
        assert_eq!(
            source.matches(progress_ctor).count(),
            source.matches(focus_rounding).count(),
            "Every progress bar must explicitly apply complete focus rounding"
        );
        assert!(
            !source.contains(concat!("ui", ".button(")),
            "Buttons must go through rounded button helpers"
        );
    }

    #[test]
    fn viewport_density_freezes_during_resize_drag_until_stable() {
        let mut app = GhMirrorGui::new(None);
        assert_eq!(app.viewport_density, ViewportDensity::Regular);

        app.update_viewport_density(egui::vec2(1600.0, 940.0));
        assert_eq!(app.viewport_density, ViewportDensity::Regular);
        assert!(app.resize_stabilize_until.is_some());

        app.resize_stabilize_until = Some(Instant::now() - Duration::from_millis(1));
        app.update_viewport_density(egui::vec2(1600.0, 940.0));
        assert_eq!(app.viewport_density, ViewportDensity::Spacious);
        assert!(app.resize_stabilize_until.is_none());
    }

    #[test]
    fn viewport_density_uses_hysteresis_to_reduce_resize_thrashing() {
        assert_eq!(
            ViewportDensity::for_resized_size(ViewportDensity::Dense, egui::vec2(934.0, 655.0)),
            ViewportDensity::Regular
        );
        assert_eq!(
            ViewportDensity::for_resized_size(ViewportDensity::Regular, egui::vec2(860.0, 580.0)),
            ViewportDensity::Dense
        );
        assert_eq!(
            ViewportDensity::for_resized_size(ViewportDensity::Regular, egui::vec2(1535.0, 940.0)),
            ViewportDensity::Spacious
        );
        assert_eq!(
            ViewportDensity::for_resized_size(ViewportDensity::Spacious, egui::vec2(1460.0, 860.0)),
            ViewportDensity::Regular
        );
    }

    #[test]
    fn viewport_size_change_threshold_filters_tiny_resize_jitter() {
        assert!(!viewport_size_changed_enough(
            egui::vec2(1000.0, 700.0),
            egui::vec2(1000.3, 700.2)
        ));
        assert!(viewport_size_changed_enough(
            egui::vec2(1000.0, 700.0),
            egui::vec2(1001.0, 700.0)
        ));
    }

    #[test]
    fn presentation_heartbeat_is_bounded_below_interactive_frame_budget() {
        let heartbeat_ms = ui_presentation_heartbeat_duration().as_millis();
        assert!(heartbeat_ms >= u128::from(RESIZE_REPAINT_FRAME_MS));
        assert!(heartbeat_ms <= 16);
    }

    #[test]
    fn empty_primary_column_gives_control_card_more_height_than_summary() {
        let weights = primary_column_height_weights(false, false);

        assert_eq!(weights.len(), 2);
        assert!(weights[1] > weights[0]);
    }

    #[test]
    fn viewport_density_switches_with_screen_budget() {
        assert_eq!(
            ViewportDensity::for_size(egui::vec2(760.0, 520.0)),
            ViewportDensity::Dense
        );
        assert_eq!(
            ViewportDensity::for_size(egui::vec2(1366.0, 860.0)),
            ViewportDensity::Regular
        );
        assert_eq!(
            ViewportDensity::for_size(egui::vec2(1600.0, 960.0)),
            ViewportDensity::Spacious
        );
    }

    #[test]
    fn body_layout_uses_width_and_short_viewport_reflow() {
        assert_eq!(body_layout_for_viewport(760.0, 700.0), BodyLayout::Single);
        assert_eq!(
            body_layout_for_viewport(900.0, 700.0),
            BodyLayout::GoldenTwo
        );
        assert_eq!(
            body_layout_for_viewport(1040.0, 560.0),
            BodyLayout::GoldenThree
        );
        assert_eq!(
            body_layout_for_viewport(1120.0, 700.0),
            BodyLayout::GoldenThree
        );
    }

    #[test]
    fn archive_tag_url_gets_release_picker_suggestion() {
        let release_url = release_picker_url_from_archive_input(
            "https://github.com/mindfold-ai/Trellis/archive/refs/tags/v0.6.0-beta.8.zip",
        );

        assert_eq!(
            release_url.as_deref(),
            Some("https://github.com/mindfold-ai/Trellis/releases/tag/v0.6.0-beta.8")
        );
    }

    #[test]
    fn find_assets_message_explains_direct_archive_download() {
        let input = "https://github.com/mindfold-ai/Trellis/archive/refs/tags/v0.6.0-beta.8.zip";
        let status = release_lookup_non_picker_status(
            input,
            backend_contract::resolve_download_intent(input),
        );

        assert!(status.contains("Direct GitHub download detected"));
        assert!(status.contains("Click Download to download this URL"));
        assert!(
            status.contains("https://github.com/mindfold-ai/Trellis/releases/tag/v0.6.0-beta.8")
        );
    }

    #[test]
    fn windows_proxy_server_value_defaults_to_http_proxy_url() {
        assert_eq!(
            proxy_url_from_windows_proxy_server("127.0.0.1:7897").as_deref(),
            Some("http://127.0.0.1:7897")
        );
        assert_eq!(
            proxy_url_from_windows_proxy_server(
                "http=127.0.0.1:7897;https=127.0.0.1:7897;socks=127.0.0.1:7898"
            )
            .as_deref(),
            Some("http://127.0.0.1:7897")
        );
        assert_eq!(
            proxy_url_from_windows_proxy_server("socks=127.0.0.1:7898").as_deref(),
            Some("socks5://127.0.0.1:7898")
        );
    }

    #[test]
    fn registry_proxy_enable_parser_accepts_hex_enabled() {
        assert!(reg_dword_enabled("0x1"));
        assert!(reg_dword_enabled("1"));
        assert!(!reg_dword_enabled("0x0"));
    }
}
