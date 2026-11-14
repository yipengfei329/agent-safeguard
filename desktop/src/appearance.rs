use gpui_kit::component::StyledExt;
use gpui_kit::component::{Icon, IconName, Theme, ThemeMode};
use gpui_kit::*;
pub const BG: u32 = 0x15161B;
pub const SIDEBAR: u32 = 0x101115;
pub const SURFACE: u32 = 0x1B1C22;
pub const BORDER: u32 = 0x2B2D35;
pub const TEXT: u32 = 0xE8E8EF;
pub const MUTED: u32 = 0x93949F;
pub const ACCENT: u32 = 0x8D81F5;
pub fn init(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    Theme::update(cx, |t| {
        t.font_size = px(14.);
        t.radius = px(6.);
        t.radius_lg = px(8.);
        let c = &mut t.colors;
        c.background = rgb(BG).into();
        c.foreground = rgb(TEXT).into();
        c.border = rgb(BORDER).into();
        c.sidebar = rgb(SIDEBAR).into();
        c.sidebar_foreground = rgb(TEXT).into();
        c.sidebar_border = rgb(BORDER).into();
        c.sidebar_accent = rgb(0x24252D).into();
        c.sidebar_accent_foreground = rgb(TEXT).into();
        c.muted = rgb(SURFACE).into();
        c.muted_foreground = rgb(MUTED).into();
        c.accent = rgb(0x282930).into();
        c.accent_foreground = rgb(TEXT).into();
        c.primary = rgb(0x7566DC).into();
        c.primary_hover = rgb(0x8474EE).into();
        c.primary_active = rgb(0x6859CE).into();
        c.primary_foreground = rgb(0xFFFFFF).into();
        c.button_primary = c.primary;
        c.button_primary_hover = c.primary_hover;
        c.button_primary_active = c.primary_active;
        c.button_primary_foreground = c.primary_foreground;
        c.button = rgb(0x24252D).into();
        c.button_hover = rgb(0x2D2E38).into();
        c.button_active = rgb(0x353641).into();
        c.button_foreground = rgb(TEXT).into();
        c.secondary = c.button;
        c.secondary_foreground = c.button_foreground;
        c.secondary_hover = c.button_hover;
        c.secondary_active = c.button_active;
        c.input = rgb(BORDER).into();
        c.caret = rgb(ACCENT).into();
        c.ring = rgb(ACCENT).into();
        c.switch = rgb(0x363843).into();
        c.switch_thumb = rgb(0xECECF1).into();
    });
}
pub fn icon(name: IconName) -> Icon {
    Icon::new(name).size(px(16.)).text_color(rgb(MUTED))
}
pub fn badge(text: impl Into<SharedString>, accent: bool) -> Div {
    div()
        .flex()
        .items_center()
        .gap_2()
        .px_2()
        .py_1()
        .rounded_md()
        .bg(rgb(if accent { 0x29243E } else { 0x25262E }))
        .text_color(rgb(if accent { 0xB6ABFF } else { 0xB0B1BC }))
        .text_size(px(11.))
        .child(text.into())
}
pub fn section(title: &str, description: &str) -> Div {
    div()
        .v_flex()
        .gap_1()
        .mt_3()
        .mb_1()
        .child(
            div()
                .text_size(px(13.))
                .font_weight(FontWeight::SEMIBOLD)
                .child(title.to_owned()),
        )
        .child(
            div()
                .text_size(px(12.))
                .text_color(rgb(MUTED))
                .child(description.to_owned()),
        )
}
pub fn revision(value: &str) -> String {
    value
        .strip_prefix("desktop-")
        .map(|s| format!("r{}", &s[s.len().saturating_sub(6)..]))
        .unwrap_or_else(|| value.to_owned())
}
