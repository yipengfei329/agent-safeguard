use gpui_kit::component::{Icon, IconName, Theme, ThemeMode};
use gpui_kit::component::{
    Selectable,
    button::{Button, ButtonVariants},
};
use gpui_kit::*;
pub const BG: u32 = 0x15161B;
pub const SIDEBAR: u32 = 0x101115;
pub const SURFACE: u32 = 0x1B1C22;
pub const SURFACE_SUBTLE: u32 = 0x17181E;
pub const BORDER: u32 = 0x2B2D35;
pub const BORDER_WARN: u32 = 0x6B4F24;
pub const TEXT: u32 = 0xE8E8EF;
pub const MUTED: u32 = 0x93949F;
pub const ACCENT: u32 = 0x8D81F5;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Neutral,
    Accent,
    Success,
    Warning,
}

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
/// A full-width content row keeps icons and labels on shared leading edges.
/// Styling the Button root alone leaves GPUI Kit's inner label centered.
pub fn navigation_item(
    id: &'static str,
    label: &'static str,
    glyph: IconName,
    active: bool,
) -> Button {
    Button::new(id)
        .ghost()
        .accessibility_label(label)
        .selected(active)
        .w_full()
        .h(px(42.))
        .px_3()
        .rounded(px(8.))
        .bg(rgb(if active { 0x2A2B36 } else { SIDEBAR }))
        .text_color(rgb(TEXT))
        .child(
            div()
                .w_full()
                .flex()
                .items_center()
                .gap(px(11.))
                .child(
                    div()
                        .w(px(22.))
                        .flex_shrink_0()
                        .flex()
                        .items_center()
                        .justify_center()
                        .child(Icon::new(glyph).size(px(18.)).text_color(rgb(if active {
                            0xC3B9FF
                        } else {
                            0x9B9DAA
                        }))),
                )
                .child(
                    div()
                        .text_size(px(14.))
                        .font_weight(if active {
                            FontWeight::SEMIBOLD
                        } else {
                            FontWeight::NORMAL
                        })
                        .child(label),
                ),
        )
}
pub fn pill(text: impl Into<SharedString>, tone: Tone) -> Div {
    let (bg, fg) = match tone {
        Tone::Neutral => (0x25262E, 0xB0B1BC),
        Tone::Accent => (0x29243E, 0xB6ABFF),
        Tone::Success => (0x1B3129, 0x7CE2B3),
        Tone::Warning => (0x362A18, 0xF5C97B),
    };
    div()
        .flex()
        .items_center()
        .gap_2()
        .px_2()
        .py_1()
        .rounded_md()
        .bg(rgb(bg))
        .text_color(rgb(fg))
        .text_size(px(11.))
        .font_weight(FontWeight::MEDIUM)
        .child(text.into())
}
