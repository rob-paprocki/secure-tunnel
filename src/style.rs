//! Look of the original, measured from screenshots of WireSock Secure Connect
//! 3.8.2.1 running (checks/original/*.png): colours, the custom title bar,
//! the top tab bar of the preferences window and its settings cards.

use eframe::egui::{self, Align2, Color32, CornerRadius, FontId, Rect, Sense, Stroke, Vec2, pos2, vec2};

static DARK: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Called each frame with the theme egui is drawing in.
pub fn set_dark(dark: bool) {
    DARK.store(dark, std::sync::atomic::Ordering::Relaxed);
}

pub fn is_dark() -> bool {
    DARK.load(std::sync::atomic::Ordering::Relaxed)
}

fn pick(dark: Color32, light: Color32) -> Color32 {
    if is_dark() { dark } else { light }
}

/// Dark colours are the original's (#202020 window, #2B2B2B cards), with text
/// brightened for easier reading; light colours follow Windows 11's light theme.
pub fn bg() -> Color32 {
    pick(Color32::from_rgb(0x20, 0x20, 0x20), Color32::from_rgb(0xF3, 0xF3, 0xF3))
}
pub fn card_fill() -> Color32 {
    pick(Color32::from_rgb(0x2B, 0x2B, 0x2B), Color32::WHITE)
}
pub fn card_border() -> Color32 {
    pick(Color32::from_rgb(0x1D, 0x1D, 0x1D), Color32::from_rgb(0xE1, 0xE1, 0xE1))
}
/// Main text.
pub fn text() -> Color32 {
    pick(Color32::from_rgb(0xF5, 0xF5, 0xF5), Color32::from_rgb(0x1A, 0x1A, 0x1A))
}
/// Secondary text (descriptions): 7:1 contrast or better on cards in both themes.
pub fn sub() -> Color32 {
    pick(Color32::from_rgb(0xD0, 0xD0, 0xD0), Color32::from_rgb(0x4A, 0x4A, 0x4A))
}
/// Status and label text.
pub fn muted() -> Color32 {
    pick(Color32::from_rgb(0xC4, 0xC4, 0xC4), Color32::from_rgb(0x55, 0x55, 0x55))
}
pub fn link() -> Color32 {
    pick(Color32::from_rgb(0x8A, 0xD2, 0xE4), Color32::from_rgb(0x00, 0x5F, 0xB8))
}
pub fn icon() -> Color32 {
    pick(Color32::from_rgb(0xA6, 0xA6, 0xA6), Color32::from_rgb(0x5A, 0x5A, 0x5A))
}
pub fn title_text() -> Color32 {
    pick(Color32::from_rgb(0xEC, 0xEC, 0xEC), Color32::from_rgb(0x1A, 0x1A, 0x1A))
}
pub fn tab_selected() -> Color32 {
    pick(Color32::from_rgb(0x2E, 0x2E, 0x2E), Color32::from_rgb(0xE4, 0xE4, 0xE4))
}
pub fn splitter() -> Color32 {
    pick(Color32::from_rgb(0x5E, 0x5E, 0x5E), Color32::from_rgb(0xC8, 0xC8, 0xC8))
}
pub fn list_selected() -> Color32 {
    pick(Color32::from_rgb(0x4C, 0x4C, 0x4C), Color32::from_rgb(0xCC, 0xE0, 0xF4))
}
pub fn hover() -> Color32 {
    pick(Color32::from_rgb(0x3D, 0x3D, 0x3D), Color32::from_rgb(0xE0, 0xE0, 0xE0))
}
pub fn border() -> Color32 {
    pick(Color32::from_rgb(0x55, 0x55, 0x55), Color32::from_rgb(0xC0, 0xC0, 0xC0))
}
pub fn disabled() -> Color32 {
    pick(Color32::from_rgb(0x6A, 0x6A, 0x6A), Color32::from_rgb(0xA8, 0xA8, 0xA8))
}
/// Toggle switch "on" fill (same in both themes).
pub const ACCENT: Color32 = Color32::from_rgb(0x00, 0x63, 0xB1);
pub const TAB_LINE: Color32 = Color32::from_rgb(0x3B, 0x76, 0x95);
pub const CLOSE_HOVER: Color32 = Color32::from_rgb(0xC4, 0x2B, 0x1C);
/// Title bar height and caption-button width.
pub const TITLE_H: f32 = 31.0;
pub const CAPTION_W: f32 = 40.0;
/// Settings card height and gap (50 px tall, 8 px apart).
pub const CARD_H: f32 = 50.0;
pub const CARD_GAP: f32 = 8.0;

/// The app draws its own title bar on Windows and Linux, like the original;
/// macOS keeps its native window buttons.
pub const CUSTOM_TITLE: bool = !cfg!(target_os = "macos");

/// Window colours and readable text for one theme.
pub fn apply_theme(v: &mut egui::Visuals, dark: bool) {
    set_dark(dark);
    v.panel_fill = bg();
    v.window_fill = bg();
    v.extreme_bg_color = if dark { card_border() } else { Color32::WHITE };
    v.faint_bg_color = card_fill();
    v.selection.bg_fill = ACCENT;
    v.selection.stroke = Stroke::new(1.0_f32, Color32::WHITE);
    v.hyperlink_color = link();
    v.widgets.inactive.weak_bg_fill = if dark { card_fill() } else { Color32::from_rgb(0xFB, 0xFB, 0xFB) };
    v.widgets.inactive.bg_fill = v.widgets.inactive.weak_bg_fill;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, border());
    // egui's default label grey is too faint; use the palette's text colours.
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, text());
    v.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, text());
    v.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, text());
    v.widgets.active.fg_stroke = Stroke::new(1.0_f32, text());
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, border());
    v.weak_text_color = Some(muted());
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Caption {
    Minimize,
    Maximize,
    Close,
}

/// Draws the title bar across the top of `rect`; dragging it moves the window.
pub fn title_bar(ui: &mut egui::Ui, rect: Rect, title: &str, maximize: bool) -> Option<Caption> {
    let p = ui.painter().clone();
    p.rect_filled(rect, 0.0, bg());
    crate::icons::logo(&p, Rect::from_center_size(rect.left_center() + vec2(13.0, 0.0), vec2(15.0, 16.0)), false);
    p.text(rect.left_center() + vec2(26.0, 0.0), Align2::LEFT_CENTER, title, FontId::proportional(12.5), title_text());
    let buttons: Vec<Caption> = if maximize { vec![Caption::Minimize, Caption::Maximize, Caption::Close] } else { vec![Caption::Minimize, Caption::Close] };
    let mut clicked = None;
    let mut x = rect.right() - CAPTION_W * buttons.len() as f32;
    let drag_rect = Rect::from_min_max(rect.min, pos2(x, rect.bottom()));
    let drag = ui.interact(drag_rect, ui.id().with("title_drag"), Sense::click_and_drag());
    if drag.drag_started() {
        ui.ctx().send_viewport_cmd(egui::ViewportCommand::StartDrag);
    }
    if drag.double_clicked() && maximize {
        clicked = Some(Caption::Maximize);
    }
    for b in buttons {
        let r = Rect::from_min_size(pos2(x, rect.top()), vec2(CAPTION_W, rect.height()));
        let resp = ui.interact(r, ui.id().with(("caption", b as u8)), Sense::click());
        if resp.hovered() {
            p.rect_filled(r, 0.0, if b == Caption::Close { CLOSE_HOVER } else { hover() });
        }
        let c = r.center();
        let s = Stroke::new(1.0_f32, if resp.hovered() && b == Caption::Close { Color32::WHITE } else { text() });
        match b {
            Caption::Minimize => {
                p.line_segment([c - vec2(5.0, 0.0), c + vec2(5.0, 0.0)], s);
            }
            Caption::Maximize => {
                p.rect_stroke(Rect::from_center_size(c, vec2(10.0, 10.0)), 0.0, s, egui::StrokeKind::Middle);
            }
            Caption::Close => {
                p.line_segment([c - vec2(5.0, 5.0), c + vec2(5.0, 5.0)], s);
                p.line_segment([c + vec2(-5.0, 5.0), c + vec2(5.0, -5.0)], s);
            }
        }
        if resp.clicked() {
            clicked = Some(b);
        }
        x += CAPTION_W;
    }
    clicked
}

/// Carries out a title-bar button press for the current viewport.
pub fn run_caption(ctx: &egui::Context, c: Caption) {
    match c {
        Caption::Minimize => ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true)),
        Caption::Maximize => {
            let max = ctx.input(|i| i.viewport().maximized.unwrap_or(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Maximized(!max));
        }
        Caption::Close => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
    }
}

/// Windows-style toggle: 44 x 20 pill, blue when on, white with a dark knob when off.
pub fn switch(ui: &mut egui::Ui, on: &mut bool) -> egui::Response {
    let (rect, mut resp) = ui.allocate_exact_size(vec2(44.0, 20.0), Sense::click());
    if resp.clicked() {
        *on = !*on;
        resp.mark_changed();
    }
    let t = ui.ctx().animate_bool_with_time(resp.id, *on, 0.12);
    let p = ui.painter();
    let r = CornerRadius::same(10);
    if *on {
        p.rect_filled(rect, r, ACCENT);
    } else if is_dark() {
        p.rect_filled(rect, r, Color32::WHITE);
    } else {
        p.rect(rect, r, Color32::WHITE, Stroke::new(1.0_f32, Color32::from_gray(0x80)), egui::StrokeKind::Inside);
    }
    let x = egui::lerp(rect.left() + 10.0..=rect.right() - 10.0, t);
    let knob = if *on { Color32::WHITE } else if is_dark() { Color32::from_gray(0x33) } else { Color32::from_gray(0x5A) };
    p.circle_filled(pos2(x, rect.center().y), 6.0, knob);
    resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// One settings card: title and description on the left, `right` on the right.
pub fn card<R>(ui: &mut egui::Ui, title: &str, desc: &str, right: impl FnOnce(&mut egui::Ui) -> R) -> R {
    let width = ui.available_width();
    let desc_lines = if desc.is_empty() { 0.0 } else { (desc.len() as f32 * 6.2 / (width - 160.0).max(200.0)).ceil().max(1.0) };
    let height = (CARD_H + (desc_lines - 1.0).max(0.0) * 13.0).max(CARD_H);
    let (rect, _) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let p = ui.painter().clone();
    p.rect(rect, CornerRadius::same(4), card_fill(), Stroke::new(1.0_f32, card_border()), egui::StrokeKind::Inside);
    let text_w = rect.width() - 170.0;
    let mut child = ui.new_child(egui::UiBuilder::new().max_rect(Rect::from_min_size(rect.min + vec2(10.0, 6.0), vec2(text_w, height - 8.0))));
    child.spacing_mut().item_spacing.y = 1.0;
    child.label(egui::RichText::new(title).size(17.0).color(text()));
    if !desc.is_empty() {
        child.label(egui::RichText::new(desc).size(12.5).color(sub()));
    }
    let right_rect = Rect::from_min_max(pos2(rect.right() - 160.0, rect.top()), pos2(rect.right() - 12.0, rect.bottom()));
    let mut rui = ui.new_child(egui::UiBuilder::new().max_rect(right_rect).layout(egui::Layout::right_to_left(egui::Align::Center)));
    let out = right(&mut rui);
    // Cards sit 8 px apart, like the original's.
    ui.add_space((CARD_GAP - ui.spacing().item_spacing.y).max(0.0));
    out
}

/// A card with an On/Off switch. Returns true when it was flipped.
pub fn card_toggle(ui: &mut egui::Ui, on: &mut bool, title: &str, desc: &str) -> bool {
    card(ui, title, desc, |ui| {
        let changed = switch(ui, on).changed();
        ui.label(egui::RichText::new(if *on { "On" } else { "Off" }).size(15.0).color(text()));
        changed
    })
}

/// A card with an On/Off switch and a chevron that folds out details below
/// it (closed at first, as in the original). Returns (flipped, open).
pub fn card_toggle_fold(ui: &mut egui::Ui, id: &str, on: &mut bool, title: &str, desc: &str) -> (bool, bool) {
    let key = egui::Id::new(("fold", id));
    let mut open = ui.ctx().data(|d| d.get_temp::<bool>(key)).unwrap_or(false);
    let changed = card(ui, title, desc, |ui| {
        let (r, resp) = ui.allocate_exact_size(vec2(22.0, 22.0), Sense::click());
        let c = r.center();
        let s = Stroke::new(1.3_f32, text());
        let d = if open { -3.0 } else { 3.0 };
        ui.painter().line_segment([c + vec2(-5.0, -d), c + vec2(0.0, d)], s);
        ui.painter().line_segment([c + vec2(0.0, d), c + vec2(5.0, -d)], s);
        if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
            open = !open;
        }
        ui.add_space(6.0);
        let changed = switch(ui, on).changed();
        ui.label(egui::RichText::new(if *on { "On" } else { "Off" }).size(15.0).color(text()));
        changed
    });
    ui.ctx().data_mut(|d| d.insert_temp(key, open));
    (changed, open)
}

/// A group heading inside a page (the original's expander cards).
pub fn group(ui: &mut egui::Ui, title: &str, desc: &str) {
    ui.add_space(6.0);
    ui.label(egui::RichText::new(title).size(17.0).color(text()));
    if !desc.is_empty() {
        ui.label(egui::RichText::new(desc).size(12.5).color(sub()));
    }
    ui.add_space(4.0);
}

// ---------- tab icons (simple vector drawings) ----------

pub fn tab_icon(p: &egui::Painter, r: Rect, which: crate::app::Tab, color: Color32) {
    use crate::app::Tab;
    let s = Stroke::new(2.0_f32, color);
    let c = r.center();
    let rad = r.width() * 0.42;
    match which {
        Tab::Profiles => {
            p.circle_stroke(c, rad, s);
            p.line_segment([c - vec2(rad, 0.0), c + vec2(rad, 0.0)], s);
            let pts: Vec<_> = (0..=20).map(|i| {
                let a = std::f32::consts::PI * (i as f32 / 20.0 - 0.5);
                c + vec2(a.sin() * rad * 0.45, a.cos() * -rad)
            }).collect();
            p.add(egui::Shape::line(pts.clone(), s));
            p.add(egui::Shape::line(pts.iter().map(|q| pos2(2.0 * c.x - q.x, q.y)).collect(), s));
        }
        Tab::General => crate::icons::gear(p, r, color),
        Tab::Network => {
            p.circle_stroke(c - vec2(3.0, 3.0), rad * 0.8, s);
            crate::icons::gear(p, Rect::from_center_size(c + vec2(rad * 0.55, rad * 0.55), Vec2::splat(r.width() * 0.5)), color);
        }
        Tab::Security => {
            let pts = vec![
                c + vec2(0.0, -rad),
                c + vec2(rad * 0.85, -rad * 0.65),
                c + vec2(rad * 0.75, rad * 0.3),
                c + vec2(0.0, rad),
                c + vec2(-rad * 0.75, rad * 0.3),
                c + vec2(-rad * 0.85, -rad * 0.65),
            ];
            p.add(egui::Shape::closed_line(pts, s));
            p.rect_filled(Rect::from_center_size(c + vec2(0.0, 2.0), vec2(8.0, 7.0)), 1.0, color);
            p.circle_stroke(c - vec2(0.0, 3.0), 3.0, Stroke::new(1.6_f32, color));
        }
        Tab::Advanced => {
            crate::icons::gear(p, Rect::from_center_size(c + vec2(-4.0, 3.0), Vec2::splat(r.width() * 0.7)), color);
            crate::icons::gear(p, Rect::from_center_size(c + vec2(8.0, -8.0), Vec2::splat(r.width() * 0.42)), color);
        }
        Tab::Logs => log_doc(p, r, color),
        Tab::Report => {
            p.circle_stroke(c + vec2(-4.0, -4.0), rad * 0.35, s);
            p.add(egui::Shape::line(
                (0..=12).map(|i| {
                    let a = std::f32::consts::PI * (1.0 + i as f32 / 12.0);
                    c + vec2(-4.0 + a.cos() * rad * 0.6, rad * 0.9 + a.sin() * rad * 0.6)
                }).collect(),
                s,
            ));
            p.rect_stroke(Rect::from_min_size(c + vec2(2.0, -rad), vec2(rad * 0.95, rad * 0.75)), 2.0, s, egui::StrokeKind::Middle);
        }
        Tab::About => {
            p.circle_stroke(c, rad, s);
            p.circle_filled(c - vec2(0.0, rad * 0.45), 2.0, color);
            p.line_segment([c - vec2(0.0, rad * 0.15), c + vec2(0.0, rad * 0.55)], Stroke::new(2.5_f32, color));
        }
    }
}

/// Document with a "LOG" label, as on the original's Logs buttons.
pub fn log_doc(p: &egui::Painter, r: Rect, color: Color32) {
    let s = Stroke::new(r.width() * 0.06, color);
    let page = Rect::from_min_max(r.min + r.size() * vec2(0.2, 0.08), r.min + r.size() * vec2(0.8, 0.92));
    let fold = r.width() * 0.18;
    p.add(egui::Shape::closed_line(
        vec![
            page.left_top(),
            pos2(page.right() - fold, page.top()),
            pos2(page.right(), page.top() + fold),
            page.right_bottom(),
            page.left_bottom(),
        ],
        s,
    ));
    let label = Rect::from_min_max(pos2(r.left() + r.width() * 0.08, r.top() + r.height() * 0.45), pos2(r.right() - r.width() * 0.08, r.top() + r.height() * 0.75));
    p.rect_filled(label, 2.0, color);
    p.text(label.center(), Align2::CENTER_CENTER, "LOG", FontId::proportional(label.height() * 0.8), bg());
}

/// Bug, for "Report issue".
pub fn bug(p: &egui::Painter, r: Rect, color: Color32) {
    let c = r.center() + vec2(0.0, r.height() * 0.06);
    let body = Rect::from_center_size(c, vec2(r.width() * 0.42, r.height() * 0.62));
    p.rect_filled(body, CornerRadius::same((r.width() * 0.2) as u8), color);
    p.line_segment([body.center_top(), body.center_bottom()], Stroke::new(1.5_f32, bg()));
    let s = Stroke::new(r.width() * 0.06, color);
    for k in [-0.18f32, 0.05, 0.25] {
        let y = c.y + k * r.height();
        p.line_segment([pos2(body.left(), y), pos2(r.left() + r.width() * 0.12, y + k * 12.0)], s);
        p.line_segment([pos2(body.right(), y), pos2(r.right() - r.width() * 0.12, y + k * 12.0)], s);
    }
    p.circle_filled(pos2(c.x, body.top() - r.height() * 0.06), r.width() * 0.13, color);
}
