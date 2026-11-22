//! Simple vector icons drawn with the painter (no bundled artwork).

use eframe::egui::{self, Color32, Pos2, Rect, Shape, Stroke, Vec2, pos2, vec2};

pub const GREEN: Color32 = Color32::from_rgb(0x00, 0x80, 0x00);
pub const GRAY: Color32 = Color32::from_rgb(0x80, 0x80, 0x80);
pub const STEEL_BLUE: Color32 = Color32::from_rgb(0x46, 0x82, 0xB4);
pub const ACCENT_GREEN: Color32 = Color32::from_rgb(0x44, 0xAA, 0x00);
pub const INDIAN_RED: Color32 = Color32::from_rgb(0xCD, 0x5C, 0x5C);
pub const DARK_GRAY: Color32 = Color32::from_rgb(0xA9, 0xA9, 0xA9);

/// 64x64 window icon: a shield in a teal-to-blue gradient.
pub fn app_icon() -> egui::IconData {
    let n = 64usize;
    let mut rgba = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let fx = (x as f32 + 0.5) / n as f32;
            let fy = (y as f32 + 0.5) / n as f32;
            if in_shield(fx, fy) {
                let t = fy;
                let i = (y * n + x) * 4;
                rgba[i] = (0x1f as f32 * (1.0 - t) + 0x2b as f32 * t) as u8;
                rgba[i + 1] = (0xb5 as f32 * (1.0 - t) + 0x6c as f32 * t) as u8;
                rgba[i + 2] = (0x9e as f32 * (1.0 - t) + 0xd6 as f32 * t) as u8;
                rgba[i + 3] = 255;
            }
        }
    }
    egui::IconData { rgba, width: n as u32, height: n as u32 }
}

fn in_shield(x: f32, y: f32) -> bool {
    let dx = (x - 0.5).abs();
    if !(0.08..=0.95).contains(&y) {
        return false;
    }
    if y < 0.55 {
        dx < 0.40
    } else {
        // Taper to a point at the bottom.
        dx < 0.40 * (0.95 - y) / 0.40
    }
}

fn shield_points(r: Rect) -> Vec<Pos2> {
    let p = |x: f32, y: f32| pos2(r.left() + x * r.width(), r.top() + y * r.height());
    vec![
        p(0.5, 0.02),
        p(0.92, 0.16),
        p(0.90, 0.55),
        p(0.5, 0.98),
        p(0.10, 0.55),
        p(0.08, 0.16),
    ]
}

/// Product mark for the header: a shield with a keyhole.
pub fn logo(painter: &egui::Painter, r: Rect, connected: bool) {
    let fill = if connected { Color32::from_rgb(0x1f, 0xa0, 0x5a) } else { Color32::from_rgb(0x2b, 0x6c, 0xd6) };
    painter.add(Shape::convex_polygon(shield_points(r), fill, Stroke::NONE));
    let c = r.center() - vec2(0.0, r.height() * 0.06);
    painter.circle_filled(c, r.width() * 0.12, Color32::WHITE);
    let w = r.width() * 0.08;
    painter.rect_filled(
        Rect::from_min_max(pos2(c.x - w / 2.0, c.y), pos2(c.x + w / 2.0, c.y + r.height() * 0.26)),
        2.0,
        Color32::WHITE,
    );
}

pub fn plus(painter: &egui::Painter, r: Rect, color: Color32) {
    let c = r.center();
    let h = r.width() * 0.32;
    let s = Stroke::new(r.width() * 0.08, color);
    painter.circle_stroke(c, r.width() * 0.44, Stroke::new(r.width() * 0.05, color));
    painter.line_segment([c - vec2(h, 0.0), c + vec2(h, 0.0)], s);
    painter.line_segment([c - vec2(0.0, h), c + vec2(0.0, h)], s);
}



pub fn gear(painter: &egui::Painter, r: Rect, color: Color32) {
    let c = r.center();
    let ro = r.width() * 0.40;
    let ri = r.width() * 0.29;
    let mut pts = Vec::new();
    let teeth = 8;
    for i in 0..teeth * 4 {
        let a = i as f32 / (teeth * 4) as f32 * std::f32::consts::TAU;
        let rad = if (i / 2) % 2 == 0 { ro } else { ri };
        pts.push(c + Vec2::angled(a) * rad);
    }
    painter.add(Shape::closed_line(pts, Stroke::new(r.width() * 0.06, color)));
    painter.circle_stroke(c, r.width() * 0.12, Stroke::new(r.width() * 0.06, color));
}

pub fn arrow(painter: &egui::Painter, r: Rect, up: bool, color: Color32) {
    let s = Stroke::new(r.width() * 0.10, color);
    let (a, b) = if up { (r.center_bottom(), r.center_top()) } else { (r.center_top(), r.center_bottom()) };
    let a = a + (b - a) * 0.1;
    let b = b - (b - a) * 0.05;
    painter.line_segment([a, b], s);
    let d = if up { 1.0 } else { -1.0 };
    let w = r.width() * 0.30;
    painter.line_segment([b, b + vec2(-w, w * d)], s);
    painter.line_segment([b, b + vec2(w, w * d)], s);
}

pub fn spinner(painter: &egui::Painter, c: Pos2, radius: f32, t: f64, color: Color32) {
    let n = 24;
    let start = (t * 4.0) as f32;
    let pts: Vec<Pos2> = (0..=n)
        .map(|i| {
            let a = start + i as f32 / n as f32 * std::f32::consts::PI * 1.4;
            c + Vec2::angled(a) * radius
        })
        .collect();
    painter.add(Shape::line(pts, Stroke::new(radius * 0.22, color)));
}
