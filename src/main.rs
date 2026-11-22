#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod apps;
mod boot;
mod crypt;
mod datapath;
mod engine;
mod flatpak;
mod netlock;
mod socks;
mod icons;
mod pages;
mod profile;
mod obfs;
mod stats;
mod style;
mod tcpkill;
mod store;
mod tray;
mod tunnel;
mod wfp;
mod winfilter;

use std::path::PathBuf;

/// Main window size from the original layout (390 x 610).
pub const MAIN_W: f32 = 390.0;
pub const MAIN_H: f32 = 610.0;

fn main() -> eframe::Result<()> {
    // Privileged helper mode: run the built-in tunnel engine, no window.
    let all: Vec<String> = std::env::args().collect();
    if let Some(i) = all.iter().position(|a| a == "--tunnel-helper") {
        let conf = all.get(i + 1).map(PathBuf::from).unwrap_or_default();
        std::process::exit(engine::run_helper(&conf));
    }
    if let Some(i) = all.iter().position(|a| a == "--unlock-network") {
        let dir = all.get(i + 1).map(PathBuf::from).unwrap_or_default();
        std::process::exit(engine::run_unlock(&dir));
    }
    let mut screenshot: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        if a == "--screenshot" {
            screenshot = args.next().map(PathBuf::from);
        } else if let Some(v) = a.strip_prefix("--screenshot=") {
            screenshot = Some(PathBuf::from(v));
        }
    }

    let mut viewport = eframe::egui::ViewportBuilder::default()
        .with_title("Secure Tunnel")
        .with_inner_size([MAIN_W, MAIN_H])
        .with_decorations(!style::CUSTOM_TITLE)
        .with_resizable(!style::CUSTOM_TITLE)
        .with_maximize_button(false)
        .with_min_inner_size([320.0, 500.0])
        .with_icon(icons::app_icon());
    // "Start minimized": open straight into the tray / menu bar.
    if screenshot.is_none() && store::Settings::load().start_minimized {
        viewport = viewport.with_visible(false);
    }
    if screenshot.is_some() {
        viewport = viewport.with_active(false);
        #[cfg(windows)]
        {
            viewport = viewport.with_window_level(eframe::egui::WindowLevel::AlwaysOnBottom);
        }
    }

    #[allow(unused_mut)]
    let mut options = eframe::NativeOptions { viewport, ..Default::default() };
    #[cfg(target_os = "macos")]
    if screenshot.is_some() {
        options.event_loop_builder = Some(Box::new(|b| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            b.with_activate_ignoring_other_apps(false);
        }));
    }

    eframe::run_native(
        "Secure Tunnel",
        options,
        Box::new(move |cc| Ok(Box::new(app::App::new(cc, screenshot)))),
    )
}
