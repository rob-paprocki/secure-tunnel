//! Main window, shared state and dialogs. Settings pages are in `pages.rs`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use eframe::egui::{
    self, Align, Align2, Color32, FontId, Layout, Rect, RichText, Sense, UiBuilder, pos2, vec2,
};

use crate::icons;
use crate::profile::{self, Profile};
use crate::store::{LogLevel, ProfileStore, Settings, Theme};
use crate::tunnel::{self, Cmd, ConnectRequest, Shared, State, Tunnel};

/// Font sizes from the original (S=12, M=16, L=18, XS=10).
pub const FS_XS: f32 = 10.0;
pub const FS_S: f32 = 12.0;
pub const FS_M: f32 = 16.0;
pub const FS_L: f32 = 18.0;

/// Frames drawn before the `--screenshot` picture is taken.
const SHOT_FRAME: u64 = 120;

// ---------- formats (same rules as the original) ----------

/// Bits per second (the service multiplies byte deltas by 8), divided by 1024 per unit step, one decimal.
pub fn fmt_speed(bytes: u64) -> String {
    let units = ["bps", "kbps", "mbps", "gbps", "tbps"];
    scaled(bytes, &units, 1)
}

/// Byte totals, divided by 1024 per unit step, up to two decimals.
pub fn fmt_size(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    scaled(bytes, &units, 2)
}

fn scaled(bytes: u64, units: &[&str], decimals: usize) -> String {
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < units.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    let mut s = format!("{v:.decimals$}");
    if s.contains('.') {
        s = s.trim_end_matches('0').trim_end_matches('.').to_string();
    }
    format!("{s} {}", units[i])
}

/// `hh:mm:ss`, with a `Nd ` prefix past one day.
pub fn fmt_uptime(d: Duration) -> String {
    let t = d.as_secs();
    let days = t / 86_400;
    let (h, m, s) = ((t % 86_400) / 3600, (t % 3600) / 60, t % 60);
    if days > 0 { format!("{days}d {h:02}:{m:02}:{s:02}") } else { format!("{h:02}:{m:02}:{s:02}") }
}

// ---------- state ----------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tab {
    Profiles,
    General,
    Network,
    Security,
    Advanced,
    Logs,
    Report,
    About,
}

impl Tab {
    pub const ALL: [Tab; 8] =
        [Tab::Profiles, Tab::General, Tab::Network, Tab::Security, Tab::Advanced, Tab::Logs, Tab::Report, Tab::About];
    pub fn label(self) -> &'static str {
        match self {
            Tab::Profiles => "Profiles",
            Tab::General => "General",
            Tab::Network => "Network",
            Tab::Security => "Security",
            Tab::Advanced => "Advanced",
            Tab::Logs => "Logs",
            Tab::Report => "Report",
            Tab::About => "About",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EditMode {
    Form,
    Text,
}

pub struct Editor {
    /// None for a profile that isn't saved yet.
    pub original: Option<String>,
    pub name: String,
    pub mode: EditMode,
    pub profile: Profile,
    pub text: String,
    pub baseline: String,
    pub errors: Vec<(&'static str, String)>,
    pub message: String,
}

impl Editor {
    pub fn new(original: Option<String>, name: String, profile: Profile, mode: EditMode) -> Self {
        let text = profile.to_conf();
        Editor { original, name, mode, baseline: text.clone(), text, profile, errors: Vec::new(), message: String::new() }
    }
    pub fn current_text(&self) -> String {
        match self.mode {
            EditMode::Form => self.profile.to_conf(),
            EditMode::Text => self.text.clone(),
        }
    }
    pub fn dirty(&self) -> bool {
        self.current_text() != self.baseline || self.original.is_none()
    }
}

pub enum Action {
    Disconnect,
    SwitchProfile(String),
    Remove(String),
    DiscardEditor,
    UnlockNetwork,
    ExitApp,
}

pub enum Dialog {
    Confirm { title: String, text: String, action: Action },
    Message { title: String, text: String },
    Rename { old: String, new: String, error: String },
}

pub struct App {
    pub store: ProfileStore,
    pub settings: Settings,
    pub tunnel: Tunnel,
    pub snap: Shared,
    pub live: bool,
    pub screenshot: Option<PathBuf>,
    pub frame: u64,
    pub shot_sent: bool,
    pub settings_open: bool,
    pub tab: Tab,
    pub profiles_sel: String,
    pub editor: Option<Editor>,
    pub dialog: Option<Dialog>,
    pub toast: Option<(String, Instant)>,
    pub log_view_level: LogLevel,
    pub autostart_error: String,
    /// "Select process" window for the app lists.
    pub picker: Option<crate::pages::Picker>,
    /// "Manage combo box domains" window: the list being edited, one per line.
    pub domains_edit: Option<String>,
    /// A startup-connection change waiting for the administrator prompt.
    pub boot_job: Option<std::sync::mpsc::Receiver<Result<bool, String>>>,
    /// The tunnel file last written for startup connection.
    pub boot_text: String,
    /// Test aid: with --screenshot, SECURE_TUNNEL_SHOT_TAB=<tab> pictures the preferences window instead.
    pub shot_tab: Option<Tab>,
    /// Test aid: with --screenshot, SECURE_TUNNEL_SHOT_CONNECTED pictures a connected tunnel.
    shot_connected: Option<Instant>,
    /// The scale the windows were last sized for.
    sized_zoom: f32,
    /// Test aid: SECURE_TUNNEL_SHOT_SCALES=1.6,0.8 changes the scale during a screenshot run.
    shot_scales: Vec<f32>,
    /// Tray / menu-bar icon (None when there is none, e.g. screenshot runs).
    pub tray: Option<Arc<crate::tray::Control>>,
    pub window: crate::tray::NativeWindow,
    pub tray_refresh: Instant,
}

impl App {
    pub fn new(cc: &eframe::CreationContext<'_>, screenshot: Option<PathBuf>) -> Self {
        let live = screenshot.is_none();
        let settings = Settings::load();
        let mut store = ProfileStore::new(crate::store::base_dir().join("profiles"));
        store.encrypt = settings.profile_encryption;
        let mut settings = settings;
        if screenshot.is_none() {
            // The switch shows what the system really has set up.
            settings.connect_at_boot = crate::boot::installed();
        }
        let tunnel = Tunnel::new(live);
        apply_style(&cc.egui_ctx, &settings);
        let mut app = App {
            snap: tunnel.snapshot(),
            store,
            tunnel,
            live,
            screenshot,
            frame: 0,
            shot_sent: false,
            settings_open: false,
            tab: Tab::Profiles,
            profiles_sel: String::new(),
            editor: None,
            dialog: None,
            toast: None,
            log_view_level: settings.log_level,
            autostart_error: String::new(),
            picker: None,
            domains_edit: None,
            boot_job: None,
            boot_text: String::new(),
            shot_tab: None,
            shot_connected: None,
            sized_zoom: 0.0,
            shot_scales: Vec::new(),
            tray: None,
            window: crate::tray::NativeWindow::from_cc(cc),
            tray_refresh: Instant::now() - Duration::from_secs(10),
            settings,
        };
        if app.settings.active_profile.is_empty() || !app.store.exists(&app.settings.active_profile) {
            app.settings.active_profile = app.store.names.first().cloned().unwrap_or_default();
        }
        app.profiles_sel = app.settings.active_profile.clone();
        if !live {
            if let Ok(v) = std::env::var("SECURE_TUNNEL_SHOT_SCALES") {
                app.shot_scales = v.split(',').filter_map(|x| x.trim().parse().ok()).collect();
            }
            if std::env::var("SECURE_TUNNEL_SHOT_CONNECTED").is_ok() {
                app.shot_connected = Some(Instant::now() - std::time::Duration::from_secs(3725));
            }
            // Test aid: SECURE_TUNNEL_SHOT_THEME=light|dark pictures one theme.
            if let Ok(t) = std::env::var("SECURE_TUNNEL_SHOT_THEME") {
                cc.egui_ctx.set_theme(if t.eq_ignore_ascii_case("light") {
                    egui::ThemePreference::Light
                } else {
                    egui::ThemePreference::Dark
                });
            }
            if let Ok(t) = std::env::var("SECURE_TUNNEL_SHOT_TAB") {
                app.shot_tab = Tab::ALL.iter().copied().find(|x| x.label().eq_ignore_ascii_case(&t));
                if let Some(t) = app.shot_tab {
                    app.settings_open = true;
                    app.tab = t;
                    if t == Tab::Profiles && std::env::var("SECURE_TUNNEL_SHOT_EDIT").is_ok() {
                        let n = app.settings.active_profile.clone();
                        app.open_editor(&n, EditMode::Form);
                    }
                }
            }
        }
        if (app.settings.ui_scale - 1.0).abs() > 0.01 {
            apply_scale(&cc.egui_ctx, app.settings.ui_scale);
        }
        if live {
            let control = Arc::new(crate::tray::Control {
                shared: app.tunnel.shared.clone(),
                sender: std::sync::Mutex::new(app.tunnel.sender()),
                // Filled now as well, for a window that starts hidden in the tray.
                prepared: std::sync::Mutex::new(
                    app.store.names.iter().filter_map(|n| app.build_request_for(n).ok().map(|r| (n.clone(), r))).collect(),
                ),
                menu: std::sync::Mutex::new(crate::tray::MenuModel {
                    profiles: app.store.names.clone(),
                    active: app.settings.active_profile.clone(),
                    hide_import: app.settings.hide_import_button,
                }),
                requests: std::sync::Mutex::new(Default::default()),
                visible: std::sync::atomic::AtomicBool::new(!app.settings.start_minimized),
                prefs: std::sync::Mutex::new(Default::default()),
                ctx: cc.egui_ctx.clone(),
                window: app.window,
                exit_requested: std::sync::atomic::AtomicBool::new(false),
            });
            if crate::tray::start(control.clone()) {
                app.tray = Some(control);
            }
            // macOS: ask for the Network Extension approval once, on first launch,
            // so per-app routing is ready before it's first needed.
            #[cfg(target_os = "macos")]
            if crate::apps::mac_controller().is_some() {
                let marker = crate::store::base_dir().join("netext-approved");
                if !marker.exists() {
                    let shared = app.tunnel.shared.clone();
                    std::thread::spawn(move || {
                        let r = crate::apps::mac_netext(&["install".to_string()]);
                        if let Ok(mut s) = shared.lock() {
                            match &r {
                                Ok(t) => s.log(LogLevel::Info, format!("Per-app routing extension: {t}")),
                                Err(e) => s.log(LogLevel::Warning, format!("Per-app routing extension: {e}")),
                            }
                        }
                        if matches!(&r, Ok(t) if t.starts_with("installed")) {
                            let _ = std::fs::create_dir_all(crate::store::base_dir());
                            let _ = std::fs::write(marker, b"1");
                        }
                    });
                }
            }
            if app.settings.start_minimized {
                if app.tray.is_some() {
                    app.window.hide(&cc.egui_ctx);
                } else {
                    cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    cc.egui_ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
                }
            }
            if app.settings.auto_connect && !app.settings.active_profile.is_empty() {
                app.connect();
            }
        }
        app
    }

    pub fn save_settings(&self) {
        if self.live {
            self.settings.save();
        }
    }

    pub fn toast(&mut self, s: impl Into<String>) {
        self.toast = Some((s.into(), Instant::now()));
    }

    pub fn message(&mut self, title: &str, text: impl Into<String>) {
        self.dialog = Some(Dialog::Message { title: title.into(), text: text.into() });
    }

    pub fn log(&self, level: LogLevel, text: impl Into<String>) {
        if let Ok(mut s) = self.tunnel.shared.lock() {
            s.log(level, text);
        }
    }

    pub fn is_busy(&self) -> bool {
        matches!(self.snap.state, State::Connected | State::Connecting | State::Disconnecting)
    }

    /// Global split tunnelling replaces the profile's when it is on and either
    /// "override" is set or the profile has no split tunnelling of its own.
    pub fn split_override(&self, p: &Profile) -> Option<tunnel::SplitOverride> {
        let s = &self.settings;
        if !s.global_split_tunnel {
            return None;
        }
        let profile_has = p.has_split_tunnel() || !default_allowed(&p.allowed_ips);
        if s.override_profile_split || !profile_has {
            Some(tunnel::SplitOverride {
                allowed_ips: s.global_allowed_ips.clone(),
                disallowed_ips: s.global_disallowed_ips.clone(),
                allowed_apps: s.global_allowed_apps.clone(),
                disallowed_apps: s.global_disallowed_apps.clone(),
            })
        } else {
            None
        }
    }

    pub fn split_status(&self) -> String {
        let p = self.store.load(&self.settings.active_profile).ok();
        let profile_has = p.as_ref().map(|p| p.has_split_tunnel() || !default_allowed(&p.allowed_ips)).unwrap_or(false);
        let s = &self.settings;
        if !profile_has && !s.global_split_tunnel {
            return "Split-tunneling: Not set".into();
        }
        if s.global_split_tunnel && (s.override_profile_split || !profile_has) {
            let global_has = !s.global_disallowed_ips.trim().is_empty()
                || !s.global_allowed_apps.trim().is_empty()
                || !s.global_disallowed_apps.trim().is_empty()
                || !default_allowed(&s.global_allowed_ips);
            return if global_has { "Split-tunneling: On (global)".into() } else { "Split-tunneling: Off (global)".into() };
        }
        "Split-tunneling: On (profile)".into()
    }

    /// The request that connects the selected profile with the current settings.
    /// Once a new scale is in effect, sizes the windows in its points. Sizing in
    /// the same frame as the change used the old scale: shrinking left a big
    /// window around small contents, growing cut contents off.
    fn fit_windows(&mut self, ctx: &egui::Context) {
        let z = ctx.zoom_factor();
        if (z - self.sized_zoom).abs() < 0.001 {
            return;
        }
        let first = self.sized_zoom == 0.0;
        self.sized_zoom = z;
        if first && (z - 1.0).abs() < 0.001 {
            return;
        }
        if self.shot_tab.is_none() {
            ctx.send_viewport_cmd_to(egui::ViewportId::ROOT, egui::ViewportCommand::InnerSize(vec2(crate::MAIN_W, crate::MAIN_H)));
        }
        ctx.send_viewport_cmd_to(egui::ViewportId::from_hash_of("preferences"), egui::ViewportCommand::InnerSize(vec2(800.0, 610.0)));
    }

    pub fn build_request(&self) -> Result<ConnectRequest, (&'static str, String)> {
        self.build_request_for(&self.settings.active_profile)
    }

    pub fn build_request_for(&self, name: &str) -> Result<ConnectRequest, (&'static str, String)> {
        let name = name.to_string();
        if name.is_empty() {
            return Err(("Select profile", "Choose a connection profile first.".into()));
        }
        let p = self.store.load(&name).map_err(|e| ("Failed to load profile", e))?;
        if let Some((field, msg)) = p.validate().first() {
            return Err(("Invalid profile", format!("{field}: {msg}")));
        }
        Ok(ConnectRequest {
            name,
            split_override: self.split_override(&p),
            profile: p,
            timeout_secs: self.settings.connection_timeout,
            reconnect: self.settings.reconnect,
            use_junk: self.settings.global_dpi,
            junk: (self.settings.global_jc.clone(), self.settings.global_jmin.clone(), self.settings.global_jmax.clone()),
            bypass_lan: self.settings.bypass_lan,
            kill_switch: self.settings.kill_switch,
            preserve_lock: self.settings.kill_switch && self.settings.preserve_lock,
            tcp_termination: self.settings.tcp_termination,
        })
    }

    pub fn connect(&mut self) {
        let req = match self.build_request() {
            Ok(r) => r,
            Err((title, msg)) => {
                self.message(title, msg);
                return;
            }
        };
        if let Ok(mut s) = self.tunnel.shared.lock() {
            s.state = State::Connecting;
            s.profile = req.name.clone();
        }
        self.tunnel.send(Cmd::Connect(Box::new(req)));
    }

    /// Turns "Connect at system startup" on or off (asks for administrator approval).
    pub fn set_connect_at_boot(&mut self, on: bool) {
        let text = match (on, self.build_request()) {
            (true, Ok(r)) => crate::tunnel::tunnel_file_text(&r),
            (true, Err((_, e))) => {
                self.message("Connect at system startup", e);
                return;
            }
            (false, _) => String::new(),
        };
        self.boot_text = text.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(crate::boot::set(on, "boot", &text).map(|_| on));
        });
        self.boot_job = Some(rx);
    }

    /// Keeps the startup tunnel file in step with the selected profile and settings.
    fn refresh_boot_file(&mut self) {
        if let Some(rx) = &self.boot_job {
            if let Ok(r) = rx.try_recv() {
                self.boot_job = None;
                match r {
                    Ok(on) => {
                        self.settings.connect_at_boot = on;
                        self.save_settings();
                        self.toast(if on { "The VPN will connect at system startup" } else { "Startup connection turned off" });
                    }
                    Err(e) => self.message("Connect at system startup", e),
                }
            }
            return;
        }
        if !self.settings.connect_at_boot {
            return;
        }
        if let Ok(r) = self.build_request() {
            let text = crate::tunnel::tunnel_file_text(&r);
            if text != self.boot_text {
                let conf = crate::boot::boot_dir().join("boot.conf");
                if std::fs::write(&conf, &text).is_ok() {
                    crate::store::restrict_permissions(&conf);
                    self.boot_text = text;
                }
            }
        }
    }

    pub fn unlock_network(&mut self) {
        match crate::engine::launch_unlock(&tunnel::run_dir()) {
            Ok(()) => self.log(LogLevel::Info, "Unlocking the network (administrator approval needed)"),
            Err(e) => self.message("Unlock network", e),
        }
    }

    pub fn disconnect(&mut self) {
        if let Ok(mut s) = self.tunnel.shared.lock() {
            if s.state != State::Disconnected {
                s.state = State::Disconnecting;
            }
        }
        self.tunnel.send(Cmd::Disconnect);
    }

    pub fn select_profile(&mut self, name: String) {
        if name == self.settings.active_profile {
            return;
        }
        if self.is_busy() {
            if self.settings.confirm_reconnect {
                self.dialog = Some(Dialog::Confirm {
                    title: "Reconnect".into(),
                    text: "Reconnect using new connection profile?".into(),
                    action: Action::SwitchProfile(name),
                });
            } else {
                self.settings.active_profile = name;
                self.save_settings();
                self.connect();
            }
        } else {
            self.settings.active_profile = name;
            self.save_settings();
        }
    }

    pub fn toggle_connection(&mut self) {
        match self.snap.state {
            State::Disconnected => self.connect(),
            State::Disconnecting => {}
            _ => {
                if self.settings.confirm_disconnect {
                    let name = self.snap.profile.clone();
                    self.dialog = Some(Dialog::Confirm {
                        title: "Disconnect".into(),
                        text: format!("Do you want to disconnect from {name}?"),
                        action: Action::Disconnect,
                    });
                } else {
                    self.disconnect();
                }
            }
        }
    }

    pub fn import_files(&mut self, files: Vec<PathBuf>) {
        let mut last = None;
        let mut errs = Vec::new();
        for f in files {
            match self.store.import_file(&f) {
                Ok(n) => {
                    self.log(LogLevel::Info, format!("Imported profile {n}"));
                    last = Some(n)
                }
                Err(e) => errs.push(format!("{}: {e}", f.display())),
            }
        }
        if let Some(n) = last {
            if self.settings.active_profile.is_empty() {
                self.settings.active_profile = n.clone();
                self.save_settings();
            }
            self.profiles_sel = n.clone();
            self.toast(format!("Imported {n}"));
        }
        if !errs.is_empty() {
            self.message("Import profile", errs.join("\n"));
        }
    }

    pub fn pick_and_import(&mut self) {
        if !self.live {
            return;
        }
        if let Some(files) = rfd::FileDialog::new()
            .set_title("Select config file(s)...")
            .add_filter("WireGuard config file", &["conf"])
            .add_filter("All files", &["*"])
            .pick_files()
        {
            self.import_files(files);
        }
    }

    fn run_action(&mut self, a: Action) {
        match a {
            Action::Disconnect => self.disconnect(),
            Action::SwitchProfile(n) => {
                self.settings.active_profile = n;
                self.save_settings();
                self.connect();
            }
            Action::Remove(n) => {
                if self.snap.profile == n && self.is_busy() {
                    self.message("Remove profile", "Disconnect before removing the active profile.");
                    return;
                }
                match self.store.remove(&n) {
                    Ok(()) => {
                        if self.settings.active_profile == n {
                            self.settings.active_profile = self.store.names.first().cloned().unwrap_or_default();
                            self.save_settings();
                        }
                        self.profiles_sel = self.store.names.first().cloned().unwrap_or_default();
                        self.toast(format!("Removed {n}"));
                    }
                    Err(e) => self.message("Remove profile", e),
                }
            }
            Action::DiscardEditor => self.editor = None,
            Action::UnlockNetwork => self.unlock_network(),
            Action::ExitApp => {
                if let Some(t) = &self.tray {
                    t.exit();
                }
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        let Some(d) = self.dialog.take() else { return };
        let mut keep = true;
        let mut run: Option<Action> = None;
        let mut d = d;
        egui::Modal::new(egui::Id::new("dialog")).show(ctx, |ui| {
            ui.set_width(300.0);
            match &mut d {
                Dialog::Confirm { title, text, .. } => {
                    ui.heading(title.as_str());
                    ui.add_space(6.0);
                    ui.label(text.as_str());
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        if ui.button("Yes").clicked() {
                            keep = false;
                            run = Some(Action::DiscardEditor);
                        }
                        if ui.button("No").clicked() {
                            keep = false;
                        }
                    });
                }
                Dialog::Message { title, text } => {
                    ui.heading(title.as_str());
                    ui.add_space(6.0);
                    ui.label(text.as_str());
                    ui.add_space(10.0);
                    if ui.button("Okay").clicked() {
                        keep = false;
                    }
                }
                Dialog::Rename { old, new, error } => {
                    ui.heading("Rename profile");
                    ui.label(format!("Current name: {old}"));
                    ui.label("New profile name:");
                    let r = ui.text_edit_singleline(new);
                    if let Some(e) = profile::name_problem(new) {
                        *error = e;
                    } else {
                        error.clear();
                    }
                    if !error.is_empty() {
                        ui.colored_label(Color32::RED, error.as_str());
                    }
                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        let ok = error.is_empty() && (ui.button("Save").clicked() || r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)));
                        if ok {
                            keep = false;
                        }
                        if ui.button("Cancel").clicked() {
                            keep = false;
                            new.clone_from(old);
                        }
                    });
                }
            }
        });
        if keep {
            self.dialog = Some(d);
            return;
        }
        match d {
            Dialog::Confirm { action, .. } => {
                if run.is_some() {
                    self.run_action(action);
                }
            }
            Dialog::Rename { old, new, .. } => {
                if new != old {
                    match self.store.rename(&old, &new) {
                        Ok(()) => {
                            if self.settings.active_profile == old {
                                self.settings.active_profile = new.clone();
                                self.save_settings();
                            }
                            self.profiles_sel = new;
                        }
                        Err(e) => self.message("Rename profile", e),
                    }
                }
            }
            Dialog::Message { .. } => {}
        }
    }

    // ---------- main window ----------

    fn main_window(&mut self, ui: &mut egui::Ui) {
        let mut full = ui.max_rect();
        if crate::style::CUSTOM_TITLE {
            let bar = Rect::from_min_size(full.min, vec2(full.width(), crate::style::TITLE_H));
            let title = format!("Secure Tunnel {}", env!("CARGO_PKG_VERSION"));
            if let Some(c) = crate::style::title_bar(ui, bar, &title, false) {
                crate::style::run_caption(ui.ctx(), c);
            }
            full.min.y += crate::style::TITLE_H;
        }
        let w = full.width();
        let h = full.height();
        let snap = self.snap.clone();
        let s = &snap;
        let connected = s.state == State::Connected;
        let has_profiles = !self.store.names.is_empty();

        // Row heights follow the original grid: Auto rows fixed, star rows share the rest.
        // Network lock is on while the Kill Switch blocks traffic with no tunnel up.
        let locked = self.live && s.state == State::Disconnected && crate::netlock::is_active(&tunnel::run_dir());
        let kill_h = if self.settings.kill_switch || locked { 26.0 } else { 0.0 };
        let banner_h = 0.0;
        let logo_h = 62.0;
        let hs_h = 22.0;
        let split_h = 26.0;
        let tool_h = 60.0;
        let fixed = kill_h + banner_h + logo_h + hs_h + split_h + tool_h;
        let star = ((h - fixed) / 5.4).max(30.0);
        let mut y = full.top();
        let mut row = |hgt: f32| {
            let r = Rect::from_min_size(pos2(full.left(), y), vec2(w, hgt));
            y += hgt;
            r
        };
        let r_kill = row(kill_h);
        let r_banner = row(star * 0.8 + banner_h);
        let r_logo = row(logo_h);
        let r_switch = row(star);
        let r_status = row(star * 0.3);
        let r_name = row(star * 0.3);
        let r_hs = row(hs_h);
        let r_profile = row(star);
        let r_split = row(split_h);
        let r_stats = row(star * 2.0);
        let r_tool = row(tool_h);
        let painter = ui.painter().clone();
        let text_col = ui.visuals().text_color();
        let weak = ui.visuals().weak_text_color();

        // Kill switch bar.
        if kill_h > 0.0 {
            // Colours from the original: #A9A9A9 armed, #CD5C5C blocking.
            let (fill, text, tip) = if locked {
                (icons::INDIAN_RED, "Network is blocked (Kill Switch)", "Network traffic is blocked because the VPN is disconnected.")
            } else {
                (icons::DARK_GRAY, "Kill Switch is enabled", "Network traffic is blocked when the VPN connection drops.")
            };
            painter.rect_filled(r_kill, 0.0, fill);
            painter.text(r_kill.left_center() + vec2(15.0, 0.0), Align2::LEFT_CENTER, text, FontId::proportional(FS_S), Color32::from_rgb(0xF8, 0xF8, 0xFF));
            ui.interact(r_kill, egui::Id::new("killbar"), Sense::hover()).on_hover_text(tip);
            if locked {
                let b = Rect::from_min_size(pos2(r_kill.right() - 80.0, r_kill.top() + 3.0), vec2(70.0, r_kill.height() - 6.0));
                let resp = ui.put(b, egui::Button::new(RichText::new("Unlock").size(FS_S).color(Color32::from_rgb(0xF8, 0xF8, 0xFF))).fill(Color32::from_rgba_unmultiplied(255, 255, 255, 42)));
                if resp.on_hover_text("Reset Network Lock").clicked() {
                    if self.settings.confirm_unlock_network {
                        self.dialog = Some(Dialog::Confirm {
                            title: "Unlock network".into(),
                            text: "Unlock the network?
This may allow traffic outside the VPN and cause data leakage.".into(),
                            action: Action::UnlockNetwork,
                        });
                    } else {
                        self.unlock_network();
                    }
                }
            }
        }

        // Banner area: engine missing or last error.
        let banner = if !s.error.is_empty() && s.state == State::Disconnected {
            Some((s.error.clone(), Color32::from_rgb(0xC0, 0x39, 0x2B)))
        } else {
            None
        };
        if let Some((text, col)) = banner {
            let r = r_banner.shrink2(vec2(10.0, 8.0));
            painter.rect_filled(r, 4.0, col);
            ui.scope_builder(UiBuilder::new().max_rect(r.shrink(6.0)), |ui| {
                ui.label(RichText::new(text).color(Color32::from_rgb(0xF8, 0xF8, 0xFF)).size(FS_S));
            });
        }

        // Logo and name.
        let title = "Secure Tunnel";
        let galley = painter.layout_no_wrap(title.into(), FontId::proportional(30.0), text_col);
        let total = 40.0 + 8.0 + galley.size().x;
        let x0 = r_logo.center().x - total / 2.0;
        let cy = r_logo.top() + 26.0;
        icons::logo(&painter, Rect::from_center_size(pos2(x0 + 18.0, cy), vec2(36.0, 40.0)), connected);
        painter.galley(pos2(x0 + 48.0, cy - galley.size().y / 2.0), galley, text_col);

        // The big switch.
        self.switcher(ui, r_switch);

        // Status lines.
        let status = match s.state {
            State::Disconnected => {
                if has_profiles { "Not connected" } else { "No profiles are registered" }
            }
            State::Connecting => "Connecting to",
            State::Connected => "Connected to",
            State::Disconnecting => "Disconnecting from",
        };
        painter.text(r_status.center_bottom(), Align2::CENTER_BOTTOM, status, FontId::proportional(FS_M), crate::style::muted());
        if s.state != State::Disconnected {
            let name = if self.settings.hide_endpoint_name { s.profile.clone() } else { format!("{} ({})", s.profile, host_of(&s.endpoint)) };
            painter.text(r_name.center_top() + vec2(0.0, 2.0), Align2::CENTER_TOP, name, FontId::proportional(FS_L), text_col);
            let hs = if s.handshake { "Handshake received" } else { "Awaiting server response" };
            painter.text(r_hs.center(), Align2::CENTER_CENTER, hs, FontId::proportional(FS_XS), weak);
        }

        // Profile selector.
        let inner = Rect::from_min_max(pos2(full.left() + w * 0.1, r_profile.top() + 5.0), pos2(full.left() + w * 0.9, r_profile.bottom()));
        ui.scope_builder(UiBuilder::new().max_rect(inner).layout(Layout::top_down(Align::Min)), |ui| {
            if has_profiles {
                ui.label(RichText::new("Selected profile").size(FS_M).color(weak));
                let mut chosen: Option<String> = None;
                let mut import = false;
                let sel = self.settings.active_profile.clone();
                ui.style_mut().spacing.interact_size.y = 30.0;
                egui::ComboBox::from_id_salt("profile_combo")
                    .width(ui.available_width())
                    .height(260.0)
                    .selected_text(RichText::new(if sel.is_empty() { "Choose connection profile" } else { &sel }).size(FS_M))
                    .show_ui(ui, |ui| {
                        for n in self.store.names.clone() {
                            if ui.selectable_label(n == sel, RichText::new(&n).size(FS_M)).clicked() {
                                chosen = Some(n);
                            }
                        }
                        if !self.settings.hide_import_button {
                            ui.separator();
                            if ui.selectable_label(false, RichText::new("+ Import profile...").italics().strong()).clicked() {
                                import = true;
                            }
                        }
                    })
                    .response
                    .on_hover_text("Select the connection profile");
                if let Some(n) = chosen {
                    self.select_profile(n);
                }
                if import {
                    self.pick_and_import();
                }
            }
        });

        // Split tunnelling status.
        if has_profiles {
            let status = self.split_status();
            let edit = if status.ends_with("Not set") { "Setup" } else { "Edit" };
            let r = r_split;
            ui.scope_builder(UiBuilder::new().max_rect(r).layout(Layout::left_to_right(Align::Center)), |ui| {
                let galley_w = ui.fonts_mut(|f| f.layout_no_wrap(status.clone(), FontId::proportional(FS_S), text_col).size().x);
                ui.add_space(((r.width() - galley_w - 60.0) / 2.0).max(0.0));
                ui.label(RichText::new(&status).size(FS_S));
                ui.menu_button(RichText::new(format!("{edit}…")).size(FS_S), |ui| {
                    if ui.button("Profile settings").clicked() {
                        self.open_editor_for_active();
                        ui.close();
                    }
                    if ui.button("Global settings").clicked() {
                        self.settings_open = true;
                        self.tab = Tab::Network;
                        ui.close();
                    }
                });
            });
        }

        // Statistics.
        if connected && !self.settings.hide_connection_stats {
            self.stats(ui, r_stats);
        } else if !has_profiles {
            // "How to connect" link, where the original shows it.
            let g = painter.layout_no_wrap("How to connect".into(), FontId::proportional(FS_M), crate::style::link());
            let r = Rect::from_center_size(r_stats.center_top() + vec2(0.0, 8.0 + g.size().y / 2.0), g.size());
            let resp = ui.interact(r, egui::Id::new("how_to_connect"), Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
            painter.galley(r.min, g, crate::style::link());
            painter.line_segment([r.left_bottom() + vec2(0.0, -1.0), r.right_bottom() + vec2(0.0, -1.0)], egui::Stroke::new(1.0_f32, crate::style::link()));
            if resp.clicked() {
                self.message(
                    "How to connect",
                    "1. Get a WireGuard configuration file (.conf) from your VPN provider or server.\n2. Click + below, or drop the file on this window.\n3. Turn on the switch.",
                );
            }
        }

        // Toolbar.
        self.toolbar(ui, r_tool.shrink2(vec2(12.0, 6.0)));

        if let Some((t, at)) = &self.toast {
            if at.elapsed() < Duration::from_secs(3) {
                let r = Rect::from_center_size(r_tool.center_top() - vec2(0.0, 14.0), vec2(w * 0.8, 24.0));
                painter.rect_filled(r, 6.0, ui.visuals().extreme_bg_color);
                painter.text(r.center(), Align2::CENTER_CENTER, t, FontId::proportional(FS_S), text_col);
            } else {
                self.toast = None;
            }
        }
    }

    fn switcher(&mut self, ui: &mut egui::Ui, row: Rect) {
        // 230x100 control in the middle 60% of the row, scaled to fit.
        let avail = vec2(row.width() * 0.6, row.height());
        let scale = (avail.x / 230.0).min(avail.y / 100.0);
        let rect = Rect::from_center_size(row.center(), vec2(230.0, 100.0) * scale);
        let state = self.snap.state;
        let on = matches!(state, State::Connected | State::Connecting);
        let loading = matches!(state, State::Connecting | State::Disconnecting);
        let enabled = !self.settings.active_profile.is_empty() && state != State::Disconnecting;
        let resp = ui.interact(rect, egui::Id::new("switcher"), if enabled { Sense::click() } else { Sense::hover() });
        let t = ui.ctx().animate_bool_with_time_and_easing(egui::Id::new("switch_anim"), on, 0.2, egui::emath::easing::cubic_in_out);
        let bg = if loading {
            icons::STEEL_BLUE
        } else if state == State::Connected {
            icons::GREEN
        } else {
            icons::GRAY
        };
        // The original keeps the same grey when the switch is disabled.
        let p = ui.painter();
        let h = rect.height();
        p.rect_filled(rect, egui::CornerRadius::same((h / 2.0).min(255.0) as u8), bg);
        let knob = h * 0.8;
        let travel = rect.width() - knob - h * 0.2;
        let cx = rect.left() + h * 0.1 + knob / 2.0 + travel * t;
        let c = pos2(cx, rect.center().y);
        p.circle_filled(c, knob / 2.0, ui.visuals().window_fill);
        if loading {
            icons::spinner(p, c, knob * 0.6 / 2.0, ui.input(|i| i.time), bg);
            ui.ctx().request_repaint();
        }
        if resp.clicked() {
            self.toggle_connection();
        }
        resp.on_hover_text(if on { "Disconnect" } else { "Connect" }).on_hover_cursor(egui::CursorIcon::PointingHand);
    }

    fn stats(&self, ui: &mut egui::Ui, r: Rect) {
        let s = &self.snap;
        let p = ui.painter();
        let text = ui.visuals().text_color();
        let gray = crate::style::muted();
        let row_h = r.height() / 8.0;
        let c0 = r.left();
        let c1 = r.left() + r.width() * 0.25;
        let c2 = r.left() + r.width() * 0.5;
        let y = |i: f32| r.top() + row_h * i;
        let lbl = |x: f32, i: f32, t: &str| {
            p.text(pos2(x, y(i) + row_h), Align2::LEFT_BOTTOM, t, FontId::proportional(FS_S), gray);
        };
        let val = |x: f32, i: f32, t: String| {
            p.text(pos2(x, y(i) + row_h / 2.0), Align2::LEFT_CENTER, t, FontId::proportional(FS_M), text);
        };
        p.text(pos2(c1, y(0.0) + row_h / 2.0), Align2::LEFT_CENTER, "Uptime", FontId::proportional(FS_M), gray);
        val(c2, 0.0, s.since.map(|t| fmt_uptime(t.elapsed())).unwrap_or_else(|| "00:00:00".into()));
        let arrow_col = |active: bool| if active { icons::ACCENT_GREEN } else { gray.gamma_multiply(0.8) };
        icons::arrow(p, Rect::from_min_size(pos2(c1 - 34.0, y(1.0) + 6.0), vec2(22.0, row_h * 2.0 - 8.0)), true, arrow_col(s.tx_rate > 0));
        lbl(c1, 1.0, "Send");
        val(c1, 2.0, fmt_speed(s.tx_rate));
        lbl(c2, 1.0, "Total sent");
        val(c2, 2.0, fmt_size(s.tx));
        icons::arrow(p, Rect::from_min_size(pos2(c1 - 34.0, y(3.0) + 6.0), vec2(22.0, row_h * 2.0 - 8.0)), false, arrow_col(s.rx_rate > 0));
        lbl(c1, 3.0, "Receive");
        val(c1, 4.0, fmt_speed(s.rx_rate));
        lbl(c2, 3.0, "Total received");
        val(c2, 4.0, fmt_size(s.rx));
        lbl(c1, 5.0, "Ping");
        val(c1, 6.0, s.rtt.map(|r| format!("{r} ms")).unwrap_or_else(|| "n/a".into()));
        lbl(c2, 5.0, "Packet loss");
        val(c2, 6.0, s.loss.map(crate::stats::fmt_loss).unwrap_or_else(|| "n/a".into()));
        let _ = c0;
    }

    fn toolbar(&mut self, ui: &mut egui::Ui, r: Rect) {
        let size = r.height().min(48.0);
        let col = crate::style::icon();
        let button = |ui: &mut egui::Ui, rect: Rect, id: &str, tip: &str, draw: fn(&egui::Painter, Rect, Color32)| -> bool {
            let resp = ui.interact(rect, egui::Id::new(id), Sense::click()).on_hover_text(tip).on_hover_cursor(egui::CursorIcon::PointingHand);
            if resp.hovered() {
                ui.painter().rect_filled(rect, 6.0, ui.visuals().widgets.hovered.weak_bg_fill);
            }
            draw(ui.painter(), rect.shrink(4.0), if resp.hovered() { ui.visuals().text_color() } else { col });
            resp.clicked()
        };
        let y = r.bottom() - size;
        if !self.settings.hide_import_button {
            let rect = Rect::from_min_size(pos2(r.left(), y), vec2(size, size));
            if button(ui, rect, "tb_import", "Import existing profile", icons::plus) {
                self.pick_and_import();
            }
        }
        let mut x = r.right() - size;
        let rect = Rect::from_min_size(pos2(x, y), vec2(size, size));
        if button(ui, rect, "tb_prefs", "Preferences", icons::gear) {
            self.settings_open = true;
            if self.tab == Tab::Logs || self.tab == Tab::Report {
                self.tab = Tab::Profiles;
            }
        }
        if !self.settings.hide_feedback_button {
            x -= size + 10.0;
            let rect = Rect::from_min_size(pos2(x, y), vec2(size, size));
            if button(ui, rect, "tb_report", "Report issue", crate::style::bug) {
                self.settings_open = true;
                self.tab = Tab::Report;
            }
        }
        if !self.settings.hide_logs_button {
            x -= size + 10.0;
            let rect = Rect::from_min_size(pos2(x, y), vec2(size, size));
            if button(ui, rect, "tb_logs", "Show logs", crate::style::log_doc) {
                self.settings_open = true;
                self.tab = Tab::Logs;
            }
        }
    }

    pub fn open_editor_for_active(&mut self) {
        let n = self.settings.active_profile.clone();
        self.open_editor(&n, EditMode::Form);
    }

    pub fn open_editor(&mut self, name: &str, mode: EditMode) {
        match self.store.load(name) {
            Ok(p) => {
                self.editor = Some(Editor::new(Some(name.to_string()), name.to_string(), p, mode));
                if mode == EditMode::Text {
                    if let (Some(ed), Ok(t)) = (self.editor.as_mut(), self.store.read_text(name)) {
                        ed.text = t.clone();
                        ed.baseline = t;
                    }
                }
                self.settings_open = true;
                self.tab = Tab::Profiles;
            }
            Err(e) => self.message("Failed to load profile", e),
        }
    }

    pub fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some(path) = self.screenshot.clone() else { return };
        self.frame += 1;
        ctx.request_repaint();
        if self.frame >= SHOT_FRAME && !self.shot_sent {
            self.shot_sent = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
        let shot = ctx.input(|i| {
            i.raw.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(img) = shot {
            let [w, h] = img.size;
            let bytes: Vec<u8> = img.pixels.iter().flat_map(|c| c.to_array()).collect();
            if let Some(dir) = path.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            match image::RgbaImage::from_raw(w as u32, h as u32, bytes) {
                Some(buf) => {
                    if let Err(e) = buf.save(&path) {
                        eprintln!("failed to save screenshot: {e}");
                    }
                }
                None => eprintln!("screenshot buffer has the wrong size"),
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.frame > SHOT_FRAME + 600 {
            eprintln!("screenshot never arrived");
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

pub fn default_allowed(s: &str) -> bool {
    let l = profile::split_list(s);
    l.is_empty() || l.iter().all(|x| x == "0.0.0.0/0" || x == "::/0")
}

pub fn host_of(endpoint: &str) -> String {
    let e = endpoint.trim();
    if let Some(rest) = e.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    e.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| e.to_string())
}

pub fn apply_style(ctx: &egui::Context, s: &Settings) {
    ctx.set_theme(match s.theme {
        Theme::System => egui::ThemePreference::System,
        Theme::Light => egui::ThemePreference::Light,
        Theme::Dark => egui::ThemePreference::Dark,
    });
    let mut light = egui::Visuals::light();
    crate::style::apply_theme(&mut light, false);
    ctx.set_visuals_of(egui::Theme::Light, light);
    let mut dark = egui::Visuals::dark();
    crate::style::apply_theme(&mut dark, true);
    ctx.set_visuals_of(egui::Theme::Dark, dark);
    ctx.all_styles_mut(|st| {
        st.spacing.item_spacing = vec2(8.0, 6.0);
        st.spacing.button_padding = vec2(10.0, 4.0);
    });
}

/// Sets the interface scale. The new scale takes effect on the next frame;
/// `App::fit_windows` then resizes the windows to match it.
pub fn apply_scale(ctx: &egui::Context, scale: f32) {
    ctx.set_zoom_factor(scale);
    ctx.request_repaint();
}

pub fn open_folder(p: &std::path::Path) {
    let _ = std::fs::create_dir_all(p);
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("explorer").arg(p).spawn();
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(p).spawn();
    #[cfg(all(unix, not(target_os = "macos")))]
    let _ = std::process::Command::new("xdg-open").arg(p).spawn();
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        crate::style::set_dark(ctx.style().visuals.dark_mode);
        self.snap = self.tunnel.snapshot();
        if let Some(since) = self.shot_connected {
            let s = &mut self.snap;
            s.state = crate::tunnel::State::Connected;
            s.profile = "Sample".into();
            s.endpoint = "203.0.113.10:51820".into();
            s.since = Some(since);
            (s.rx, s.tx, s.rx_rate, s.tx_rate) = (734_003_200, 52_428_800, 1_258_291, 98_304);
            (s.handshake, s.rtt, s.loss) = (true, Some(38), Some(0.0));
        }
        if !self.shot_scales.is_empty() && self.frame % 30 == 10 {
            let z = self.shot_scales.remove(0);
            apply_scale(ctx, z);
        }
        self.fit_windows(ctx);
        // Closing the window hides it in the tray; "Exit" in the tray menu quits.
        if let Some(t) = self.tray.clone() {
            if self.settings.minimize_to_tray && ctx.input(|i| i.viewport().close_requested()) {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                // Preferences is drawn by this window, so it would freeze while
                // this one is hidden: it goes to the tray too. Unsaved profile
                // edits are asked about first.
                if self.settings_open && self.editor.as_ref().map(|e| e.dirty()).unwrap_or(false) {
                    self.dialog = Some(Dialog::Confirm {
                        title: "Closing the config edit page".into(),
                        text: "Do you want to discard all changes and close the page?".into(),
                        action: Action::DiscardEditor,
                    });
                } else {
                    self.settings_open = false;
                    self.editor = None;
                    t.hide();
                }
            }
            // Choices made in the tray menu.
            let req = t.requests.lock().map(|mut r| std::mem::take(&mut *r)).unwrap_or_default();
            if let Some(name) = req.select {
                if self.store.names.contains(&name) && self.snap.state == State::Disconnected {
                    self.settings.active_profile = name.clone();
                    self.profiles_sel = name;
                    self.save_settings();
                }
            }
            if req.preferences {
                self.settings_open = true;
                if self.tab == Tab::Logs || self.tab == Tab::Report {
                    self.tab = Tab::Profiles;
                }
            }
            if req.import {
                self.pick_and_import();
            }
            if req.hide {
                if self.settings_open && self.editor.as_ref().map(|e| e.dirty()).unwrap_or(false) {
                    self.dialog = Some(Dialog::Confirm {
                        title: "Closing the config edit page".into(),
                        text: "Do you want to discard all changes and close the page?".into(),
                        action: Action::DiscardEditor,
                    });
                } else {
                    self.settings_open = false;
                    self.editor = None;
                    t.hide();
                }
            }
            if self.tray_refresh.elapsed() >= crate::tray::TICK {
                self.tray_refresh = Instant::now();
                self.refresh_boot_file();
                let all: std::collections::HashMap<String, ConnectRequest> =
                    self.store.names.iter().filter_map(|n| self.build_request_for(n).ok().map(|r| (n.clone(), r))).collect();
                if let Ok(mut p) = t.prepared.lock() {
                    *p = all;
                }
                if let Ok(mut m) = t.menu.lock() {
                    *m = crate::tray::MenuModel {
                        profiles: self.store.names.clone(),
                        active: self.settings.active_profile.clone(),
                        hide_import: self.settings.hide_import_button,
                    };
                }
                if let Ok(mut p) = t.prefs.lock() {
                    p.notifications = self.settings.show_notifications;
                    p.disconnect_on_exit = self.settings.disconnect_on_exit;
                    p.confirm_exit = self.settings.confirm_disconnect_on_exit;
                    p.plain_tooltip = self.settings.use_system_tooltip;
                    p.hide_endpoint = self.settings.hide_endpoint_name;
                }
            }
            if t.exit_requested.swap(false, std::sync::atomic::Ordering::Relaxed) {
                let name = self.snap.profile.clone();
                self.dialog = Some(Dialog::Confirm {
                    title: "Exit".into(),
                    text: format!("Exiting will disconnect from {name}. Exit anyway?"),
                    action: Action::ExitApp,
                });
            }
        }
        if self.snap.state != State::Disconnected || self.toast.is_some() {
            ctx.request_repaint_after(Duration::from_millis(250));
        }
        // Drag-and-drop import.
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if !dropped.is_empty() && self.live {
            self.import_files(dropped);
        }

        if self.shot_tab.is_some() {
            // Test aid: draw the preferences pages in this window.
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(vec2(800.0, 610.0)));
            self.settings_contents(ctx);
        } else {
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(ctx.style().visuals.panel_fill))
                .show(ctx, |ui| self.main_window(ui));
        }

        if self.settings_open && self.shot_tab.is_none() {
            self.settings_viewport(ctx);
        }
        self.dialogs(ctx);
        self.handle_screenshot(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // The tunnel runs in its own helper and keeps going after the window
        // closes, unless the person asked for it to stop.
        if self.live && self.is_busy() && self.settings.disconnect_on_exit {
            self.tunnel.send(Cmd::Disconnect);
            let until = std::time::Instant::now() + Duration::from_secs(30);
            while std::time::Instant::now() < until && self.tunnel.shared.lock().map(|s| s.state != State::Disconnected).unwrap_or(false) {
                std::thread::sleep(Duration::from_millis(200));
            }
        }
        self.save_settings();
    }
}
