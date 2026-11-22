//! Notification-area / menu-bar icon. Closing the window hides it here; the
//! app only quits from the menu's "Exit". The menu follows the original's
//! (`SysTrayMenu` in NotifyIconResources.xaml):
//!   [icon] <active profile>        connect / disconnect
//!   ---
//!   Profiles >  <each profile, active one checked> --- Import profile...
//!   Connect | Disconnect
//!   ---
//!   Preferences
//!   Open app | Hide app
//!   ---
//!   Exit
//! Profiles can only be switched while disconnected. A left click shows or
//! hides the window (Windows); notifications on connect and disconnect
//! (settings `MinimizeToTray`, `ShowTrayNotifications`, both on by default).
//!
//! A hidden window stops the window's own update loop, so the tray runs on
//! its own: a 1 s timer on the main thread (Windows, macOS) or the tray's
//! D-Bus thread (Linux) refreshes the icon and sends notifications, and its
//! menu talks to the tunnel directly.

use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use eframe::egui;

use crate::tunnel::{Cmd, ConnectRequest, Shared, State};

pub const TICK: Duration = Duration::from_secs(1);

#[derive(Clone, Default)]
pub struct TrayPrefs {
    pub notifications: bool,
    pub disconnect_on_exit: bool,
    /// Ask before an Exit that would disconnect (original "Confirm disconnect on exit").
    pub confirm_exit: bool,
    /// Short tooltip (original "Use the system tooltip") instead of the detailed one.
    pub plain_tooltip: bool,
    pub hide_endpoint: bool,
}

/// What the menu shows, kept current by the window.
#[derive(Clone, Default, PartialEq)]
pub struct MenuModel {
    pub profiles: Vec<String>,
    pub active: String,
    pub hide_import: bool,
}

/// Menu choices the window carries out when it next runs.
#[derive(Default)]
pub struct Requests {
    pub select: Option<String>,
    pub preferences: bool,
    pub import: bool,
    /// "Hide app": the window closes Preferences (which it draws) and hides itself.
    pub hide: bool,
}

pub struct Control {
    pub shared: Arc<Mutex<Shared>>,
    pub sender: Mutex<Option<Sender<Cmd>>>,
    /// A ready connect request for every profile, kept current by the window,
    /// so the tray can connect any of them while the window is hidden.
    pub prepared: Mutex<std::collections::HashMap<String, ConnectRequest>>,
    pub menu: Mutex<MenuModel>,
    pub requests: Mutex<Requests>,
    pub visible: std::sync::atomic::AtomicBool,
    pub prefs: Mutex<TrayPrefs>,
    pub ctx: egui::Context,
    pub window: NativeWindow,
    /// Set by the tray's Exit when the window must ask first.
    pub exit_requested: std::sync::atomic::AtomicBool,
}

impl Control {
    fn state(&self) -> (State, String) {
        self.shared.lock().map(|s| (s.state, s.profile.clone())).unwrap_or((State::Disconnected, String::new()))
    }

    fn send(&self, c: Cmd) {
        if let Ok(g) = self.sender.lock() {
            if let Some(tx) = g.as_ref() {
                let _ = tx.send(c);
            }
        }
    }

    pub fn model(&self) -> MenuModel {
        self.menu.lock().map(|m| m.clone()).unwrap_or_default()
    }

    pub fn is_visible(&self) -> bool {
        self.visible.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn toggle(&self) {
        let (state, _) = self.state();
        match state {
            State::Disconnected => {
                let active = self.model().active;
                let req = self.prepared.lock().ok().and_then(|p| p.get(&active).cloned());
                match req {
                    Some(r) => self.send(Cmd::Connect(Box::new(r))),
                    None => self.open(),
                }
            }
            State::Disconnecting => {}
            _ => self.send(Cmd::Disconnect),
        }
    }

    pub fn open(&self) {
        self.visible.store(true, std::sync::atomic::Ordering::Relaxed);
        self.window.show(&self.ctx);
    }

    pub fn hide(&self) {
        self.visible.store(false, std::sync::atomic::Ordering::Relaxed);
        self.window.hide(&self.ctx);
    }

    /// "Open app" / "Hide app".
    pub fn show_hide(&self) {
        if self.is_visible() {
            if let Ok(mut r) = self.requests.lock() {
                r.hide = true;
            }
            self.ctx.request_repaint();
        } else {
            self.open();
        }
    }

    pub fn show_hide_label(&self) -> &'static str {
        if self.is_visible() { "Hide app" } else { "Open app" }
    }

    /// Profiles > name: makes it the active profile (only while disconnected).
    pub fn select(&self, name: &str) {
        if !self.can_select() {
            return;
        }
        if let Ok(mut m) = self.menu.lock() {
            m.active = name.to_string();
        }
        // Saved now, so the choice survives an Exit before the window is opened.
        let mut st = crate::store::Settings::load();
        st.active_profile = name.to_string();
        st.save();
        if let Ok(mut r) = self.requests.lock() {
            r.select = Some(name.to_string());
        }
        self.ctx.request_repaint();
    }

    pub fn preferences(&self) {
        if let Ok(mut r) = self.requests.lock() {
            r.preferences = true;
        }
        self.open();
    }

    pub fn import(&self) {
        if let Ok(mut r) = self.requests.lock() {
            r.import = true;
        }
        self.open();
    }

    /// Profile switching is offered only while disconnected, like the original.
    pub fn can_select(&self) -> bool {
        self.state().0 == State::Disconnected
    }

    /// Quits the app. The tunnel keeps running unless "Disconnect VPN when app closes" is on.
    pub fn exit(&self) {
        let prefs = self.prefs.lock().map(|p| p.clone()).unwrap_or_default();
        let wait = prefs.disconnect_on_exit && self.state().0 != State::Disconnected;
        // Icon and window go at once; any waiting for the disconnect happens off
        // the main thread, so the desktop never sees the app hang.
        remove_icon();
        self.window.hide(&self.ctx);
        if !wait {
            std::process::exit(0);
        }
        self.send(Cmd::Disconnect);
        let shared = self.shared.clone();
        std::thread::spawn(move || {
            let until = std::time::Instant::now() + crate::stats::DISCONNECT_TIMEOUT;
            while std::time::Instant::now() < until && shared.lock().map(|s| s.state != State::Disconnected).unwrap_or(false) {
                std::thread::sleep(Duration::from_millis(200));
            }
            std::process::exit(0);
        });
    }

    pub fn tooltip(&self) -> String {
        let (state, name) = self.state();
        let line = match state {
            State::Disconnected => "Secure Tunnel: not connected".to_string(),
            State::Connecting => format!("Secure Tunnel: connecting to {name}"),
            State::Connected => format!("Secure Tunnel: connected to {name}"),
            State::Disconnecting => format!("Secure Tunnel: disconnecting from {name}"),
        };
        let prefs = self.prefs.lock().map(|p| p.clone()).unwrap_or_default();
        if prefs.plain_tooltip || state != State::Connected {
            return line;
        }
        // Detailed tooltip: server, uptime and traffic.
        let s = match self.shared.lock() {
            Ok(s) => (s.endpoint.clone(), s.since, s.rx, s.tx),
            Err(_) => return line,
        };
        let mut t = line;
        if !prefs.hide_endpoint && !s.0.is_empty() {
            t.push_str(&format!("\nServer: {}", crate::app::host_of(&s.0)));
        }
        if let Some(since) = s.1 {
            t.push_str(&format!("\nUptime: {}", crate::app::fmt_uptime(since.elapsed())));
        }
        t.push_str(&format!("\nSent: {}  Received: {}", crate::app::fmt_size(s.3), crate::app::fmt_size(s.2)));
        t
    }

    /// Tray Exit: asks in the window first when exiting would disconnect.
    pub fn request_exit(&self) {
        let prefs = self.prefs.lock().map(|p| p.clone()).unwrap_or_default();
        if prefs.confirm_exit && prefs.disconnect_on_exit && self.state().0 != State::Disconnected {
            self.exit_requested.store(true, std::sync::atomic::Ordering::Relaxed);
            self.open();
        } else {
            self.exit();
        }
    }

    pub fn toggle_label(&self) -> &'static str {
        match self.state().0 {
            State::Disconnected => "Connect",
            _ => "Disconnect",
        }
    }
}

/// Shows a desktop notification without blocking the caller.
pub fn notify(body: String) {
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new().summary("Secure Tunnel").body(&body).show();
    });
}

/// Tracks state changes for notifications.
pub struct Watch {
    last: Option<State>,
}

impl Watch {
    pub fn new() -> Self {
        Watch { last: None }
    }
    /// Returns true when the state changed.
    pub fn step(&mut self, c: &Control) -> bool {
        let (state, name) = c.state();
        if self.last == Some(state) {
            return false;
        }
        let first = self.last.is_none();
        let was = self.last.replace(state);
        let on = c.prefs.lock().map(|p| p.notifications).unwrap_or(false);
        if on && !first {
            match (was, state) {
                (_, State::Connected) => notify(format!("Connected to {name}")),
                (Some(State::Connected), State::Disconnected) => notify(format!("Disconnected from {name}")),
                _ => {}
            }
        }
        true
    }
}

/// Square shield icon in RGBA.
pub fn icon_rgba(size: u32, state: State) -> Vec<u8> {
    let (r, g, b) = match state {
        State::Connected => (0x1f, 0xa0, 0x5a),
        State::Connecting | State::Disconnecting => (0x46, 0x82, 0xb4),
        State::Disconnected => (0x80, 0x80, 0x80),
    };
    let n = size as usize;
    let mut v = vec![0u8; n * n * 4];
    for y in 0..n {
        for x in 0..n {
            let fx = (x as f32 + 0.5) / n as f32;
            let fy = (y as f32 + 0.5) / n as f32;
            let dx = (fx - 0.5).abs();
            let inside = (0.06..=0.96).contains(&fy) && if fy < 0.55 { dx < 0.42 } else { dx < 0.42 * (0.96 - fy) / 0.41 };
            if inside {
                let hole = ((fx - 0.5).powi(2) + (fy - 0.42).powi(2)).sqrt() < 0.11 || (dx < 0.045 && (0.42..0.68).contains(&fy));
                let i = (y * n + x) * 4;
                let (cr, cg, cb) = if hole { (255, 255, 255) } else { (r, g, b) };
                v[i] = cr;
                v[i + 1] = cg;
                v[i + 2] = cb;
                v[i + 3] = 255;
            }
        }
    }
    v
}

// ---------- the window, shown and hidden natively ----------

/// Native handle of the main window (HWND on Windows, NSView on macOS).
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeWindow(#[allow(dead_code)] pub usize);

impl NativeWindow {
    pub fn from_cc(cc: &eframe::CreationContext<'_>) -> Self {
        #[allow(unused_imports)]
        use raw_window_handle::{HasWindowHandle, RawWindowHandle};
        match cc.window_handle().map(|h| h.as_raw()) {
            #[cfg(windows)]
            Ok(RawWindowHandle::Win32(h)) => NativeWindow(h.hwnd.get() as usize),
            #[cfg(target_os = "macos")]
            Ok(RawWindowHandle::AppKit(h)) => NativeWindow(h.ns_view.as_ptr() as usize),
            _ => NativeWindow(0),
        }
    }

    pub fn show(&self, ctx: &egui::Context) {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::UI::WindowsAndMessaging::{SW_RESTORE, SW_SHOW, SetForegroundWindow, ShowWindow};
            let h = self.0 as windows_sys::Win32::Foundation::HWND;
            ShowWindow(h, SW_SHOW);
            ShowWindow(h, SW_RESTORE);
            SetForegroundWindow(h);
        }
        #[cfg(target_os = "macos")]
        unsafe {
            mac::show(self.0);
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        ctx.request_repaint();
    }

    pub fn hide(&self, ctx: &egui::Context) {
        #[cfg(windows)]
        unsafe {
            use windows_sys::Win32::UI::WindowsAndMessaging::{SW_HIDE, ShowWindow};
            ShowWindow(self.0 as windows_sys::Win32::Foundation::HWND, SW_HIDE);
        }
        #[cfg(target_os = "macos")]
        unsafe {
            mac::hide(self.0);
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(true));
        let _ = ctx;
    }
}

#[cfg(target_os = "macos")]
mod mac {
    use objc2::msg_send;
    use objc2::runtime::{AnyClass, AnyObject};

    unsafe fn app() -> *mut AnyObject {
        let cls = AnyClass::get(c"NSApplication").expect("NSApplication");
        unsafe { msg_send![cls, sharedApplication] }
    }

    /// Back in the Dock and in front.
    pub unsafe fn show(view: usize) {
        unsafe {
            let app = app();
            let _: bool = msg_send![app, setActivationPolicy: 0isize];
            let _: () = msg_send![app, activateIgnoringOtherApps: true];
            if view != 0 {
                let win: *mut AnyObject = msg_send![view as *mut AnyObject, window];
                if !win.is_null() {
                    let _: () = msg_send![win, makeKeyAndOrderFront: std::ptr::null::<AnyObject>()];
                }
            }
        }
    }

    /// Window away and no Dock icon: only the menu-bar icon remains.
    pub unsafe fn hide(view: usize) {
        unsafe {
            if view != 0 {
                let win: *mut AnyObject = msg_send![view as *mut AnyObject, window];
                if !win.is_null() {
                    let _: () = msg_send![win, orderOut: std::ptr::null::<AnyObject>()];
                }
            }
            let _: bool = msg_send![app(), setActivationPolicy: 1isize];
        }
    }

    unsafe extern "C" {
        static _dispatch_main_q: std::ffi::c_void;
        fn dispatch_async_f(queue: *const std::ffi::c_void, context: *mut std::ffi::c_void, work: extern "C" fn(*mut std::ffi::c_void));
    }

    extern "C" fn on_main(_: *mut std::ffi::c_void) {
        super::desktop::tick();
    }

    /// Runs the tray tick on the main thread once a second.
    pub fn start_ticker() {
        std::thread::spawn(|| loop {
            std::thread::sleep(super::TICK);
            unsafe { dispatch_async_f(&raw const _dispatch_main_q, std::ptr::null_mut(), on_main) };
        });
    }
}

// ---------- Windows and macOS: tray-icon ----------

#[cfg(any(windows, target_os = "macos"))]
mod desktop {
    use super::*;
    use std::cell::RefCell;
    use tray_icon::menu::{CheckMenuItem, IconMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
    use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

    struct Live {
        icon: TrayIcon,
        control: Arc<Control>,
        watch: Watch,
        /// What the menu was last built from; it is rebuilt when this changes.
        built: Option<(MenuModel, State, bool)>,
    }

    thread_local! {
        static LIVE: RefCell<Option<Live>> = const { RefCell::new(None) };
    }

    fn icon(state: State) -> Option<Icon> {
        Icon::from_rgba(icon_rgba(32, state), 32, 32).ok()
    }

    fn build_menu(c: &Control) -> Menu {
        let m = c.model();
        let menu = Menu::new();
        if !m.active.is_empty() {
            let small = tray_icon::menu::Icon::from_rgba(icon_rgba(16, State::Connected), 16, 16).ok();
            let _ = menu.append(&IconMenuItem::with_id("toggle", &m.active, true, small, None));
            let _ = menu.append(&PredefinedMenuItem::separator());
        }
        let profiles = Submenu::new("Profiles", true);
        let can = c.can_select();
        for (i, name) in m.profiles.iter().enumerate() {
            let _ = profiles.append(&CheckMenuItem::with_id(format!("profile:{i}"), name, can, *name == m.active, None));
        }
        if !m.hide_import {
            if !m.profiles.is_empty() {
                let _ = profiles.append(&PredefinedMenuItem::separator());
            }
            let _ = profiles.append(&MenuItem::with_id("import", "Import profile...", true, None));
        }
        let _ = menu.append(&profiles);
        let _ = menu.append(&MenuItem::with_id("toggle", c.toggle_label(), !m.active.is_empty(), None));
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&MenuItem::with_id("prefs", "Preferences", true, None));
        let _ = menu.append(&MenuItem::with_id("showhide", c.show_hide_label(), true, None));
        let _ = menu.append(&PredefinedMenuItem::separator());
        let _ = menu.append(&MenuItem::with_id("exit", "Exit", true, None));
        menu
    }

    pub fn start(control: Arc<Control>) -> bool {
        let built = TrayIconBuilder::new()
            .with_menu(Box::new(build_menu(&control)))
            .with_menu_on_left_click(cfg!(target_os = "macos"))
            .with_tooltip(control.tooltip())
            .with_icon(icon(State::Disconnected).expect("icon"))
            .build();
        let Ok(tray) = built else { return false };
        let c1 = control.clone();
        MenuEvent::set_event_handler(Some(move |e: MenuEvent| match e.id.0.as_str() {
            "toggle" => c1.toggle(),
            "prefs" => c1.preferences(),
            "showhide" => c1.show_hide(),
            "import" => c1.import(),
            "exit" => c1.request_exit(),
            id => {
                if let Some(i) = id.strip_prefix("profile:").and_then(|i| i.parse::<usize>().ok()) {
                    if let Some(name) = c1.model().profiles.get(i).cloned() {
                        c1.select(&name);
                    }
                }
            }
        }));
        let c2 = control.clone();
        TrayIconEvent::set_event_handler(Some(move |e: TrayIconEvent| {
            // Original: a left click shows or hides the window, a double click opens it.
            if cfg!(windows) {
                match e {
                    TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } => c2.show_hide(),
                    TrayIconEvent::DoubleClick { button: MouseButton::Left, .. } => c2.open(),
                    _ => {}
                }
            }
        }));
        LIVE.with(|l| *l.borrow_mut() = Some(Live { icon: tray, control, watch: Watch::new(), built: None }));
        tick();
        #[cfg(windows)]
        unsafe {
            extern "system" fn on_timer(_: windows_sys::Win32::Foundation::HWND, _: u32, _: usize, _: u32) {
                tick();
            }
            windows_sys::Win32::UI::WindowsAndMessaging::SetTimer(std::ptr::null_mut(), 0, TICK.as_millis() as u32, Some(on_timer));
        }
        #[cfg(target_os = "macos")]
        super::mac::start_ticker();
        true
    }

    /// Refreshes icon, tooltip and menu; sends notifications. Main thread only.
    pub fn tick() {
        LIVE.with(|l| {
            if let Some(live) = l.borrow_mut().as_mut() {
                let changed = live.watch.step(&live.control);
                let state = live.control.state().0;
                if changed {
                    let _ = live.icon.set_icon(icon(state));
                }
                let now = (live.control.model(), state, live.control.is_visible());
                if live.built.as_ref() != Some(&now) {
                    live.icon.set_menu(Some(Box::new(build_menu(&live.control))));
                    live.built = Some(now);
                }
                // The detailed tooltip carries live traffic, so it is refreshed every tick.
                let plain = live.control.prefs.lock().map(|p| p.plain_tooltip).unwrap_or(true);
                if changed || !plain {
                    let _ = live.icon.set_tooltip(Some(live.control.tooltip()));
                }
            }
        });
    }

    pub fn remove() {
        LIVE.with(|l| {
            l.borrow_mut().take();
        });
    }
}

// ---------- Linux: StatusNotifierItem over D-Bus ----------

#[cfg(all(unix, not(target_os = "macos")))]
mod desktop {
    use super::*;
    use ksni::blocking::TrayMethods;

    struct LinuxTray {
        control: Arc<Control>,
        state: State,
    }

    impl ksni::Tray for LinuxTray {
        fn id(&self) -> String {
            "secure-tunnel".into()
        }
        fn title(&self) -> String {
            "Secure Tunnel".into()
        }
        fn icon_pixmap(&self) -> Vec<ksni::Icon> {
            // RGBA -> ARGB (network byte order).
            let rgba = icon_rgba(32, self.state);
            let mut argb = Vec::with_capacity(rgba.len());
            for p in rgba.chunks(4) {
                argb.extend_from_slice(&[p[3], p[0], p[1], p[2]]);
            }
            vec![ksni::Icon { width: 32, height: 32, data: argb }]
        }
        fn tool_tip(&self) -> ksni::ToolTip {
            ksni::ToolTip { title: self.control.tooltip(), ..Default::default() }
        }
        fn activate(&mut self, _x: i32, _y: i32) {
            self.control.show_hide();
        }
        fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
            use ksni::menu::{CheckmarkItem, StandardItem, SubMenu};
            let c = &self.control;
            let m = c.model();
            let mut items: Vec<ksni::MenuItem<Self>> = Vec::new();
            if !m.active.is_empty() {
                items.push(StandardItem { label: m.active.clone(), icon_name: "network-vpn".into(), activate: Box::new(|t: &mut Self| t.control.toggle()), ..Default::default() }.into());
                items.push(ksni::MenuItem::Separator);
            }
            let can = c.can_select();
            let mut sub: Vec<ksni::MenuItem<Self>> = m
                .profiles
                .iter()
                .map(|name| {
                    let n = name.clone();
                    CheckmarkItem { label: name.clone(), enabled: can, checked: *name == m.active, activate: Box::new(move |t: &mut Self| t.control.select(&n)), ..Default::default() }.into()
                })
                .collect();
            if !m.hide_import {
                if !sub.is_empty() {
                    sub.push(ksni::MenuItem::Separator);
                }
                sub.push(StandardItem { label: "Import profile...".into(), activate: Box::new(|t: &mut Self| t.control.import()), ..Default::default() }.into());
            }
            items.push(SubMenu { label: "Profiles".into(), submenu: sub, ..Default::default() }.into());
            items.push(StandardItem { label: c.toggle_label().into(), enabled: !m.active.is_empty(), activate: Box::new(|t: &mut Self| t.control.toggle()), ..Default::default() }.into());
            items.push(ksni::MenuItem::Separator);
            items.push(StandardItem { label: "Preferences".into(), activate: Box::new(|t: &mut Self| t.control.preferences()), ..Default::default() }.into());
            items.push(StandardItem { label: c.show_hide_label().into(), activate: Box::new(|t: &mut Self| t.control.show_hide()), ..Default::default() }.into());
            items.push(ksni::MenuItem::Separator);
            items.push(StandardItem { label: "Exit".into(), activate: Box::new(|t: &mut Self| t.control.request_exit()), ..Default::default() }.into());
            items
        }
    }

    pub fn start(control: Arc<Control>) -> bool {
        let tray = LinuxTray { control: control.clone(), state: State::Disconnected };
        let Ok(handle) = tray.spawn() else { return false };
        std::thread::spawn(move || {
            let mut watch = Watch::new();
            let mut built = None;
            loop {
                let changed = watch.step(&control);
                let now = (control.model(), control.is_visible());
                if changed || built.as_ref() != Some(&now) {
                    built = Some(now);
                    let s = control.state().0;
                    // Updating also makes the desktop read the menu again.
                    if handle.update(|t| t.state = s).is_none() {
                        return;
                    }
                }
                std::thread::sleep(TICK);
            }
        });
        true
    }

    pub fn remove() {}
}

#[cfg(not(any(windows, unix)))]
mod desktop {
    use super::*;
    pub fn start(_c: Arc<Control>) -> bool {
        false
    }
    pub fn remove() {}
}

/// Creates the tray icon. Returns false where the desktop has no tray.
pub fn start(control: Arc<Control>) -> bool {
    desktop::start(control)
}

fn remove_icon() {
    desktop::remove();
}
