//! Preferences window (800 x 610, as the original) with its pages.

use std::time::{SystemTime, UNIX_EPOCH};

use eframe::egui::{self, Color32, RichText, vec2};

use crate::app::{Action, App, Dialog, EditMode, Editor, FS_M, FS_S, Tab, open_folder};
use crate::profile::{self, Profile};
use crate::store::{LogLevel, Theme};
use crate::tunnel::State;

/// Per-app split tunnelling works on Linux; elsewhere it needs a network driver.
fn apps_note() -> &'static str {
    if crate::apps::enforced() {
        "Names (.exe or .app optional), full paths or folders, comma separated. If both lists are set, tunneled apps win."
    } else if cfg!(target_os = "macos") {
        "Applications: run Secure Tunnel.app (with its Network Extension) to apply these."
    } else {
        "Applications: kept in your settings, but on this system they need a network driver, so they aren't applied yet (they work on Linux and macOS)."
    }
}

fn section(ui: &mut egui::Ui, title: &str, desc: &str) {
    crate::style::group(ui, title, desc);
}

fn group_label(ui: &mut egui::Ui, t: &str) {
    ui.add_space(4.0);
    ui.label(RichText::new(t).size(13.0).color(crate::style::muted()));
}

/// A settings card with an On/Off switch, like the original's.
fn toggle(ui: &mut egui::Ui, on: &mut bool, title: &str, desc: &str) -> bool {
    crate::style::card_toggle(ui, on, title, desc)
}


impl App {
    pub fn settings_viewport(&mut self, ctx: &egui::Context) {
        let builder = egui::ViewportBuilder::default()
            .with_title("Secure Tunnel - Preferences")
            .with_inner_size([800.0, 610.0])
            .with_min_inner_size([640.0, 480.0])
            .with_decorations(!crate::style::CUSTOM_TITLE);
        ctx.show_viewport_immediate(egui::ViewportId::from_hash_of("preferences"), builder, |ctx, _class| {
            if ctx.input(|i| i.viewport().close_requested()) {
                if self.editor.as_ref().map(|e| e.dirty()).unwrap_or(false) {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                    self.dialog = Some(Dialog::Confirm {
                        title: "Closing the config edit page".into(),
                        text: "Do you want to discard all changes and close the page?".into(),
                        action: Action::DiscardEditor,
                    });
                } else {
                    self.settings_open = false;
                    self.editor = None;
                }
            }
            self.settings_contents(ctx);
        });
    }

    pub fn settings_contents(&mut self, ctx: &egui::Context) {
        use crate::style;
        if style::CUSTOM_TITLE {
            egui::TopBottomPanel::top("pref_title").exact_height(style::TITLE_H).frame(egui::Frame::NONE).show(ctx, |ui| {
                let r = ui.max_rect();
                if let Some(c) = style::title_bar(ui, r, "Secure Tunnel - Preferences", true) {
                    style::run_caption(ui.ctx(), c);
                }
            });
        }
        // Tab bar: 70 x 70 buttons with a 32 px icon and a label; the selected
        // one is lighter with a blue underline.
        egui::TopBottomPanel::top("pref_tabs").exact_height(72.0).frame(egui::Frame::NONE.fill(style::bg())).show(ctx, |ui| {
            let top = ui.max_rect().min;
            let mut x = top.x + 1.0;
            for t in Tab::ALL {
                let s = &self.settings;
                let hidden = (t == Tab::Logs && s.hide_logs_tab)
                    || (t == Tab::About && s.hide_about_tab)
                    || (t == Tab::Security && s.hide_security_tab)
                    || (t == Tab::Report && s.hide_feedback_tab);
                if hidden {
                    continue;
                }
                let r = egui::Rect::from_min_size(egui::pos2(x, top.y), vec2(70.0, 70.0));
                let resp = ui.interact(r, egui::Id::new(("tab", t.label())), egui::Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                let sel = self.tab == t;
                let p = ui.painter();
                if sel || resp.hovered() {
                    p.rect_filled(r, 0.0, style::tab_selected());
                }
                if sel {
                    p.rect_filled(egui::Rect::from_min_size(egui::pos2(r.left() + 5.0, r.bottom() - 3.0), vec2(60.0, 2.0)), 1.0, style::TAB_LINE);
                }
                style::tab_icon(p, egui::Rect::from_min_size(egui::pos2(r.left() + 19.0, r.top() + 9.0), vec2(32.0, 32.0)), t, crate::style::text());
                let label = if t == Tab::Report { "Feedback" } else { t.label() };
                p.text(egui::pos2(r.center().x, r.top() + 52.0), egui::Align2::CENTER_CENTER, label, egui::FontId::proportional(12.0), crate::style::text());
                if resp.clicked() && !sel {
                    self.tab = t;
                }
                x += 70.0;
            }
            let line_y = top.y + 71.0;
            ui.painter().line_segment([egui::pos2(ui.max_rect().left(), line_y), egui::pos2(ui.max_rect().right(), line_y)], egui::Stroke::new(1.0_f32, crate::style::border()));
        });
        egui::CentralPanel::default().frame(egui::Frame::NONE.fill(style::bg()).inner_margin(egui::Margin::symmetric(12, 8))).show(ctx, |ui| {
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| match self.tab {
                Tab::Profiles => {
                    if self.editor.is_some() {
                        self.page_editor(ui);
                    } else {
                        self.page_profiles(ui);
                    }
                }
                Tab::General => self.page_general(ui),
                Tab::Network => self.page_network(ui),
                Tab::Security => self.page_security(ui),
                Tab::Advanced => self.page_advanced(ui),
                Tab::Logs => self.page_logs(ui),
                Tab::Report => self.page_report(ui),
                Tab::About => self.page_about(ui),
            });
        });
        self.picker_window(ctx);
        self.domains_window(ctx);
    }

    // ---------- Profiles ----------

    fn page_profiles(&mut self, ui: &mut egui::Ui) {
        use crate::style;
        if self.profiles_sel.is_empty() || !self.store.exists(&self.profiles_sel) {
            self.profiles_sel = self.store.names.first().cloned().unwrap_or_default();
        }
        let sel = self.profiles_sel.clone();
        let has = !sel.is_empty();

        // Toolbar of 20 x 20 icon buttons, as in the original.
        ui.horizontal(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            if glyph_button(ui, Glyph::Add, true, "Import existing profile") {
                self.pick_and_import();
            }
            if glyph_button(ui, Glyph::New, true, "Create a new blank profile.") {
                let name = next_free(&self.store.names, "New profile");
                self.editor = Some(Editor::new(None, name, Profile::blank(), EditMode::Form));
            }
            if glyph_button(ui, Glyph::NewText, true, "Create a new profile in text mode") {
                let name = next_free(&self.store.names, "New profile");
                self.editor = Some(Editor::new(None, name, Profile::blank(), EditMode::Text));
            }
            if glyph_button(ui, Glyph::Duplicate, has, "Duplicate profile") {
                self.duplicate_selected(&sel);
            }
            if glyph_button(ui, Glyph::Reload, true, "Reload list of profiles") {
                self.store.reload();
            }
            if glyph_button(ui, Glyph::Export, has, "Export profile to file") {
                self.export_selected(&sel);
            }
            if glyph_button(ui, Glyph::Zip, !self.store.names.is_empty(), "Export profiles to ZIP file") {
                if let Some(path) = rfd::FileDialog::new().set_file_name("profiles.zip").add_filter("ZIP archive", &["zip"]).save_file() {
                    match self.store.export_zip(&path) {
                        Ok(()) => self.toast("Profiles exported"),
                        Err(e) => self.message("Export profiles", e),
                    }
                }
            }
            if glyph_button(ui, Glyph::Folder, true, "Open the profiles folder") {
                open_folder(&self.store.dir);
            }
        });
        ui.add_space(4.0);

        // Left: profile tree (199 px). Right: details or the import drop area.
        let area = ui.available_rect_before_wrap();
        let left = egui::Rect::from_min_size(area.min, vec2(199.0, area.height()));
        let split = egui::Rect::from_min_size(egui::pos2(left.right() + 3.0, area.top() - 30.0), vec2(1.5, area.height() + 38.0));
        let right = egui::Rect::from_min_max(egui::pos2(split.right() + 10.0, area.top()), area.max);
        ui.painter().rect_filled(split, 0.0, style::splitter());

        let mut action: Option<(&'static str, String)> = None;
        ui.scope_builder(egui::UiBuilder::new().max_rect(left), |ui| {
            ui.spacing_mut().item_spacing.y = 0.0;
            let row = |ui: &mut egui::Ui, indent: f32, id: &str| {
                let (r, resp) = ui.allocate_exact_size(vec2(left.width(), 20.0), egui::Sense::click());
                (egui::Rect::from_min_max(r.min + vec2(indent, 0.0), r.max), resp, id.to_string())
            };
            let (r, _, _) = row(ui, 0.0, "root");
            crate::icons::logo(ui.painter(), egui::Rect::from_min_size(r.min + vec2(4.0, 2.0), vec2(15.0, 16.0)), false);
            ui.painter().text(r.min + vec2(24.0, 10.0), egui::Align2::LEFT_CENTER, "Secure Tunnel profiles", egui::FontId::proportional(13.0), crate::style::text());
            for n in self.store.names.clone() {
                let (r, resp, _) = row(ui, 20.0, &n);
                let active = n == self.settings.active_profile;
                if n == sel {
                    ui.painter().rect_filled(r, 0.0, style::list_selected());
                } else if resp.hovered() {
                    ui.painter().rect_filled(r, 0.0, crate::style::hover());
                }
                let mut txt = n.clone();
                if active {
                    txt = format!("{n}  •");
                }
                ui.painter().text(r.min + vec2(6.0, 10.0), egui::Align2::LEFT_CENTER, txt, egui::FontId::proportional(13.0), crate::style::text());
                let resp = resp.on_hover_text("Double-click the profile name to connect");
                if resp.clicked() {
                    self.profiles_sel = n.clone();
                }
                if resp.double_clicked() {
                    action = Some(("connect", n.clone()));
                }
                resp.context_menu(|ui| {
                    for (label, key) in [
                        ("Connect", "connect"),
                        ("Edit profile", "edit"),
                        ("Edit the profile in a text editor", "edit_text"),
                        ("Rename profile", "rename"),
                        ("Duplicate", "duplicate"),
                        ("Export profile to file", "export"),
                        ("Remove", "remove"),
                    ] {
                        if ui.button(label).clicked() {
                            action = Some((key, n.clone()));
                            ui.close();
                        }
                    }
                });
            }
            let (r, resp, _) = row(ui, 20.0, "import");
            let hover = resp.hovered();
            ui.painter().rect_stroke(r.shrink(0.5), 0.0, egui::Stroke::new(1.0_f32, if hover { crate::style::sub() } else { crate::style::border() }), egui::StrokeKind::Inside);
            draw_glyph(ui.painter(), egui::Rect::from_min_size(r.min + vec2(3.0, 2.0), vec2(16.0, 16.0)), Glyph::Add, crate::style::text());
            ui.painter().text(r.min + vec2(24.0, 10.0), egui::Align2::LEFT_CENTER, "Import profile...", egui::FontId::proportional(13.0), crate::style::text());
            if resp.on_hover_cursor(egui::CursorIcon::PointingHand).clicked() {
                action = Some(("import", String::new()));
            }
        });

        ui.scope_builder(egui::UiBuilder::new().max_rect(right), |ui| {
            if !has {
                // The original's import area: big plus, then the instructions.
                let c = egui::pos2(right.center().x, right.top() + 170.0);
                let resp = ui.interact(right, egui::Id::new("import_area"), egui::Sense::click()).on_hover_cursor(egui::CursorIcon::PointingHand);
                let p = ui.painter();
                p.circle_stroke(c, 58.0, egui::Stroke::new(9.0_f32, crate::style::text()));
                p.line_segment([c - vec2(30.0, 0.0), c + vec2(30.0, 0.0)], egui::Stroke::new(9.0_f32, crate::style::text()));
                p.line_segment([c - vec2(0.0, 30.0), c + vec2(0.0, 30.0)], egui::Stroke::new(9.0_f32, crate::style::text()));
                let mut y = c.y + 105.0;
                for (t, size, strong) in [
                    ("Import profile", 15.0, true),
                    ("Drop config file here", 14.0, false),
                    ("(may not be available if the app is running with elevated privileges)", 9.5, false),
                    ("or", 14.0, false),
                    ("Click to browse for a file", 14.0, false),
                ] {
                    let col = if strong { crate::style::text() } else { crate::style::text() };
                    p.text(egui::pos2(c.x, y), egui::Align2::CENTER_CENTER, t, egui::FontId::proportional(size), col);
                    y += if size < 10.0 { 16.0 } else { 19.0 };
                }
                if resp.clicked() {
                    action = Some(("import", String::new()));
                }
                return;
            }
            egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                match self.store.load(&sel) {
                    Ok(p) => profile_details(ui, &sel, &p),
                    Err(e) => {
                        ui.colored_label(Color32::RED, e);
                    }
                }
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    if ui.button("Edit profile").clicked() {
                        action = Some(("edit", sel.clone()));
                    }
                    if ui.button("Edit text").clicked() {
                        action = Some(("edit_text", sel.clone()));
                    }
                    if ui.button("Rename").clicked() {
                        action = Some(("rename", sel.clone()));
                    }
                    if ui.button("Remove").clicked() {
                        action = Some(("remove", sel.clone()));
                    }
                });
            });
        });

        if let Some((key, n)) = action {
            match key {
                "connect" => {
                    self.select_profile(n);
                    if self.snap.state == State::Disconnected {
                        self.connect();
                    }
                }
                "edit" => self.open_editor(&n, EditMode::Form),
                "edit_text" => self.open_editor(&n, EditMode::Text),
                "rename" => self.dialog = Some(Dialog::Rename { old: n.clone(), new: n, error: String::new() }),
                "duplicate" => self.duplicate_selected(&n),
                "export" => self.export_selected(&n),
                "remove" => {
                    if self.settings.confirm_profile_removal {
                        self.dialog = Some(Dialog::Confirm {
                            title: "Remove profile".into(),
                            text: format!("Are you sure you want to remove this profile?\n{n}"),
                            action: Action::Remove(n),
                        });
                    } else if let Err(e) = self.store.remove(&n) {
                        self.message("Remove profile", e);
                    }
                }
                "import" => self.pick_and_import(),
                _ => {}
            }
        }
    }

    fn duplicate_selected(&mut self, n: &str) {
        match self.store.duplicate(n) {
            Ok(new) => self.profiles_sel = new,
            Err(e) => self.message("Duplicate profile", e),
        }
    }

    fn export_selected(&mut self, n: &str) {
        if let Some(path) = rfd::FileDialog::new().set_file_name(format!("{n}.conf")).add_filter("WireGuard profile", &["conf"]).save_file() {
            match self.store.read_text(n).and_then(|t| std::fs::write(&path, t).map_err(|e| e.to_string())) {
                Ok(()) => self.toast("Profile exported"),
                Err(e) => self.message("Export profile", e),
            }
        }
    }

    // ---------- Editor ----------

    fn page_editor(&mut self, ui: &mut egui::Ui) {
        let Some(mut ed) = self.editor.take() else { return };
        let title = if ed.original.is_none() { "Create New Profile" } else { "Edit Profile" };
        ui.heading(title);
        ui.horizontal(|ui| {
            ui.label("Profile name:");
            ui.add(egui::TextEdit::singleline(&mut ed.name).desired_width(220.0));
            ui.separator();
            if ui.selectable_label(ed.mode == EditMode::Form, "Form").clicked() && ed.mode == EditMode::Text {
                match Profile::parse(&ed.text) {
                    Ok(p) => {
                        ed.profile = p;
                        ed.mode = EditMode::Form;
                        ed.message.clear();
                    }
                    Err(e) => ed.message = e,
                }
            }
            if ui.selectable_label(ed.mode == EditMode::Text, "Text").clicked() && ed.mode == EditMode::Form {
                ed.text = ed.profile.to_conf();
                ed.mode = EditMode::Text;
            }
        });
        let mut close = false;
        let mut save = false;
        ui.horizontal(|ui| {
            if ui.button(RichText::new("Save and close").strong()).clicked() {
                save = true;
            }
            if ui.button("Discard and close").clicked() {
                if ed.dirty() {
                    self.dialog = Some(Dialog::Confirm {
                        title: "Closing the config edit page".into(),
                        text: "Do you want to discard all changes and close the page?".into(),
                        action: Action::DiscardEditor,
                    });
                } else {
                    close = true;
                }
            }
        });
        if !ed.message.is_empty() {
            ui.colored_label(Color32::RED, &ed.message);
        }
        ui.separator();
        match ed.mode {
            EditMode::Text => {
                ui.label("Profile content:");
                ui.add(
                    egui::TextEdit::multiline(&mut ed.text)
                        .font(egui::TextStyle::Monospace)
                        .desired_rows(30)
                        .desired_width(f32::INFINITY)
                        .code_editor(),
                );
            }
            EditMode::Form => {
                ed.errors = ed.profile.validate();
                let req = form(ui, &mut ed, &self.settings.masking_domains);
                if let Some(t) = req.pick {
                    self.picker = Some(Picker::new(t));
                }
                if req.manage_domains {
                    self.domains_edit = Some(self.settings.masking_domains.join("\n"));
                }
            }
        }
        if save {
            let parsed = match ed.mode {
                EditMode::Form => Ok(ed.profile.clone()),
                EditMode::Text => Profile::parse(&ed.text),
            };
            let result = parsed.and_then(|p| {
                if let Some(e) = profile::name_problem(&ed.name) {
                    return Err(e);
                }
                let renamed = ed.original.as_deref() != Some(ed.name.as_str());
                if renamed && self.store.exists(&ed.name) && !ed.original.as_deref().map(|o| o.eq_ignore_ascii_case(&ed.name)).unwrap_or(false) {
                    return Err(format!("A profile named {} already exists", ed.name));
                }
                let errs = p.validate();
                if let Some((f, m)) = errs.first() {
                    return Err(format!("Some profile fields contain invalid values. {f}: {m}"));
                }
                let text = if ed.mode == EditMode::Text { ed.text.clone() } else { p.to_conf() };
                self.store.save_text(&ed.name, &text)?;
                if let Some(old) = &ed.original {
                    if old != &ed.name {
                        let _ = self.store.remove(old);
                        if &self.settings.active_profile == old {
                            self.settings.active_profile = ed.name.clone();
                        }
                    }
                }
                if self.settings.active_profile.is_empty() {
                    self.settings.active_profile = ed.name.clone();
                }
                self.save_settings();
                Ok(())
            });
            match result {
                Ok(()) => {
                    self.profiles_sel = ed.name.clone();
                    if self.is_busy() && self.snap.profile == ed.name {
                        self.toast("You need to reconnect to apply this setting.");
                    } else {
                        self.toast("Profile saved");
                    }
                    close = true;
                }
                Err(e) => ed.message = e,
            }
        }
        if !close {
            self.editor = Some(ed);
        }
    }

    // ---------- General ----------

    fn page_general(&mut self, ui: &mut egui::Ui) {
        let s = &mut self.settings;
        let mut changed = false;
        section(ui, "Startup & auto-connect", "Control how the app starts and whether it connects automatically.");
        if toggle(ui, &mut s.auto_start, "Start app on sign-in", "Automatically launch the app when you sign in.") {
            changed = true;
            if self.live {
                self.autostart_error = crate::tunnel::set_autostart(s.auto_start).err().unwrap_or_default();
            }
        }
        if !self.autostart_error.is_empty() {
            ui.colored_label(Color32::RED, format!("Error changing autorun: {}", self.autostart_error));
        }
        changed |= toggle(ui, &mut s.auto_connect, "Connect on app launch", "Automatically connect to the VPN when the app starts.");
        let mut boot = s.connect_at_boot;
        let busy_boot = self.boot_job.is_some();
        let desc = if busy_boot { "Waiting for administrator approval..." } else { "Connect to the VPN when the computer starts, before sign-in." };
        let boot_changed = toggle(ui, &mut boot, "Connect at system startup", desc);
        let s = &mut self.settings;
        changed |= toggle(ui, &mut s.disconnect_on_exit, "Disconnect VPN when app closes", "Otherwise the tunnel keeps running after the app is closed.");

        section(ui, "Confirmation prompts", "Control when the app asks you to confirm actions that may interrupt connectivity.");
        changed |= toggle(ui, &mut s.confirm_disconnect, "Confirm before disconnecting", "");
        changed |= toggle(ui, &mut s.confirm_reconnect, "Confirm before reconnecting", "");
        changed |= toggle(ui, &mut s.confirm_profile_removal, "Confirm profile deletion", "");
        changed |= toggle(ui, &mut s.confirm_disconnect_on_exit, "Confirm disconnect on exit", "Ask for confirmation before disconnecting when closing the app.");

        section(ui, "Application appearance", "");
        ui.horizontal(|ui| {
            ui.label("App theme");
            for (t, l) in [(Theme::System, "Use system settings"), (Theme::Light, "Light"), (Theme::Dark, "Dark")] {
                if ui.radio_value(&mut s.theme, t, l).changed() {
                    changed = true;
                }
            }
        });
        let mut rescale = false;
        ui.horizontal(|ui| {
            ui.label("Interface scale");
            // Rescaling while dragging moves the slider out from under the pointer,
            // so the new size is applied when the slider is let go.
            let id = ui.id().with("ui_scale_pending");
            let mut v = ui.data(|d| d.get_temp::<f32>(id)).unwrap_or(s.ui_scale);
            let resp = ui.add(egui::Slider::new(&mut v, 0.8..=1.6).step_by(0.1).custom_formatter(|n, _| format!("{:.0}%", n * 100.0)));
            if resp.dragged() {
                ui.data_mut(|d| d.insert_temp(id, v));
            } else {
                ui.data_mut(|d| d.remove::<f32>(id));
                if (v - s.ui_scale).abs() > 0.001 {
                    s.ui_scale = (v * 10.0).round() / 10.0;
                    changed = true;
                    rescale = true;
                }
            }
        });

        section(ui, if cfg!(target_os = "macos") { "Menu bar" } else { "System tray" }, "");
        changed |= toggle(
            ui,
            &mut s.minimize_to_tray,
            "Minimize to system tray when closed",
            "Closing the window keeps the app running in the tray (menu bar on macOS). Quit with Exit in its menu.",
        );
        changed |= toggle(ui, &mut s.show_notifications, "Show system tray notifications", "Show notifications when the VPN connects or disconnects.");
        changed |= toggle(ui, &mut s.start_minimized, "Start minimized to tray", "Start in the tray instead of showing the main window.");
        if changed {
            let ctx = ui.ctx().clone();
            crate::app::apply_style(&ctx, &self.settings);
            if rescale {
                crate::app::apply_scale(&ctx, self.settings.ui_scale);
            }
            self.save_settings();
        }
        if boot_changed && !busy_boot && self.live {
            self.set_connect_at_boot(boot);
        }
    }

    // ---------- Network ----------

    fn page_network(&mut self, ui: &mut egui::Ui) {
        use crate::style;
        let mut pick: Option<PickTarget> = None;
        let s = &mut self.settings;
        let mut changed = false;
        // Same order as the original's Network page.
        let (c, open) = style::card_toggle_fold(ui, "dpi", &mut s.global_dpi, "Apply DPI protection to all profiles", "Apply DPI protection globally to help bypass VPN restrictions.");
        changed |= c;
        if open {
            ui.indent("dpi", |ui| {
                ui.horizontal(|ui| {
                    for (l, v) in [("Jc", &mut s.global_jc), ("Jmin", &mut s.global_jmin), ("Jmax", &mut s.global_jmax)] {
                        ui.label(l);
                        changed |= ui.add(egui::TextEdit::singleline(v).desired_width(60.0)).changed();
                    }
                });
                ui.label(RichText::new("Junk packets are sent before every handshake; they work with any WireGuard server. Profiles with their own Jc/Jmin/Jmax keep theirs.").size(FS_S - 1.0).weak());
            });
            ui.add_space(style::CARD_GAP);
        }
        let (c, open) = style::card_toggle_fold(ui, "split", &mut s.global_split_tunnel, "Apply split tunneling to all profiles", "Apply split tunneling settings globally to all profiles.");
        changed |= c;
        if open {
            ui.indent("split", |ui| {
                changed |= ui.checkbox(&mut s.override_profile_split, "Override profile settings").changed();
                egui::Grid::new("split").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
                    ui.label("Tunneled networks/addresses");
                    changed |= ui.add(egui::TextEdit::singleline(&mut s.global_allowed_ips).desired_width(300.0)).changed();
                    ui.end_row();
                    ui.label("Non-tunneled networks/addresses");
                    changed |= ui.add(egui::TextEdit::singleline(&mut s.global_disallowed_ips).desired_width(300.0).hint_text("e.g. 203.0.113.0/24")).changed();
                    ui.end_row();
                    ui.label("Tunneled applications");
                    ui.horizontal(|ui| {
                        changed |= ui.add(egui::TextEdit::singleline(&mut s.global_allowed_apps).desired_width(240.0)).changed();
                        if ui.button("Select...").on_hover_text("Select process").clicked() {
                            pick = Some(PickTarget::GlobalAllowed);
                        }
                    });
                    ui.end_row();
                    ui.label("Non-tunneled applications");
                    ui.horizontal(|ui| {
                        changed |= ui.add(egui::TextEdit::singleline(&mut s.global_disallowed_apps).desired_width(240.0)).changed();
                        if ui.button("Select...").on_hover_text("Select process").clicked() {
                            pick = Some(PickTarget::GlobalDisallowed);
                        }
                    });
                    ui.end_row();
                });
                ui.label(RichText::new(apps_note()).size(FS_S - 1.0).weak());
            });
            ui.add_space(style::CARD_GAP);
        }
        style::card(ui, "Use virtual adapter mode", "This version always uses its own virtual network adapter.", |ui| {
            let mut on = true;
            ui.add_enabled_ui(false, |ui| style::switch(ui, &mut on));
            ui.label(RichText::new("On").size(15.0).color(crate::style::text()));
        });
        let (c, open) = style::card_toggle_fold(ui, "killswitch", &mut s.kill_switch, "Enable Kill Switch", "Block network access if the VPN connection drops to prevent data leaks.");
        changed |= c;
        if open {
            ui.indent("ks", |ui| {
                changed |= toggle(
                    ui,
                    &mut s.preserve_lock,
                    "Keep network blocked when VPN disconnects",
                    "Traffic stays blocked after you disconnect, until you connect again or unlock it. DNS doesn't work while blocked, so use the server's IP address in the profile.",
                );
            });
        }
        changed |= toggle(
            ui,
            &mut s.tcp_termination,
            "Terminate TCP connections on connect",
            if cfg!(target_os = "macos") { "Not available on macOS: the system offers no way to close other apps' connections." } else { "Close existing TCP connections when the VPN connects." },
        );
        changed |= toggle(
            ui,
            &mut s.bypass_lan,
            "Bypass LAN traffic",
            "Allow local network traffic to bypass the VPN tunnel. DNS requests are still sent through the VPN, so local resources might not resolve by hostname. Use IP addresses instead.",
        );
        changed |= toggle(ui, &mut s.reconnect, "Automatically reconnect", "Reconnect to the VPN automatically if the connection is lost.");
        style::card(ui, "Connection timeout", "Specify how long the app should try to establish a VPN connection.", |ui| {
            let label = |v: u32| match v {
                0 => "Continuously retry",
                10 => "10 sec",
                30 => "30 sec",
                60 => "1 min",
                _ => "2 min",
            };
            egui::ComboBox::from_id_salt("timeout").width(130.0).selected_text(label(s.connection_timeout)).show_ui(ui, |ui| {
                for v in [10u32, 30, 60, 120, 0] {
                    if ui.selectable_value(&mut s.connection_timeout, v, label(v)).changed() {
                        changed = true;
                    }
                }
            });
        });
        if let Some(t) = pick {
            self.picker = Some(Picker::new(t));
        }
        if changed {
            self.save_settings();
        }
        if self.is_busy() && changed {
            self.toast("You need to reconnect to apply this setting.");
        }
    }

    // ---------- Security ----------

    fn page_security(&mut self, ui: &mut egui::Ui) {
        // Profile encryption: a Pro feature in the original, free here.
        let mut enc = self.settings.profile_encryption;
        let how = if cfg!(windows) {
            "Encrypt profiles on disk with Windows DPAPI for your user account (files compatible with the original app)."
        } else if cfg!(target_os = "macos") {
            "Encrypt profiles on disk with a key kept in your login keychain."
        } else {
            "Encrypt profiles on disk with a key kept in your keyring (Secret Service), or a private key file without one."
        };
        if toggle(ui, &mut enc, "Enable profile encryption", how) {
            match self.store.set_encryption(enc) {
                Ok(()) => {
                    self.settings.profile_encryption = enc;
                    self.save_settings();
                    self.toast(if enc { "Profiles encrypted" } else { "Profiles decrypted" });
                }
                Err(e) => {
                    self.store.encrypt = self.settings.profile_encryption;
                    self.message("Profile encryption", e);
                }
            }
        }
        let s = &mut self.settings;
        let mut changed = false;
        changed |= toggle(ui, &mut s.confirm_unlock_network, "Confirm network access restoration", "When Kill Switch is enabled, ask for confirmation before restoring network access.");
        crate::style::card(ui, "Kill Switch", "Turn it on under Network. It uses the system firewall: Windows Firewall, nftables on Linux, pf on macOS.", |_| {});
        let dir = self.store.dir.clone();
        let mut open = false;
        crate::style::card(ui, "Profiles folder", "Profiles are WireGuard files (encrypted when profile encryption is on), readable only by your user account.", |ui| {
            open = ui.button("Open folder").clicked();
        });
        if open {
            open_folder(&dir);
        }
        if changed {
            self.save_settings();
        }
    }

    // ---------- Advanced ----------

    fn page_advanced(&mut self, ui: &mut egui::Ui) {
        let s = &mut self.settings;
        let mut changed = false;
        section(ui, "Logs", "");
        ui.horizontal(|ui| {
            ui.label("Level:");
            egui::ComboBox::from_id_salt("loglevel").selected_text(s.log_level.label()).show_ui(ui, |ui| {
                for l in LogLevel::ALL {
                    changed |= ui.selectable_value(&mut s.log_level, l, l.label()).changed();
                }
            });
            ui.label("Limit:");
            egui::ComboBox::from_id_salt("loglimit").selected_text(s.log_limit.to_string()).show_ui(ui, |ui| {
                for l in [50usize, 100, 500, 1000, 5000] {
                    changed |= ui.selectable_value(&mut s.log_limit, l, l.to_string()).changed();
                }
            });
        });
        section(ui, "Application view customization", "Show or hide controls and sensitive information.");
        // A Pro feature in the original; available to everyone here.
        group_label(ui, "Main window");
        changed |= toggle(ui, &mut s.hide_logs_button, "Hide Logs button", "");
        changed |= toggle(ui, &mut s.hide_feedback_button, "Hide Feedback button", "");
        changed |= toggle(ui, &mut s.hide_import_button, "Hide Import button", "");
        changed |= toggle(ui, &mut s.hide_connection_stats, "Hide connection statistics", "");
        group_label(ui, "Preferences window");
        changed |= toggle(ui, &mut s.hide_security_tab, "Hide Security tab", "");
        changed |= toggle(ui, &mut s.hide_logs_tab, "Hide Logs tab", "");
        changed |= toggle(ui, &mut s.hide_feedback_tab, "Hide Feedback tab", "");
        changed |= toggle(ui, &mut s.hide_about_tab, "Hide About tab", "");
        group_label(ui, "Privacy");
        changed |= toggle(ui, &mut s.hide_endpoint_name, "Hide the VPN server name and address", "Hide the DNS name or IP address of the VPN server from the main window and the system tray.");
        changed |= toggle(ui, &mut s.use_system_tooltip, "Use the system tooltip in the system tray", "Show a short tooltip instead of the detailed one with traffic and uptime.");
        section(ui, "Tunnel engine", "Everything the tunnel needs is built into this app: nothing else to install.");
        ui.label(RichText::new(self.snap.engine.name.clone()).size(FS_S));
        ui.label(RichText::new("WireGuard protocol, junk packets, protocol masking and AmneziaWG magic headers all run inside the app. Connecting asks once for administrator approval to create the network adapter.").size(FS_S).weak());
        if changed {
            self.save_settings();
        }
    }

    // ---------- Logs ----------

    fn page_logs(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Level:");
            egui::ComboBox::from_id_salt("logview").selected_text(self.log_view_level.label()).show_ui(ui, |ui| {
                for l in LogLevel::ALL {
                    ui.selectable_value(&mut self.log_view_level, l, l.label());
                }
            });
            if ui.checkbox(&mut self.settings.log_autoscroll, "Autoscroll").on_hover_text("Automatically scroll to the latest log message").changed() {
                self.save_settings();
            }
            if ui.button("Open folder").on_hover_text("Open folder with log files").clicked() {
                open_folder(&crate::tunnel::log_dir());
            }
            if ui.button("Cleanup").on_hover_text("Clear all log messages from the UI").clicked() {
                if let Ok(mut s) = self.tunnel.shared.lock() {
                    s.logs.clear();
                }
            }
            if ui.button("Save to file...").clicked() {
                if let Some(p) = rfd::FileDialog::new().set_file_name("tunnel-log.txt").save_file() {
                    let _ = std::fs::write(p, logs_text(&self.tunnel.logs(), LogLevel::All, usize::MAX));
                }
            }
        });
        if self.log_view_level == LogLevel::All {
            ui.label(RichText::new("Showing 'all logs' may use more memory.").size(FS_S).weak());
        }
        ui.separator();
        let text = logs_text(&self.tunnel.logs(), self.log_view_level, self.settings.log_limit);
        egui::Frame::group(ui.style()).show(ui, |ui| {
            egui::ScrollArea::vertical().max_height(520.0).stick_to_bottom(self.settings.log_autoscroll).auto_shrink([false, false]).show(ui, |ui| {
                if text.is_empty() {
                    ui.label(RichText::new("No log messages yet.").weak());
                }
                ui.label(RichText::new(text).monospace().size(FS_S));
            });
        });
    }

    // ---------- Report ----------

    fn page_report(&mut self, ui: &mut egui::Ui) {
        ui.heading("Report issue");
        ui.label("Save a diagnostic report you can attach to a message to whoever helps you.");
        ui.label(RichText::new("It includes the app logs and your settings. Profiles and keys are never included.").size(FS_S).weak());
        ui.add_space(10.0);
        if ui.button(RichText::new("Save diagnostic report...").size(FS_M)).clicked() {
            if let Some(path) = rfd::FileDialog::new().set_file_name("tunnel-report.txt").save_file() {
                let mut t = String::new();
                t.push_str(&format!("Secure Tunnel {}\nOS: {} {}\n\n", env!("CARGO_PKG_VERSION"), std::env::consts::OS, std::env::consts::ARCH));
                t.push_str(&format!("Engine: {}\nState: {:?}\n\n", self.snap.engine.name, self.snap.state));
                t.push_str("Settings:\n");
                t.push_str(&serde_json::to_string_pretty(&self.settings).unwrap_or_default());
                t.push_str("\n\nLogs:\n");
                t.push_str(&logs_text(&self.tunnel.logs(), LogLevel::All, usize::MAX));
                match std::fs::write(&path, t) {
                    Ok(()) => self.toast("Report saved"),
                    Err(e) => self.message("Report issue", e.to_string()),
                }
            }
        }
    }

    // ---------- About ----------

    fn page_about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.label(RichText::new("Secure Tunnel").size(22.0).strong());
        ui.label(format!("Current version: {}", env!("CARGO_PKG_VERSION")));
        ui.add_space(8.0);
        ui.label("A WireGuard client for Windows, macOS and Linux: manage profiles, connect with one switch and watch live traffic.");
        ui.add_space(8.0);
        ui.label(RichText::new("Profiles folder").strong());
        ui.label(self.store.dir.display().to_string());
        if ui.button("Open folder").clicked() {
            open_folder(&self.store.dir);
        }
        ui.add_space(8.0);
        ui.label(RichText::new("WireGuard is a registered trademark of Jason A. Donenfeld.").size(FS_S).weak());
    }
}

fn next_free(names: &[String], base: &str) -> String {
    if !names.iter().any(|n| n.eq_ignore_ascii_case(base)) {
        return base.to_string();
    }
    profile::duplicate_name(base, names)
}

fn logs_text(s: &crate::tunnel::Shared, level: LogLevel, limit: usize) -> String {
    let rank = |l: LogLevel| match l {
        LogLevel::ConnectionStatus => 0,
        LogLevel::Error => 1,
        LogLevel::Warning => 2,
        LogLevel::Info => 3,
        LogLevel::Debug => 4,
        LogLevel::All => 5,
    };
    let lines: Vec<String> = s
        .logs
        .iter()
        .filter(|l| rank(l.level) <= rank(level))
        .map(|l| {
            let secs = l.time.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            let (h, m, sec) = ((secs / 3600) % 24, (secs / 60) % 60, secs % 60);
            let tag = match l.level {
                LogLevel::Error => "ERROR",
                LogLevel::Warning => "WARN ",
                LogLevel::Debug => "DEBUG",
                LogLevel::ConnectionStatus => "STATE",
                _ => "INFO ",
            };
            format!("{h:02}:{m:02}:{sec:02} UTC  {tag}  {}", l.text)
        })
        .collect();
    let start = lines.len().saturating_sub(limit);
    let _ = SystemTime::now();
    lines[start..].join("\n")
}

fn profile_details(ui: &mut egui::Ui, name: &str, p: &Profile) {
    ui.label(RichText::new(format!("Profile: {name}")).size(FS_M).strong());
    let row = |ui: &mut egui::Ui, k: &str, v: &str| {
        if !v.is_empty() {
            ui.label(RichText::new(k).weak());
            ui.add(egui::Label::new(v).wrap());
            ui.end_row();
        }
    };
    ui.add_space(4.0);
    ui.label(RichText::new("Local interface").strong());
    egui::Grid::new("pd_if").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        row(ui, "Address", &p.address);
        row(ui, "DNS", &p.dns);
        row(ui, "MTU", &p.mtu);
        row(ui, "ListenPort", &p.listen_port);
        let pubk = profile::public_from_private(&p.private_key).unwrap_or_default();
        row(ui, "Public key", &pubk);
    });
    ui.add_space(4.0);
    ui.label(RichText::new("Remote server").strong());
    egui::Grid::new("pd_peer").num_columns(2).spacing([8.0, 4.0]).show(ui, |ui| {
        row(ui, "Endpoint", &p.endpoint);
        row(ui, "AllowedIPs", &p.allowed_ips);
        row(ui, "Keep-alive", &p.keepalive);
    });
    ui.add_space(4.0);
    ui.label(RichText::new("Split tunneling").strong());
    let on = if p.has_split_tunnel() || p.bypass_lan_on() { "On" } else { "Off" };
    ui.label(on);
    ui.label(RichText::new("DPI protection").strong());
    let dpi = match (p.has_junk_packets(), p.needs_amnezia()) {
        (_, true) => "Magic headers (AmneziaWG)",
        (true, false) => "Junk packets",
        _ => "Off",
    };
    ui.label(dpi);
    let unenforced = p.unenforced_features();
    if !unenforced.is_empty() {
        ui.add_space(4.0);
        ui.label(RichText::new(format!("Not enforced in this version: {}", unenforced.join(", "))).size(FS_S).italics().color(if crate::style::is_dark() { Color32::from_rgb(0xE0, 0xA0, 0x40) } else { Color32::from_rgb(0x8A, 0x55, 0x00) }));
    }
    let errs = p.validate();
    if !errs.is_empty() {
        ui.add_space(4.0);
        ui.colored_label(Color32::RED, format!("{} field(s) need attention.", errs.len()));
    }
}

#[derive(Default)]
struct FormRequest {
    pick: Option<PickTarget>,
    manage_domains: bool,
}

fn form(ui: &mut egui::Ui, ed: &mut Editor, domains: &[String]) -> FormRequest {
    let mut req = FormRequest::default();
    let errs = ed.errors.clone();
    let p = &mut ed.profile;
    let err_for = |k: &str| errs.iter().find(|(f, _)| *f == k).map(|(_, m)| m.clone());
    let field = |ui: &mut egui::Ui, label: &str, key: &str, v: &mut String, hint: &str, tip: &str| {
        let e = err_for(key);
        let text = if e.is_some() { format!("{label} *") } else { label.to_string() };
        let l = ui.label(if e.is_some() { RichText::new(text).color(Color32::RED) } else { RichText::new(text) });
        if !tip.is_empty() {
            l.on_hover_text(tip);
        }
        let r = ui.add(egui::TextEdit::singleline(v).desired_width(330.0).hint_text(hint));
        if let Some(m) = e {
            r.on_hover_text(m);
        }
        ui.end_row();
    };
    ui.label(RichText::new("Local interface").size(FS_M).strong());
    ui.label(RichText::new("Your device's settings in the VPN network.").size(FS_S).weak());
    egui::Grid::new("f_if").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
        field(ui, "Name (comment)", "", &mut p.interface_name, "", "A comment to identify the node. WireGuard ignores it.");
        ui.label(if err_for("PrivateKey").is_some() { RichText::new("Private key *").color(Color32::RED) } else { RichText::new("Private key") });
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut p.private_key).desired_width(270.0).password(true));
            if ui.button("Gen").on_hover_text("Generate a new private key for the local interface").clicked() {
                p.private_key = profile::generate_private_key();
            }
        });
        ui.end_row();
        let pubk = profile::public_from_private(&p.private_key).unwrap_or_default();
        ui.label("Public key");
        ui.horizontal(|ui| {
            ui.label(RichText::new(&pubk).monospace().size(FS_S));
            if !pubk.is_empty() && ui.small_button("Copy").on_hover_text("Copy public key to clipboard").clicked() {
                ui.ctx().copy_text(pubk.clone());
            }
        });
        ui.end_row();
        field(ui, "Address", "Address", &mut p.address, "192.168.100.2/32, fd00::2/128", "IP address(es) assigned to the interface.");
        field(ui, "DNS", "DNS", &mut p.dns, "1.1.1.1", "DNS servers used while the tunnel is up, comma separated.");
        field(ui, "MTU", "MTU", &mut p.mtu, "automatic", "576 to 65535.");
        field(ui, "ListenPort", "ListenPort", &mut p.listen_port, "random", "1 to 65535.");
    });
    egui::CollapsingHeader::new("Scripts").show(ui, |ui| {
        egui::Grid::new("f_sc").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
            field(ui, "PreUp", "", &mut p.pre_up, "", "Run before the interface comes up.");
            field(ui, "PostUp", "", &mut p.post_up, "", "Run after the interface comes up.");
            field(ui, "PreDown", "", &mut p.pre_down, "", "Run before the interface goes down.");
            field(ui, "PostDown", "", &mut p.post_down, "", "Run after the interface goes down.");
            field(ui, "Script timeout (s)", "ScriptExecTimeout", &mut p.script_timeout, "", "0 to 65535.");
        });
    });
    ui.add_space(8.0);
    ui.label(RichText::new("Remote server").size(FS_M).strong());
    egui::Grid::new("f_peer").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
        field(ui, "Name (comment)", "", &mut p.peer_name, "", "");
        field(ui, "Public key", "PublicKey", &mut p.public_key, "base64, 44 characters", "The server's public key.");
        field(ui, "Preshared key", "PresharedKey", &mut p.preshared_key, "optional", "Must match the server.");
        field(ui, "Endpoint", "Endpoint", &mut p.endpoint, "vpn.example.com:51820", "Server address and port.");
        field(ui, "Persistent keep-alive", "PersistentKeepalive", &mut p.keepalive, "seconds, e.g. 25", "0 to 65535.");
        field(ui, "Tunneled networks (AllowedIPs)", "AllowedIPs", &mut p.allowed_ips, "0.0.0.0/0, ::/0", "Traffic to these addresses goes through the tunnel.");
    });
    ui.add_space(8.0);
    ui.label(RichText::new("Split tunneling").size(FS_M).strong());
    egui::Grid::new("f_split").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
        field(ui, "Non-tunneled networks", "DisallowedIPs", &mut p.disallowed_ips, "e.g. 192.0.2.0/24", "Addresses that skip the tunnel.");
        let mut lan = p.bypass_lan_on();
        ui.label("Bypass LAN traffic");
        if ui.checkbox(&mut lan, "").changed() {
            p.bypass_lan = if lan { "true".into() } else { String::new() };
        }
        ui.end_row();
        field(ui, "Tunneled applications", "", &mut p.allowed_apps, "e.g. firefox, chrome", apps_note());
        field(ui, "Non-tunneled applications", "", &mut p.disallowed_apps, "", apps_note());
    });
    ui.horizontal(|ui| {
        if ui.button("Select process for tunneled apps...").clicked() {
            req.pick = Some(PickTarget::ProfileAllowed);
        }
        if ui.button("Select process for non-tunneled apps...").clicked() {
            req.pick = Some(PickTarget::ProfileDisallowed);
        }
    });
    egui::CollapsingHeader::new("DPI protection (junk packets, magic headers, masking)").show(ui, |ui| {
        ui.label(RichText::new("Junk packets and protocol masking work with regular WireGuard servers and are sent by this app before every handshake. Magic headers (S1-S4, H1-H4) are built in too, but must match the server settings.").size(FS_S).weak());
        egui::Grid::new("f_dpi").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
            field(ui, "Jc - junk packet count", "Jc", &mut p.jc, "0-128", "");
            field(ui, "Jmin - min junk size", "Jmin", &mut p.jmin, "0-1280", "");
            field(ui, "Jmax - max junk size", "Jmax", &mut p.jmax, "0-1280", "");
            field(ui, "Jd - junk send delay (ms)", "Jd", &mut p.jd, "0-200", "Pause between junk packets. Default 0.");
            field(ui, "S1 - init padding", "S1", &mut p.s1, "", "");
            field(ui, "S2 - response padding", "S2", &mut p.s2, "", "");
            field(ui, "S3 - cookie padding", "S3", &mut p.s3, "", "");
            field(ui, "S4 - transport padding", "S4", &mut p.s4, "", "");
            field(ui, "H1 - init header", "H1", &mut p.h1, "number or min-max", "");
            field(ui, "H2 - response header", "H2", &mut p.h2, "", "");
            field(ui, "H3 - cookie header", "H3", &mut p.h3, "", "");
            field(ui, "H4 - transport header", "H4", &mut p.h4, "", "");
            field(ui, "Id - masking domain", "Id", &mut p.mask_domain, "e.g. a popular site in your region", "Turns on protocol masking: one packet that looks like QUIC, DNS, SIP or STUN traffic to this domain is sent before every handshake.");
            ui.label("");
            ui.horizontal(|ui| {
                ui.menu_button("Choose a domain", |ui| {
                    for d in domains {
                        if ui.button(d).clicked() {
                            p.mask_domain = d.clone();
                            ui.close();
                        }
                    }
                    ui.separator();
                    if ui.button("Manage combo box domains...").clicked() {
                        req.manage_domains = true;
                        ui.close();
                    }
                });
            });
            ui.end_row();
            ui.label("Ip - masking protocol");
            egui::ComboBox::from_id_salt("ip").selected_text(if p.mask_protocol.is_empty() { "none" } else { &p.mask_protocol }).show_ui(ui, |ui| {
                ui.selectable_value(&mut p.mask_protocol, String::new(), "none");
                for v in profile::MASKING_PROTOCOLS {
                    ui.selectable_value(&mut p.mask_protocol, v.to_string(), *v);
                }
            });
            ui.end_row();
            ui.label("Ib - browser");
            egui::ComboBox::from_id_salt("ib").selected_text(if p.mask_browser.is_empty() { "none" } else { &p.mask_browser }).show_ui(ui, |ui| {
                ui.selectable_value(&mut p.mask_browser, String::new(), "none");
                for v in profile::MASKING_BROWSERS {
                    ui.selectable_value(&mut p.mask_browser, v.to_string(), *v);
                }
            });
            ui.end_row();
        });
    });
    egui::CollapsingHeader::new("SOCKS5 proxy").show(ui, |ui| {
        ui.label(RichText::new("Sends the VPN's traffic through a SOCKS5 proxy (UDP relay) if a direct connection is blocked. The proxy and the server must both be IPv4 or both IPv6.").size(FS_S).weak());
        egui::Grid::new("f_socks").num_columns(2).spacing([10.0, 6.0]).min_col_width(200.0).show(ui, |ui| {
            field(ui, "SOCKS5 proxy", "Socks5Proxy", &mut p.socks5, "host:1080", "");
            field(ui, "Username (optional)", "", &mut p.socks5_user, "", "");
            ui.label("Password (optional)");
            ui.add(egui::TextEdit::singleline(&mut p.socks5_pass).password(true).desired_width(330.0));
            ui.end_row();
            let mut all = p.socks5_all.eq_ignore_ascii_case("true");
            ui.label("Route all traffic through the proxy");
            if ui.checkbox(&mut all, "").changed() {
                p.socks5_all = if all { "true".into() } else { String::new() };
            }
            ui.end_row();
        });
    });
    if !errs.is_empty() {
        ui.add_space(6.0);
        ui.colored_label(Color32::RED, "Some profile fields contain invalid values. They are marked with an asterisk.");
        for (f, m) in &errs {
            ui.label(RichText::new(format!("• {f}: {m}")).size(FS_S).color(Color32::RED));
        }
    }
    req
}

// ---------- small toolbar glyphs (16 px) ----------

#[derive(Clone, Copy)]
enum Glyph {
    Add,
    New,
    NewText,
    Duplicate,
    Reload,
    Export,
    Zip,
    Folder,
}

fn draw_glyph(p: &egui::Painter, r: egui::Rect, g: Glyph, col: Color32) {
    let s = egui::Stroke::new(1.4_f32, col);
    let c = r.center();
    let doc = |p: &egui::Painter| {
        let d = egui::Rect::from_min_max(r.min + vec2(2.5, 1.0), r.max - vec2(2.5, 1.0));
        p.add(egui::Shape::closed_line(
            vec![d.left_top(), egui::pos2(d.right() - 3.5, d.top()), egui::pos2(d.right(), d.top() + 3.5), d.right_bottom(), d.left_bottom()],
            s,
        ));
        d
    };
    match g {
        Glyph::Add => {
            p.circle_stroke(c, 7.0, s);
            p.line_segment([c - vec2(4.0, 0.0), c + vec2(4.0, 0.0)], s);
            p.line_segment([c - vec2(0.0, 4.0), c + vec2(0.0, 4.0)], s);
        }
        Glyph::New => {
            let d = doc(p);
            let k = d.center() + vec2(0.0, 1.5);
            p.line_segment([k - vec2(3.0, 0.0), k + vec2(3.0, 0.0)], s);
            p.line_segment([k - vec2(0.0, 3.0), k + vec2(0.0, 3.0)], s);
        }
        Glyph::NewText | Glyph::Zip => {
            let d = doc(p);
            let label = egui::Rect::from_min_max(egui::pos2(r.left(), d.center().y - 2.5), egui::pos2(r.right(), d.center().y + 4.5));
            p.rect_filled(label, 1.0, col);
            let t = if matches!(g, Glyph::Zip) { "ZIP" } else { "TXT" };
            p.text(label.center(), egui::Align2::CENTER_CENTER, t, egui::FontId::proportional(6.5), crate::style::bg());
        }
        Glyph::Duplicate => {
            p.rect_stroke(egui::Rect::from_min_size(r.min + vec2(1.0, 4.0), vec2(10.0, 10.0)), 1.0, s, egui::StrokeKind::Middle);
            p.rect_stroke(egui::Rect::from_min_size(r.min + vec2(5.0, 1.0), vec2(10.0, 10.0)), 1.0, s, egui::StrokeKind::Middle);
        }
        Glyph::Reload => {
            let pts: Vec<_> = (0..=16)
                .map(|i| {
                    let a = 0.6 + i as f32 / 16.0 * 5.2;
                    c + vec2(a.cos(), a.sin()) * 6.0
                })
                .collect();
            let end = *pts.last().unwrap();
            p.add(egui::Shape::line(pts, s));
            p.line_segment([end, end + vec2(3.5, 0.5)], s);
            p.line_segment([end, end + vec2(0.5, 3.5)], s);
        }
        Glyph::Export => {
            let d = doc(p);
            let y = d.center().y + 1.0;
            p.line_segment([egui::pos2(d.left() + 2.0, y), egui::pos2(r.right(), y)], s);
            p.line_segment([egui::pos2(r.right(), y), egui::pos2(r.right() - 3.0, y - 3.0)], s);
            p.line_segment([egui::pos2(r.right(), y), egui::pos2(r.right() - 3.0, y + 3.0)], s);
        }
        Glyph::Folder => {
            p.add(egui::Shape::closed_line(
                vec![
                    r.min + vec2(1.0, 3.0),
                    r.min + vec2(6.0, 3.0),
                    r.min + vec2(8.0, 5.0),
                    r.min + vec2(15.0, 5.0),
                    r.min + vec2(15.0, 14.0),
                    r.min + vec2(1.0, 14.0),
                ],
                s,
            ));
        }
    }
}

/// 20 x 20 toolbar button with a 16 px glyph.
fn glyph_button(ui: &mut egui::Ui, g: Glyph, enabled: bool, tip: &str) -> bool {
    let (rect, resp) = ui.allocate_exact_size(vec2(20.0, 20.0), if enabled { egui::Sense::click() } else { egui::Sense::hover() });
    if enabled && resp.hovered() {
        ui.painter().rect_filled(rect, 2.0, crate::style::hover());
    }
    let col = if enabled { crate::style::text() } else { crate::style::disabled() };
    draw_glyph(ui.painter(), rect.shrink(2.0), g, col);
    resp.on_hover_text(tip).clicked() && enabled
}

// ---------- "Select process" and masking-domain windows ----------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PickTarget {
    ProfileAllowed,
    ProfileDisallowed,
    GlobalAllowed,
    GlobalDisallowed,
}

/// The original's process list dialog: running programs with their paths.
pub struct Picker {
    target: PickTarget,
    filter: String,
    procs: Vec<(String, String)>,
}

impl Picker {
    pub fn new(target: PickTarget) -> Self {
        let mut p = Picker { target, filter: String::new(), procs: Vec::new() };
        p.reload();
        p
    }

    fn reload(&mut self) {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
        let Ok(mut sys) = System::new() else {
            self.procs.clear();
            return;
        };
        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::Always));
        let mut seen = std::collections::BTreeMap::new();
        for p in sys.processes().values() {
            let name = p.name().to_string_lossy().to_string();
            let path = p.exe().map(|e| e.display().to_string()).unwrap_or_default();
            seen.entry(name.to_lowercase()).or_insert((name, path));
        }
        self.procs = seen.into_values().collect();
    }
}

fn add_to_list(list: &mut String, item: &str) {
    let mut items = profile::split_list(list);
    if !items.iter().any(|x| x.eq_ignore_ascii_case(item)) {
        items.push(item.to_string());
    }
    *list = items.join(", ");
}

impl App {
    fn picker_window(&mut self, ctx: &egui::Context) {
        let Some(mut pk) = self.picker.take() else { return };
        let mut open = true;
        let mut chosen: Option<String> = None;
        egui::Window::new("Select process").open(&mut open).default_size([520.0, 420.0]).collapsible(false).show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Filter:");
                ui.text_edit_singleline(&mut pk.filter);
                if ui.button("Reload").on_hover_text("Reload list of processes").clicked() {
                    pk.reload();
                }
            });
            ui.label(RichText::new("Double-click a process to add its name; use \"Add path\" to add its full path.").size(FS_S).weak());
            egui::ScrollArea::vertical().max_height(320.0).show(ui, |ui| {
                let f = pk.filter.to_lowercase();
                egui::Grid::new("procs").striped(true).num_columns(3).show(ui, |ui| {
                    for (name, path) in pk.procs.iter().filter(|(n, p)| f.is_empty() || n.to_lowercase().contains(&f) || p.to_lowercase().contains(&f)) {
                        if ui.add(egui::Label::new(name.as_str()).sense(egui::Sense::click())).double_clicked() {
                            chosen = Some(name.trim_end_matches(".exe").to_string());
                        }
                        ui.add(egui::Label::new(RichText::new(path.as_str()).size(FS_S).weak()).truncate());
                        if !path.is_empty() && ui.small_button("Add path").clicked() {
                            chosen = Some(path.clone());
                        }
                        ui.end_row();
                    }
                });
            });
        });
        if let Some(item) = chosen {
            match pk.target {
                PickTarget::ProfileAllowed | PickTarget::ProfileDisallowed => {
                    if let Some(ed) = self.editor.as_mut() {
                        let list = if pk.target == PickTarget::ProfileAllowed { &mut ed.profile.allowed_apps } else { &mut ed.profile.disallowed_apps };
                        add_to_list(list, &item);
                    }
                }
                PickTarget::GlobalAllowed => add_to_list(&mut self.settings.global_allowed_apps, &item),
                PickTarget::GlobalDisallowed => add_to_list(&mut self.settings.global_disallowed_apps, &item),
            }
            self.save_settings();
            self.toast(format!("Added {item}"));
        }
        if open {
            self.picker = Some(pk);
        }
    }

    fn domains_window(&mut self, ctx: &egui::Context) {
        let Some(mut text) = self.domains_edit.take() else { return };
        let mut open = true;
        let mut save = false;
        egui::Window::new("Masking domains").open(&mut open).collapsible(false).show(ctx, |ui| {
            ui.label("Enter the list of predefined domains to be used in the combo box:");
            ui.add(egui::TextEdit::multiline(&mut text).desired_rows(8).desired_width(320.0));
            save = ui.button("Save").clicked();
        });
        if save {
            self.settings.masking_domains = text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
            self.save_settings();
            return;
        }
        if open {
            self.domains_edit = Some(text);
        }
    }
}
