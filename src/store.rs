//! Profiles live as `<name>.conf` files in one folder (or `<name>.dapi` when
//! profile encryption is on); settings as JSON.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::crypt;
use crate::profile::{self, Profile};

pub const EXT: &str = "conf";

pub fn base_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("SECURE_TUNNEL_HOME") {
        return PathBuf::from(dir);
    }
    directories::ProjectDirs::from("org", "SecureTunnel", "SecureTunnel")
        .map(|d| d.config_dir().to_path_buf())
        .unwrap_or_else(|| std::env::temp_dir().join("secure-tunnel"))
}

pub struct ProfileStore {
    pub dir: PathBuf,
    pub names: Vec<String>,
    /// Save profiles encrypted (`.dapi`).
    pub encrypt: bool,
}

impl ProfileStore {
    pub fn new(dir: PathBuf) -> Self {
        let mut s = ProfileStore { dir, names: Vec::new(), encrypt: false };
        s.reload();
        s
    }

    /// Lists `*.conf` and `*.dapi`, skipping temp files that start with `~`, sorted.
    pub fn reload(&mut self) {
        let mut names = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.dir) {
            for e in rd.flatten() {
                let p = e.path();
                let ext = p.extension().and_then(|x| x.to_str());
                if ext == Some(EXT) || ext == Some(crypt::ENC_EXT) {
                    if let Some(stem) = p.file_stem().and_then(|x| x.to_str()) {
                        if !stem.starts_with('~') && !names.iter().any(|n: &String| n == stem) {
                            names.push(stem.to_string());
                        }
                    }
                }
            }
        }
        names.sort_by_key(|a| a.to_lowercase());
        self.names = names;
    }

    /// The file a profile is in now (encrypted or not).
    pub fn path(&self, name: &str) -> PathBuf {
        let enc = self.dir.join(format!("{name}.{}", crypt::ENC_EXT));
        if enc.exists() { enc } else { self.dir.join(format!("{name}.{EXT}")) }
    }

    fn path_for(&self, name: &str, encrypted: bool) -> PathBuf {
        self.dir.join(format!("{name}.{}", if encrypted { crypt::ENC_EXT } else { EXT }))
    }

    /// Re-saves every profile encrypted or as plain text.
    pub fn set_encryption(&mut self, on: bool) -> Result<(), String> {
        self.encrypt = on;
        let mut errors = Vec::new();
        for n in self.names.clone() {
            match self.read_text(&n) {
                Ok(t) => {
                    if let Err(e) = self.save_text(&n, &t) {
                        errors.push(format!("{n}: {e}"));
                    }
                }
                Err(e) => errors.push(format!("{n}: {e}")),
            }
        }
        if errors.is_empty() { Ok(()) } else { Err(errors.join("\n")) }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.names.iter().any(|n| n.eq_ignore_ascii_case(name))
    }

    pub fn read_text(&self, name: &str) -> Result<String, String> {
        let p = self.path(name);
        let bytes = fs::read(&p).map_err(|e| format!("Failed to load profile: {e}"))?;
        let bytes = if p.extension().and_then(|x| x.to_str()) == Some(crypt::ENC_EXT) { crypt::decrypt(&bytes)? } else { bytes };
        String::from_utf8(bytes).map_err(|_| "Failed to load profile: not text".to_string())
    }

    pub fn load(&self, name: &str) -> Result<Profile, String> {
        Profile::parse(&self.read_text(name)?)
    }

    pub fn save_text(&mut self, name: &str, text: &str) -> Result<(), String> {
        fs::create_dir_all(&self.dir).map_err(|e| format!("Failed to create directory: {e}"))?;
        let tmp = self.dir.join(format!("~{name}.{EXT}"));
        let body = if self.encrypt { crypt::encrypt(text.as_bytes())? } else { text.as_bytes().to_vec() };
        {
            let mut f = fs::File::create(&tmp).map_err(|e| format!("Failed to save profile: {e}"))?;
            f.write_all(&body).map_err(|e| format!("Failed to save profile: {e}"))?;
        }
        restrict_permissions(&tmp);
        fs::rename(&tmp, self.path_for(name, self.encrypt)).map_err(|e| format!("Failed to save profile: {e}"))?;
        // Only one copy is kept: the other form is removed.
        let _ = fs::remove_file(self.path_for(name, !self.encrypt));
        self.reload();
        Ok(())
    }

    #[allow(dead_code)]
    pub fn save(&mut self, name: &str, p: &Profile) -> Result<(), String> {
        self.save_text(name, &p.to_conf())
    }

    pub fn import_file(&mut self, file: &Path) -> Result<String, String> {
        let text = fs::read_to_string(file).map_err(|e| format!("Cannot open config file: {e}"))?;
        Profile::parse(&text)?;
        let name = file
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or("Invalid file name")?
            .to_string();
        let name = sanitize_name(&name);
        if self.exists(&name) {
            return Err(format!("A profile named {name} already exists"));
        }
        self.save_text(&name, &text)?;
        Ok(name)
    }

    pub fn remove(&mut self, name: &str) -> Result<(), String> {
        fs::remove_file(self.path(name)).map_err(|e| format!("Cannot delete file: {e}"))?;
        self.reload();
        Ok(())
    }

    pub fn rename(&mut self, old: &str, new: &str) -> Result<(), String> {
        if let Some(e) = profile::name_problem(new) {
            return Err(e);
        }
        if !old.eq_ignore_ascii_case(new) && self.exists(new) {
            return Err(format!("A profile named {new} already exists"));
        }
        let from = self.path(old);
        let to = self.dir.join(format!("{new}.{}", from.extension().and_then(|x| x.to_str()).unwrap_or(EXT)));
        fs::rename(from, to).map_err(|e| format!("Profile renaming failed: {e}"))?;
        self.reload();
        Ok(())
    }

    pub fn duplicate(&mut self, name: &str) -> Result<String, String> {
        let new = profile::duplicate_name(name, &self.names);
        let from = self.path(name);
        let to = self.dir.join(format!("{new}.{}", from.extension().and_then(|x| x.to_str()).unwrap_or(EXT)));
        fs::copy(from, to).map_err(|e| format!("Failed to copy file: {e}"))?;
        self.reload();
        Ok(new)
    }

    pub fn export_zip(&self, target: &Path) -> Result<(), String> {
        let f = fs::File::create(target).map_err(|e| e.to_string())?;
        let mut z = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for n in &self.names {
            let text = self.read_text(n)?;
            z.start_file(format!("{n}.{EXT}"), opts).map_err(|e| e.to_string())?;
            z.write_all(text.as_bytes()).map_err(|e| e.to_string())?;
        }
        z.finish().map_err(|e| e.to_string())?;
        Ok(())
    }
}

pub fn sanitize_name(n: &str) -> String {
    let s: String = n
        .chars()
        .map(|c| if profile::INVALID_NAME_CHARS.contains(&c) { '_' } else { c })
        .collect();
    if s.trim().is_empty() { "profile".into() } else { s.trim().to_string() }
}

#[cfg(unix)]
pub fn restrict_permissions(p: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(p, fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
pub fn restrict_permissions(_p: &Path) {}

// ---------- settings ----------

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Theme {
    System,
    Light,
    Dark,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum LogLevel {
    ConnectionStatus,
    Error,
    Warning,
    Info,
    Debug,
    All,
}

impl LogLevel {
    pub const ALL: [LogLevel; 6] = [
        LogLevel::ConnectionStatus,
        LogLevel::Error,
        LogLevel::Warning,
        LogLevel::Info,
        LogLevel::Debug,
        LogLevel::All,
    ];
    pub fn label(self) -> &'static str {
        match self {
            LogLevel::ConnectionStatus => "Connection status (default)",
            LogLevel::Error => "Error",
            LogLevel::Warning => "Warning",
            LogLevel::Info => "Info",
            LogLevel::Debug => "Debug",
            LogLevel::All => "All logs",
        }
    }
}

/// Defaults copied from the original's settings defaults (see MECHANICS.md).
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct Settings {
    pub active_profile: String,
    // General
    pub auto_start: bool,
    pub auto_connect: bool,
    pub start_minimized: bool,
    pub minimize_to_tray: bool,
    pub show_notifications: bool,
    pub confirm_disconnect: bool,
    pub confirm_reconnect: bool,
    pub confirm_disconnect_on_exit: bool,
    pub confirm_profile_removal: bool,
    pub confirm_unlock_network: bool,
    pub disconnect_on_exit: bool,
    pub theme: Theme,
    // Network
    pub kill_switch: bool,
    pub preserve_lock: bool,
    pub reconnect: bool,
    /// Seconds; 0 = keep retrying.
    pub connection_timeout: u32,
    pub tcp_termination: bool,
    pub virtual_adapter: bool,
    pub global_split_tunnel: bool,
    pub override_profile_split: bool,
    pub global_allowed_ips: String,
    pub global_disallowed_ips: String,
    pub global_allowed_apps: String,
    pub global_disallowed_apps: String,
    pub bypass_lan: bool,
    pub global_dpi: bool,
    pub global_jc: String,
    pub global_jmin: String,
    pub global_jmax: String,
    // Advanced
    pub log_level: LogLevel,
    pub log_limit: usize,
    pub log_autoscroll: bool,
    pub hide_external_ip: bool,
    pub hide_endpoint_name: bool,
    pub hide_connection_stats: bool,
    pub hide_logs_button: bool,
    pub hide_import_button: bool,
    pub hide_logs_tab: bool,
    pub hide_about_tab: bool,
    pub hide_feedback_button: bool,
    pub hide_feedback_tab: bool,
    pub hide_security_tab: bool,
    /// Plain system tray tooltip instead of the detailed one.
    pub use_system_tooltip: bool,
    /// Save profiles encrypted (original Pro feature, free here).
    pub profile_encryption: bool,
    /// Connect at system startup, before sign-in (original AutoConnectService).
    pub connect_at_boot: bool,
    /// Domains offered for protocol masking (original PreferredMaskingDomains).
    pub masking_domains: Vec<String>,
    pub ui_scale: f32,
    pub engine_path: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            active_profile: String::new(),
            auto_start: false,
            auto_connect: false,
            start_minimized: false,
            minimize_to_tray: true,
            show_notifications: true,
            confirm_disconnect: true,
            confirm_reconnect: true,
            confirm_disconnect_on_exit: true,
            confirm_profile_removal: true,
            confirm_unlock_network: true,
            disconnect_on_exit: false,
            theme: Theme::System,
            kill_switch: false,
            preserve_lock: false,
            reconnect: true,
            connection_timeout: 0,
            tcp_termination: false,
            virtual_adapter: false,
            global_split_tunnel: false,
            override_profile_split: false,
            global_allowed_ips: "0.0.0.0/0, ::/0".into(),
            global_disallowed_ips: String::new(),
            global_allowed_apps: String::new(),
            global_disallowed_apps: String::new(),
            bypass_lan: false,
            global_dpi: true,
            global_jc: "3".into(),
            global_jmin: "50".into(),
            global_jmax: "1000".into(),
            log_level: LogLevel::ConnectionStatus,
            log_limit: 50,
            log_autoscroll: true,
            hide_external_ip: false,
            hide_endpoint_name: false,
            hide_connection_stats: false,
            hide_logs_button: false,
            hide_import_button: false,
            hide_logs_tab: false,
            hide_about_tab: false,
            hide_feedback_button: false,
            hide_feedback_tab: false,
            hide_security_tab: false,
            use_system_tooltip: false,
            profile_encryption: false,
            connect_at_boot: false,
            masking_domains: vec!["www.google.com".into(), "www.microsoft.com".into(), "www.apple.com".into(), "www.cloudflare.com".into(), "www.amazon.com".into()],
            ui_scale: 1.0,
            engine_path: String::new(),
        }
    }
}

impl Settings {
    pub fn file() -> PathBuf {
        base_dir().join("settings.json")
    }
    pub fn load() -> Settings {
        fs::read_to_string(Self::file())
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default()
    }
    pub fn save(&self) {
        let _ = fs::create_dir_all(base_dir());
        if let Ok(t) = serde_json::to_string_pretty(self) {
            let _ = fs::write(Self::file(), t);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn encryption_roundtrip() {
        let dir = std::env::temp_dir().join(format!("st-store-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut st = ProfileStore::new(dir.clone());
        let text = "[Interface]
PrivateKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI=
Address = 192.168.100.2/32
[Peer]
PublicKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI=
Endpoint = 192.0.2.1:51820
AllowedIPs = 0.0.0.0/0
";
        st.save_text("Home", text).unwrap();
        st.set_encryption(true).unwrap();
        assert!(dir.join("Home.dapi").exists() && !dir.join("Home.conf").exists());
        assert!(!fs::read(dir.join("Home.dapi")).unwrap().windows(9).any(|w| w == b"Interface"));
        assert_eq!(st.read_text("Home").unwrap(), text);
        st.rename("Home", "Work").unwrap();
        assert_eq!(st.names, vec!["Work".to_string()]);
        st.set_encryption(false).unwrap();
        assert_eq!(fs::read_to_string(dir.join("Work.conf")).unwrap(), text);
        let _ = fs::remove_dir_all(&dir);
    }
}
