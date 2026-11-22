//! Running inside a Flatpak sandbox (Linux).
//!
//! The tunnel helper needs root, which `pkexec` on the host grants. From inside
//! the sandbox that means `flatpak-spawn --host pkexec <program>`, where
//! `<program>` is this binary's path as the host sees it. The binary targets
//! glibc 2.31 and needs only libc, so it runs on the host as is. The window and
//! the helper talk through files under the app's config folder, which has the
//! same absolute path inside and outside the sandbox.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::path::{Path, PathBuf};
use std::process::Command;

const INFO: &str = "/.flatpak-info";

/// The Flatpak app ID, used for `flatpak run` in the autostart entry.
pub const APP_ID: &str = "org.securetunnel.SecureTunnel";

pub fn active() -> bool {
    cfg!(target_os = "linux") && Path::new(INFO).is_file()
}

/// A command that runs `program` on the host when sandboxed, or directly otherwise.
pub fn host_command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    if active() {
        let mut c = Command::new("flatpak-spawn");
        c.arg("--host").arg(program);
        c
    } else {
        Command::new(program)
    }
}

/// `exe` as the host (and root) sees it. Inside Flatpak, `/app/...` lives under the
/// deployment's `current/active/files`, which stays valid across updates. Inside an
/// AppImage, the program runs from a FUSE mount that root can't read, so the
/// `.AppImage` file itself (`$APPIMAGE`) is what gets started.
pub fn host_path(exe: &Path) -> PathBuf {
    if cfg!(target_os = "linux") {
        if let Some(appimage) = std::env::var_os("APPIMAGE").filter(|v| !v.is_empty()) {
            return PathBuf::from(appimage);
        }
    }
    if !active() {
        return exe.to_path_buf();
    }
    let info = std::fs::read_to_string(INFO).unwrap_or_default();
    match (app_path(&info), exe.strip_prefix("/app")) {
        (Some(files), Ok(rel)) => stable_files_dir(&files).join(rel),
        _ => exe.to_path_buf(),
    }
}

/// `app-path=` from the `[Instance]` section of /.flatpak-info.
fn app_path(info: &str) -> Option<PathBuf> {
    let mut in_instance = false;
    for line in info.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_instance = line == "[Instance]";
        } else if in_instance {
            if let Some(v) = line.strip_prefix("app-path=") {
                return Some(PathBuf::from(v.trim()));
            }
        }
    }
    None
}

/// `<base>/app/<id>/<arch>/<branch>/<commit>/files` -> `<base>/app/<id>/current/active/files`.
fn stable_files_dir(files: &Path) -> PathBuf {
    let parts: Vec<_> = files.components().collect();
    let n = parts.len();
    if n >= 6 && files.ends_with("files") {
        // Drop <arch>/<branch>/<commit>/files.
        let app_dir: PathBuf = parts[..n - 4].iter().collect();
        return app_dir.join("current").join("active").join("files");
    }
    files.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_app_path_from_instance_section() {
        let info = "[Application]\nname=x\n\n[Instance]\ninstance-id=1\napp-path=/var/lib/flatpak/app/org.example.App/x86_64/stable/abc123/files\n";
        assert_eq!(app_path(info), Some(PathBuf::from("/var/lib/flatpak/app/org.example.App/x86_64/stable/abc123/files")));
        assert_eq!(app_path("[Application]\napp-path=/nope\n"), None);
    }

    #[test]
    fn maps_commit_dir_to_stable_link() {
        let p = Path::new("/var/lib/flatpak/app/org.example.App/x86_64/stable/abc123/files");
        assert_eq!(stable_files_dir(p), PathBuf::from("/var/lib/flatpak/app/org.example.App/current/active/files"));
        let user = Path::new("/home/u/.local/share/flatpak/app/org.example.App/x86_64/stable/abc/files");
        assert_eq!(stable_files_dir(user), PathBuf::from("/home/u/.local/share/flatpak/app/org.example.App/current/active/files"));
    }
}
