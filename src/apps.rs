//! Per-app split tunnelling. Matching rules come from the original's help text:
//! names with or without ".exe", full paths, and folders ("paths with slashes
//! are treated as full directories"); if both lists are set, tunneled apps win.
//!
//! Linux enforces it with a cgroup, an nftables mark and a policy-routing
//! table. Windows and macOS would need a kernel network driver (the original
//! ships one) or Apple's Network Extension entitlement, so there the lists are
//! kept but not enforced.

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Only these apps use the tunnel.
    OnlyThese(Vec<String>),
    /// These apps skip the tunnel.
    Except(Vec<String>),
}

pub fn mode(allowed: &str, disallowed: &str) -> Option<Mode> {
    let list = |s: &str| -> Vec<String> { s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect() };
    let a = list(allowed);
    let d = list(disallowed);
    if !a.is_empty() {
        Some(Mode::OnlyThese(a))
    } else if !d.is_empty() {
        Some(Mode::Except(d))
    } else {
        None
    }
}

/// Linux: always (cgroup + nftables). Windows x64: the bundled WinDivert
/// filter. macOS: when running from Secure Tunnel.app, whose Network Extension
/// does the routing. Other targets keep the lists but don't enforce them.
pub fn enforced() -> bool {
    if cfg!(target_os = "linux") {
        return true;
    }
    if crate::winfilter::SUPPORTED {
        return true;
    }
    cfg!(target_os = "macos") && mac_controller().is_some()
}

/// `Secure Tunnel` (the app's controller) next to this program inside the app bundle.
pub fn mac_controller() -> Option<std::path::PathBuf> {
    let exe = std::env::current_exe().ok()?;
    let ctl = exe.parent()?.join("Secure Tunnel");
    (cfg!(target_os = "macos") && ctl.is_file()).then_some(ctl)
}

/// Runs the macOS controller: `--netext install|enable <mode> <apps>|disable`.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn mac_netext(args: &[String]) -> Result<String, String> {
    let ctl = mac_controller().ok_or("Per-app routing on macOS needs the full Secure Tunnel.app")?;
    let o = std::process::Command::new(ctl).arg("--netext").args(args).output().map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&o.stdout).trim().to_string();
    if o.status.success() { Ok(text) } else { Err(text) }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn norm(s: &str) -> String {
    let s = s.trim().replace('\\', "/").to_lowercase();
    s.strip_suffix(".exe").map(|x| x.to_string()).unwrap_or(s)
}

/// Does a running program (its executable path and short name) match a rule?
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn matches(rule: &str, exe: &str, comm: &str) -> bool {
    let r = norm(rule);
    if r.is_empty() {
        return false;
    }
    let exe_n = norm(exe);
    if r.contains('/') {
        // A full path to the program, or a folder holding it.
        let dir = r.trim_end_matches('/');
        return exe_n == dir || exe_n.starts_with(&format!("{dir}/"));
    }
    let base = exe_n.rsplit('/').next().unwrap_or("");
    base == r || norm(comm) == r
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::*;
    use std::path::Path;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    pub const CGROUP: &str = "/sys/fs/cgroup/securetunnel";
    pub const MARK: u32 = 0x5354;
    pub const TABLE: u32 = 0x5354;
    /// How often running programs are checked and moved into the cgroup.
    pub const SCAN: Duration = Duration::from_secs(1);

    fn run(prog: &str, args: &[&str], log: &mut dyn FnMut(String)) -> bool {
        match Command::new(prog).args(args).output() {
            Ok(o) if o.status.success() => true,
            Ok(o) => {
                log(format!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()));
                false
            }
            Err(e) => {
                log(format!("{prog}: {e}"));
                false
            }
        }
    }

    pub fn nft(tun: &str, only_these: bool) -> String {
        let nat = if only_these { format!("oifname \"{tun}\"") } else { format!("oifname != \"{tun}\"") };
        format!(
            "table inet securetunnel_apps {{}}\ndelete table inet securetunnel_apps\ntable inet securetunnel_apps {{\n  chain mark {{\n    type route hook output priority mangle;\n    socket cgroupv2 level 1 \"securetunnel\" meta mark set {MARK:#x}\n  }}\n  chain nat {{\n    type nat hook postrouting priority srcnat;\n    meta mark {MARK:#x} {nat} masquerade\n  }}\n}}\n"
        )
    }

    /// Sets up marking and the rule that sends traffic to the tunnel table.
    /// The tunnel's routes must go into table `TABLE`.
    pub fn setup(tun: &str, mode: &Mode, run_dir: &Path, log: &mut dyn FnMut(String)) -> Result<(), String> {
        std::fs::create_dir_all(CGROUP).map_err(|e| format!("Per-app split tunnelling needs cgroup v2 ({e})"))?;
        run("sysctl", &["-q", "-w", "net.ipv4.conf.all.src_valid_mark=1"], log);
        let only = matches!(mode, Mode::OnlyThese(_));
        let file = run_dir.join("apps.nft");
        std::fs::write(&file, nft(tun, only)).map_err(|e| e.to_string())?;
        if !run("nft", &["-f", &file.display().to_string()], log) {
            return Err("Per-app split tunnelling needs nftables with cgroup v2 socket matching".into());
        }
        let table = TABLE.to_string();
        let mark = format!("{MARK:#x}");
        for fam in ["-4", "-6"] {
            let mut a = vec![fam, "rule", "add"];
            if !only {
                a.push("not");
            }
            a.extend(["fwmark", &mark, "lookup", &table, "priority", &table]);
            run("ip", &a, log);
        }
        Ok(())
    }

    pub fn teardown(log: &mut dyn FnMut(String)) {
        let table = TABLE.to_string();
        for fam in ["-4", "-6"] {
            // Rules are removed by priority, whichever form they took.
            let _ = Command::new("ip").args([fam, "rule", "del", "priority", &table]).output();
        }
        run("nft", &["delete", "table", "inet", "securetunnel_apps"], log);
        // Hand the programs back to the root cgroup, then remove ours.
        if let Ok(pids) = std::fs::read_to_string(format!("{CGROUP}/cgroup.procs")) {
            for pid in pids.lines() {
                let _ = std::fs::write("/sys/fs/cgroup/cgroup.procs", pid);
            }
        }
        let _ = std::fs::remove_dir(CGROUP);
    }

    /// Moves matching programs into the cgroup until `stop` is set.
    pub fn watch(mode: Mode, stop: Arc<AtomicBool>) {
        let rules = match &mode {
            Mode::OnlyThese(r) | Mode::Except(r) => r.clone(),
        };
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Ok(rd) = std::fs::read_dir("/proc") {
                    for e in rd.flatten() {
                        let name = e.file_name();
                        let Some(pid) = name.to_str().filter(|s| s.chars().all(|c| c.is_ascii_digit())) else { continue };
                        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default();
                        let comm = std::fs::read_to_string(format!("/proc/{pid}/comm")).unwrap_or_default();
                        if exe.is_empty() && comm.is_empty() {
                            continue;
                        }
                        if !rules.iter().any(|r| matches(r, &exe, comm.trim())) {
                            continue;
                        }
                        let cg = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
                        if !cg.contains("/securetunnel") {
                            let _ = std::fs::write(format!("{CGROUP}/cgroup.procs"), pid);
                        }
                    }
                }
                std::thread::sleep(SCAN);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_rules() {
        assert!(matches("firefox", "/usr/lib/firefox/firefox", "firefox"));
        assert!(matches("Firefox.exe", "C:\\Program Files\\Mozilla Firefox\\firefox.exe", ""));
        assert!(matches("/usr/lib/firefox", "/usr/lib/firefox/firefox-bin", ""));
        assert!(matches("C:\\Games\\", "C:\\Games\\Steam\\steam.exe", ""));
        assert!(!matches("fire", "/usr/bin/firefox", "firefox"));
        assert!(matches("chrome", "/opt/google/chrome/chrome", "chrome"));
    }

    #[test]
    fn tunneled_apps_win() {
        assert_eq!(mode("a, b", "c"), Some(Mode::OnlyThese(vec!["a".into(), "b".into()])));
        assert_eq!(mode("", "c"), Some(Mode::Except(vec!["c".into()])));
        assert_eq!(mode(" ", ""), None);
    }
}
