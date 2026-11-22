//! Kill switch / network lock: blocks all outgoing traffic except the tunnel,
//! the way to the VPN server (or SOCKS5 proxy), loopback, DHCP and, when
//! "Bypass LAN" is on, the local network. Like the original
//! (`network_lock_mode` enabled/disabled, `wgb_drop_tunnel(preserve_network_lock)`,
//! `wg_reset_network_lock`), the lock outlives a dropped tunnel, is lifted on a
//! normal disconnect unless "preserve" is set, and can be reset by hand.
//! The Windows Filtering Platform (src/wfp.rs), nftables on Linux and pf on
//! macOS do the blocking.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

#[cfg_attr(not(windows), allow(dead_code))]
pub const NAME: &str = "SecureTunnel lock";

#[derive(Clone, Debug, Default)]
pub struct LockSpec {
    #[cfg_attr(windows, allow(dead_code))]
    pub tun_name: String,
    #[cfg_attr(not(windows), allow(dead_code))]
    pub tun_ips: Vec<IpAddr>,
    /// Remote endpoints that must stay reachable: (address, UDP port or None for any protocol).
    pub allow: Vec<(IpAddr, Option<u16>)>,
    pub lan: bool,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Marker {
    /// Windows, older versions: firewall policy per profile before the lock
    /// (domain, private, public). Empty for the WFP kill switch.
    pub policy: Vec<String>,
    /// macOS: pf enable token to release.
    pub pf_token: String,
}

pub fn marker_path(run_dir: &Path) -> PathBuf {
    run_dir.join("netlock.json")
}

pub fn is_active(run_dir: &Path) -> bool {
    marker_path(run_dir).exists()
}

#[cfg_attr(target_os = "linux", allow(dead_code))]
fn read_marker(run_dir: &Path) -> Option<Marker> {
    serde_json::from_str(&std::fs::read_to_string(marker_path(run_dir)).ok()?).ok()
}

fn write_marker(run_dir: &Path, m: &Marker) {
    if let Ok(t) = serde_json::to_string(m) {
        let _ = std::fs::write(marker_path(run_dir), t);
    }
}

fn run(prog: &str, args: &[&str], log: &mut dyn FnMut(String)) -> Option<String> {
    let mut c = Command::new(prog);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    match c.output() {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr)),
        Ok(o) => {
            log(format!("{prog} {}: {}", args.join(" "), String::from_utf8_lossy(&o.stderr).trim()));
            None
        }
        Err(e) => {
            log(format!("{prog}: {e}"));
            None
        }
    }
}

pub const LAN_V4: &[&str] = &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"];
pub const LAN_V6: &[&str] = &["fe80::/10", "fd00::/8", "ff00::/8"];

// ---------- Windows ----------

#[cfg(windows)]
const PROFILES: [&str; 3] = ["domainprofile", "privateprofile", "publicprofile"];

/// Policy tokens such as `BlockInbound,AllowOutbound` (they aren't translated).
#[cfg(test)]
pub fn parse_policies(text: &str) -> Vec<String> {
    text.split_whitespace()
        .filter(|w| (w.starts_with("Block") || w.starts_with("Allow")) && w.contains("Inbound") && w.contains("Outbound"))
        .map(|w| w.to_string())
        .collect()
}

#[cfg(windows)]
pub fn apply(spec: &LockSpec, run_dir: &Path, log: &mut dyn FnMut(String)) -> Result<(), String> {
    // Windows Filtering Platform filters (see src/wfp.rs). A lock from an older
    // version (firewall policy + netsh rules) is lifted first.
    let marker = read_marker(run_dir).unwrap_or_default();
    if !marker.policy.is_empty() {
        remove_legacy(&marker, log);
    }
    write_marker(run_dir, &Marker::default());
    crate::wfp::apply(spec).map_err(|e| {
        log(e.clone());
        format!("Could not turn on the Kill Switch: {e}")
    })
}

#[cfg(windows)]
fn delete_rules(log: &mut dyn FnMut(String)) {
    let mut quiet = |_: String| {};
    let _ = log;
    for suffix in ["tunnel", "loopback", "dhcp", "dhcpv6", "lan"] {
        run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={NAME} {suffix}")], &mut quiet);
    }
    for i in 0..4 {
        run("netsh", &["advfirewall", "firewall", "delete", "rule", &format!("name={NAME} server {i}")], &mut quiet);
    }
}

#[cfg(windows)]
pub fn remove(run_dir: &Path, log: &mut dyn FnMut(String)) {
    let marker = read_marker(run_dir).unwrap_or_default();
    if !marker.policy.is_empty() {
        remove_legacy(&marker, log);
    }
    if let Err(e) = crate::wfp::remove() {
        log(e);
    }
    let _ = std::fs::remove_file(marker_path(run_dir));
}

/// Lifts a lock made by an earlier build, before the WFP kill switch: restores the
/// firewall policy it saved and deletes its rules.
#[cfg(windows)]
fn remove_legacy(marker: &Marker, log: &mut dyn FnMut(String)) {
    if marker.policy.len() == 3 {
        for (i, prof) in PROFILES.iter().enumerate() {
            run("netsh", &["advfirewall", "set", prof, "firewallpolicy", &marker.policy[i]], log);
        }
    }
    delete_rules(log);
}

// ---------- Linux ----------

#[cfg(any(target_os = "linux", test))]
pub fn nft_rules(spec: &LockSpec) -> String {
    let mut r = String::from("table inet securetunnel_lock {}\ndelete table inet securetunnel_lock\ntable inet securetunnel_lock {\n  chain out {\n    type filter hook output priority 0; policy drop;\n    oifname \"lo\" accept\n");
    if !spec.tun_name.is_empty() {
        r.push_str(&format!("    oifname \"{}\" accept\n", spec.tun_name));
    }
    for (ip, port) in &spec.allow {
        let fam = if ip.is_ipv4() { "ip" } else { "ip6" };
        match port {
            Some(p) => r.push_str(&format!("    {fam} daddr {ip} udp dport {p} accept\n")),
            None => r.push_str(&format!("    {fam} daddr {ip} accept\n")),
        }
    }
    r.push_str("    udp sport 68 udp dport 67 accept\n    udp sport 546 udp dport 547 accept\n");
    if spec.lan {
        r.push_str(&format!("    ip daddr {{ {} }} accept\n", LAN_V4.join(", ")));
        r.push_str(&format!("    ip6 daddr {{ {} }} accept\n", LAN_V6.join(", ")));
    }
    r.push_str("  }\n}\n");
    r
}

#[cfg(target_os = "linux")]
pub fn apply(spec: &LockSpec, run_dir: &Path, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let file = run_dir.join("netlock.nft");
    std::fs::write(&file, nft_rules(spec)).map_err(|e| e.to_string())?;
    if run("nft", &["-f", &file.display().to_string()], log).is_none() {
        return Err("Could not turn on the Kill Switch (nftables is needed)".into());
    }
    write_marker(run_dir, &Marker::default());
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn remove(run_dir: &Path, log: &mut dyn FnMut(String)) {
    run("nft", &["delete", "table", "inet", "securetunnel_lock"], log);
    let _ = std::fs::remove_file(marker_path(run_dir));
}

// ---------- macOS ----------

#[cfg(any(target_os = "macos", test))]
pub fn pf_rules(spec: &LockSpec) -> String {
    let mut r = String::from("pass out quick on lo0 all\n");
    if !spec.tun_name.is_empty() {
        r.push_str(&format!("pass out quick on {} all\n", spec.tun_name));
    }
    for (ip, port) in &spec.allow {
        let fam = if ip.is_ipv4() { "inet" } else { "inet6" };
        match port {
            Some(p) => r.push_str(&format!("pass out quick {fam} proto udp to {ip} port {p}\n")),
            None => r.push_str(&format!("pass out quick {fam} to {ip}\n")),
        }
    }
    r.push_str("pass out quick proto udp from any port 68 to any port 67\npass out quick proto udp from any port 546 to any port 547\n");
    if spec.lan {
        r.push_str(&format!("pass out quick inet to {{ {} }}\n", LAN_V4.join(", ")));
        r.push_str(&format!("pass out quick inet6 to {{ {} }}\n", LAN_V6.join(", ")));
    }
    r.push_str("block drop out quick all\n");
    r
}

#[cfg(target_os = "macos")]
const ANCHOR: &str = "com.apple/securetunnel";

#[cfg(target_os = "macos")]
pub fn apply(spec: &LockSpec, run_dir: &Path, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let file = run_dir.join("netlock.pf");
    std::fs::write(&file, pf_rules(spec)).map_err(|e| e.to_string())?;
    if run("pfctl", &["-a", ANCHOR, "-f", &file.display().to_string()], log).is_none() {
        return Err("Could not turn on the Kill Switch (pf refused the rules)".into());
    }
    let mut marker = read_marker(run_dir).unwrap_or_default();
    if marker.pf_token.is_empty() {
        let out = run("pfctl", &["-E"], log).unwrap_or_default();
        marker.pf_token = out.lines().find_map(|l| l.split("Token :").nth(1)).map(|t| t.trim().to_string()).unwrap_or_default();
    }
    write_marker(run_dir, &marker);
    Ok(())
}

#[cfg(target_os = "macos")]
pub fn remove(run_dir: &Path, log: &mut dyn FnMut(String)) {
    run("pfctl", &["-a", ANCHOR, "-F", "all"], log);
    if let Some(m) = read_marker(run_dir) {
        if !m.pf_token.is_empty() {
            run("pfctl", &["-X", &m.pf_token], log);
        }
    }
    let _ = std::fs::remove_file(marker_path(run_dir));
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn apply(_s: &LockSpec, _r: &Path, _l: &mut dyn FnMut(String)) -> Result<(), String> {
    Err("The Kill Switch isn't supported on this system".into())
}
#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
pub fn remove(_r: &Path, _l: &mut dyn FnMut(String)) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> LockSpec {
        LockSpec {
            tun_name: "wg0".into(),
            tun_ips: vec!["192.168.100.2".parse().unwrap()],
            allow: vec![("192.0.2.1".parse().unwrap(), Some(51820)), ("2001:db8::1".parse().unwrap(), None)],
            lan: true,
        }
    }

    #[test]
    fn nft_text() {
        let r = nft_rules(&spec());
        assert!(r.contains("policy drop"));
        assert!(r.contains("oifname \"wg0\" accept"));
        assert!(r.contains("ip daddr 192.0.2.1 udp dport 51820 accept"));
        assert!(r.contains("ip6 daddr 2001:db8::1 accept"));
        assert!(r.contains("192.168.0.0/16"));
    }

    #[test]
    fn pf_text() {
        let r = pf_rules(&spec());
        assert!(r.ends_with("block drop out quick all\n"));
        assert!(r.contains("pass out quick inet proto udp to 192.0.2.1 port 51820"));
    }

    #[test]
    fn policies() {
        let t = "Domain Profile Settings:\n----\nFirewall Policy                       BlockInbound,AllowOutbound\n\nPrivate ...\nFirewall Policy  BlockInboundAlways,AllowOutbound\nPublic\nFirewallrichtlinie BlockInbound,BlockOutbound\nOk.";
        assert_eq!(parse_policies(t), vec!["BlockInbound,AllowOutbound", "BlockInboundAlways,AllowOutbound", "BlockInbound,BlockOutbound"]);
    }
}
