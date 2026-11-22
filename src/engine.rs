//! The tunnel engine, built into the app: boringtun (the same open-source
//! WireGuard implementation the original's engine is built on) driving a
//! virtual network adapter from tun-rs (Wintun on Windows, utun on macOS,
//! /dev/net/tun on Linux). It runs in a helper process started with
//! administrator rights (`--tunnel-helper <conf>`), reports through
//! `<conf>.status` once a second and stops when `<conf>.stop` appears.
//!
//! DPI protection happens here too: junk packets and the protocol look-alike
//! packet go out before every handshake initiation, and AmneziaWG magic
//! headers (S1-S4 padding, H1-H4 message types) wrap every packet.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use boringtun::noise::Tunn;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::obfs;
use crate::profile::{self, Profile};

pub const ENGINE_NAME: &str = "boringtun 0.7.1";
pub const WINTUN_VERSION: &str = "0.14.1";
/// Timer tick for boringtun's handshake/keepalive timers.
pub const TIMER_TICK: Duration = Duration::from_millis(100);
/// Status file refresh (the original's 1 s statistics period).
pub const STATUS_PERIOD: Duration = Duration::from_secs(1);
pub const DEFAULT_MTU: u16 = 1420;
use crate::datapath::{Awg, Wire};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Status {
    pub profile: String,
    pub iface: String,
    /// starting, up, stopped or error.
    pub state: String,
    pub error: String,
    pub rx: u64,
    pub tx: u64,
    pub handshake_secs: Option<u64>,
    pub rtt_ms: Option<u32>,
    pub loss: f32,
    pub pid: u32,
    pub updated: u64,
    pub log: Vec<String>,
}

pub fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

pub fn status_path(conf: &Path) -> PathBuf {
    conf.with_extension("status")
}
pub fn stop_path(conf: &Path) -> PathBuf {
    conf.with_extension("stop")
}

pub fn read_status(conf: &Path) -> Option<Status> {
    serde_json::from_str(&std::fs::read_to_string(status_path(conf)).ok()?).ok()
}

struct Reporter {
    path: PathBuf,
    status: Status,
}

impl Reporter {
    fn write(&mut self) {
        self.status.updated = now_secs();
        if self.status.log.len() > 50 {
            let cut = self.status.log.len() - 50;
            self.status.log.drain(..cut);
        }
        if let Ok(t) = serde_json::to_string(&self.status) {
            let tmp = self.path.with_extension("status.tmp");
            if std::fs::write(&tmp, t).is_ok() {
                let _ = std::fs::rename(&tmp, &self.path);
            }
        }
    }
    fn log(&mut self, s: impl Into<String>) {
        self.status.log.push(s.into());
    }
}

// ---------- helper entry ----------

/// Runs the tunnel until stopped. Returns the process exit code.
pub fn run_helper(conf: &Path) -> i32 {
    let text = std::fs::read_to_string(conf).unwrap_or_default();
    let name = text.lines().next().and_then(|l| l.strip_prefix("# profile: ")).unwrap_or("tunnel").to_string();
    let iface = conf.file_stem().and_then(|s| s.to_str()).unwrap_or("tunnel0").to_string();
    let mut rep = Reporter {
        path: status_path(conf),
        status: Status { profile: name, iface: iface.clone(), state: "starting".into(), pid: std::process::id(), ..Default::default() },
    };
    rep.write();
    let profile = match Profile::parse(&text) {
        Ok(p) => p,
        Err(e) => return fail(&mut rep, e),
    };
    match run(conf, &iface, &profile, &mut rep) {
        Ok(()) => {
            rep.status.state = "stopped".into();
            rep.write();
            0
        }
        Err(e) => fail(&mut rep, e),
    }
}

fn fail(rep: &mut Reporter, e: String) -> i32 {
    rep.status.state = "error".into();
    rep.status.error = e;
    rep.write();
    1
}

fn key32(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let b = base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| "Invalid key (not base64)".to_string())?;
    b.try_into().map_err(|_| "Invalid key (must be 32 bytes)".to_string())
}

/// Switches the window passes in the tunnel file's header comments.
#[derive(Clone, Copy, Debug, Default)]
pub struct Flags {
    pub kill_switch: bool,
    pub preserve_lock: bool,
    pub tcp_termination: bool,
}

impl Flags {
    pub fn header(&self) -> String {
        format!(
            "# killswitch: {}\n# preserve: {}\n# tcpkill: {}\n",
            self.kill_switch as u8, self.preserve_lock as u8, self.tcp_termination as u8
        )
    }
    pub fn parse(text: &str) -> Flags {
        let on = |k: &str| text.lines().take(6).any(|l| l.trim() == format!("# {k}: 1"));
        Flags { kill_switch: on("killswitch"), preserve_lock: on("preserve"), tcp_termination: on("tcpkill") }
    }
}

/// Lifts a Kill Switch lock (`--unlock-network <run folder>`).
pub fn run_unlock(run_dir: &Path) -> i32 {
    let mut quiet = |_: String| {};
    crate::netlock::remove(run_dir, &mut quiet);
    0
}

fn run(conf: &Path, iface: &str, p: &Profile, rep: &mut Reporter) -> Result<(), String> {
    use std::net::ToSocketAddrs;
    let flags = Flags::parse(&std::fs::read_to_string(conf).unwrap_or_default());
    let run_dir = conf.parent().map(|d| d.to_path_buf()).unwrap_or_default();
    let server: SocketAddr = p
        .endpoint
        .trim()
        .to_socket_addrs()
        .map_err(|e| format!("Could not resolve {}: {e}", p.endpoint))?
        .next()
        .ok_or_else(|| format!("Could not resolve {}", p.endpoint))?;
    rep.log(format!("Server {} resolved to {server}", p.endpoint));

    // Routes: AllowedIPs minus non-tunneled networks, LAN (if bypassed) and the server itself.
    let mut excluded = profile::split_list(&p.disallowed_ips);
    if p.bypass_lan_on() {
        excluded.extend(profile::PRIVATE_NETWORKS.iter().map(|s| s.to_string()));
    }
    let host = |ip: IpAddr| match ip {
        IpAddr::V4(a) => format!("{a}/32"),
        IpAddr::V6(a) => format!("{a}/128"),
    };
    excluded.push(host(server.ip()));
    // SOCKS5: WireGuard's datagrams go to the proxy, which must stay outside the tunnel.
    let socks = if p.socks5.trim().is_empty() {
        None
    } else {
        let proxy = crate::socks::resolve(&p.socks5)?;
        let s = crate::socks::Socks::connect(proxy, server, p.socks5_user.trim(), &p.socks5_pass)?;
        rep.log(format!("SOCKS5 proxy {proxy} associated, relay {}", s.relay));
        excluded.push(host(proxy.ip()));
        excluded.push(host(s.relay.ip()));
        Some(s)
    };
    let routes = split_default(profile::subtract_networks(&profile::split_list(&p.allowed_ips), &excluded));
    let full = routes.iter().any(|r| r == "0.0.0.0/1" || r == "::/1");

    run_script(&p.pre_up, iface, rep, "PreUp");
    let app_mode = crate::apps::mode(&p.allowed_apps, &p.disallowed_apps);
    #[allow(unused_mut)]
    let mut table: Option<u32> = None;
    let app_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    // Windows (x64): per-app routing uses a WinDivert filter, with no Wintun
    // adapter and no tunnel routes. The filter diverts matching programs into
    // the tunnel and lets the rest out normally (the original does this in its
    // NDISAPI driver). Everywhere else, create the Wintun/utun adapter.
    #[cfg(all(windows, target_arch = "x86_64"))]
    let winfilter_dev = if let Some(m) = &app_mode {
        let proxy = socks.as_ref().map(|s| s.proxy);
        let relay = socks.as_ref().map(|s| s.relay);
        let mut l = |msg: String| rep.log(msg);
        crate::winfilter::open(m, p, &routes, server, proxy, relay, conf, &mut l)
            .map_err(|e| rep.log(format!("Per-app split tunnelling is off ({e}); using the full tunnel")))
            .ok()
    } else {
        None
    };
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    let winfilter_dev: Option<Arc<dyn crate::datapath::PacketDevice>> = None;

    let dev: Arc<dyn crate::datapath::PacketDevice>;
    let dev_name: String;
    #[allow(unused_mut)]
    let mut cleanup: Vec<(String, Vec<String>)> = Vec::new();
    let winfilter_on = winfilter_dev.is_some();
    if let Some(wf) = winfilter_dev {
        dev_name = "per-app filter".to_string();
        dev = wf;
    } else {
        let wintun = Arc::new(open_device(conf, iface, p)?);
        dev_name = wintun.name().unwrap_or_else(|_| iface.to_string());
        rep.log(format!("Virtual adapter {dev_name} created"));
        // Per-app split tunnelling: tunnel routes go in their own table (Linux).
        #[cfg(target_os = "linux")]
        if let Some(m) = &app_mode {
            let mut l = |m: String| rep.log(m);
            match crate::apps::linux::setup(&dev_name, m, &run_dir, &mut l) {
                Ok(()) => {
                    table = Some(crate::apps::linux::TABLE);
                    crate::apps::linux::watch(m.clone(), app_stop.clone());
                    rep.log(match m {
                        crate::apps::Mode::OnlyThese(a) => format!("Only these apps use the tunnel: {}", a.join(", ")),
                        crate::apps::Mode::Except(a) => format!("These apps skip the tunnel: {}", a.join(", ")),
                    });
                }
                Err(e) => rep.log(format!("Per-app split tunnelling is off: {e}")),
            }
        }
        cleanup = configure_network(&wintun, &dev_name, &routes, &profile::split_list(&p.dns), full, table, conf, rep);
        dev = wintun;
    }
    if app_mode.is_some() && !winfilter_on && !crate::apps::enforced() {
        rep.log("Per-app split tunnelling needs a network driver on this system; the app lists are kept but not applied");
    }
    run_script(&p.post_up, iface, rep, "PostUp");

    // Kill switch: lock everything but the tunnel and the way to the server.
    // With per-app routing there is no tunnel adapter to lock to, so the kill
    // switch is left off (the lists already decide what the tunnel carries).
    if flags.kill_switch && winfilter_on {
        rep.log("Kill Switch is not applied with per-app routing");
    } else if flags.kill_switch {
        let mut allow = vec![(server.ip(), Some(server.port()))];
        if let Some(s) = &socks {
            allow = vec![(s.proxy.ip(), None), (s.relay.ip(), None)];
        }
        let tun_ips: Vec<IpAddr> = profile::split_list(&p.address).iter().filter_map(|a| a.split('/').next()?.trim().parse().ok()).collect();
        let spec = crate::netlock::LockSpec { tun_name: dev_name.clone(), tun_ips, allow, lan: p.bypass_lan_on() };
        let mut l = |m: String| rep.log(m);
        crate::netlock::apply(&spec, &run_dir, &mut l)?;
        rep.log("Kill Switch on: traffic outside the tunnel is blocked");
    } else if crate::netlock::is_active(&run_dir) {
        let mut l = |m: String| rep.log(m);
        crate::netlock::remove(&run_dir, &mut l);
        rep.log("Network lock lifted (Kill Switch is off)");
    }

    let bind: SocketAddr = match (server.is_ipv4(), p.listen_port.trim().parse::<u16>().unwrap_or(0)) {
        (true, port) => SocketAddr::from(([0, 0, 0, 0], port)),
        (false, port) => SocketAddr::from(([0u16; 8], port)),
    };
    let udp = UdpSocket::bind(bind).map_err(|e| format!("Could not open the network socket: {e}"))?;
    let target = socks.as_ref().map(|s| s.relay).unwrap_or(server);
    udp.connect(target).map_err(|e| format!("Could not reach {target}: {e}"))?;
    udp.set_read_timeout(Some(Duration::from_millis(500))).ok();
    let local = udp.local_addr().unwrap_or(bind);

    let plan = obfs::Plan::from_profile(p);
    let awg = Awg::from_profile(p);
    if plan.jc > 0 || plan.imitation.is_some() {
        rep.log(format!("DPI protection on: {}", plan.describe()));
    }
    if awg.on {
        rep.log("AmneziaWG magic headers on");
    }
    // The proxy ends the association when its control connection closes.
    let proxy_lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    if let Some(s) = &socks {
        if let Ok(mut c) = s.control.try_clone() {
            let lost = proxy_lost.clone();
            std::thread::spawn(move || {
                use std::io::Read;
                let mut b = [0u8; 64];
                while matches!(c.read(&mut b), Ok(n) if n > 0) {}
                lost.store(true, std::sync::atomic::Ordering::Relaxed);
            });
        }
    }
    let wire = Arc::new(Wire::new(crate::socks::Transport { udp, socks }, plan, awg, local));

    let psk = if p.preshared_key.trim().is_empty() { None } else { Some(key32(&p.preshared_key)?) };
    let keepalive = p.keepalive.trim().parse::<u16>().ok().filter(|k| *k > 0);
    let tunn = Tunn::new(
        boringtun::x25519::StaticSecret::from(key32(&p.private_key)?),
        boringtun::x25519::PublicKey::from(key32(&p.public_key)?),
        psk,
        keepalive,
        OsRng.next_u32() >> 8,
        None,
    );
    let tunn = Arc::new(Mutex::new(tunn));
    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    crate::datapath::spawn_loops(dev.clone(), tunn.clone(), wire.clone(), errors.clone());
    // Start the handshake right away, then run the timers.
    let mut out = vec![0u8; 2048];
    crate::datapath::send_initiation(&tunn, &wire);
    rep.status.state = "up".into();
    rep.write();
    let stop = stop_path(conf);
    let mut last_status = Instant::now();
    let mut seen_handshake = false;
    let mut failed: Option<String> = None;
    loop {
        std::thread::sleep(TIMER_TICK);
        crate::datapath::timers(&tunn, &wire, &mut out);
        if last_status.elapsed() >= STATUS_PERIOD {
            last_status = Instant::now();
            if let Ok(t) = tunn.lock() {
                let (hs, tx, rx, loss, rtt) = t.stats();
                rep.status.handshake_secs = hs.map(|d| d.as_secs());
                rep.status.tx = tx as u64;
                rep.status.rx = rx as u64;
                rep.status.loss = loss;
                rep.status.rtt_ms = rtt;
                if hs.is_some() && !seen_handshake {
                    seen_handshake = true;
                    rep.log("Handshake response received");
                    if flags.tcp_termination && !winfilter_on {
                        match crate::tcpkill::kill(&routes) {
                            Ok(n) => rep.log(format!("Closed {n} TCP connection(s) so they reconnect through the tunnel")),
                            Err(e) => rep.log(format!("TCP connections not closed: {e}")),
                        }
                    }
                }
            }
            if let Ok(mut v) = errors.lock() {
                for e in v.drain(..).take(5) {
                    rep.log(format!("Packet dropped: {e}"));
                }
            }
            rep.write();
            if stop.exists() {
                break;
            }
            if proxy_lost.load(std::sync::atomic::Ordering::Relaxed) {
                failed = Some("SOCKS5 proxy failed: the proxy closed the association".to_string());
                break;
            }
        }
    }
    rep.log("Stopping");
    app_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    #[cfg(target_os = "linux")]
    if table.is_some() {
        let mut l = |m: String| rep.log(m);
        crate::apps::linux::teardown(&mut l);
    }
    run_script(&p.pre_down, iface, rep, "PreDown");
    for (prog, args) in cleanup.drain(..).rev() {
        let _ = Command::new(&prog).args(&args).output();
    }
    drop(dev);
    run_script(&p.post_down, iface, rep, "PostDown");
    // A normal disconnect lifts the lock unless "preserve" is set; a failure keeps it.
    if flags.kill_switch && !flags.preserve_lock && failed.is_none() {
        let mut l = |m: String| rep.log(m);
        crate::netlock::remove(&run_dir, &mut l);
    }
    match failed {
        Some(e) => Err(e),
        None => Ok(()),
    }
}

/// Replaces /0 routes with two /1 halves so they win over the system's
/// default route without replacing it.
pub fn split_default(routes: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for r in routes {
        match r.as_str() {
            "0.0.0.0/0" => out.extend(["0.0.0.0/1".to_string(), "128.0.0.0/1".to_string()]),
            "::/0" => out.extend(["::/1".to_string(), "8000::/1".to_string()]),
            _ => out.push(r),
        }
    }
    out
}

fn run_script(script: &str, iface: &str, rep: &mut Reporter, label: &str) {
    if script.trim().is_empty() {
        return;
    }
    let s = script.replace("%i", iface);
    let out = if cfg!(windows) { Command::new("cmd").args(["/C", &s]).output() } else { Command::new("sh").args(["-c", &s]).output() };
    match out {
        Ok(o) if o.status.success() => rep.log(format!("{label} script finished")),
        Ok(o) => rep.log(format!("{label} script failed: {}", String::from_utf8_lossy(&o.stderr).trim())),
        Err(e) => rep.log(format!("{label} script could not start: {e}")),
    }
}

fn open_device(conf: &Path, iface: &str, p: &Profile) -> Result<tun_rs::SyncDevice, String> {
    let mtu = p.mtu.trim().parse::<u16>().unwrap_or(DEFAULT_MTU);
    let mut b = tun_rs::DeviceBuilder::new().mtu(mtu);
    if !cfg!(target_os = "macos") {
        b = b.name(iface);
    }
    let mut v4 = false;
    for a in profile::split_list(&p.address) {
        let (ip, len) = match a.split_once('/') {
            Some((ip, l)) => (ip.trim().to_string(), l.trim().parse::<u8>().ok()),
            None => (a.clone(), None),
        };
        match ip.parse::<IpAddr>() {
            Ok(IpAddr::V4(x)) if !v4 => {
                b = b.ipv4(x, len.unwrap_or(32), None);
                v4 = true;
            }
            Ok(IpAddr::V6(x)) => b = b.ipv6(x, len.unwrap_or(128)),
            _ => {}
        }
    }
    #[cfg(windows)]
    {
        b = b.wintun_file(write_wintun(conf)?);
    }
    let _ = conf;
    b.build_sync().map_err(|e| format!("Could not create the virtual network adapter: {e}"))
}

#[cfg(all(windows, target_arch = "x86_64"))]
static WINTUN_DLL: &[u8] = include_bytes!("../vendor/wintun/amd64/wintun.dll");
#[cfg(all(windows, target_arch = "aarch64"))]
static WINTUN_DLL: &[u8] = include_bytes!("../vendor/wintun/arm64/wintun.dll");
#[cfg(all(windows, target_arch = "x86"))]
static WINTUN_DLL: &[u8] = include_bytes!("../vendor/wintun/x86/wintun.dll");

/// Writes the bundled wintun.dll next to the tunnel file and returns its path.
#[cfg(windows)]
fn write_wintun(conf: &Path) -> Result<String, String> {
    let path = conf.with_file_name("wintun.dll");
    let same = std::fs::metadata(&path).map(|m| m.len() == WINTUN_DLL.len() as u64).unwrap_or(false);
    if !same {
        std::fs::write(&path, WINTUN_DLL).map_err(|e| format!("Could not write wintun.dll: {e}"))?;
    }
    Ok(path.display().to_string())
}

fn cmd(rep: &mut Reporter, prog: &str, args: &[String]) -> bool {
    match Command::new(prog).args(args).output() {
        Ok(o) if o.status.success() => true,
        Ok(o) => {
            let msg = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
            rep.log(format!("{prog} {}: {}", args.join(" "), msg.trim()));
            false
        }
        Err(e) => {
            rep.log(format!("{prog}: {e}"));
            false
        }
    }
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| x.to_string()).collect()
}

/// Adds routes and DNS for the adapter. Returns commands that undo changes
/// which outlive the adapter (routes and per-adapter DNS go with it).
#[allow(unused_variables)]
fn configure_network(
    dev: &tun_rs::SyncDevice,
    name: &str,
    routes: &[String],
    dns: &[String],
    full: bool,
    table: Option<u32>,
    conf: &Path,
    rep: &mut Reporter,
) -> Vec<(String, Vec<String>)> {
    #[allow(unused_mut)]
    let mut cleanup: Vec<(String, Vec<String>)> = Vec::new();
    let dns_ips: Vec<IpAddr> = dns.iter().filter_map(|d| d.parse().ok()).collect();
    #[cfg(windows)]
    {
        let idx = dev.if_index().map(|i| i.to_string()).unwrap_or_else(|_| name.to_string());
        for fam in ["ipv4", "ipv6"] {
            cmd(rep, "netsh", &s(&["interface", fam, "set", "interface", &idx, "metric=1"]));
        }
        let mut added = 0;
        for r in routes {
            let fam = if r.contains(':') { "ipv6" } else { "ipv4" };
            let hop = if fam == "ipv6" { "nexthop=::" } else { "nexthop=0.0.0.0" };
            let pre = format!("prefix={r}");
            let ifa = format!("interface={idx}");
            if cmd(rep, "netsh", &s(&["interface", fam, "add", "route", &pre, &ifa, hop, "metric=0", "store=active"])) {
                added += 1;
            }
        }
        rep.log(format!("{added} of {} routes added", routes.len()));
        let mut first = [true, true];
        for ip in &dns_ips {
            let (fam, i) = if ip.is_ipv4() { ("ipv4", 0) } else { ("ipv6", 1) };
            let addr = format!("address={ip}");
            let nm = format!("name={idx}");
            if first[i] {
                cmd(rep, "netsh", &s(&["interface", fam, "set", "dnsservers", &nm, "source=static", &addr, "register=none", "validate=no"]));
                first[i] = false;
            } else {
                cmd(rep, "netsh", &s(&["interface", fam, "add", "dnsservers", &nm, &addr, "validate=no"]));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut added = 0;
        for r in routes {
            let fam = if r.contains(':') { "-6" } else { "-4" };
            let mut a = s(&[fam, "route", "replace", r, "dev", name]);
            if let Some(t) = table {
                a.extend(["table".to_string(), t.to_string()]);
            }
            if cmd(rep, "ip", &a) {
                added += 1;
            }
        }
        rep.log(format!("{added} of {} routes added", routes.len()));
        if !dns_ips.is_empty() {
            if which("resolvectl").is_some() {
                let mut a = s(&["dns", name]);
                a.extend(dns_ips.iter().map(|i| i.to_string()));
                cmd(rep, "resolvectl", &a);
                if full {
                    cmd(rep, "resolvectl", &s(&["domain", name, "~."]));
                }
            } else {
                // No systemd-resolved: swap /etc/resolv.conf and put it back on stop.
                let backup = conf.with_extension("resolv.bak");
                if std::fs::copy("/etc/resolv.conf", &backup).is_ok() {
                    let body: String = dns_ips.iter().map(|i| format!("nameserver {i}\n")).collect();
                    if std::fs::write("/etc/resolv.conf", body).is_ok() {
                        cleanup.push(("cp".to_string(), vec![backup.display().to_string(), "/etc/resolv.conf".to_string()]));
                    }
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mut added = 0;
        for r in routes {
            let fam = if r.contains(':') { "-inet6" } else { "-inet" };
            if cmd(rep, "route", &s(&["-q", "-n", "add", fam, r, "-interface", name])) {
                added += 1;
            }
        }
        rep.log(format!("{added} of {} routes added", routes.len()));
        if !dns_ips.is_empty() {
            let list = Command::new("networksetup").arg("-listallnetworkservices").output().ok();
            let services: Vec<String> = list
                .map(|o| String::from_utf8_lossy(&o.stdout).lines().skip(1).filter(|l| !l.starts_with('*')).map(|l| l.to_string()).collect())
                .unwrap_or_default();
            for svc in services {
                let cur = Command::new("networksetup").args(["-getdnsservers", &svc]).output().ok();
                let old: Vec<String> = cur
                    .map(|o| String::from_utf8_lossy(&o.stdout).lines().filter(|l| l.parse::<IpAddr>().is_ok()).map(|l| l.to_string()).collect())
                    .unwrap_or_default();
                let mut a = vec!["-setdnsservers".to_string(), svc.clone()];
                a.extend(dns_ips.iter().map(|i| i.to_string()));
                if cmd(rep, "networksetup", &a) {
                    let mut undo = vec!["-setdnsservers".to_string(), svc.clone()];
                    if old.is_empty() {
                        undo.push("Empty".into());
                    } else {
                        undo.extend(old);
                    }
                    cleanup.push(("networksetup".to_string(), undo));
                }
            }
        }
    }
    cleanup
}

#[allow(dead_code)]
fn which(name: &str) -> Option<PathBuf> {
    let dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
    dirs.into_iter()
        .chain(["/usr/bin", "/bin", "/usr/sbin", "/sbin"].iter().map(PathBuf::from))
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

// ---------- starting the helper with administrator rights ----------

/// Starts `<this program> --tunnel-helper <conf>` with administrator rights.
/// Returns once the helper is launched (or the request was refused).
pub fn launch_helper(conf: &Path) -> Result<(), String> {
    launch_elevated("--tunnel-helper", conf)
}

/// Lifts the Kill Switch lock with administrator rights.
pub fn launch_unlock(run_dir: &Path) -> Result<(), String> {
    launch_elevated("--unlock-network", run_dir)
}

fn launch_elevated(mode: &str, conf: &Path) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let q = |s: &str| format!("'{}'", s.replace('\'', "''"));
        let script = format!(
            "Start-Process -FilePath {} -ArgumentList '{mode}',{} -Verb RunAs -WindowStyle Hidden",
            q(&exe.display().to_string()),
            q(&format!("\"{}\"", conf.display()))
        );
        let o = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .creation_flags(0x0800_0000)
            .output()
            .map_err(|e| format!("Could not start PowerShell: {e}"))?;
        if !o.status.success() {
            return Err("Administrator approval is needed to create the VPN adapter.".into());
        }
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let root = Command::new("id").arg("-u").output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false);
        // Inside Flatpak the helper runs on the host (see src/flatpak.rs).
        let exe = crate::flatpak::host_path(&exe);
        let mut c = if root {
            Command::new(&exe)
        } else {
            let mut c = crate::flatpak::host_command("pkexec");
            c.arg(&exe);
            c
        };
        c.arg(mode).arg(conf);
        c.stdin(std::process::Stdio::null()).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null());
        let mut child = c.spawn().map_err(|e| format!("Could not ask for administrator rights (pkexec): {e}"))?;
        // pkexec exits at once with 126/127 when the request is refused.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        return Ok(());
    }
    #[cfg(target_os = "macos")]
    {
        let q = |p: &Path| format!("'{}'", p.display().to_string().replace('\'', "'\\''"));
        let shell = format!("{} {mode} {} > /dev/null 2>&1 &", q(&exe), q(conf));
        let script = format!("do shell script \"{}\" with administrator privileges", shell.replace('\\', "\\\\").replace('"', "\\\""));
        let o = Command::new("osascript").arg("-e").arg(script).output().map_err(|e| e.to_string())?;
        if !o.status.success() {
            return Err("Administrator approval is needed to create the VPN adapter.".into());
        }
        return Ok(());
    }
    #[allow(unreachable_code)]
    {
        let _ = (exe, conf);
        Err("This system is not supported".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use boringtun::noise::TunnResult;

    #[test]
    fn awg_roundtrip() {
        let p = Profile {
            s1: "15".into(),
            s2: "20".into(),
            h1: "1000-2000".into(),
            h2: "3000".into(),
            h3: "0x10000".into(),
            h4: "5000-6000".into(),
            ..Default::default()
        };
        let a = Awg::from_profile(&p);
        let mut init = vec![0u8; 148];
        init[0] = 1;
        init[10] = 7;
        let w = a.wrap(&init);
        assert_eq!(w.len(), 148 + 15);
        let h = u32::from_le_bytes([w[15], w[16], w[17], w[18]]);
        assert!((1000..=2000).contains(&h));
        assert_eq!(a.unwrap(&w).unwrap(), init);
        let mut data = vec![0u8; 80];
        data[0] = 4;
        let w = a.wrap(&data);
        assert_eq!(a.unwrap(&w).unwrap(), data);
        assert!(a.unwrap(&[9u8; 30]).is_none());
    }

    #[test]
    fn plain_wireguard_untouched() {
        let a = Awg::from_profile(&Profile::default());
        let pkt = vec![1u8, 0, 0, 0, 5, 6];
        assert_eq!(a.wrap(&pkt), pkt);
        assert_eq!(a.unwrap(&pkt).unwrap(), pkt);
    }

    #[test]
    fn default_routes_split() {
        let r = split_default(vec!["0.0.0.0/0".into(), "::/0".into(), "10.0.0.0/8".into()]);
        assert_eq!(r, vec!["0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1", "10.0.0.0/8"]);
    }

    const AWG2_CONF: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 192.168.100.2/32, fd00::2/128
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 100000-200000
H2 = 300000-400000
H3 = 500000-600000
H4 = 700000-800000
I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0><r 16><t><c>
I2 = <r 32>
Itime = 120

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:51820
PersistentKeepalive = 25
";

    const PLAIN_CONF: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 192.168.100.2/32
DNS = 1.1.1.1

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
Endpoint = 203.0.113.5:51820
";

    /// An AmneziaWG 2.0-style profile (junk, padding, header ranges, I-packets,
    /// a key this app doesn't know) imports and drives every masking layer.
    #[test]
    fn amneziawg_profile_imports_and_masks() {
        let p = Profile::parse(AWG2_CONF).expect("AmneziaWG profile parses");
        assert!(p.validate().is_empty(), "{:?}", p.validate());
        let plan = obfs::Plan::from_profile(&p);
        assert_eq!((plan.jc, plan.jmin, plan.jmax), (4, 40, 70));
        assert_eq!(plan.special.len(), 2, "I1 and I2 are sent");
        let local: SocketAddr = "192.0.2.1:40000".parse().unwrap();
        let extra = obfs::pre_handshake(&plan, true, local);
        assert_eq!(extra.len(), 2 + 4);
        assert!(extra[0].starts_with(&[0xc6, 0, 0, 0, 1]) && extra[0].len() == 18 + 16 + 4 + 4);
        assert_eq!(extra[1].len(), 32);
        for j in &extra[2..] {
            assert!((40..=70).contains(&j.len()), "junk size {}", j.len());
        }
        let awg = Awg::from_profile(&p);
        assert!(awg.on);
        assert_eq!(awg.pad, [15, 18, 20, 23]);
        let mut init = vec![0u8; 148];
        init[0] = 1;
        let w = awg.wrap(&init);
        assert_eq!(w.len(), 148 + 15);
        assert!((100000..=200000).contains(&u32::from_le_bytes([w[15], w[16], w[17], w[18]])));
        assert_eq!(awg.unwrap(&w).unwrap(), init);
        let mut data = vec![0u8; 96];
        data[0] = 4;
        assert_eq!(awg.unwrap(&awg.wrap(&data)).unwrap(), data);
    }

    /// A plain WireGuard profile imports and goes out unchanged.
    #[test]
    fn plain_wireguard_profile_imports() {
        let p = Profile::parse(PLAIN_CONF).expect("WireGuard profile parses");
        assert!(p.validate().is_empty(), "{:?}", p.validate());
        let plan = obfs::Plan::from_profile(&p);
        assert_eq!(plan.jc, 0);
        assert!(plan.imitation.is_none() && plan.special.is_empty());
        let local: SocketAddr = "192.0.2.1:40000".parse().unwrap();
        assert!(obfs::pre_handshake(&plan, true, local).is_empty());
        assert!(!Awg::from_profile(&p).on);
    }

    /// Two boringtun peers talking through the magic-header wrapper.
    #[test]
    fn handshake_through_wrapper() {
        let a_key = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
        let b_key = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
        let a_pub = boringtun::x25519::PublicKey::from(&a_key);
        let b_pub = boringtun::x25519::PublicKey::from(&b_key);
        let mut a = Tunn::new(a_key, b_pub, None, None, 1, None);
        let mut b = Tunn::new(b_key, a_pub, None, None, 2, None);
        let p = Profile { s1: "10".into(), s2: "5".into(), h1: "111".into(), h2: "222".into(), h3: "333".into(), h4: "444".into(), ..Default::default() };
        let awg = Awg::from_profile(&p);
        let mut buf = vec![0u8; 2048];
        let mut buf2 = vec![0u8; 2048];
        let init = match a.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(p) => awg.wrap(p),
            _ => panic!(),
        };
        let resp = match b.decapsulate(None, &awg.unwrap(&init).unwrap(), &mut buf2) {
            TunnResult::WriteToNetwork(p) => awg.wrap(p),
            _ => panic!(),
        };
        let _ = a.decapsulate(None, &awg.unwrap(&resp).unwrap(), &mut buf);
        assert!(a.stats().0.is_some(), "handshake completed");
    }
}
