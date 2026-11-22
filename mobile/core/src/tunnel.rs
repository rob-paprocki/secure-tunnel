//! What the phone apps call: `plan` reads a profile and works out what the
//! VPN service must set up; `Session::start` runs the tunnel on the adapter
//! the service created.

use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use boringtun::noise::Tunn;
use rand_core::{OsRng, RngCore};
use serde::Serialize;

use crate::datapath::{self, Awg, PacketDevice, Wire};
use crate::obfs;
use crate::profile::{self, Profile};
use crate::socks;

pub const DEFAULT_MTU: u16 = 1420;

/// Everything the VPN service needs before it creates the adapter. Names are
/// resolved here, while the network is still reachable outside the tunnel.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Plan {
    pub name: String,
    pub addresses: Vec<String>,
    pub dns: Vec<String>,
    pub routes: Vec<String>,
    pub mtu: u16,
    /// The server's resolved address, passed back to `Session::start`.
    pub server: String,
    /// The SOCKS5 proxy's resolved address, when the profile uses one.
    pub proxy: String,
    pub allowed_apps: Vec<String>,
    pub disallowed_apps: Vec<String>,
    /// One line on the DPI protection in use, for the app to show.
    pub protection: String,
}

fn resolve(endpoint: &str) -> Result<SocketAddr, String> {
    endpoint
        .trim()
        .to_socket_addrs()
        .map_err(|e| format!("Could not resolve {endpoint}: {e}"))?
        .next()
        .ok_or_else(|| format!("Could not resolve {endpoint}"))
}

fn host(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => format!("{a}/32"),
        IpAddr::V6(a) => format!("{a}/128"),
    }
}

pub fn parse(config: &str) -> Result<Profile, String> {
    let p = Profile::parse(config)?;
    if let Some((field, msg)) = p.validate().first() {
        return Err(format!("{field}: {msg}"));
    }
    Ok(p)
}

pub fn plan(config: &str) -> Result<Plan, String> {
    let p = parse(config)?;
    let server = resolve(&p.endpoint)?;
    let mut excluded = profile::split_list(&p.disallowed_ips);
    if p.bypass_lan_on() {
        excluded.extend(profile::PRIVATE_NETWORKS.iter().map(|s| s.to_string()));
    }
    excluded.push(host(server.ip()));
    let proxy = if p.socks5.trim().is_empty() {
        None
    } else {
        let a = socks::resolve(&p.socks5)?;
        excluded.push(host(a.ip()));
        Some(a)
    };
    let plan = obfs::Plan::from_profile(&p);
    let awg = Awg::from_profile(&p);
    let mut protection = plan.describe();
    if awg.on {
        if !protection.is_empty() {
            protection.push_str("; ");
        }
        protection.push_str("AmneziaWG headers");
    }
    Ok(Plan {
        name: p.interface_name.clone(),
        addresses: profile::split_list(&p.address),
        dns: profile::split_list(&p.dns),
        routes: profile::subtract_networks(&profile::split_list(&p.allowed_ips), &excluded),
        mtu: p.mtu.trim().parse().unwrap_or(DEFAULT_MTU),
        server: server.to_string(),
        proxy: proxy.map(|a| a.to_string()).unwrap_or_default(),
        allowed_apps: profile::split_list(&p.allowed_apps),
        disallowed_apps: profile::split_list(&p.disallowed_apps),
        protection,
    })
}

/// The adapter the phone's VPN service created, by file descriptor.
pub struct FdDevice {
    fd: i32,
    /// iOS utun: each packet starts with a 4-byte address family.
    utun_header: bool,
}

impl FdDevice {
    pub fn new(fd: i32, utun_header: bool) -> FdDevice {
        FdDevice { fd, utun_header }
    }
}

#[cfg(unix)]
impl PacketDevice for FdDevice {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.utun_header {
            let mut tmp = vec![0u8; buf.len() + 4];
            let n = unsafe { libc::read(self.fd, tmp.as_mut_ptr().cast(), tmp.len()) };
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let n = n as usize;
            if n < 4 {
                return Ok(0);
            }
            buf[..n - 4].copy_from_slice(&tmp[4..n]);
            return Ok(n - 4);
        }
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(n as usize) }
    }

    fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        let data;
        let out: &[u8] = if self.utun_header {
            let af: u32 = if buf.first().map(|b| b >> 4) == Some(6) { libc::AF_INET6 as u32 } else { libc::AF_INET as u32 };
            data = [af.to_be_bytes().as_slice(), buf].concat();
            &data
        } else {
            buf
        };
        let n = unsafe { libc::write(self.fd, out.as_ptr().cast(), out.len()) };
        if n < 0 { Err(std::io::Error::last_os_error()) } else { Ok(buf.len()) }
    }
}

#[cfg(not(unix))]
impl PacketDevice for FdDevice {
    fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        let _ = (self.fd, self.utun_header);
        Err(std::io::Error::other("phone adapters exist only on Android and iOS"))
    }
    fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("phone adapters exist only on Android and iOS"))
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Stats {
    pub connected: bool,
    pub handshake_secs: Option<u64>,
    pub tx: u64,
    pub rx: u64,
    pub loss: f32,
    pub rtt_ms: Option<u32>,
    pub uptime_secs: u64,
    pub errors: Vec<String>,
}

pub struct Session {
    stop: Arc<AtomicBool>,
    tunn: Arc<Mutex<Tunn>>,
    errors: Arc<Mutex<Vec<String>>>,
    started: Instant,
}

fn key32(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine as _;
    let v = base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|_| "a key is not valid base64".to_string())?;
    v.try_into().map_err(|_| "a key is not 32 bytes long".to_string())
}

impl Session {
    /// Starts the tunnel on `dev`. `server` and `proxy` come from [`plan`].
    pub fn start<D: PacketDevice>(config: &str, dev: D, server: &str, proxy: &str) -> Result<Session, String> {
        let p = parse(config)?;
        let server: SocketAddr = server.parse().map_err(|_| format!("bad server address {server}"))?;
        let socks = if proxy.is_empty() {
            None
        } else {
            let proxy: SocketAddr = proxy.parse().map_err(|_| format!("bad proxy address {proxy}"))?;
            Some(socks::Socks::connect(proxy, server, p.socks5_user.trim(), &p.socks5_pass)?)
        };
        let bind: SocketAddr = if server.is_ipv4() { SocketAddr::from(([0, 0, 0, 0], 0)) } else { SocketAddr::from(([0u16; 8], 0)) };
        let udp = UdpSocket::bind(bind).map_err(|e| format!("Could not open the network socket: {e}"))?;
        if !socks::protect_raw(socks::raw_of(&udp)) {
            return Err("Could not keep the tunnel's socket outside the VPN".into());
        }
        let target = socks.as_ref().map(|s| s.relay).unwrap_or(server);
        udp.connect(target).map_err(|e| format!("Could not reach {target}: {e}"))?;
        udp.set_read_timeout(Some(Duration::from_millis(500))).ok();
        let local = udp.local_addr().unwrap_or(bind);
        let wire = Arc::new(Wire::new(socks::Transport { udp, socks }, obfs::Plan::from_profile(&p), Awg::from_profile(&p), local));
        let psk = if p.preshared_key.trim().is_empty() { None } else { Some(key32(&p.preshared_key)?) };
        let keepalive = p.keepalive.trim().parse::<u16>().ok().filter(|k| *k > 0);
        let tunn = Arc::new(Mutex::new(Tunn::new(
            boringtun::x25519::StaticSecret::from(key32(&p.private_key)?),
            boringtun::x25519::PublicKey::from(key32(&p.public_key)?),
            psk,
            keepalive,
            OsRng.next_u32() >> 8,
            None,
        )));
        let errors = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        datapath::spawn_loops_until(Arc::new(dev), tunn.clone(), wire.clone(), errors.clone(), stop.clone());
        datapath::send_initiation(&tunn, &wire);
        {
            let (tunn, wire, stop) = (tunn.clone(), wire.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut out = vec![0u8; 2048];
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(100));
                    datapath::timers(&tunn, &wire, &mut out);
                }
            });
        }
        Ok(Session { stop, tunn, errors, started: Instant::now() })
    }

    pub fn stats(&self) -> Stats {
        let mut s = Stats { uptime_secs: self.started.elapsed().as_secs(), ..Default::default() };
        if let Ok(t) = self.tunn.lock() {
            let (hs, tx, rx, loss, rtt) = t.stats();
            s.connected = hs.is_some();
            s.handshake_secs = hs.map(|d| d.as_secs());
            s.tx = tx as u64;
            s.rx = rx as u64;
            s.loss = loss;
            s.rtt_ms = rtt;
        }
        if let Ok(mut e) = self.errors.lock() {
            s.errors = e.drain(..).take(5).collect();
        }
        s
    }

    /// Stops the loops; the VPN service then closes the adapter.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AWG: &str = "[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 192.168.100.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1380
Jc = 4
Jmin = 40
Jmax = 70
S1 = 15
S2 = 18
H1 = 100000-200000
H2 = 300000-400000
H3 = 500000-600000
H4 = 700000-800000
I1 = <b 0xc6000000010843290a47ba8ba2ed000044d0><r 16>

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 203.0.113.5:51820
";

    #[test]
    fn plan_for_amneziawg_profile() {
        let p = plan(AWG).unwrap();
        assert_eq!(p.addresses, vec!["192.168.100.2/32", "fd00::2/128"]);
        assert_eq!(p.dns, vec!["1.1.1.1"]);
        assert_eq!(p.mtu, 1380);
        assert_eq!(p.server, "203.0.113.5:51820");
        assert!(!p.routes.iter().any(|r| r == "0.0.0.0/0"), "server is routed outside the tunnel");
        assert!(p.protection.contains("4 junk packets") && p.protection.contains("AmneziaWG"), "{}", p.protection);
    }
}
