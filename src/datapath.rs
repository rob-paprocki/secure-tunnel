//! The packet path shared by every platform: AmneziaWG magic headers and
//! padding, the junk / look-alike / I-packets sent before each handshake,
//! and the loops between the virtual adapter and the network. The desktop
//! engine (`engine.rs`) and the phone apps' tunnel core both run this code,
//! so masking works the same everywhere.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boringtun::noise::{Tunn, TunnResult, errors::WireGuardError};
use rand_core::{OsRng, RngCore};

use crate::obfs;
use crate::profile::Profile;

/// Standard WireGuard message lengths: initiation, response, cookie reply.
const STD_LEN: [usize; 3] = [148, 92, 64];
pub const MAX_PACKET: usize = 65_535;

/// The tunnel's side of the virtual adapter: whole IP packets in and out.
pub trait PacketDevice: Send + Sync + 'static {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize>;
    fn send(&self, buf: &[u8]) -> std::io::Result<usize>;
}

#[cfg(not(st_mobile))]
impl PacketDevice for tun_rs::SyncDevice {
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
        tun_rs::SyncDevice::recv(self, buf)
    }
    fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
        tun_rs::SyncDevice::send(self, buf)
    }
}

/// AmneziaWG magic headers (H1-H4) and padding (S1-S4).
#[derive(Clone, Debug, Default)]
pub struct Awg {
    pub on: bool,
    pub pad: [usize; 4],
    pub hdr: [(u32, u32); 4],
}

fn parse_header(s: &str, default: u32) -> (u32, u32) {
    let num = |x: &str| {
        let x = x.trim();
        x.parse::<u32>().ok().or_else(|| u32::from_str_radix(x.trim_start_matches("0x").trim_start_matches("0X"), 16).ok())
    };
    match s.split_once('-') {
        Some((a, b)) => match (num(a), num(b)) {
            (Some(a), Some(b)) if a <= b => (a, b),
            _ => (default, default),
        },
        None => num(s).map(|v| (v, v)).unwrap_or((default, default)),
    }
}

impl Awg {
    pub fn from_profile(p: &Profile) -> Awg {
        let on = [&p.s1, &p.s2, &p.s3, &p.s4, &p.h1, &p.h2, &p.h3, &p.h4].iter().any(|s| !s.trim().is_empty());
        let pad = |s: &str| s.trim().parse::<usize>().unwrap_or(0).min(MAX_PACKET / 2);
        Awg {
            on,
            pad: [pad(&p.s1), pad(&p.s2), pad(&p.s3), pad(&p.s4)],
            hdr: [parse_header(&p.h1, 1), parse_header(&p.h2, 2), parse_header(&p.h3, 3), parse_header(&p.h4, 4)],
        }
    }

    /// Standard WireGuard packet -> padded packet with a magic header.
    pub fn wrap(&self, pkt: &[u8]) -> Vec<u8> {
        if !self.on || pkt.len() < 4 || pkt[1..4] != [0, 0, 0] || !(1..=4).contains(&pkt[0]) {
            return pkt.to_vec();
        }
        let i = (pkt[0] - 1) as usize;
        let (lo, hi) = self.hdr[i];
        let h = if hi > lo { lo + OsRng.next_u32() % (hi - lo + 1) } else { lo };
        let mut out = vec![0u8; self.pad[i]];
        OsRng.fill_bytes(&mut out);
        out.extend_from_slice(&h.to_le_bytes());
        out.extend_from_slice(&pkt[4..]);
        out
    }

    /// Padded packet with a magic header -> standard WireGuard packet.
    pub fn unwrap(&self, data: &[u8]) -> Option<Vec<u8>> {
        if !self.on {
            return Some(data.to_vec());
        }
        for i in 0..4 {
            let s = self.pad[i];
            if data.len() < s + 4 {
                continue;
            }
            if i < 3 && data.len() - s != STD_LEN[i] {
                continue;
            }
            if i == 3 && data.len() - s < 32 {
                continue;
            }
            let v = u32::from_le_bytes([data[s], data[s + 1], data[s + 2], data[s + 3]]);
            let (lo, hi) = self.hdr[i];
            if v >= lo && v <= hi {
                let mut out = ((i + 1) as u32).to_le_bytes().to_vec();
                out.extend_from_slice(&data[s + 4..]);
                return Some(out);
            }
        }
        None
    }
}

pub struct Wire {
    pub net: crate::socks::Transport,
    pub plan: obfs::Plan,
    pub awg: Awg,
    pub local: SocketAddr,
}

impl Wire {
    pub fn new(net: crate::socks::Transport, plan: obfs::Plan, awg: Awg, local: SocketAddr) -> Wire {
        Wire { net, plan, awg, local }
    }

    /// Sends one WireGuard packet: junk, look-alike and I-packets go first
    /// before a handshake initiation, then the packet in its magic header.
    pub fn send(&self, pkt: &[u8]) {
        if obfs::is_handshake_init(pkt) {
            let extra = obfs::pre_handshake(&self.plan, true, self.local);
            for (i, p) in extra.iter().enumerate() {
                self.net.send(p);
                let is_junk = self.plan.imitation.is_none() || i > 0;
                if is_junk && self.plan.jd_ms > 0 {
                    std::thread::sleep(Duration::from_millis(self.plan.jd_ms as u64));
                }
            }
        }
        self.net.send(&self.awg.wrap(pkt));
    }
}

/// Starts the two packet loops: adapter -> network and network -> adapter.
/// They run for the life of the process (the desktop helper exits to stop).
#[cfg_attr(st_mobile, allow(dead_code))]
pub fn spawn_loops<D: PacketDevice + ?Sized>(dev: Arc<D>, tunn: Arc<Mutex<Tunn>>, wire: Arc<Wire>, errors: Arc<Mutex<Vec<String>>>) {
    spawn_loops_until(dev, tunn, wire, errors, Arc::new(AtomicBool::new(false)));
}

/// The same loops, ending once `stop` is set (the phone apps stop and start
/// tunnels without leaving the process). The adapter loop also ends when the
/// adapter is closed.
pub fn spawn_loops_until<D: PacketDevice + ?Sized>(
    dev: Arc<D>,
    tunn: Arc<Mutex<Tunn>>,
    wire: Arc<Wire>,
    errors: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
) {
    {
        let (dev, tunn, wire, stop) = (dev.clone(), tunn.clone(), wire.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut buf = vec![0u8; MAX_PACKET];
            let mut out = vec![0u8; MAX_PACKET + 148];
            loop {
                let Ok(n) = dev.recv(&mut buf) else { break };
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let pkt = match tunn.lock() {
                    Ok(mut t) => match t.encapsulate(&buf[..n], &mut out) {
                        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
                        _ => None,
                    },
                    Err(_) => break,
                };
                if let Some(p) = pkt {
                    wire.send(&p);
                }
            }
        });
    }
    std::thread::spawn(move || {
        let mut buf = vec![0u8; MAX_PACKET];
        let mut out = vec![0u8; MAX_PACKET];
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let (a, n) = match wire.net.recv(&mut buf) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => continue,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
            };
            // Junk and look-alike packets from the other side are simply dropped.
            let Some(data) = wire.awg.unwrap(&buf[a..n]) else { continue };
            let mut to_net = Vec::new();
            let mut to_dev = Vec::new();
            if let Ok(mut t) = tunn.lock() {
                let mut res = t.decapsulate(None, &data, &mut out);
                loop {
                    match res {
                        TunnResult::WriteToNetwork(p) => {
                            to_net.push(p.to_vec());
                            res = t.decapsulate(None, &[], &mut out);
                        }
                        TunnResult::WriteToTunnelV4(p, _) | TunnResult::WriteToTunnelV6(p, _) => {
                            to_dev.push(p.to_vec());
                            break;
                        }
                        TunnResult::Err(e) => {
                            if let Ok(mut v) = errors.lock() {
                                v.push(format!("{e:?}"));
                            }
                            break;
                        }
                        TunnResult::Done => break,
                    }
                }
            }
            for p in to_net {
                wire.send(&p);
            }
            for p in to_dev {
                let _ = dev.send(&p);
            }
        }
    });
}

/// Sends a handshake initiation now.
pub fn send_initiation(tunn: &Mutex<Tunn>, wire: &Wire) {
    let mut out = vec![0u8; 2048];
    let first = tunn.lock().ok().and_then(|mut t| match t.format_handshake_initiation(&mut out, false) {
        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
        _ => None,
    });
    if let Some(p) = first {
        wire.send(&p);
    }
}

/// One timer tick: keepalives, rekeying and handshake retries.
pub fn timers(tunn: &Mutex<Tunn>, wire: &Wire, out: &mut [u8]) {
    let pkt = tunn.lock().ok().and_then(|mut t| match t.update_timers(out) {
        TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
        TunnResult::Err(WireGuardError::ConnectionExpired) => match t.format_handshake_initiation(out, true) {
            TunnResult::WriteToNetwork(p) => Some(p.to_vec()),
            _ => None,
        },
        _ => None,
    });
    if let Some(p) = pkt {
        wire.send(&p);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::mpsc;

    /// An in-memory adapter: packets the test injects come out of `recv`,
    /// packets the tunnel delivers go to `delivered`.
    struct MemDevice {
        inbound: Mutex<mpsc::Receiver<Vec<u8>>>,
        delivered: Mutex<mpsc::Sender<Vec<u8>>>,
    }

    impl PacketDevice for MemDevice {
        fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let p = self.inbound.lock().unwrap().recv().map_err(|_| std::io::Error::other("closed"))?;
            buf[..p.len()].copy_from_slice(&p);
            Ok(p.len())
        }
        fn send(&self, buf: &[u8]) -> std::io::Result<usize> {
            let _ = self.delivered.lock().unwrap().send(buf.to_vec());
            Ok(buf.len())
        }
    }

    fn end(
        key: boringtun::x25519::StaticSecret,
        peer: boringtun::x25519::PublicKey,
        udp: UdpSocket,
        p: &Profile,
        index: u32,
    ) -> (Arc<Mutex<Tunn>>, Arc<Wire>, mpsc::Sender<Vec<u8>>, mpsc::Receiver<Vec<u8>>) {
        udp.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
        let local = udp.local_addr().unwrap();
        let wire = Arc::new(Wire::new(crate::socks::Transport { udp, socks: None }, obfs::Plan::from_profile(p), Awg::from_profile(p), local));
        let tunn = Arc::new(Mutex::new(Tunn::new(key, peer, None, None, index, None)));
        let (in_tx, in_rx) = mpsc::channel();
        let (out_tx, out_rx) = mpsc::channel();
        let dev = Arc::new(MemDevice { inbound: Mutex::new(in_rx), delivered: Mutex::new(out_tx) });
        spawn_loops(dev, tunn.clone(), wire.clone(), Arc::new(Mutex::new(Vec::new())));
        (tunn, wire, in_tx, out_rx)
    }

    /// A minimal IPv4 packet (header only plus payload), enough for boringtun.
    fn ipv4(payload: &[u8]) -> Vec<u8> {
        let len = 20 + payload.len();
        let mut p = vec![0x45, 0, (len >> 8) as u8, len as u8, 0, 0, 0, 0, 64, 17, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1];
        p.extend_from_slice(payload);
        p
    }

    /// End to end over real UDP sockets, with junk packets, I-packets and
    /// AmneziaWG headers on: the handshake completes and an IP packet put
    /// into one end comes out of the other.
    #[test]
    fn masked_tunnel_end_to_end() {
        let p = Profile {
            jc: "5".into(),
            jmin: "40".into(),
            jmax: "90".into(),
            s1: "15".into(),
            s2: "18".into(),
            s3: "20".into(),
            s4: "23".into(),
            h1: "100000-200000".into(),
            h2: "300000-400000".into(),
            h3: "500000-600000".into(),
            h4: "700000-800000".into(),
            ..Default::default()
        };
        let mut p = p;
        p.i[0] = "<b 0xc0ffee><r 20>".into();
        let a_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        a_sock.connect(b_sock.local_addr().unwrap()).unwrap();
        b_sock.connect(a_sock.local_addr().unwrap()).unwrap();
        let a_key = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
        let b_key = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
        let (a_pub, b_pub) = (boringtun::x25519::PublicKey::from(&a_key), boringtun::x25519::PublicKey::from(&b_key));
        let (a_tunn, a_wire, a_in, _a_out) = end(a_key, b_pub, a_sock, &p, 1);
        let (_b_tunn, _b_wire, _b_in, b_out) = end(b_key, a_pub, b_sock, &p, 2);

        send_initiation(&a_tunn, &a_wire);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while a_tunn.lock().unwrap().stats().0.is_none() {
            assert!(std::time::Instant::now() < deadline, "handshake did not complete");
            std::thread::sleep(Duration::from_millis(20));
        }
        let pkt = ipv4(b"hello through the masked tunnel");
        a_in.send(pkt.clone()).unwrap();
        let got = b_out.recv_timeout(Duration::from_secs(5)).expect("packet arrived");
        assert_eq!(got, pkt);
    }
}
