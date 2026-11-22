//! Windows per-app split tunnelling with WinDivert (the original does the same
//! job with its NDISAPI driver `ndiswgc.sys`).
//!
//! When a profile sets AllowedApps or DisallowedApps on Windows, no Wintun
//! adapter and no tunnel routes are created. Instead a WinDivert handle on the
//! NETWORK layer captures outbound packets; each is mapped to its program (by
//! local port through the IP Helper owner tables, as the original does with
//! `iphelper::process_lookup`). A packet that belongs in the tunnel has its
//! source address rewritten to the profile's interior address (the server's
//! cryptokey routing drops anything else), its TCP MSS clamped to the tunnel
//! MTU, and is handed to boringtun; everything else is re-injected unchanged.
//! Packets boringtun decrypts have their destination rewritten back and are
//! injected inbound, so the program receives them on its own socket.
//!
//! The address rewriting and checksum repair are plain functions tested below;
//! only the driver glue is Windows-only.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The transport protocols we rewrite (others are tunnelled as-is, no L4 fix-up).
#[allow(dead_code)]
pub const PROTO_TCP: u8 = 6;
#[allow(dead_code)]
pub const PROTO_UDP: u8 = 17;

/// The one-complement sum used by IPv4, TCP and UDP checksums.
fn ones_complement_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut i = 0;
        while i + 1 < part.len() {
            sum += u16::from_be_bytes([part[i], part[i + 1]]) as u32;
            i += 2;
        }
        if i < part.len() {
            sum += (part[i] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// IP version of a packet (4 or 6), or None if it is too short.
pub fn ip_version(pkt: &[u8]) -> Option<u8> {
    pkt.first().map(|b| b >> 4)
}

struct V4<'a> {
    pkt: &'a mut [u8],
}

impl<'a> V4<'a> {
    fn new(pkt: &'a mut [u8]) -> Option<Self> {
        if pkt.len() < 20 || pkt[0] >> 4 != 4 {
            return None;
        }
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        if ihl < 20 || pkt.len() < ihl {
            return None;
        }
        Some(V4 { pkt })
    }
    fn ihl(&self) -> usize {
        (self.pkt[0] & 0x0f) as usize * 4
    }
    fn proto(&self) -> u8 {
        self.pkt[9]
    }
    fn fix_ip_checksum(&mut self) {
        self.pkt[10] = 0;
        self.pkt[11] = 0;
        let ihl = self.ihl();
        let c = ones_complement_sum(&[&self.pkt[..ihl]]);
        self.pkt[10..12].copy_from_slice(&c.to_be_bytes());
    }
    fn fix_l4_checksum(&mut self) {
        let ihl = self.ihl();
        let proto = self.proto();
        let (off, zero) = match proto {
            PROTO_TCP => (ihl + 16, true),
            PROTO_UDP => (ihl + 6, true),
            _ => return,
        };
        if off + 2 > self.pkt.len() {
            return;
        }
        let total = u16::from_be_bytes([self.pkt[2], self.pkt[3]]) as usize;
        let l4_len = total.saturating_sub(ihl);
        let src = [self.pkt[12], self.pkt[13], self.pkt[14], self.pkt[15]];
        let dst = [self.pkt[16], self.pkt[17], self.pkt[18], self.pkt[19]];
        let pseudo = [src[0], src[1], src[2], src[3], dst[0], dst[1], dst[2], dst[3], 0, proto, (l4_len >> 8) as u8, l4_len as u8];
        if zero {
            self.pkt[off] = 0;
            self.pkt[off + 1] = 0;
        }
        let end = (ihl + l4_len).min(self.pkt.len());
        let mut c = ones_complement_sum(&[&pseudo, &self.pkt[ihl..end]]);
        // UDP: a zero checksum means "none", so it is sent as 0xffff.
        if proto == PROTO_UDP && c == 0 {
            c = 0xffff;
        }
        self.pkt[off..off + 2].copy_from_slice(&c.to_be_bytes());
    }
}

/// Rewrites the source address of an outbound IPv4 packet and repairs checksums.
pub fn snat_v4(pkt: &mut [u8], new_src: Ipv4Addr) -> bool {
    let Some(mut v) = V4::new(pkt) else { return false };
    v.pkt[12..16].copy_from_slice(&new_src.octets());
    v.fix_ip_checksum();
    v.fix_l4_checksum();
    true
}

/// Rewrites the destination of an inbound IPv4 packet and repairs checksums.
pub fn dnat_v4(pkt: &mut [u8], new_dst: Ipv4Addr) -> bool {
    let Some(mut v) = V4::new(pkt) else { return false };
    v.pkt[16..20].copy_from_slice(&new_dst.octets());
    v.fix_ip_checksum();
    v.fix_l4_checksum();
    true
}

struct V6<'a> {
    pkt: &'a mut [u8],
}

impl<'a> V6<'a> {
    fn new(pkt: &'a mut [u8]) -> Option<Self> {
        (pkt.len() >= 40 && pkt[0] >> 4 == 6).then_some(V6 { pkt })
    }
    fn next_header(&self) -> u8 {
        self.pkt[6]
    }
    fn fix_l4_checksum(&mut self) {
        let proto = self.next_header();
        let off = match proto {
            PROTO_TCP => 40 + 16,
            PROTO_UDP => 40 + 6,
            _ => return,
        };
        if off + 2 > self.pkt.len() {
            return;
        }
        let payload_len = u16::from_be_bytes([self.pkt[4], self.pkt[5]]) as usize;
        let mut pseudo = [0u8; 40];
        pseudo[..32].copy_from_slice(&self.pkt[8..40]);
        pseudo[32..36].copy_from_slice(&(payload_len as u32).to_be_bytes());
        pseudo[39] = proto;
        self.pkt[off] = 0;
        self.pkt[off + 1] = 0;
        let end = (40 + payload_len).min(self.pkt.len());
        let mut c = ones_complement_sum(&[&pseudo, &self.pkt[40..end]]);
        if proto == PROTO_UDP && c == 0 {
            c = 0xffff;
        }
        self.pkt[off..off + 2].copy_from_slice(&c.to_be_bytes());
    }
}

pub fn snat_v6(pkt: &mut [u8], new_src: Ipv6Addr) -> bool {
    let Some(mut v) = V6::new(pkt) else { return false };
    v.pkt[8..24].copy_from_slice(&new_src.octets());
    v.fix_l4_checksum();
    true
}

pub fn dnat_v6(pkt: &mut [u8], new_dst: Ipv6Addr) -> bool {
    let Some(mut v) = V6::new(pkt) else { return false };
    v.pkt[24..40].copy_from_slice(&new_dst.octets());
    v.fix_l4_checksum();
    true
}

/// On a TCP SYN, clamps the MSS option down to `mss` and repairs the checksum.
/// Fragmentation can't fix an over-large MSS once the tunnel's overhead is added.
pub fn clamp_mss(pkt: &mut [u8], mss: u16) {
    let (ver, l4_off, is_tcp) = match ip_version(pkt) {
        Some(4) if pkt.len() >= 20 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            (4u8, ihl, pkt.get(9) == Some(&PROTO_TCP))
        }
        Some(6) if pkt.len() >= 40 => (6, 40, pkt.get(6) == Some(&PROTO_TCP)),
        _ => return,
    };
    if !is_tcp || pkt.len() < l4_off + 20 {
        return;
    }
    let flags = pkt[l4_off + 13];
    if flags & 0x02 == 0 {
        return; // not a SYN
    }
    let data_off = (pkt[l4_off + 12] >> 4) as usize * 4;
    let opts_start = l4_off + 20;
    let opts_end = (l4_off + data_off).min(pkt.len());
    let mut i = opts_start;
    let mut changed = false;
    while i + 1 < opts_end {
        match pkt[i] {
            0 => break,       // end of options
            1 => i += 1,      // no-op
            2 if i + 3 < opts_end && pkt[i + 1] == 4 => {
                let cur = u16::from_be_bytes([pkt[i + 2], pkt[i + 3]]);
                if cur > mss {
                    pkt[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
                    changed = true;
                }
                break;
            }
            _ => {
                let len = pkt[i + 1] as usize;
                if len < 2 {
                    break;
                }
                i += len;
            }
        }
    }
    if changed {
        match ver {
            4 => {
                if let Some(mut v) = V4::new(pkt) {
                    v.fix_l4_checksum();
                }
            }
            _ => {
                if let Some(mut v) = V6::new(pkt) {
                    v.fix_l4_checksum();
                }
            }
        }
    }
}

/// Local (source) transport port of an outbound packet, for owner lookup.
pub fn local_port(pkt: &[u8]) -> Option<(u8, u16)> {
    let (proto, off) = match ip_version(pkt)? {
        4 => {
            let ihl = (pkt[0] & 0x0f) as usize * 4;
            (*pkt.get(9)?, ihl)
        }
        6 => (*pkt.get(6)?, 40),
        _ => return None,
    };
    if !matches!(proto, PROTO_TCP | PROTO_UDP) || pkt.len() < off + 2 {
        return None;
    }
    Some((proto, u16::from_be_bytes([pkt[off], pkt[off + 1]])))
}

/// Destination address of a packet.
pub fn dest_ip(pkt: &[u8]) -> Option<IpAddr> {
    match ip_version(pkt)? {
        4 if pkt.len() >= 20 => Some(IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]))),
        6 if pkt.len() >= 40 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// Destination transport port (for the DNS-redirect decision).
pub fn dest_port(pkt: &[u8]) -> Option<(u8, u16)> {
    let (proto, off) = match ip_version(pkt)? {
        4 => ((*pkt.get(9)?), (pkt[0] & 0x0f) as usize * 4),
        6 => (*pkt.get(6)?, 40),
        _ => return None,
    };
    if !matches!(proto, PROTO_TCP | PROTO_UDP) || pkt.len() < off + 4 {
        return None;
    }
    Some((proto, u16::from_be_bytes([pkt[off + 2], pkt[off + 3]])))
}

/// Is `ip` inside the CIDR string `cidr` (e.g. "10.0.0.0/8", "::/1")?
pub fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n.trim(), b.trim().parse::<u32>().unwrap_or(0)),
        None => (cidr.trim(), if ip.is_ipv4() { 32 } else { 128 }),
    };
    match (net.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(n)), IpAddr::V4(a)) => prefix_eq(&n.octets(), &a.octets(), bits.min(32)),
        (Ok(IpAddr::V6(n)), IpAddr::V6(a)) => prefix_eq(&n.octets(), &a.octets(), bits.min(128)),
        _ => false,
    }
}

fn prefix_eq(net: &[u8], ip: &[u8], bits: u32) -> bool {
    let full = (bits / 8) as usize;
    if net[..full] != ip[..full] {
        return false;
    }
    let rem = bits % 8;
    if rem == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - rem);
    net[full] & mask == ip[full] & mask
}

/// Whether a packet going anywhere in `routes` should enter the tunnel.
pub fn dest_in_routes(pkt: &[u8], routes: &[String]) -> bool {
    match dest_ip(pkt) {
        Some(ip) => routes.iter().any(|r| cidr_contains(r, ip)),
        None => false,
    }
}

/// OnlyThese tunnels the listed apps; Except tunnels everything but them.
pub fn should_tunnel(mode: &crate::apps::Mode, pid_matches: bool) -> bool {
    match mode {
        crate::apps::Mode::OnlyThese(_) => pid_matches,
        crate::apps::Mode::Except(_) => !pid_matches,
    }
}

/// True only where a WinDivert driver is bundled (Windows x64). Other Windows
/// architectures have no signed driver, so per-app routing isn't enforced there.
pub const SUPPORTED: bool = cfg!(all(windows, target_arch = "x86_64"));

#[cfg(all(windows, target_arch = "x86_64"))]
pub use imp::open;

#[cfg(all(windows, target_arch = "x86_64"))]
mod imp {
    use super::*;
    use std::collections::HashMap;
    use std::ffi::c_void;
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use crate::apps::Mode;
    use crate::datapath::PacketDevice;
    use crate::profile::Profile;

    type Handle = *mut c_void;
    const INVALID: Handle = usize::MAX as Handle;
    const LAYER_NETWORK: u32 = 0;
    // WINDIVERT_ADDRESS is 80 bytes; the NETWORK union puts IfIdx/SubIfIdx first.
    const ADDR_LEN: usize = 80;
    const MAX_PACKET: usize = 0xffff;

    struct Api {
        _lib: libloading::Library,
        open: unsafe extern "system" fn(*const u8, u32, i16, u64) -> Handle,
        recv: unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut u8) -> i32,
        send: unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const u8) -> i32,
        shutdown: unsafe extern "system" fn(Handle, u32) -> i32,
        close: unsafe extern "system" fn(Handle) -> i32,
    }

    unsafe impl Send for Api {}
    unsafe impl Sync for Api {}

    /// A NAT entry: where a tunnelled flow's packets must be sent back.
    #[derive(Clone)]
    struct Nat {
        original_dst: IpAddr,
        if_idx: u32,
        sub_if_idx: u32,
    }

    pub struct WinDivertDevice {
        api: Api,
        handle: Handle,
        mode: Mode,
        routes: Vec<String>,
        v4: Option<Ipv4Addr>,
        v6: Option<Ipv6Addr>,
        mss4: u16,
        mss6: u16,
        self_pid: u32,
        dns: Option<IpAddr>,
        /// PIDs of programs that match the rules, refreshed once a second.
        pids: Arc<Mutex<std::collections::HashSet<u32>>>,
        /// (proto, local port) -> PID, from the IP Helper owner tables.
        ports: Arc<Mutex<HashMap<(u8, u16), u32>>>,
        /// (proto, local port) -> how to send the replies back.
        nat: Mutex<HashMap<(u8, u16), Nat>>,
        stop: Arc<AtomicBool>,
    }

    unsafe impl Send for WinDivertDevice {}
    unsafe impl Sync for WinDivertDevice {}

    fn load_api(dll: &Path) -> Result<Api, String> {
        unsafe {
            let lib = libloading::Library::new(dll).map_err(|e| format!("WinDivert.dll: {e}"))?;
            let open = *lib.get::<unsafe extern "system" fn(*const u8, u32, i16, u64) -> Handle>(b"WinDivertOpen\0").map_err(|e| e.to_string())?;
            let recv = *lib.get::<unsafe extern "system" fn(Handle, *mut u8, u32, *mut u32, *mut u8) -> i32>(b"WinDivertRecv\0").map_err(|e| e.to_string())?;
            let send = *lib.get::<unsafe extern "system" fn(Handle, *const u8, u32, *mut u32, *const u8) -> i32>(b"WinDivertSend\0").map_err(|e| e.to_string())?;
            let shutdown = *lib.get::<unsafe extern "system" fn(Handle, u32) -> i32>(b"WinDivertShutdown\0").map_err(|e| e.to_string())?;
            let close = *lib.get::<unsafe extern "system" fn(Handle) -> i32>(b"WinDivertClose\0").map_err(|e| e.to_string())?;
            Ok(Api { _lib: lib, open, recv, send, shutdown, close })
        }
    }

    /// Builds the capture filter, excluding our own traffic and the endpoint.
    fn filter_string(server: SocketAddr, proxy: Option<SocketAddr>, relay: Option<SocketAddr>) -> String {
        let mut f = String::from("outbound and ip and not loopback");
        for a in [Some(server), proxy, relay].into_iter().flatten() {
            if let IpAddr::V4(v) = a.ip() {
                f.push_str(&format!(" and not ip.DstAddr == {v}"));
            }
        }
        f
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open(
        mode: &Mode,
        p: &Profile,
        routes: &[String],
        server: SocketAddr,
        proxy: Option<SocketAddr>,
        relay: Option<SocketAddr>,
        conf: &Path,
        log: &mut dyn FnMut(String),
    ) -> Result<Arc<WinDivertDevice>, String> {
        let dll = write_driver(conf)?;
        let api = load_api(&dll)?;
        let filter = filter_string(server, proxy, relay);
        let handle = unsafe { (api.open)(format!("{filter}\0").as_ptr(), LAYER_NETWORK, 0, 0) };
        if handle == INVALID || handle.is_null() {
            let e = std::io::Error::last_os_error();
            return Err(format!("WinDivert could not open ({e}). The driver needs administrator rights and a signed-driver-capable system."));
        }
        let mtu: u16 = p.mtu.trim().parse().unwrap_or(crate::engine::DEFAULT_MTU);
        let mut v4 = None;
        let mut v6 = None;
        for a in crate::profile::split_list(&p.address) {
            match a.split('/').next().and_then(|s| s.trim().parse::<IpAddr>().ok()) {
                Some(IpAddr::V4(x)) if v4.is_none() => v4 = Some(x),
                Some(IpAddr::V6(x)) if v6.is_none() => v6 = Some(x),
                _ => {}
            }
        }
        let dns = crate::profile::split_list(&p.dns).iter().find_map(|d| d.trim().parse::<IpAddr>().ok());
        let rules = match mode {
            Mode::OnlyThese(r) | Mode::Except(r) => r.clone(),
        };
        let pids: Arc<Mutex<std::collections::HashSet<u32>>> = Default::default();
        let ports: Arc<Mutex<HashMap<(u8, u16), u32>>> = Default::default();
        let stop = Arc::new(AtomicBool::new(false));
        spawn_owner_scan(rules, pids.clone(), ports.clone(), stop.clone());
        log(format!("WinDivert per-app filter on ({filter})"));
        Ok(Arc::new(WinDivertDevice {
            api,
            handle,
            mode: mode.clone(),
            routes: routes.to_vec(),
            v4,
            v6,
            mss4: mtu.saturating_sub(40),
            mss6: mtu.saturating_sub(60),
            self_pid: unsafe { GetCurrentProcessId() },
            dns,
            pids,
            ports,
            nat: Mutex::new(HashMap::new()),
            stop,
        }))
    }

    impl WinDivertDevice {
        /// Re-injects a packet unchanged (not tunnelled).
        fn reinject(&self, pkt: &[u8], addr: &[u8]) {
            let mut n = 0u32;
            unsafe { (self.api.send)(self.handle, pkt.as_ptr(), pkt.len() as u32, &mut n, addr.as_ptr()) };
        }

        fn owner_pid(&self, proto: u8, port: u16) -> Option<u32> {
            self.ports.lock().ok()?.get(&(proto, port)).copied()
        }

        fn pid_matches(&self, pid: u32) -> bool {
            self.pids.lock().map(|s| s.contains(&pid)).unwrap_or(false)
        }
    }

    impl PacketDevice for WinDivertDevice {
        /// Returns the next packet that belongs in the tunnel, after rewriting
        /// its source to the interior address; re-injects everything else.
        fn recv(&self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut addr = [0u8; ADDR_LEN];
            loop {
                if self.stop.load(Ordering::Relaxed) {
                    return Err(std::io::Error::other("stopped"));
                }
                let mut scratch = vec![0u8; MAX_PACKET];
                let mut len = 0u32;
                let ok = unsafe { (self.api.recv)(self.handle, scratch.as_mut_ptr(), scratch.len() as u32, &mut len, addr.as_mut_ptr()) };
                if ok == 0 {
                    // Shutdown or a transient error: let the loop end on stop.
                    if self.stop.load(Ordering::Relaxed) {
                        return Err(std::io::Error::other("stopped"));
                    }
                    continue;
                }
                let len = len as usize;
                scratch.truncate(len);
                let if_idx = u32::from_le_bytes([addr[16], addr[17], addr[18], addr[19]]);
                let sub_if_idx = u32::from_le_bytes([addr[20], addr[21], addr[22], addr[23]]);

                let Some((proto, lport)) = local_port(&scratch) else {
                    self.reinject(&scratch, &addr);
                    continue;
                };
                let pid = self.owner_pid(proto, lport);
                let mine = pid == Some(self.self_pid);
                let tunnel = !mine && pid.map(|p| should_tunnel(&self.mode, self.pid_matches(p))).unwrap_or(false) && dest_in_routes(&scratch, &self.routes);
                if !tunnel {
                    self.reinject(&scratch, &addr);
                    continue;
                }
                // DNS from a tunnelled app is answered by the system resolver, so
                // send port-53 traffic to the profile's DNS server in the tunnel.
                let mut original_dst = dest_ip(&scratch);
                if let (Some((_, 53)), Some(dns)) = (dest_port(&scratch), self.dns) {
                    original_dst = dest_ip(&scratch);
                    match (ip_version(&scratch), dns) {
                        (Some(4), IpAddr::V4(d)) => {
                            dnat_v4(&mut scratch, d);
                        }
                        (Some(6), IpAddr::V6(d)) => {
                            dnat_v6(&mut scratch, d);
                        }
                        _ => {}
                    }
                }
                let rewritten = match ip_version(&scratch) {
                    Some(4) => self.v4.map(|s| snat_v4(&mut scratch, s)).unwrap_or(false),
                    Some(6) => self.v6.map(|s| snat_v6(&mut scratch, s)).unwrap_or(false),
                    _ => false,
                };
                if !rewritten {
                    self.reinject(&scratch, &addr);
                    continue;
                }
                let mss = if ip_version(&scratch) == Some(6) { self.mss6 } else { self.mss4 };
                clamp_mss(&mut scratch, mss);
                if let (Some(dst), Ok(mut t)) = (original_dst, self.nat.lock()) {
                    t.insert((proto, lport), Nat { original_dst: dst, if_idx, sub_if_idx });
                }
                if scratch.len() > buf.len() {
                    self.reinject(&scratch, &addr);
                    continue;
                }
                buf[..scratch.len()].copy_from_slice(&scratch);
                return Ok(scratch.len());
            }
        }

        /// A packet boringtun decrypted: restore its destination to the program's
        /// real address and inject it inbound so the program's socket gets it.
        fn send(&self, pkt: &[u8]) -> std::io::Result<usize> {
            let mut data = pkt.to_vec();
            // The reply's transport destination port is the flow's local port.
            let dport = dest_port(&data);
            let proto = dport.map(|(p, _)| p);
            let lport = dport.map(|(_, p)| p);
            let entry = match (proto, lport) {
                (Some(proto), Some(lport)) => self.nat.lock().ok().and_then(|t| t.get(&(proto, lport)).cloned()),
                _ => None,
            };
            let Some(nat) = entry else {
                // No record: nothing to deliver it to.
                return Ok(pkt.len());
            };
            match (ip_version(&data), nat.original_dst) {
                (Some(4), IpAddr::V4(d)) => {
                    dnat_v4(&mut data, d);
                }
                (Some(6), IpAddr::V6(d)) => {
                    dnat_v6(&mut data, d);
                }
                _ => return Ok(pkt.len()),
            }
            // Inbound address on the recorded interface (Outbound=0).
            let mut addr = [0u8; ADDR_LEN];
            addr[16..20].copy_from_slice(&nat.if_idx.to_le_bytes());
            addr[20..24].copy_from_slice(&nat.sub_if_idx.to_le_bytes());
            if ip_version(&data) == Some(6) {
                addr[8] |= 0x10; // IPv6 flag (bit 4 of the flags word)
            }
            let mut n = 0u32;
            unsafe { (self.api.send)(self.handle, data.as_ptr(), data.len() as u32, &mut n, addr.as_ptr()) };
            Ok(pkt.len())
        }
    }

    impl Drop for WinDivertDevice {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            unsafe {
                (self.api.shutdown)(self.handle, 0x3); // WINDIVERT_SHUTDOWN_BOTH
                (self.api.close)(self.handle);
            }
        }
    }

    // ---- the bundled driver, written next to the conf like wintun.dll ----

    static DLL: &[u8] = include_bytes!("../vendor/windivert/amd64/WinDivert.dll");
    static SYS: &[u8] = include_bytes!("../vendor/windivert/amd64/WinDivert64.sys");

    fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<(), String> {
        let same = std::fs::metadata(path).map(|m| m.len() == bytes.len() as u64).unwrap_or(false);
        if !same {
            std::fs::write(path, bytes).map_err(|e| format!("Could not write {}: {e}", path.display()))?;
        }
        Ok(())
    }

    /// WinDivert.dll loads WinDivert64.sys from the same folder.
    fn write_driver(conf: &Path) -> Result<std::path::PathBuf, String> {
        let dll = conf.with_file_name("WinDivert.dll");
        write_if_changed(&dll, DLL)?;
        write_if_changed(&conf.with_file_name("WinDivert64.sys"), SYS)?;
        Ok(dll)
    }

    // ---- owner lookup, like the original's iphelper::process_lookup ----

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcessId() -> u32;
    }
    #[link(name = "iphlpapi")]
    unsafe extern "system" {
        fn GetExtendedTcpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: i32, reserved: u32) -> u32;
        fn GetExtendedUdpTable(table: *mut c_void, size: *mut u32, order: i32, af: u32, class: i32, reserved: u32) -> u32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn CloseHandle(h: Handle) -> i32;
        fn QueryFullProcessImageNameW(h: Handle, flags: u32, buf: *mut u16, size: *mut u32) -> i32;
    }

    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const TCP_TABLE_OWNER_PID_ALL: i32 = 5;
    const UDP_TABLE_OWNER_PID: i32 = 1;

    fn image_path(pid: u32) -> Option<String> {
        unsafe {
            let h = OpenProcess(0x1000, 0, pid); // PROCESS_QUERY_LIMITED_INFORMATION
            if h.is_null() {
                return None;
            }
            let mut buf = [0u16; 512];
            let mut n = buf.len() as u32;
            let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut n);
            CloseHandle(h);
            (ok != 0).then(|| String::from_utf16_lossy(&buf[..n as usize]))
        }
    }

    /// One protocol's owner table (TCP or UDP), for one address family.
    /// `row_size`, `pid_off` and `port_off` are the MIB row layout.
    type Getter = unsafe extern "system" fn(*mut c_void, *mut u32, i32, u32, i32, u32) -> u32;

    #[allow(clippy::too_many_arguments)]
    fn scan_table(
        getter: Getter,
        af: u32,
        class: i32,
        proto: u8,
        row_size: usize,
        pid_off: usize,
        port_off: usize,
        rules: &[String],
        ports: &mut HashMap<(u8, u16), u32>,
        matched: &mut std::collections::HashSet<u32>,
        names: &mut HashMap<u32, Option<String>>,
    ) {
        unsafe {
            let mut size = 0u32;
            getter(std::ptr::null_mut(), &mut size, 1, af, class, 0);
            if size == 0 {
                return;
            }
            let mut buf = vec![0u8; size as usize];
            if getter(buf.as_mut_ptr().cast(), &mut size, 1, af, class, 0) != 0 {
                return;
            }
            let count = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            for i in 0..count {
                let row = 4 + i * row_size;
                if row + row_size > buf.len() {
                    break;
                }
                let pid = u32::from_ne_bytes([buf[row + pid_off], buf[row + pid_off + 1], buf[row + pid_off + 2], buf[row + pid_off + 3]]);
                // Ports in these tables are big-endian in the low 16 bits.
                let port = u16::from_be_bytes([buf[row + port_off], buf[row + port_off + 1]]);
                ports.insert((proto, port), pid);
                let name = names.entry(pid).or_insert_with(|| image_path(pid));
                if let Some(path) = name {
                    let comm = path.rsplit(['\\', '/']).next().unwrap_or("");
                    if rules.iter().any(|r| crate::apps::matches(r, path, comm)) {
                        matched.insert(pid);
                    }
                }
            }
        }
    }

    /// Reads the TCP+UDP owner tables for one address family.
    fn scan_family(
        af: u32,
        rules: &[String],
        ports: &mut HashMap<(u8, u16), u32>,
        matched: &mut std::collections::HashSet<u32>,
        names: &mut HashMap<u32, Option<String>>,
    ) {
        let v4 = af == AF_INET;
        scan_table(
            GetExtendedTcpTable,
            af,
            TCP_TABLE_OWNER_PID_ALL,
            PROTO_TCP,
            if v4 { 24 } else { 56 },
            if v4 { 12 } else { 48 },
            if v4 { 8 } else { 20 },
            rules,
            ports,
            matched,
            names,
        );
        scan_table(
            GetExtendedUdpTable,
            af,
            UDP_TABLE_OWNER_PID,
            PROTO_UDP,
            if v4 { 12 } else { 28 },
            if v4 { 8 } else { 24 },
            if v4 { 4 } else { 16 },
            rules,
            ports,
            matched,
            names,
        );
    }

    fn spawn_owner_scan(
        rules: Vec<String>,
        pids: Arc<Mutex<std::collections::HashSet<u32>>>,
        ports: Arc<Mutex<HashMap<(u8, u16), u32>>>,
        stop: Arc<AtomicBool>,
    ) {
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let mut new_ports = HashMap::new();
                let mut matched = std::collections::HashSet::new();
                let mut names = HashMap::new();
                scan_family(AF_INET, &rules, &mut new_ports, &mut matched, &mut names);
                scan_family(AF_INET6, &rules, &mut new_ports, &mut matched, &mut names);
                if let Ok(mut p) = ports.lock() {
                    *p = new_ports;
                }
                if let Ok(mut p) = pids.lock() {
                    *p = matched;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal IPv4 UDP packet: 20-byte header + 8-byte UDP + payload.
    fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = PROTO_UDP;
        p[12..16].copy_from_slice(&src.octets());
        p[16..20].copy_from_slice(&dst.octets());
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        let mut v = V4::new(&mut p).unwrap();
        v.fix_ip_checksum();
        v.fix_l4_checksum();
        p
    }

    fn checksum_ok_v4(pkt: &[u8]) -> bool {
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        // IP header checksum over the header must be zero.
        if ones_complement_sum(&[&pkt[..ihl]]) != 0 {
            return false;
        }
        let total = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
        let proto = pkt[9];
        let l4 = total - ihl;
        let pseudo = [pkt[12], pkt[13], pkt[14], pkt[15], pkt[16], pkt[17], pkt[18], pkt[19], 0, proto, (l4 >> 8) as u8, l4 as u8];
        ones_complement_sum(&[&pseudo, &pkt[ihl..ihl + l4]]) == 0
    }

    #[test]
    fn snat_keeps_checksums_valid() {
        let mut p = udp_v4(Ipv4Addr::new(192, 168, 1, 50), Ipv4Addr::new(1, 1, 1, 1), 40000, 443, b"hello");
        assert!(checksum_ok_v4(&p));
        assert!(snat_v4(&mut p, Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(&p[12..16], &[10, 8, 0, 2]);
        assert!(checksum_ok_v4(&p), "checksums valid after SNAT");
        // And the reverse restores a valid packet.
        assert!(dnat_v4(&mut p, Ipv4Addr::new(192, 168, 1, 50)));
        assert!(checksum_ok_v4(&p));
    }

    #[test]
    fn mss_is_clamped_on_syn() {
        // IPv4 TCP SYN with an MSS option of 1460.
        let mut p = vec![0u8; 20 + 24];
        let total = (p.len() as u16).to_be_bytes();
        p[0] = 0x45;
        p[2..4].copy_from_slice(&total);
        p[9] = PROTO_TCP;
        p[12..16].copy_from_slice(&[10, 0, 0, 1]);
        p[16..20].copy_from_slice(&[10, 0, 0, 2]);
        p[20 + 12] = 6 << 4; // data offset = 6 words (24 bytes)
        p[20 + 13] = 0x02; // SYN
        p[20 + 20] = 2; // MSS option kind
        p[20 + 21] = 4; // length
        p[20 + 22..20 + 24].copy_from_slice(&1460u16.to_be_bytes());
        clamp_mss(&mut p, 1340);
        assert_eq!(u16::from_be_bytes([p[20 + 22], p[20 + 23]]), 1340);
    }

    #[test]
    fn cidr_membership() {
        assert!(cidr_contains("192.168.0.0/16", "192.168.100.20".parse().unwrap()));
        assert!(!cidr_contains("192.168.0.0/16", "198.51.100.1".parse().unwrap()));
        assert!(cidr_contains("0.0.0.0/1", "127.0.0.1".parse().unwrap()));
        assert!(!cidr_contains("128.0.0.0/1", "127.0.0.1".parse().unwrap()));
        assert!(cidr_contains("::/0", "2606:4700::1111".parse().unwrap()));
        assert!(cidr_contains("2001:db8::/32", "2001:db8::5".parse().unwrap()));
        assert!(!cidr_contains("2001:db8::/32", "2001:dead::5".parse().unwrap()));
    }

    #[test]
    fn tunnel_decision_per_mode() {
        let only = Mode::OnlyThese(vec!["a".into()]);
        let except = Mode::Except(vec!["a".into()]);
        assert!(should_tunnel(&only, true));
        assert!(!should_tunnel(&only, false));
        assert!(!should_tunnel(&except, true));
        assert!(should_tunnel(&except, false));
    }

    #[test]
    fn ports_and_dest_are_read() {
        let p = udp_v4(Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(8, 8, 8, 8), 5353, 53, b"q");
        assert_eq!(local_port(&p), Some((PROTO_UDP, 5353)));
        assert_eq!(dest_port(&p), Some((PROTO_UDP, 53)));
        assert_eq!(dest_ip(&p), Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    use crate::apps::Mode;
}
