//! WireGuard over a SOCKS5 proxy: RFC 1928 UDP ASSOCIATE with optional
//! RFC 1929 username/password, like the original's `socks5_udp_client`
//! (wgbooster strings 0x180270290-0x180270f60). Every WireGuard datagram is
//! sent to the proxy's relay port with a SOCKS5 UDP header naming the server.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::Duration;

/// How long to wait for the proxy's TCP connection and replies (estimated).
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Socks {
    /// Kept open: the association ends when this connection closes.
    pub control: TcpStream,
    pub proxy: SocketAddr,
    pub relay: SocketAddr,
    header: Vec<u8>,
}

pub fn resolve(endpoint: &str) -> Result<SocketAddr, String> {
    endpoint
        .trim()
        .to_socket_addrs()
        .map_err(|e| format!("the SOCKS5 proxy did not parse or resolve ({e}); the profile is refused instead of running without it"))?
        .next()
        .ok_or_else(|| "the SOCKS5 proxy did not parse or resolve; the profile is refused instead of running without it".into())
}

fn addr_bytes(a: SocketAddr) -> Vec<u8> {
    let mut v = Vec::new();
    match a.ip() {
        IpAddr::V4(ip) => {
            v.push(1);
            v.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            v.push(4);
            v.extend_from_slice(&ip.octets());
        }
    }
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

/// UDP request header for datagrams to `target` (RSV RSV FRAG ATYP ADDR PORT).
pub fn udp_header(target: SocketAddr) -> Vec<u8> {
    let mut h = vec![0, 0, 0];
    h.extend(addr_bytes(target));
    h
}

/// Length of the SOCKS5 UDP header at the start of `data`, if valid.
pub fn header_len(data: &[u8]) -> Option<usize> {
    if data.len() < 4 || data[2] != 0 {
        return None;
    }
    let n = match data[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 4 + 1 + *data.get(4)? as usize + 2,
        _ => return None,
    };
    (data.len() >= n).then_some(n)
}

/// Phone apps must keep the tunnel's own sockets out of the VPN (Android's
/// `VpnService.protect`) before they connect; the hook does that. Desktop
/// leaves it unset.
type ProtectHook = Box<dyn Fn(i64) -> bool + Send + Sync>;
static PROTECT: std::sync::Mutex<Option<ProtectHook>> = std::sync::Mutex::new(None);

#[cfg_attr(not(st_mobile), allow(dead_code))]
pub fn set_protect(hook: Option<ProtectHook>) {
    if let Ok(mut p) = PROTECT.lock() {
        *p = hook;
    }
}

fn has_protect() -> bool {
    PROTECT.lock().map(|p| p.is_some()).unwrap_or(false)
}

/// Runs the hook on a socket; true when there is none.
pub fn protect_raw(fd: i64) -> bool {
    PROTECT.lock().ok().and_then(|p| p.as_ref().map(|f| f(fd))).unwrap_or(true)
}

#[cfg(unix)]
pub fn raw_of<S: std::os::fd::AsRawFd>(s: &S) -> i64 {
    s.as_raw_fd() as i64
}
#[cfg(windows)]
pub fn raw_of<S: std::os::windows::io::AsRawSocket>(s: &S) -> i64 {
    s.as_raw_socket() as i64
}

fn tcp_connect(addr: SocketAddr) -> std::io::Result<TcpStream> {
    if !has_protect() {
        return TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT);
    }
    let s = socket2::Socket::new(socket2::Domain::for_address(addr), socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    if !protect_raw(raw_of(&s)) {
        return Err(std::io::Error::other("could not keep the proxy connection outside the VPN"));
    }
    s.connect_timeout(&addr.into(), CONNECT_TIMEOUT)?;
    Ok(s.into())
}

impl Socks {
    pub fn connect(proxy: SocketAddr, server: SocketAddr, user: &str, pass: &str) -> Result<Socks, String> {
        if proxy.is_ipv4() != server.is_ipv4() {
            return Err("the SOCKS5 proxy and the WireGuard endpoint have different address families, a combination this implementation does not relay; the profile is refused instead of running without the proxy".into());
        }
        if user.len() > 255 || pass.len() > 255 {
            return Err("SOCKS5: username or password length exceeds the limits".into());
        }
        let mut t = tcp_connect(proxy).map_err(|e| format!("SOCKS5 proxy {proxy}: {e}"))?;
        t.set_read_timeout(Some(CONNECT_TIMEOUT)).ok();
        t.set_write_timeout(Some(CONNECT_TIMEOUT)).ok();
        t.set_nodelay(true).ok();
        let io = |e: std::io::Error| format!("SOCKS5 proxy {proxy}: {e}");
        let with_auth = !user.is_empty();
        let hello: &[u8] = if with_auth { &[5, 2, 0, 2] } else { &[5, 1, 0] };
        t.write_all(hello).map_err(io)?;
        let mut r = [0u8; 2];
        t.read_exact(&mut r).map_err(io)?;
        if r[0] != 5 {
            return Err("SOCKS5 proxy answered with another protocol".into());
        }
        match r[1] {
            0 => {}
            2 => {
                if !with_auth {
                    return Err("RFC 1928: X'02' USERNAME/PASSWORD is chosen but USERNAME is not provided".into());
                }
                let mut a = vec![1, user.len() as u8];
                a.extend_from_slice(user.as_bytes());
                a.push(pass.len() as u8);
                a.extend_from_slice(pass.as_bytes());
                t.write_all(&a).map_err(io)?;
                t.read_exact(&mut r).map_err(io)?;
                if r[1] != 0 {
                    return Err("SOCKS5 USERNAME/PASSWORD authentication has failed".into());
                }
            }
            _ => return Err("SOCKS5 authentication has failed (no acceptable method)".into()),
        }
        // UDP ASSOCIATE from any address/port of ours.
        let any: SocketAddr = if server.is_ipv4() { SocketAddr::from(([0, 0, 0, 0], 0)) } else { SocketAddr::from(([0u16; 8], 0)) };
        let mut req = vec![5, 3, 0];
        req.extend(addr_bytes(any));
        t.write_all(&req).map_err(io)?;
        let mut head = [0u8; 4];
        t.read_exact(&mut head).map_err(io)?;
        if head[1] != 0 {
            return Err(format!("SOCKS5 ASSOCIATE has failed (reply {})", head[1]));
        }
        let ip: IpAddr = match head[3] {
            1 => {
                let mut b = [0u8; 4];
                t.read_exact(&mut b).map_err(io)?;
                IpAddr::from(b)
            }
            4 => {
                let mut b = [0u8; 16];
                t.read_exact(&mut b).map_err(io)?;
                IpAddr::from(b)
            }
            3 => {
                let mut l = [0u8; 1];
                t.read_exact(&mut l).map_err(io)?;
                let mut name = vec![0u8; l[0] as usize];
                t.read_exact(&mut name).map_err(io)?;
                let mut p = [0u8; 2];
                t.read_exact(&mut p).map_err(io)?;
                let host = String::from_utf8_lossy(&name).to_string();
                let port = u16::from_be_bytes(p);
                let relay = (host.as_str(), port).to_socket_addrs().map_err(io)?.next().ok_or("SOCKS5 relay did not resolve")?;
                t.set_read_timeout(None).ok();
                return Ok(Socks { control: t, proxy, relay, header: udp_header(server) });
            }
            _ => return Err("SOCKS5 ASSOCIATE reply has an unknown address type".into()),
        };
        let mut p = [0u8; 2];
        t.read_exact(&mut p).map_err(io)?;
        let port = u16::from_be_bytes(p);
        // An unspecified relay address means "the proxy's own address".
        let relay = SocketAddr::new(if ip.is_unspecified() { proxy.ip() } else { ip }, port);
        t.set_read_timeout(None).ok();
        Ok(Socks { control: t, proxy, relay, header: udp_header(server) })
    }

    pub fn wrap(&self, pkt: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.header.len() + pkt.len());
        v.extend_from_slice(&self.header);
        v.extend_from_slice(pkt);
        v
    }
}

/// Socket the WireGuard datagrams use: straight to the server, or to the proxy's relay.
pub struct Transport {
    pub udp: UdpSocket,
    pub socks: Option<Socks>,
}

impl Transport {
    pub fn send(&self, pkt: &[u8]) {
        match &self.socks {
            Some(s) => {
                let _ = self.udp.send(&s.wrap(pkt));
            }
            None => {
                let _ = self.udp.send(pkt);
            }
        }
    }

    /// Receives one datagram; returns the WireGuard payload's range in `buf`.
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<Option<(usize, usize)>> {
        let n = self.udp.recv(buf)?;
        Ok(match &self.socks {
            Some(_) => header_len(&buf[..n]).map(|h| (h, n)),
            None => Some((0, n)),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn headers() {
        let h = udp_header("192.0.2.7:51820".parse().unwrap());
        assert_eq!(h, vec![0, 0, 0, 1, 192, 0, 2, 7, 0xca, 0x6c]);
        assert_eq!(header_len(&[h.clone(), vec![9, 9]].concat()), Some(10));
        assert_eq!(header_len(&[0, 0, 1, 1]), None);
    }

    /// A tiny SOCKS5 server: checks the login, grants an association and
    /// echoes one datagram back with its header.
    #[test]
    fn associate_and_relay() {
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (tcp_addr, relay_addr) = (tcp.local_addr().unwrap(), relay.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut c, _) = tcp.accept().unwrap();
            let mut b = [0u8; 64];
            c.read_exact(&mut b[..4]).unwrap();
            assert_eq!(&b[..4], &[5, 2, 0, 2]);
            c.write_all(&[5, 2]).unwrap();
            c.read_exact(&mut b[..2]).unwrap();
            let ul = b[1] as usize;
            c.read_exact(&mut b[..ul + 1]).unwrap();
            let pl = b[ul] as usize;
            c.read_exact(&mut b[..pl]).unwrap();
            c.write_all(&[1, 0]).unwrap();
            c.read_exact(&mut b[..10]).unwrap();
            assert_eq!(&b[..2], &[5, 3]);
            let mut rep = vec![5, 0, 0, 1, 0, 0, 0, 0];
            rep.extend_from_slice(&relay_addr.port().to_be_bytes());
            c.write_all(&rep).unwrap();
            let mut d = [0u8; 256];
            let (n, from) = relay.recv_from(&mut d).unwrap();
            relay.send_to(&d[..n], from).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let target: SocketAddr = "192.0.2.9:51820".parse().unwrap();
        let s = Socks::connect(tcp_addr, target, "user", "secret").unwrap();
        assert_eq!(s.relay, relay_addr);
        let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
        udp.connect(s.relay).unwrap();
        udp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let t = Transport { udp, socks: Some(s) };
        t.send(b"hello");
        let mut buf = [0u8; 256];
        let (a, b) = t.recv(&mut buf).unwrap().unwrap();
        assert_eq!(&buf[a..b], b"hello");
        server.join().unwrap();
    }

    #[test]
    fn family_mismatch_refused() {
        let e = Socks::connect("127.0.0.1:1".parse().unwrap(), "[::1]:51820".parse().unwrap(), "", "").err().unwrap();
        assert!(e.contains("different address families"));
    }
}
