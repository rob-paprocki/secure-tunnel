//! "Terminate TCP connections on connect" (original setting TCPSocketTermination,
//! off by default): once the tunnel is up, established TCP connections to
//! addresses the tunnel now carries are closed, so apps reconnect through it
//! instead of keeping old direct connections. Windows: SetTcpEntry with
//! MIB_TCP_STATE_DELETE_TCB (IPv4). Linux: `ss -K`. macOS has no supported way.

use std::net::IpAddr;
#[cfg(windows)]
use std::net::Ipv4Addr;

/// Does `ip` fall inside the CIDR `net`?
#[cfg_attr(not(windows), allow(dead_code))]
pub fn in_cidr(ip: IpAddr, net: &str) -> bool {
    let (base, len) = match net.split_once('/') {
        Some((b, l)) => (b, l.parse::<u32>().unwrap_or(128)),
        None => (net, 128),
    };
    match (ip, base.parse::<IpAddr>()) {
        (IpAddr::V4(a), Ok(IpAddr::V4(b))) => {
            let len = len.min(32);
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), Ok(IpAddr::V6(b))) => {
            let len = len.min(128);
            let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Closes established TCP connections whose remote address is in `routes`.
/// Returns how many were closed, or why it couldn't.
#[cfg(windows)]
pub fn kill(routes: &[String]) -> Result<usize, String> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{GetTcpTable, MIB_TCPROW_LH, MIB_TCPTABLE, SetTcpEntry};
    const ESTABLISHED: u32 = 5;
    const DELETE_TCB: u32 = 12;
    unsafe {
        let mut size = 0u32;
        GetTcpTable(std::ptr::null_mut(), &mut size, 0);
        if size == 0 {
            return Ok(0);
        }
        let mut buf = vec![0u8; size as usize + 1024];
        let table = buf.as_mut_ptr() as *mut MIB_TCPTABLE;
        if GetTcpTable(table, &mut size, 0) != 0 {
            return Err("GetTcpTable failed".into());
        }
        let n = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts((*table).table.as_ptr(), n);
        let mut closed = 0;
        for row in rows {
            if row.Anonymous.dwState != ESTABLISHED {
                continue;
            }
            let remote = IpAddr::V4(Ipv4Addr::from(u32::from_be(row.dwRemoteAddr)));
            if remote.is_loopback() || !routes.iter().any(|r| in_cidr(remote, r)) {
                continue;
            }
            let mut r: MIB_TCPROW_LH = *row;
            r.Anonymous.dwState = DELETE_TCB;
            if SetTcpEntry(&r) == 0 {
                closed += 1;
            }
        }
        Ok(closed)
    }
}

#[cfg(target_os = "linux")]
pub fn kill(routes: &[String]) -> Result<usize, String> {
    let mut ok = 0;
    for r in routes {
        let o = std::process::Command::new("ss").args(["-K", "-n", "state", "established", "dst", r]).output().map_err(|e| e.to_string())?;
        if o.status.success() {
            // Each closed socket is listed after the header line.
            ok += String::from_utf8_lossy(&o.stdout).lines().skip(1).filter(|l| !l.trim().is_empty()).count();
        }
    }
    Ok(ok)
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn kill(_routes: &[String]) -> Result<usize, String> {
    Err("closing other apps' TCP connections isn't supported on this system".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr() {
        assert!(in_cidr("192.168.100.20".parse().unwrap(), "192.168.0.0/16"));
        assert!(!in_cidr("203.0.113.5".parse().unwrap(), "192.168.0.0/16"));
        assert!(in_cidr("203.0.113.1".parse().unwrap(), "128.0.0.0/1"));
        assert!(in_cidr("2001:db8::5".parse().unwrap(), "2001:db8::/32"));
        assert!(!in_cidr("192.168.100.1".parse().unwrap(), "::/1"));
    }
}
