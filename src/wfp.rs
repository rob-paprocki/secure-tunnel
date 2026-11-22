//! Windows kill switch on the Windows Filtering Platform (WFP).
//!
//! Changing Windows Firewall's default outbound action to "block" isn't enough:
//! any enabled rule that allows outbound traffic (Windows ships dozens) still
//! lets matching traffic out. WFP evaluates every sublayer, and a block from
//! one sublayer wins over ordinary permits from the others, so this module adds
//! its own provider and maximum-weight sublayer holding:
//!
//! - permits (weight 15) for the tunnel's local addresses, the VPN server,
//!   loopback, DHCP/DHCPv6 and, with "Bypass LAN", private address ranges;
//! - a block (weight 0) for everything else,
//!
//! at the outbound connection layers for IPv4 and IPv6. All objects are
//! persistent: a crashed helper (or a reboot) can't open a gap. `remove`
//! deletes them; it is safe to call when nothing is installed.
//!
//! [`plan`] is plain Rust and unit-tested on every platform; `apply` and
//! `remove` (Windows only) turn the plan into WFP objects.
#![cfg_attr(not(windows), allow(dead_code))]

use std::net::IpAddr;

use crate::netlock::{LockSpec, LAN_V4, LAN_V6};

/// Splits a CIDR range such as "fd00::/8" into its address and prefix length.
pub fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (a, p) = s.split_once('/')?;
    Some((a.parse().ok()?, p.parse().ok()?))
}

const UDP: u8 = 17;
const PERMIT_WEIGHT: u8 = 15;
const BLOCK_WEIGHT: u8 = 0;
/// Upper bound on filters one plan can hold; `remove` deletes this many keys.
pub const MAX_FILTERS: u16 = 64;

#[derive(Clone, Debug, PartialEq)]
pub enum Cond {
    LocalAddr(IpAddr),
    RemoteAddr(IpAddr),
    RemoteNet(IpAddr, u8),
    Protocol(u8),
    LocalPort(u16),
    RemotePort(u16),
    Loopback,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Filter {
    pub name: String,
    pub v6: bool,
    pub permit: bool,
    /// Conditions on different fields must all match; several conditions on the
    /// same field (the LAN ranges) match if any one does.
    pub conds: Vec<Cond>,
}

impl Filter {
    fn permit(name: &str, v6: bool, conds: Vec<Cond>) -> Filter {
        Filter { name: name.into(), v6, permit: true, conds }
    }
    pub fn weight(&self) -> u8 {
        if self.permit { PERMIT_WEIGHT } else { BLOCK_WEIGHT }
    }
}

/// The filters for a kill switch, permits first, then the two blocks.
pub fn plan(spec: &LockSpec) -> Vec<Filter> {
    let mut f = Vec::new();
    for ip in &spec.tun_ips {
        f.push(Filter::permit("tunnel", ip.is_ipv6(), vec![Cond::LocalAddr(*ip)]));
    }
    for (ip, port) in &spec.allow {
        let mut conds = vec![Cond::RemoteAddr(*ip)];
        if let Some(p) = port {
            conds.extend([Cond::Protocol(UDP), Cond::RemotePort(*p)]);
        }
        f.push(Filter::permit("server", ip.is_ipv6(), conds));
    }
    for v6 in [false, true] {
        f.push(Filter::permit("loopback", v6, vec![Cond::Loopback]));
    }
    f.push(Filter::permit("dhcp", false, vec![Cond::Protocol(UDP), Cond::LocalPort(68), Cond::RemotePort(67)]));
    f.push(Filter::permit("dhcpv6", true, vec![Cond::Protocol(UDP), Cond::LocalPort(546), Cond::RemotePort(547)]));
    if spec.lan {
        let nets = |list: &[&str]| {
            list.iter().filter_map(|s| parse_cidr(s)).map(|(a, p)| Cond::RemoteNet(a, p)).collect()
        };
        f.push(Filter::permit("lan", false, nets(LAN_V4)));
        f.push(Filter::permit("lan", true, nets(LAN_V6)));
    }
    for v6 in [false, true] {
        f.push(Filter { name: "block".into(), v6, permit: false, conds: vec![] });
    }
    f.truncate(MAX_FILTERS as usize);
    f
}

/// IPv4 netmask in host byte order for a prefix length.
pub fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - prefix.min(32) as u32) }
}

#[cfg(windows)]
mod sys {
    use super::*;
    use std::ptr::{null, null_mut};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    const PROVIDER: GUID = GUID::from_u128(0x795df61f_d3ff_46ee_9b4d_77ddc3c23455);
    const SUBLAYER: GUID = GUID::from_u128(0x0952bc0b_b44a_4279_b0f3_5cc4d8611677);
    const FILTER_BASE: u128 = 0x1e307e46_0764_4476_9386_d923568d0000;
    const RPC_C_AUTHN_WINNT: u32 = 10;
    const FWP_E_FILTER_NOT_FOUND: u32 = 0x8032_0003;
    const FWP_E_PROVIDER_NOT_FOUND: u32 = 0x8032_0005;
    const FWP_E_SUBLAYER_NOT_FOUND: u32 = 0x8032_0007;
    const FWP_E_ALREADY_EXISTS: u32 = 0x8032_0009;

    fn filter_key(i: u16) -> GUID {
        GUID::from_u128(FILTER_BASE | i as u128)
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn check(what: &str, rc: u32) -> Result<(), String> {
        if rc == 0 { Ok(()) } else { Err(format!("{what} failed (0x{rc:08X})")) }
    }

    /// An open WFP engine with a transaction; aborted unless committed.
    struct Session {
        engine: HANDLE,
        committed: bool,
    }

    impl Session {
        fn open() -> Result<Session, String> {
            let mut engine: HANDLE = null_mut();
            // A non-dynamic session, so the objects outlive this process.
            let rc = unsafe { FwpmEngineOpen0(null(), RPC_C_AUTHN_WINNT, null(), null(), &mut engine) };
            check("Opening the Windows Filtering Platform", rc)?;
            let s = Session { engine, committed: false };
            check("Starting a WFP transaction", unsafe { FwpmTransactionBegin0(engine, 0) })?;
            Ok(s)
        }
        fn commit(mut self) -> Result<(), String> {
            self.committed = true;
            check("Saving the WFP changes", unsafe { FwpmTransactionCommit0(self.engine) })
        }
        fn delete_filters(&self) -> Result<(), String> {
            for i in 0..MAX_FILTERS {
                let key = filter_key(i);
                let rc = unsafe { FwpmFilterDeleteByKey0(self.engine, &key) };
                if rc != 0 && rc != FWP_E_FILTER_NOT_FOUND {
                    return Err(format!("Removing a kill switch filter failed (0x{rc:08X})"));
                }
            }
            Ok(())
        }
    }

    impl Drop for Session {
        fn drop(&mut self) {
            unsafe {
                if !self.committed {
                    FwpmTransactionAbort0(self.engine);
                }
                FwpmEngineClose0(self.engine);
            }
        }
    }

    fn display(name: &mut Vec<u16>) -> FWPM_DISPLAY_DATA0 {
        FWPM_DISPLAY_DATA0 { name: name.as_mut_ptr(), description: null_mut() }
    }

    fn no_blob() -> FWP_BYTE_BLOB {
        FWP_BYTE_BLOB { size: 0, data: null_mut() }
    }

    /// Storage that condition values point into; kept alive until the filter is added.
    #[derive(Default)]
    struct Values {
        v4nets: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
        v6nets: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
        v6addrs: Vec<Box<FWP_BYTE_ARRAY16>>,
    }

    fn condition(c: &Cond, vals: &mut Values) -> FWPM_FILTER_CONDITION0 {
        let mut value = FWP_CONDITION_VALUE0 { r#type: FWP_EMPTY, Anonymous: FWP_CONDITION_VALUE0_0 { uint32: 0 } };
        let mut match_type = FWP_MATCH_EQUAL;
        let field = match c {
            Cond::LocalAddr(ip) | Cond::RemoteAddr(ip) => {
                match ip {
                    IpAddr::V4(a) => {
                        value.r#type = FWP_UINT32;
                        value.Anonymous.uint32 = u32::from(*a);
                    }
                    IpAddr::V6(a) => {
                        let mut b = Box::new(FWP_BYTE_ARRAY16 { byteArray16: a.octets() });
                        value.r#type = FWP_BYTE_ARRAY16_TYPE;
                        value.Anonymous.byteArray16 = &mut *b;
                        vals.v6addrs.push(b);
                    }
                }
                if matches!(c, Cond::LocalAddr(_)) { FWPM_CONDITION_IP_LOCAL_ADDRESS } else { FWPM_CONDITION_IP_REMOTE_ADDRESS }
            }
            Cond::RemoteNet(ip, prefix) => {
                match ip {
                    IpAddr::V4(a) => {
                        let mut m = Box::new(FWP_V4_ADDR_AND_MASK { addr: u32::from(*a), mask: v4_mask(*prefix) });
                        value.r#type = FWP_V4_ADDR_MASK;
                        value.Anonymous.v4AddrMask = &mut *m;
                        vals.v4nets.push(m);
                    }
                    IpAddr::V6(a) => {
                        let mut m = Box::new(FWP_V6_ADDR_AND_MASK { addr: a.octets(), prefixLength: *prefix });
                        value.r#type = FWP_V6_ADDR_MASK;
                        value.Anonymous.v6AddrMask = &mut *m;
                        vals.v6nets.push(m);
                    }
                }
                FWPM_CONDITION_IP_REMOTE_ADDRESS
            }
            Cond::Protocol(p) => {
                value.r#type = FWP_UINT8;
                value.Anonymous.uint8 = *p;
                FWPM_CONDITION_IP_PROTOCOL
            }
            Cond::LocalPort(p) | Cond::RemotePort(p) => {
                value.r#type = FWP_UINT16;
                value.Anonymous.uint16 = *p;
                if matches!(c, Cond::LocalPort(_)) { FWPM_CONDITION_IP_LOCAL_PORT } else { FWPM_CONDITION_IP_REMOTE_PORT }
            }
            Cond::Loopback => {
                value.r#type = FWP_UINT32;
                value.Anonymous.uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK;
                match_type = FWP_MATCH_FLAGS_ALL_SET;
                FWPM_CONDITION_FLAGS
            }
        };
        FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: match_type, conditionValue: value }
    }

    pub fn apply(spec: &LockSpec) -> Result<(), String> {
        let s = Session::open()?;
        let mut provider_key = PROVIDER;
        let mut pname = wide(crate::netlock::NAME);

        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER,
            displayData: display(&mut pname),
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            providerData: no_blob(),
            serviceName: null_mut(),
        };
        let rc = unsafe { FwpmProviderAdd0(s.engine, &provider, null_mut()) };
        if rc != FWP_E_ALREADY_EXISTS {
            check("Adding the kill switch provider", rc)?;
        }
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER,
            displayData: display(&mut pname),
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &mut provider_key,
            providerData: no_blob(),
            weight: u16::MAX,
        };
        let rc = unsafe { FwpmSubLayerAdd0(s.engine, &sublayer, null_mut()) };
        if rc != FWP_E_ALREADY_EXISTS {
            check("Adding the kill switch sublayer", rc)?;
        }
        // Replace whatever an earlier lock left.
        s.delete_filters()?;

        for (i, f) in plan(spec).iter().enumerate() {
            let mut vals = Values::default();
            let mut conds: Vec<FWPM_FILTER_CONDITION0> = f.conds.iter().map(|c| condition(c, &mut vals)).collect();
            let mut name = wide(&format!("{} {}{}", crate::netlock::NAME, f.name, if f.v6 { " (IPv6)" } else { "" }));
            let filter = FWPM_FILTER0 {
                filterKey: filter_key(i as u16),
                displayData: display(&mut name),
                flags: FWPM_FILTER_FLAG_PERSISTENT,
                providerKey: &mut provider_key,
                providerData: no_blob(),
                layerKey: if f.v6 { FWPM_LAYER_ALE_AUTH_CONNECT_V6 } else { FWPM_LAYER_ALE_AUTH_CONNECT_V4 },
                subLayerKey: SUBLAYER,
                weight: FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: f.weight() } },
                numFilterConditions: conds.len() as u32,
                filterCondition: if conds.is_empty() { null_mut() } else { conds.as_mut_ptr() },
                action: FWPM_ACTION0 {
                    r#type: if f.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK },
                    Anonymous: FWPM_ACTION0_0 { filterType: GUID::from_u128(0) },
                },
                Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
                reserved: null_mut(),
                filterId: 0,
                effectiveWeight: FWP_VALUE0 { r#type: FWP_EMPTY, Anonymous: FWP_VALUE0_0 { uint32: 0 } },
            };
            let mut id = 0u64;
            let rc = unsafe { FwpmFilterAdd0(s.engine, &filter, null_mut(), &mut id) };
            check(&format!("Adding the kill switch filter '{}'", f.name), rc)?;
            drop(vals);
        }
        s.commit()
    }

    pub fn remove() -> Result<(), String> {
        let s = Session::open()?;
        s.delete_filters()?;
        let rc = unsafe { FwpmSubLayerDeleteByKey0(s.engine, &SUBLAYER) };
        if rc != FWP_E_SUBLAYER_NOT_FOUND {
            check("Removing the kill switch sublayer", rc)?;
        }
        let rc = unsafe { FwpmProviderDeleteByKey0(s.engine, &PROVIDER) };
        if rc != FWP_E_PROVIDER_NOT_FOUND {
            check("Removing the kill switch provider", rc)?;
        }
        s.commit()
    }
}

#[cfg(windows)]
pub use sys::{apply, remove};

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(lan: bool) -> LockSpec {
        LockSpec {
            tun_name: "wg0".into(),
            tun_ips: vec!["192.168.100.2".parse().unwrap(), "fd00::2".parse().unwrap()],
            allow: vec![("192.0.2.1".parse().unwrap(), Some(51820)), ("2001:db8::1".parse().unwrap(), None)],
            lan,
        }
    }

    #[test]
    fn plan_permits_then_blocks() {
        let p = plan(&spec(false));
        let names: Vec<_> = p.iter().map(|f| (f.name.as_str(), f.v6, f.permit)).collect();
        assert_eq!(names, vec![
            ("tunnel", false, true), ("tunnel", true, true),
            ("server", false, true), ("server", true, true),
            ("loopback", false, true), ("loopback", true, true),
            ("dhcp", false, true), ("dhcpv6", true, true),
            ("block", false, false), ("block", true, false),
        ]);
        assert!(p.iter().filter(|f| !f.permit).all(|f| f.conds.is_empty() && f.weight() == 0));
        assert!(p.iter().filter(|f| f.permit).all(|f| f.weight() == 15));
    }

    #[test]
    fn server_permit_is_udp_to_its_port() {
        let p = plan(&spec(false));
        assert_eq!(p[2].conds, vec![Cond::RemoteAddr("192.0.2.1".parse().unwrap()), Cond::Protocol(17), Cond::RemotePort(51820)]);
        assert_eq!(p[3].conds, vec![Cond::RemoteAddr("2001:db8::1".parse().unwrap())]);
    }

    #[test]
    fn lan_ranges_only_with_bypass() {
        assert!(!plan(&spec(false)).iter().any(|f| f.name == "lan"));
        let p = plan(&spec(true));
        let lan4 = p.iter().find(|f| f.name == "lan" && !f.v6).unwrap();
        assert_eq!(lan4.conds.len(), LAN_V4.len());
        let (addr, prefix) = parse_cidr(LAN_V4[1]).unwrap();
        assert!(lan4.conds.contains(&Cond::RemoteNet(addr, prefix)));
        assert_eq!(parse_cidr("fd00::/8"), Some(("fd00::".parse().unwrap(), 8)));
        // The blocks stay last, after the LAN permits.
        assert!(!p[p.len() - 1].permit && !p[p.len() - 2].permit);
    }

    #[test]
    fn masks() {
        assert_eq!(v4_mask(8), 0xFF00_0000);
        assert_eq!(v4_mask(12), 0xFFF0_0000);
        assert_eq!(v4_mask(0), 0);
        assert_eq!(v4_mask(32), u32::MAX);
    }
}
