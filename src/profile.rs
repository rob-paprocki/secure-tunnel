//! Tunnel profiles: a WireGuard `.conf` with optional extension keys.
//!
//! Extension keys that plain WireGuard does not understand are written behind a
//! `#@ws:` comment prefix so the file stays loadable by standard tools.
//! Rules and ranges are listed in MECHANICS.md.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;

/// Prefix that hides an extension key from plain WireGuard parsers.
pub const EXT_PREFIX: &str = "#@ws";

/// Characters a profile name must not contain.
pub const INVALID_NAME_CHARS: &[char] = &['\\', '/', ':', '*', '?', '"', '<', '>', '|', ',', ';'];

/// Private networks excluded when "Bypass LAN traffic" is on.
pub const PRIVATE_NETWORKS: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
    "169.254.0.0/16",
    "224.0.0.0/24",
    "fd00::/8",
    "ff02::/16",
    "fe80::/10",
    "ff00::/8",
];

pub const MASKING_PROTOCOLS: &[&str] = &["quic", "dns", "sip", "stun"];
pub const MASKING_BROWSERS: &[&str] = &["chrome", "firefox", "cURL", "random"];

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Profile {
    // [Interface]
    pub interface_name: String,
    pub address: String,
    pub listen_port: String,
    pub private_key: String,
    pub dns: String,
    pub table: String,
    pub mtu: String,
    pub script_timeout: String,
    pub pre_up: String,
    pub post_up: String,
    pub pre_down: String,
    pub post_down: String,
    pub bypass_lan: String,
    pub virtual_adapter: String,
    pub jc: String,
    pub jmin: String,
    pub jmax: String,
    pub jd: String,
    pub s1: String,
    pub s2: String,
    pub s3: String,
    pub s4: String,
    pub h1: String,
    pub h2: String,
    pub h3: String,
    pub h4: String,
    pub i: [String; 5],
    pub mask_domain: String,
    pub mask_protocol: String,
    pub mask_browser: String,
    // [Peer]
    pub peer_name: String,
    pub endpoint: String,
    pub public_key: String,
    pub preshared_key: String,
    pub keepalive: String,
    pub allowed_ips: String,
    pub disallowed_ips: String,
    pub allowed_apps: String,
    pub disallowed_apps: String,
    pub socks5: String,
    pub socks5_user: String,
    pub socks5_pass: String,
    pub socks5_all: String,
    /// Keys we don't know, kept so saving never loses them.
    pub unknown: Vec<(String, String, String)>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Section {
    None,
    Interface,
    Peer,
    Other,
}

fn strip_ext(s: &str) -> &str {
    let t = s.trim();
    if let Some(rest) = t.strip_prefix(EXT_PREFIX) {
        let rest = rest.trim_start();
        rest.strip_prefix(':').unwrap_or(rest).trim()
    } else {
        t
    }
}

impl Profile {
    pub fn parse(text: &str) -> Result<Profile, String> {
        let mut p = Profile::default();
        let mut section = Section::None;
        let mut seen_interface = false;
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                let name = line[1..line.len() - 1].trim();
                section = match name.to_ascii_lowercase().as_str() {
                    "interface" => {
                        seen_interface = true;
                        Section::Interface
                    }
                    "peer" => Section::Peer,
                    _ => Section::Other,
                };
                if section == Section::Peer && !p.public_key.is_empty() {
                    // Only the first peer is managed; more are kept verbatim.
                    section = Section::Other;
                }
                continue;
            }
            // "#Name = x" comments name the node.
            if let Some(rest) = line.strip_prefix('#') {
                if !line.starts_with(EXT_PREFIX) {
                    if let Some((k, v)) = rest.split_once('=') {
                        if k.trim().eq_ignore_ascii_case("name") {
                            match section {
                                Section::Interface => p.interface_name = v.trim().into(),
                                Section::Peer => p.peer_name = v.trim().into(),
                                _ => {}
                            }
                        }
                    }
                    continue;
                }
            }
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let key = strip_ext(k).to_string();
            let value = v.trim().to_string();
            let sec_name = match section {
                Section::Interface => "Interface",
                Section::Peer => "Peer",
                _ => "Other",
            };
            if !p.set(section, &key, value.clone()) {
                p.unknown.push((sec_name.into(), key, value));
            }
        }
        if !seen_interface {
            return Err("Invalid config file: no [Interface] section".into());
        }
        Ok(p)
    }

    fn set(&mut self, section: Section, key: &str, v: String) -> bool {
        let k = key.to_ascii_lowercase();
        let slot: &mut String = match (section, k.as_str()) {
            (Section::Interface, "address") => &mut self.address,
            (Section::Interface, "listenport") => &mut self.listen_port,
            (Section::Interface, "privatekey") => &mut self.private_key,
            (Section::Interface, "dns") => &mut self.dns,
            (Section::Interface, "table") => &mut self.table,
            (Section::Interface, "mtu") => &mut self.mtu,
            (Section::Interface, "scriptexectimeout") => &mut self.script_timeout,
            (Section::Interface, "preup") => &mut self.pre_up,
            (Section::Interface, "postup") => &mut self.post_up,
            (Section::Interface, "predown") => &mut self.pre_down,
            (Section::Interface, "postdown") => &mut self.post_down,
            (Section::Interface, "bypasslantraffic") => &mut self.bypass_lan,
            (Section::Interface, "virtualadaptermode") => &mut self.virtual_adapter,
            (Section::Interface, "jc") => &mut self.jc,
            (Section::Interface, "jmin") => &mut self.jmin,
            (Section::Interface, "jmax") => &mut self.jmax,
            (Section::Interface, "jd") => &mut self.jd,
            (Section::Interface, "s1") => &mut self.s1,
            (Section::Interface, "s2") => &mut self.s2,
            (Section::Interface, "s3") => &mut self.s3,
            (Section::Interface, "s4") => &mut self.s4,
            (Section::Interface, "h1") => &mut self.h1,
            (Section::Interface, "h2") => &mut self.h2,
            (Section::Interface, "h3") => &mut self.h3,
            (Section::Interface, "h4") => &mut self.h4,
            (Section::Interface, "i1") => &mut self.i[0],
            (Section::Interface, "i2") => &mut self.i[1],
            (Section::Interface, "i3") => &mut self.i[2],
            (Section::Interface, "i4") => &mut self.i[3],
            (Section::Interface, "i5") => &mut self.i[4],
            (Section::Interface, "id") => &mut self.mask_domain,
            (Section::Interface, "ip") => &mut self.mask_protocol,
            (Section::Interface, "ib") => &mut self.mask_browser,
            (Section::Peer, "endpoint") => &mut self.endpoint,
            (Section::Peer, "publickey") => &mut self.public_key,
            (Section::Peer, "presharedkey") => &mut self.preshared_key,
            (Section::Peer, "persistentkeepalive") => &mut self.keepalive,
            (Section::Peer, "allowedips") => &mut self.allowed_ips,
            (Section::Peer, "disallowedips") => &mut self.disallowed_ips,
            (Section::Peer, "allowedapps") => &mut self.allowed_apps,
            (Section::Peer, "disallowedapps") => &mut self.disallowed_apps,
            (Section::Peer, "socks5proxy") => &mut self.socks5,
            (Section::Peer, "socks5proxyusername") => &mut self.socks5_user,
            (Section::Peer, "socks5proxypassword") => &mut self.socks5_pass,
            (Section::Peer, "socks5proxyalltraffic") => &mut self.socks5_all,
            _ => return false,
        };
        *slot = v;
        true
    }

    /// Writes the profile in the same order and with the same comments the
    /// original uses, so files round-trip between both apps.
    pub fn to_conf(&self) -> String {
        let mut o = String::new();
        let kv = |o: &mut String, k: &str, v: &str| {
            if !v.is_empty() {
                let _ = writeln!(o, "{k} = {v}");
            }
        };
        o.push_str("[Interface]\n");
        if !self.interface_name.is_empty() {
            let _ = writeln!(o, "#Name = {}", self.interface_name);
        }
        kv(&mut o, "Address", &self.address);
        kv(&mut o, "ListenPort", &self.listen_port);
        kv(&mut o, "PrivateKey", &self.private_key);
        kv(&mut o, "DNS", &self.dns);
        kv(&mut o, "Table", &self.table);
        kv(&mut o, "MTU", &self.mtu);
        if [&self.pre_up, &self.post_up, &self.pre_down, &self.post_down]
            .iter()
            .any(|s| !s.is_empty())
        {
            o.push_str("\n# Pre/Post Scripts\n\n");
        }
        kv(&mut o, "#@ws:ScriptExecTimeout", &self.script_timeout);
        kv(&mut o, "PreUp", &self.pre_up);
        kv(&mut o, "PostUp", &self.post_up);
        kv(&mut o, "PreDown", &self.pre_down);
        kv(&mut o, "PostDown", &self.post_down);
        if !self.bypass_lan.is_empty() || !self.virtual_adapter.is_empty() {
            o.push_str("\n# [Interface] extensions\n");
        }
        kv(&mut o, "#@ws:BypassLanTraffic", &self.bypass_lan);
        kv(&mut o, "#@ws:VirtualAdapterMode", &self.virtual_adapter);
        if self.has_amnezia_any() {
            o.push_str("\n# Amnezia WG extension\n\n");
        }
        kv(&mut o, "Jc", &self.jc);
        kv(&mut o, "Jmin", &self.jmin);
        kv(&mut o, "Jmax", &self.jmax);
        kv(&mut o, "#@ws:Jd", &self.jd);
        kv(&mut o, "S1", &self.s1);
        kv(&mut o, "S2", &self.s2);
        kv(&mut o, "S3", &self.s3);
        kv(&mut o, "S4", &self.s4);
        kv(&mut o, "H1", &self.h1);
        kv(&mut o, "H2", &self.h2);
        kv(&mut o, "H3", &self.h3);
        kv(&mut o, "H4", &self.h4);
        for (n, v) in self.i.iter().enumerate() {
            kv(&mut o, &format!("I{}", n + 1), v);
        }
        if !self.mask_domain.is_empty() {
            o.push_str("\n# Protocol masking\n\n");
        }
        kv(&mut o, "Id", &self.mask_domain);
        kv(&mut o, "Ip", &self.mask_protocol);
        kv(&mut o, "Ib", &self.mask_browser);
        for (s, k, v) in &self.unknown {
            if s == "Interface" {
                kv(&mut o, k, v);
            }
        }
        o.push_str("\n[Peer]\n");
        if !self.peer_name.is_empty() {
            let _ = writeln!(o, "#Name = {}", self.peer_name);
        }
        kv(&mut o, "Endpoint", &self.endpoint);
        kv(&mut o, "PublicKey", &self.public_key);
        kv(&mut o, "PresharedKey", &self.preshared_key);
        kv(&mut o, "PersistentKeepalive", &self.keepalive);
        kv(&mut o, "AllowedIPs", &self.allowed_ips);
        if !self.disallowed_ips.is_empty()
            || !self.allowed_apps.is_empty()
            || !self.disallowed_apps.is_empty()
        {
            o.push_str("\n# [Peer] extensions\n");
        }
        kv(&mut o, "#@ws:DisallowedIPs", &self.disallowed_ips);
        kv(&mut o, "#@ws:AllowedApps", &self.allowed_apps);
        kv(&mut o, "#@ws:DisallowedApps", &self.disallowed_apps);
        kv(&mut o, "#@ws:Socks5Proxy", &self.socks5);
        kv(&mut o, "#@ws:Socks5ProxyUsername", &self.socks5_user);
        kv(&mut o, "#@ws:Socks5ProxyPassword", &self.socks5_pass);
        kv(&mut o, "#@ws:Socks5ProxyAllTraffic", &self.socks5_all);
        for (s, k, v) in &self.unknown {
            if s == "Peer" {
                kv(&mut o, k, v);
            }
        }
        o
    }

    pub fn has_amnezia_any(&self) -> bool {
        [
            &self.jc, &self.jmin, &self.jmax, &self.jd, &self.s1, &self.s2, &self.h1, &self.h2,
            &self.h3, &self.h4,
        ]
        .iter()
        .any(|s| !s.is_empty())
    }

    /// Keys that need an AmneziaWG-capable engine (awg-quick).
    pub fn needs_amnezia(&self) -> bool {
        [
            &self.s1, &self.s2, &self.s3, &self.s4, &self.h1, &self.h2, &self.h3, &self.h4,
        ]
        .iter()
        .any(|s| !s.is_empty())
            || self.i.iter().any(|s| !s.is_empty())
    }

    pub fn has_junk_packets(&self) -> bool {
        !self.jc.is_empty() || !self.jmin.is_empty() || !self.jmax.is_empty()
    }

    pub fn bypass_lan_on(&self) -> bool {
        self.bypass_lan.eq_ignore_ascii_case("true")
    }

    pub fn has_split_tunnel(&self) -> bool {
        !self.disallowed_ips.is_empty()
            || !self.allowed_apps.is_empty()
            || !self.disallowed_apps.is_empty()
    }

    /// Settings this version keeps but can't enforce with standard WireGuard.
    pub fn unenforced_features(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !crate::apps::enforced() && (!self.allowed_apps.is_empty() || !self.disallowed_apps.is_empty()) {
            v.push("per-app split tunnelling (needs a network driver on this system)");
        }
        v
    }

    /// Checks every field with the ranges the original enforces; returns
    /// (field label, message) for each problem.
    pub fn validate(&self) -> Vec<(&'static str, String)> {
        let mut e = Vec::new();
        let mut int = |label: &'static str, v: &str, min: u64, max: u64| {
            if !v.is_empty() && !in_range(v, min, max, false) {
                e.push((label, format!("{label} should be between {min} and {max}.")));
            }
        };
        int("ListenPort", &self.listen_port, 1, 65535);
        int("MTU", &self.mtu, 576, 65535);
        int("PersistentKeepalive", &self.keepalive, 0, 65535);
        int("ScriptExecTimeout", &self.script_timeout, 0, 65535);
        int("Jc", &self.jc, 0, 128);
        int("Jmin", &self.jmin, 0, 1280);
        int("Jmax", &self.jmax, 0, 1280);
        int("Jd", &self.jd, 0, 200);
        int("S1", &self.s1, 0, u32::MAX as u64);
        int("S2", &self.s2, 0, u32::MAX as u64);
        int("S3", &self.s3, 0, u32::MAX as u64);
        int("S4", &self.s4, 0, u32::MAX as u64);
        for (label, v) in [("H1", &self.h1), ("H2", &self.h2), ("H3", &self.h3), ("H4", &self.h4)] {
            if !v.is_empty() && !header_ok(v) {
                e.push((
                    label,
                    format!("{label} must be a decimal or hex number from 0 to FFFFFFFF, or a range min-max."),
                ));
            }
        }
        if self.private_key.trim().is_empty() {
            e.push(("PrivateKey", "Private key is required.".into()));
        } else if !key_ok(&self.private_key) {
            e.push(("PrivateKey", "Keys are 32-byte values in base64 (44 characters).".into()));
        }
        if self.public_key.trim().is_empty() {
            e.push(("PublicKey", "Peer public key is required.".into()));
        } else if !key_ok(&self.public_key) {
            e.push(("PublicKey", "Keys are 32-byte values in base64 (44 characters).".into()));
        }
        if !self.preshared_key.is_empty() && !key_ok(&self.preshared_key) {
            e.push(("PresharedKey", "Keys are 32-byte values in base64 (44 characters).".into()));
        }
        if self.address.trim().is_empty() {
            e.push(("Address", "Field Address is required and cannot be empty.".into()));
        } else if !list_ok(&self.address) {
            e.push(("Address", "Address must be IPs in CIDR notation, comma separated.".into()));
        }
        if self.allowed_ips.trim().is_empty() {
            e.push(("AllowedIPs", "AllowedIPs must be defined. Default: 0.0.0.0/0, ::/0".into()));
        } else if !list_ok(&self.allowed_ips) {
            e.push(("AllowedIPs", "Enter IPs or subnets in CIDR notation.".into()));
        }
        if !self.disallowed_ips.is_empty() && !list_ok(&self.disallowed_ips) {
            e.push(("DisallowedIPs", "Enter IPs or subnets in CIDR notation.".into()));
        }
        if self.endpoint.trim().is_empty() {
            e.push(("Endpoint", "Endpoint is required (host:port).".into()));
        } else if !endpoint_ok(&self.endpoint) {
            e.push(("Endpoint", "Endpoint must be IP:PORT or name:PORT. IPv6 as [addr]:port.".into()));
        }
        if !self.socks5.is_empty() && !endpoint_ok(&self.socks5) {
            e.push(("Socks5Proxy", "Socks5Proxy must be IP:PORT or name:PORT.".into()));
        }
        if !self.mask_domain.is_empty() && !domain_ok(&self.mask_domain) {
            e.push(("Id", "The Id field must contain a valid domain name.".into()));
        }
        if !self.mask_protocol.is_empty()
            && !MASKING_PROTOCOLS.iter().any(|p| p.eq_ignore_ascii_case(&self.mask_protocol))
        {
            e.push(("Ip", "Masking protocol must be quic, dns, sip or stun.".into()));
        }
        if !self.mask_browser.is_empty()
            && !MASKING_BROWSERS.iter().any(|p| p.eq_ignore_ascii_case(&self.mask_browser))
        {
            e.push(("Ib", "Browser must be chrome, firefox, cURL or random.".into()));
        }
        // AmneziaWG needs S1-S2 and H1-H4 together.
        let amn = [&self.s1, &self.s2, &self.h1, &self.h2, &self.h3, &self.h4];
        let set = amn.iter().filter(|s| !s.is_empty()).count();
        if set > 0 && set < amn.len() {
            e.push(("S1", "All S1-S2 and H1-H4 parameters are required to configure AmneziaWG.".into()));
        }
        for (label, v) in [("Table", &self.table), ("BypassLanTraffic", &self.bypass_lan), ("Socks5ProxyAllTraffic", &self.socks5_all)] {
            if !v.is_empty() && label != "Table" && !matches!(v.to_ascii_lowercase().as_str(), "true" | "false") {
                e.push((label, format!("{label} must be true or false.")));
            }
        }
        e
    }

    pub fn blank() -> Profile {
        Profile {
            private_key: generate_private_key(),
            address: String::new(),
            dns: String::new(),
            allowed_ips: "0.0.0.0/0, ::/0".into(),
            ..Default::default()
        }
    }
}

pub fn split_list(s: &str) -> Vec<String> {
    s.split(',').map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect()
}

fn in_range(v: &str, min: u64, max: u64, hex: bool) -> bool {
    let v = v.trim();
    let n = v.parse::<u64>().ok().or_else(|| {
        if hex {
            let h = v.trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(h, 16).ok()
        } else {
            None
        }
    });
    matches!(n, Some(n) if n >= min && n <= max)
}

fn header_ok(v: &str) -> bool {
    let v = v.trim();
    if let Some((a, b)) = v.split_once('-') {
        in_range(a, 0, u32::MAX as u64, true) && in_range(b, 0, u32::MAX as u64, true)
    } else {
        in_range(v, 0, u32::MAX as u64, true)
    }
}

pub fn key_ok(k: &str) -> bool {
    matches!(B64.decode(k.trim()), Ok(b) if b.len() == 32)
}

fn list_ok(s: &str) -> bool {
    let l = split_list(s);
    !l.is_empty() && l.iter().all(|x| parse_cidr(x).is_some())
}

fn domain_ok(d: &str) -> bool {
    let d = d.trim().trim_end_matches('.');
    !d.is_empty()
        && d.len() <= 253
        && d.contains('.')
        && d.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

pub fn endpoint_ok(e: &str) -> bool {
    let e = e.trim();
    let (host, port) = if let Some(rest) = e.strip_prefix('[') {
        match rest.split_once("]:") {
            Some((h, p)) => (h, p),
            None => return false,
        }
    } else {
        match e.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') => (h, p),
            _ => return false,
        }
    };
    let port_ok = matches!(port.parse::<u32>(), Ok(p) if (1..=65535).contains(&p));
    let host_ok = host.parse::<std::net::IpAddr>().is_ok() || domain_ok(host) || host == "localhost";
    port_ok && host_ok
}

pub fn name_problem(name: &str) -> Option<String> {
    if name.trim().is_empty() {
        return Some("Profile name cannot be empty.".into());
    }
    if name.chars().any(|c| INVALID_NAME_CHARS.contains(&c)) {
        return Some("Profile name cannot contain the following characters: \\ / : * ? \" < > | , ;".into());
    }
    None
}

/// "Home" -> "Home(1)", "Home(1)" -> "Home(2)", skipping numbers in use.
pub fn duplicate_name(current: &str, existing: &[String]) -> String {
    fn numbered(s: &str) -> Option<(&str, u32)> {
        if s.len() > 3 && s.ends_with(')') {
            let open = s.rfind('(')?;
            if open + 3 <= s.len() {
                let n = s[open + 1..s.len() - 1].parse::<u32>().ok()?;
                return Some((&s[..open], n));
            }
        }
        None
    }
    let base = numbered(current).map(|(b, _)| b).unwrap_or(current);
    let mut next = 1;
    for p in existing.iter().filter(|p| p.starts_with(base)) {
        if let Some((_, n)) = numbered(p) {
            if n >= next {
                next = n + 1;
            }
        }
    }
    format!("{base}({next})")
}

// ---------- keys ----------

pub fn generate_private_key() -> String {
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    B64.encode(secret.to_bytes())
}

pub fn public_from_private(private_b64: &str) -> Option<String> {
    let bytes = B64.decode(private_b64.trim()).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    let secret = x25519_dalek::StaticSecret::from(arr);
    let public = x25519_dalek::PublicKey::from(&secret);
    Some(B64.encode(public.as_bytes()))
}

// ---------- network maths ----------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Net {
    v6: bool,
    start: u128,
    end: u128,
}

fn parse_cidr(s: &str) -> Option<Net> {
    let (ip, len) = match s.split_once('/') {
        Some((a, b)) => (a.trim(), Some(b.trim().parse::<u32>().ok()?)),
        None => (s.trim(), None),
    };
    let addr: std::net::IpAddr = ip.parse().ok()?;
    let (v6, bits, val) = match addr {
        std::net::IpAddr::V4(a) => (false, 32u32, u32::from(a) as u128),
        std::net::IpAddr::V6(a) => (true, 128u32, u128::from(a)),
    };
    let len = len.unwrap_or(bits);
    if len > bits {
        return None;
    }
    let host_bits = bits - len;
    let mask: u128 = if host_bits == 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
    let start = val & !mask;
    Some(Net { v6, start, end: start | mask })
}

fn range_to_cidrs(v6: bool, mut start: u128, end: u128, out: &mut Vec<String>) {
    let bits = if v6 { 128 } else { 32 };
    loop {
        // Largest aligned block starting at `start` that fits before `end`.
        let mut size_bits = if start == 0 { bits } else { start.trailing_zeros().min(bits) };
        loop {
            let last = if size_bits == 128 { u128::MAX } else { start + ((1u128 << size_bits) - 1) };
            if last <= end && (size_bits == 128 || last >= start) {
                break;
            }
            size_bits -= 1;
        }
        let prefix = bits - size_bits;
        let text = if v6 {
            format!("{}/{}", std::net::Ipv6Addr::from(start), prefix)
        } else {
            format!("{}/{}", std::net::Ipv4Addr::from(start as u32), prefix)
        };
        out.push(text);
        let last = if size_bits == 128 { u128::MAX } else { start + ((1u128 << size_bits) - 1) };
        if last >= end {
            break;
        }
        start = last + 1;
    }
}

/// Allowed networks minus excluded ones, as a minimal CIDR list.
pub fn subtract_networks(allowed: &[String], excluded: &[String]) -> Vec<String> {
    let ex: Vec<Net> = excluded.iter().filter_map(|s| parse_cidr(s)).collect();
    let mut out = Vec::new();
    for a in allowed.iter().filter_map(|s| parse_cidr(s)) {
        let mut pieces = vec![(a.start, a.end)];
        for e in ex.iter().filter(|e| e.v6 == a.v6) {
            let mut next = Vec::new();
            for (s, t) in pieces {
                if e.end < s || e.start > t {
                    next.push((s, t));
                    continue;
                }
                if e.start > s {
                    next.push((s, e.start - 1));
                }
                if e.end < t {
                    next.push((e.end + 1, t));
                }
            }
            pieces = next;
        }
        for (s, t) in pieces {
            range_to_cidrs(a.v6, s, t, &mut out);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let text = "[Interface]\nPrivateKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI=\nAddress = 192.168.100.2/32\n#@ws:BypassLanTraffic = true\n[Peer]\nPublicKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n#@ws:AllowedApps = firefox\n";
        let p = Profile::parse(text).unwrap();
        assert_eq!(p.bypass_lan, "true");
        assert_eq!(p.allowed_apps, "firefox");
        let again = Profile::parse(&p.to_conf()).unwrap();
        assert_eq!(p, again);
    }

    #[test]
    fn duplicate() {
        let ex = vec!["Home".to_string(), "Home(1)".to_string(), "Home(4)".to_string()];
        assert_eq!(duplicate_name("Home", &ex), "Home(5)");
        assert_eq!(duplicate_name("Work", &[]), "Work(1)");
    }

    #[test]
    fn subtract() {
        let r = subtract_networks(&["0.0.0.0/0".into()], &["128.0.0.0/1".into()]);
        assert_eq!(r, vec!["0.0.0.0/1"]);
        let r = subtract_networks(&["10.0.0.0/8".into()], &["10.0.0.0/9".into()]);
        assert_eq!(r, vec!["10.128.0.0/9"]);
    }

    #[test]
    fn keys() {
        let k = generate_private_key();
        assert!(key_ok(&k));
        assert!(public_from_private(&k).is_some());
    }
}
