//! DPI protection: junk packets and protocol imitation sent before every
//! WireGuard handshake by the built-in engine. Rules and addresses are in
//! MECHANICS.md.

use std::net::SocketAddr;

use rand_core::{OsRng, RngCore};

use crate::profile::Profile;

/// Engine defaults when Jmin/Jmax are missing or invalid (wgbooster 0x180005820, 0x1800f7570).
pub const JMIN_DEFAULT: u16 = 50;
pub const JMAX_DEFAULT: u16 = 1000;
pub const JC_MAX: u16 = 128;
pub const JD_MAX: u16 = 200;
pub const JSIZE_MAX: u16 = 1280;
/// Smallest QUIC Initial datagram a client may send (RFC 9000 §14.1).
pub const QUIC_MIN_DATAGRAM: usize = 1200;
/// WireGuard handshake initiation: type 1, 148 bytes.
pub const HANDSHAKE_INIT_LEN: usize = 148;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proto {
    Quic,
    Dns,
    Sip,
    Stun,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Browser {
    Chrome,
    Firefox,
    Curl,
    Random,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Imitation {
    pub proto: Proto,
    pub domain: String,
    pub browser: Browser,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Plan {
    pub jc: u16,
    pub jmin: u16,
    pub jmax: u16,
    pub jd_ms: u16,
    pub imitation: Option<Imitation>,
    /// AmneziaWG I1-I5 packet templates (tag format), sent in order.
    pub special: Vec<String>,
}

impl Plan {
    /// Applies the engine's rules: out-of-range values fall back to defaults
    /// instead of failing.
    pub fn from_profile(p: &Profile) -> Plan {
        let num = |s: &str| s.trim().parse::<u16>().ok();
        let mut jc = num(&p.jc).unwrap_or(0);
        if jc > JC_MAX {
            jc = 0;
        }
        let (mut jmin, mut jmax) = (num(&p.jmin).unwrap_or(0), num(&p.jmax).unwrap_or(0));
        if jmin > jmax || jmax > JSIZE_MAX || (p.jmin.trim().is_empty() != p.jmax.trim().is_empty()) {
            (jmin, jmax) = (JMIN_DEFAULT, JMAX_DEFAULT);
        }
        if jc > 0 && jmin == 0 && jmax == 0 {
            (jmin, jmax) = (JMIN_DEFAULT, JMAX_DEFAULT);
        }
        let mut jd_ms = num(&p.jd).unwrap_or(0);
        if jd_ms > JD_MAX {
            jd_ms = 0;
        }
        let imitation = if domain_ok(&p.mask_domain) {
            let proto = match p.mask_protocol.trim().to_ascii_lowercase().as_str() {
                "dns" => Proto::Dns,
                "sip" => Proto::Sip,
                "stun" => Proto::Stun,
                _ => Proto::Quic,
            };
            let browser = match p.mask_browser.trim().to_ascii_lowercase().as_str() {
                "chrome" => Browser::Chrome,
                "firefox" => Browser::Firefox,
                "random" => Browser::Random,
                _ => Browser::Curl,
            };
            Some(Imitation { proto, domain: p.mask_domain.trim().to_string(), browser })
        } else {
            None
        };
        let special = p.i.iter().map(|x| x.trim().to_string()).filter(|x| !x.is_empty()).collect();
        Plan { jc, jmin, jmax, jd_ms, imitation, special }
    }

    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.jc > 0 {
            parts.push(format!("{} junk packets of {}-{} bytes, {} ms apart", self.jc, self.jmin, self.jmax, self.jd_ms));
        }
        if let Some(i) = &self.imitation {
            parts.push(format!("{:?} imitation as {}", i.proto, i.domain).to_lowercase());
        }
        if !self.special.is_empty() {
            parts.push(format!("{} special packet(s) (I1-I5)", self.special.len()));
        }
        parts.join("; ")
    }
}

/// 1-253 characters of [A-Za-z0-9.-], no leading or trailing '.' or '-'.
pub fn domain_ok(d: &str) -> bool {
    let d = d.trim();
    (1..=253).contains(&d.len())
        && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !d.starts_with(['.', '-'])
        && !d.ends_with(['.', '-'])
}

pub fn is_handshake_init(pkt: &[u8]) -> bool {
    pkt.len() == HANDSHAKE_INIT_LEN && pkt[0] == 1 && pkt[1..4] == [0, 0, 0]
}

fn rand_range(lo: u32, hi: u32) -> u32 {
    if hi <= lo { lo } else { lo + OsRng.next_u32() % (hi - lo + 1) }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

fn rand_token(n: usize) -> String {
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    (0..n).map(|_| A[(OsRng.next_u32() as usize) % A.len()] as char).collect()
}

pub fn junk_packet(plan: &Plan) -> Vec<u8> {
    rand_bytes(rand_range(plan.jmin as u32, plan.jmax as u32) as usize)
}

/// The packets sent before one handshake, in order.
pub fn pre_handshake(plan: &Plan, inject_junk: bool, local: SocketAddr) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    if let Some(i) = &plan.imitation {
        out.push(imitation_packet(i, local));
    }
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for t in &plan.special {
        if let Ok(p) = cps_packet(t, n) {
            out.push(p);
        }
    }
    if inject_junk {
        for _ in 0..plan.jc {
            out.push(junk_packet(plan));
        }
    }
    out
}

static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Builds one AmneziaWG I1-I5 packet from its tags: `<b 0xHEX>` fixed bytes,
/// `<r N>` random bytes, `<rc N>` random letters, `<rd N>` random digits,
/// `<t>` Unix time (4 bytes, big-endian) and `<c>` packet counter (4 bytes).
pub fn cps_packet(spec: &str, counter: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut rest = spec.trim();
    while !rest.is_empty() {
        let start = rest.find('<').ok_or_else(|| format!("expected '<' in {spec}"))?;
        if !rest[..start].trim().is_empty() {
            return Err(format!("text outside a tag in {spec}"));
        }
        let end = rest[start..].find('>').ok_or_else(|| format!("missing '>' in {spec}"))? + start;
        let inner = rest[start + 1..end].trim();
        rest = &rest[end + 1..];
        let mut parts = inner.split_whitespace();
        let tag = parts.next().unwrap_or("");
        let arg = parts.next().unwrap_or("");
        let count = || arg.parse::<usize>().map(|n| n.min(65_535)).map_err(|_| format!("<{tag}> needs a length"));
        match tag {
            "b" => {
                let h = arg.trim_start_matches("0x").trim_start_matches("0X");
                if h.len() % 2 != 0 {
                    return Err("odd number of hex digits in <b>".into());
                }
                for i in (0..h.len()).step_by(2) {
                    out.push(u8::from_str_radix(&h[i..i + 2], 16).map_err(|_| "bad hex in <b>".to_string())?);
                }
            }
            "r" => out.extend(rand_bytes(count()?)),
            "rc" => {
                const L: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                out.extend((0..count()?).map(|_| L[(OsRng.next_u32() as usize) % L.len()]));
            }
            "rd" => out.extend((0..count()?).map(|_| b'0' + (OsRng.next_u32() % 10) as u8)),
            "t" => {
                let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as u32).unwrap_or(0);
                out.extend_from_slice(&t.to_be_bytes());
            }
            "c" => out.extend_from_slice(&counter.to_be_bytes()),
            _ => return Err(format!("unknown tag <{tag}>")),
        }
    }
    Ok(out)
}

pub fn imitation_packet(i: &Imitation, local: SocketAddr) -> Vec<u8> {
    match i.proto {
        Proto::Quic => {
            let b = match i.browser {
                Browser::Random => [Browser::Chrome, Browser::Firefox, Browser::Curl][(OsRng.next_u32() % 3) as usize],
                b => b,
            };
            quic_initial(&i.domain, b)
        }
        Proto::Dns => dns_query(&i.domain),
        Proto::Sip => sip_invite(&i.domain, local),
        Proto::Stun => stun_binding(),
    }
}

// ---------- QUIC Initial (RFC 9000 / RFC 9001) ----------

const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f,
    0x0a,
];

fn expand_label(hk: &hkdf::Hkdf<sha2::Sha256>, label: &str, len: usize) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0);
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("hkdf length");
    out
}

/// Client Initial key, IV and header-protection key for a destination CID.
pub fn initial_keys(dcid: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let (_, hk) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&INITIAL_SALT), dcid);
    let secret = expand_label(&hk, "client in", 32);
    let hk2 = hkdf::Hkdf::<sha2::Sha256>::from_prk(&secret).expect("prk");
    (expand_label(&hk2, "quic key", 16), expand_label(&hk2, "quic iv", 12), expand_label(&hk2, "quic hp", 16))
}

fn varint(v: u64, out: &mut Vec<u8>) {
    if v < 64 {
        out.push(v as u8);
    } else if v < 16384 {
        out.extend_from_slice(&((v as u16) | 0x4000).to_be_bytes());
    } else if v < 1 << 30 {
        out.extend_from_slice(&((v as u32) | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(v | 0xC000_0000_0000_0000).to_be_bytes());
    }
}

fn u16_prefixed(body: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
}

fn ext(kind: u16, body: &[u8]) -> Vec<u8> {
    let mut e = kind.to_be_bytes().to_vec();
    u16_prefixed(body, &mut e);
    e
}

fn grease() -> u16 {
    let n = (OsRng.next_u32() % 16) as u16;
    (n << 12) | 0x0a00 | (n << 4) | 0x0a
}

fn transport_params(scid: &[u8], b: Browser) -> Vec<u8> {
    let mut tp = Vec::new();
    let mut param = |id: u64, val: &[u8]| {
        varint(id, &mut tp);
        varint(val.len() as u64, &mut tp);
        tp.extend_from_slice(val);
    };
    let num = |v: u64| {
        let mut x = Vec::new();
        varint(v, &mut x);
        x
    };
    let (max_data, stream, idle) = match b {
        Browser::Chrome => (15_728_640, 6_291_456, 30_000),
        Browser::Firefox => (25_165_824, 12_582_912, 30_000),
        _ => (10_485_760, 1_048_576, 60_000),
    };
    param(0x01, &num(idle));
    param(0x03, &num(1472));
    param(0x04, &num(max_data));
    param(0x05, &num(stream));
    param(0x06, &num(stream));
    param(0x07, &num(stream));
    param(0x08, &num(100));
    param(0x09, &num(103));
    param(0x0f, scid);
    tp
}

/// A TLS 1.3 ClientHello for HTTP/3 with the given server name, shaped like
/// the chosen client (cipher order, groups, extension order, GREASE).
pub fn client_hello(domain: &str, b: Browser, scid: &[u8]) -> Vec<u8> {
    let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public = x25519_dalek::PublicKey::from(&secret);
    let mut sni = Vec::new();
    let mut name = vec![0u8];
    u16_prefixed(domain.as_bytes(), &mut name);
    u16_prefixed(&name, &mut sni);
    let alpn = {
        let mut a = Vec::new();
        u16_prefixed(&[2, b'h', b'3'], &mut a);
        a
    };
    let list16 = |xs: &[u16]| {
        let mut v = Vec::new();
        let body: Vec<u8> = xs.iter().flat_map(|x| x.to_be_bytes()).collect();
        u16_prefixed(&body, &mut v);
        v
    };
    let mut ks_entry = 0x001du16.to_be_bytes().to_vec();
    u16_prefixed(public.as_bytes(), &mut ks_entry);
    let mut key_share = Vec::new();
    u16_prefixed(&ks_entry, &mut key_share);
    let versions = [2u8, 0x03, 0x04];
    let psk = [1u8, 1];
    let tp = transport_params(scid, b);
    let sigs = [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601];

    let (suites, mut exts): (Vec<u16>, Vec<Vec<u8>>) = match b {
        Browser::Chrome => {
            let mut e = vec![
                ext(0x0000, &sni),
                ext(0x000a, &list16(&[0x001d, 0x0017, 0x0018])),
                ext(0x000d, &list16(&sigs)),
                ext(0x0010, &alpn),
                ext(0x002b, &versions),
                ext(0x002d, &psk),
                ext(0x0033, &key_share),
                ext(0x0039, &tp),
                ext(0x001b, &[2, 0, 2]),
            ];
            // Chrome shuffles its extension order and adds GREASE at both ends.
            for i in (1..e.len()).rev() {
                let j = (OsRng.next_u32() as usize) % (i + 1);
                e.swap(i, j);
            }
            e.insert(0, ext(grease(), &[]));
            e.push(ext(grease(), &[0]));
            (vec![0x1301, 0x1302, 0x1303], e)
        }
        Browser::Firefox => (
            vec![0x1301, 0x1303, 0x1302],
            vec![
                ext(0x0000, &sni),
                ext(0x000a, &list16(&[0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101])),
                ext(0x0010, &alpn),
                ext(0x0033, &key_share),
                ext(0x002b, &versions),
                ext(0x000d, &list16(&sigs)),
                ext(0x002d, &psk),
                ext(0x001c, &0x4001u16.to_be_bytes()),
                ext(0x0039, &tp),
            ],
        ),
        _ => (
            vec![0x1302, 0x1303, 0x1301],
            vec![
                ext(0x0000, &sni),
                ext(0x0010, &alpn),
                ext(0x000a, &list16(&[0x001d, 0x0017, 0x001e, 0x0019, 0x0018])),
                ext(0x000d, &list16(&sigs)),
                ext(0x002b, &versions),
                ext(0x002d, &psk),
                ext(0x0033, &key_share),
                ext(0x0039, &tp),
            ],
        ),
    };
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&rand_bytes(32));
    body.push(0); // empty legacy session id (QUIC)
    let mut s = suites;
    if b == Browser::Chrome {
        s.insert(0, grease());
    }
    body.extend_from_slice(&list16(&s));
    body.extend_from_slice(&[1, 0]);
    let all: Vec<u8> = exts.drain(..).flatten().collect();
    u16_prefixed(&all, &mut body);
    let mut msg = vec![1u8];
    let len = body.len() as u32;
    msg.extend_from_slice(&len.to_be_bytes()[1..]);
    msg.extend_from_slice(&body);
    msg
}

/// An encrypted, header-protected QUIC v1 Initial carrying a ClientHello,
/// padded to 1200 bytes like a browser's first packet.
pub fn quic_initial(domain: &str, b: Browser) -> Vec<u8> {
    use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
    use aes_gcm::aead::AeadInPlace;

    let dcid = rand_bytes(8);
    let scid = if b == Browser::Chrome { Vec::new() } else { rand_bytes(8) };
    let (key, iv, hp) = initial_keys(&dcid);
    let ch = client_hello(domain, b, &scid);

    let pn: u32 = 0;
    let pn_len = 1usize;
    let mut frame = vec![0x06];
    varint(0, &mut frame);
    varint(ch.len() as u64, &mut frame);
    frame.extend_from_slice(&ch);

    let mut header = vec![0xC0 | (pn_len as u8 - 1), 0, 0, 0, 1, dcid.len() as u8];
    header.extend_from_slice(&dcid);
    header.push(scid.len() as u8);
    header.extend_from_slice(&scid);
    varint(0, &mut header); // no token
    let fixed = header.len() + 2 + pn_len + 16;
    let payload_len = frame.len().max(QUIC_MIN_DATAGRAM.saturating_sub(fixed));
    let length = (pn_len + payload_len + 16) as u64;
    header.extend_from_slice(&((length as u16) | 0x4000).to_be_bytes());
    let pn_off = header.len();
    header.extend_from_slice(&pn.to_be_bytes()[4 - pn_len..]);

    let mut payload = frame;
    payload.resize(payload_len, 0); // PADDING frames
    let mut nonce = iv.clone();
    for (i, byte) in pn.to_be_bytes().iter().enumerate() {
        nonce[8 + i] ^= byte;
    }
    let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).expect("key");
    let tag = cipher
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), &header, &mut payload)
        .expect("encrypt");
    payload.extend_from_slice(&tag);

    let sample_at = 4 - pn_len;
    let mut block = GenericArray::clone_from_slice(&payload[sample_at..sample_at + 16]);
    aes::Aes128::new_from_slice(&hp).expect("hp").encrypt_block(&mut block);
    header[0] ^= block[0] & 0x0f;
    for i in 0..pn_len {
        header[pn_off + i] ^= block[1 + i];
    }
    header.extend_from_slice(&payload);
    header
}

// ---------- DNS, SIP, STUN ----------

pub fn dns_query(domain: &str) -> Vec<u8> {
    let mut q = (OsRng.next_u32() as u16).to_be_bytes().to_vec();
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]);
    for label in domain.trim_end_matches('.').split('.') {
        q.push(label.len().min(63) as u8);
        q.extend_from_slice(&label.as_bytes()[..label.len().min(63)]);
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]); // A, IN
    q.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 0]); // EDNS0, 1232-byte UDP
    q
}

/// (User-Agent, Allow, Supported) of common SIP phones (wgbooster 0x1801f7bb0).
pub const SIP_AGENTS: &[(&str, &str, &str)] = &[
    ("PJSUA v2.13 Linux-6.1/x86_64", "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, PRACK, UPDATE, REFER, NOTIFY, MESSAGE, SUBSCRIBE", "100rel, timer, replaces, norefersub"),
    ("Linphone/5.2.5 (belle-sip/5.2.0)", "INVITE, ACK, BYE, CANCEL, OPTIONS, INFO, UPDATE, REFER, MESSAGE", "replaces, outbound, gruu, path, 100rel, timer"),
    ("Twinkle/1.10.2", "INVITE, ACK, CANCEL, OPTIONS, BYE, REFER, NOTIFY, MESSAGE, INFO", "replaces, timer, 100rel"),
    ("Zoiper rv2.10.16.6", "INVITE, ACK, CANCEL, BYE, OPTIONS, INFO, PRACK, UPDATE, REFER, NOTIFY", "timer, 100rel, replaces, norefersub"),
    ("MicroSIP/3.21.5", "ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, REFER, SUBSCRIBE", "replaces, 100rel, timer"),
];

pub fn sip_invite(domain: &str, local: SocketAddr) -> Vec<u8> {
    let (ua, allow, supported) = SIP_AGENTS[(OsRng.next_u32() as usize) % SIP_AGENTS.len()];
    let user = rand_token(8);
    let host = match local {
        SocketAddr::V6(a) => format!("[{}]:{}", a.ip(), a.port()),
        SocketAddr::V4(a) => format!("{}:{}", a.ip(), a.port()),
    };
    format!(
        "INVITE sip:{user}@{domain} SIP/2.0\r\nVia: SIP/2.0/UDP {host};branch=z9hG4bK{b}\r\nMax-Forwards: 70\r\nFrom: <sip:{me}@{domain}>;tag={tag}\r\nTo: <sip:{user}@{domain}>\r\nCall-ID: {cid}\r\nCSeq: 1 INVITE\r\nContact: <sip:{me}@{host}>\r\nUser-Agent: {ua}\r\nAllow: {allow}\r\nSupported: {supported}\r\nContent-Length: 0\r\n\r\n",
        b = rand_token(10),
        me = rand_token(6),
        tag = rand_token(8),
        cid = rand_token(16),
    )
    .into_bytes()
}

/// SOFTWARE attribute values the engine picks from (wgbooster 0x1801f8398).
pub const STUN_SOFTWARE: &[&str] = &["libnice 0.1.21", "PJSIP 2.13.0", "Chromium", "Linphone/5.2", "Mozilla"];

fn crc32(data: &[u8]) -> u32 {
    let mut c = 0xFFFF_FFFFu32;
    for &b in data {
        c ^= b as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 { (c >> 1) ^ 0xEDB8_8320 } else { c >> 1 };
        }
    }
    !c
}

pub fn stun_binding() -> Vec<u8> {
    let sw = STUN_SOFTWARE[(OsRng.next_u32() as usize) % STUN_SOFTWARE.len()].as_bytes();
    let mut attrs = Vec::new();
    attrs.extend_from_slice(&0x8022u16.to_be_bytes());
    attrs.extend_from_slice(&(sw.len() as u16).to_be_bytes());
    attrs.extend_from_slice(sw);
    while attrs.len() % 4 != 0 {
        attrs.push(0);
    }
    let mut m = vec![0x00, 0x01];
    m.extend_from_slice(&((attrs.len() + 8) as u16).to_be_bytes());
    m.extend_from_slice(&0x2112_A442u32.to_be_bytes());
    m.extend_from_slice(&rand_bytes(12));
    m.extend_from_slice(&attrs);
    let fp = crc32(&m) ^ 0x5354_554e;
    m.extend_from_slice(&[0x80, 0x28, 0, 4]);
    m.extend_from_slice(&fp.to_be_bytes());
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn rfc9001_initial_keys() {
        let (k, iv, hp) = initial_keys(&hex("8394c8f03e515708"));
        assert_eq!(k, hex("1f369613dd76d5467730efcbe3b1a22d"));
        assert_eq!(iv, hex("fa044b2f42a3fd3b46fb255c"));
        assert_eq!(hp, hex("9f50449e04a0e810283a1e9933adedd2"));
    }

    #[test]
    fn quic_packet_decrypts() {
        use aes::cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray};
        use aes_gcm::aead::AeadInPlace;
        for b in [Browser::Chrome, Browser::Firefox, Browser::Curl] {
            let pkt = quic_initial("www.example.com", b);
            assert!(pkt.len() >= QUIC_MIN_DATAGRAM);
            assert_eq!(&pkt[1..5], &[0, 0, 0, 1]);
            let dlen = pkt[5] as usize;
            let dcid = &pkt[6..6 + dlen];
            let slen = pkt[6 + dlen] as usize;
            let mut off = 7 + dlen + slen + 1; // token length 0
            let length = (u16::from_be_bytes([pkt[off], pkt[off + 1]]) & 0x3fff) as usize;
            off += 2;
            let (key, iv, hp) = initial_keys(dcid);
            let mut block = GenericArray::clone_from_slice(&pkt[off + 4..off + 20]);
            aes::Aes128::new_from_slice(&hp).unwrap().encrypt_block(&mut block);
            let mut header = pkt[..off + 1].to_vec();
            header[0] ^= block[0] & 0x0f;
            header[off] ^= block[1];
            assert_eq!(header[0] & 0x03, 0);
            let pn = header[off] as u8;
            let mut nonce = iv.clone();
            nonce[11] ^= pn;
            let mut body = pkt[off + 1..off + length].to_vec();
            let tag = body.split_off(body.len() - 16);
            aes_gcm::Aes128Gcm::new_from_slice(&key)
                .unwrap()
                .decrypt_in_place_detached(aes_gcm::Nonce::from_slice(&nonce), &header, &mut body, aes_gcm::Tag::from_slice(&tag))
                .unwrap();
            assert_eq!(body[0], 0x06); // CRYPTO frame
            let text = String::from_utf8_lossy(&body);
            assert!(text.contains("www.example.com"));
        }
    }

    #[test]
    fn engine_rules() {
        let mut p = Profile { jc: "200".into(), ..Default::default() };
        assert_eq!(Plan::from_profile(&p).jc, 0);
        p.jc = "4".into();
        let plan = Plan::from_profile(&p);
        assert_eq!((plan.jmin, plan.jmax), (50, 1000));
        p.jmin = "900".into();
        p.jmax = "100".into();
        assert_eq!(Plan::from_profile(&p).jmin, 50);
        p.jd = "500".into();
        assert_eq!(Plan::from_profile(&p).jd_ms, 0);
        p.mask_domain = "-bad".into();
        assert!(Plan::from_profile(&p).imitation.is_none());
        p.mask_domain = "www.example.com".into();
        p.mask_protocol = "nonsense".into();
        p.mask_browser = "opera".into();
        let i = Plan::from_profile(&p).imitation.unwrap();
        assert_eq!((i.proto, i.browser), (Proto::Quic, Browser::Curl));
    }

    #[test]
    fn cps_tags() {
        let p = cps_packet("<b 0xc0ffee><r 4><rd 3><rc 2><c><t>", 7).unwrap();
        assert_eq!(&p[..3], &[0xc0, 0xff, 0xee]);
        assert_eq!(p.len(), 3 + 4 + 3 + 2 + 4 + 4);
        assert!(p[7..10].iter().all(|b| b.is_ascii_digit()));
        assert!(p[10..12].iter().all(|b| b.is_ascii_alphabetic()));
        assert_eq!(&p[12..16], &7u32.to_be_bytes());
        assert!(cps_packet("<x 1>", 0).is_err());
        assert!(cps_packet("<b 0xabc>", 0).is_err());
    }

    #[test]
    fn stun_and_dns_shapes() {
        let s = stun_binding();
        assert_eq!(&s[4..8], &0x2112_A442u32.to_be_bytes());
        assert_eq!(u16::from_be_bytes([s[2], s[3]]) as usize, s.len() - 20);
        let d = dns_query("a.example.com");
        assert_eq!(&d[12..15], &[1, b'a', 7]);
        let sip = String::from_utf8(sip_invite("example.com", "192.0.2.1:5000".parse().unwrap())).unwrap();
        assert!(sip.starts_with("INVITE sip:") && sip.contains("Max-Forwards: 70"));
    }
}
