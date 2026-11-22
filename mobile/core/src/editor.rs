//! Profile editing for the phone apps.
//!
//! The editor screens read and write profiles through the desktop app's own
//! parser and writer (`src/profile.rs`), so a profile edited on a phone saves
//! byte-for-byte the way the desktop would, keeps unknown keys, and is checked
//! with the same rules.

use base64::Engine as _;
use rand_core::OsRng;
use serde_json::{Map, Value};

use crate::profile::Profile;

/// Every editable field, by the JSON key the app uses.
macro_rules! fields {
    ($($key:literal => $($f:ident)+;)*) => {
        fn get(p: &Profile, key: &str) -> Option<String> {
            match key {
                $($key => Some(p.$($f)+.clone()),)*
                "I1" => Some(p.i[0].clone()),
                "I2" => Some(p.i[1].clone()),
                "I3" => Some(p.i[2].clone()),
                "I4" => Some(p.i[3].clone()),
                "I5" => Some(p.i[4].clone()),
                _ => None,
            }
        }
        fn set(p: &mut Profile, key: &str, v: String) -> bool {
            match key {
                $($key => { p.$($f)+ = v; true })*
                "I1" => { p.i[0] = v; true }
                "I2" => { p.i[1] = v; true }
                "I3" => { p.i[2] = v; true }
                "I4" => { p.i[3] = v; true }
                "I5" => { p.i[4] = v; true }
                _ => false,
            }
        }
        pub const KEYS: &[&str] = &[$($key,)* "I1", "I2", "I3", "I4", "I5"];
    };
}

fields! {
    "PrivateKey" => private_key;
    "Address" => address;
    "DNS" => dns;
    "MTU" => mtu;
    "ListenPort" => listen_port;
    "BypassLanTraffic" => bypass_lan;
    "Jc" => jc;
    "Jmin" => jmin;
    "Jmax" => jmax;
    "Jd" => jd;
    "S1" => s1;
    "S2" => s2;
    "S3" => s3;
    "S4" => s4;
    "H1" => h1;
    "H2" => h2;
    "H3" => h3;
    "H4" => h4;
    "Id" => mask_domain;
    "Ip" => mask_protocol;
    "Ib" => mask_browser;
    "PublicKey" => public_key;
    "PresharedKey" => preshared_key;
    "Endpoint" => endpoint;
    "AllowedIPs" => allowed_ips;
    "DisallowedIPs" => disallowed_ips;
    "AllowedApps" => allowed_apps;
    "DisallowedApps" => disallowed_apps;
    "PersistentKeepalive" => keepalive;
    "Socks5Proxy" => socks5;
    "Socks5ProxyUsername" => socks5_user;
    "Socks5ProxyPassword" => socks5_pass;
}

fn problems(p: &Profile) -> Value {
    Value::Array(
        p.validate()
            .into_iter()
            .map(|(field, msg)| serde_json::json!({ "field": field, "message": msg }))
            .collect(),
    )
}

/// `{fields:{key:value}, problems:[{field,message}], public_key_of_private}` for a profile's text.
/// Empty text gives a new, empty profile.
pub fn fields(text: &str) -> Result<Value, String> {
    let p = if text.trim().is_empty() { Profile::default() } else { Profile::parse(text)? };
    let mut m = Map::new();
    for k in KEYS {
        m.insert((*k).to_string(), Value::String(get(&p, k).unwrap_or_default()));
    }
    Ok(serde_json::json!({
        "fields": m,
        "problems": problems(&p),
        "own_public_key": public_key(&p.private_key).unwrap_or_default(),
    }))
}

/// Applies `changes` (a JSON object of key -> string) to the profile `text`
/// (empty for a new one) and returns `{text, problems}`.
pub fn update(text: &str, changes: &str) -> Result<Value, String> {
    let mut p = if text.trim().is_empty() { Profile::default() } else { Profile::parse(text)? };
    let changes: Map<String, Value> = serde_json::from_str(changes).map_err(|e| format!("Bad editor data: {e}"))?;
    for (k, v) in changes {
        let v = v.as_str().unwrap_or_default().trim().to_string();
        if !set(&mut p, &k, v) {
            return Err(format!("Unknown field {k}"));
        }
    }
    Ok(serde_json::json!({ "text": p.to_conf(), "problems": problems(&p) }))
}

/// A new WireGuard key pair, base64 like `wg genkey` / `wg pubkey`.
pub fn generate_keypair() -> Value {
    let secret = boringtun::x25519::StaticSecret::random_from_rng(OsRng);
    let public = boringtun::x25519::PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::STANDARD;
    serde_json::json!({ "private": b64.encode(secret.to_bytes()), "public": b64.encode(public.as_bytes()) })
}

/// The public key for a base64 private key, if it's valid.
pub fn public_key(private: &str) -> Option<String> {
    let b64 = base64::engine::general_purpose::STANDARD;
    let bytes: [u8; 32] = b64.decode(private.trim()).ok()?.try_into().ok()?;
    let secret = boringtun::x25519::StaticSecret::from(bytes);
    Some(b64.encode(boringtun::x25519::PublicKey::from(&secret).as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONF: &str = "[Interface]\nPrivateKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI=\nAddress = 192.168.100.2/32\nJc = 4\nI1 = <b 0x01>\nSomethingNew = keep me\n[Peer]\nPublicKey = aGVsbG9oZWxsb2hlbGxvaGVsbG9oZWxsb2hlbGxvMTI=\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0\n";

    #[test]
    fn reads_every_field() {
        let v = fields(CONF).unwrap();
        let f = &v["fields"];
        assert_eq!(f["Address"], "192.168.100.2/32");
        assert_eq!(f["Jc"], "4");
        assert_eq!(f["I1"], "<b 0x01>");
        assert_eq!(f["Endpoint"], "vpn.example.com:51820");
        assert_eq!(f.as_object().unwrap().len(), KEYS.len());
        assert!(!v["own_public_key"].as_str().unwrap().is_empty());
    }

    #[test]
    fn update_keeps_unknown_keys_and_validates() {
        let r = update(CONF, r#"{"Jc":"200","AllowedApps":"org.example.browser"}"#).unwrap();
        let text = r["text"].as_str().unwrap();
        assert!(text.contains("SomethingNew = keep me"));
        assert!(text.contains("org.example.browser"));
        let probs = r["problems"].as_array().unwrap();
        assert!(probs.iter().any(|p| p["field"] == "Jc"), "{probs:?}");
        assert!(update(CONF, r#"{"Nope":"1"}"#).is_err());
    }

    #[test]
    fn new_profile_and_keys() {
        let kp = generate_keypair();
        let private = kp["private"].as_str().unwrap();
        assert_eq!(public_key(private).as_deref(), kp["public"].as_str());
        let r = update("", &format!(r#"{{"PrivateKey":"{private}","Address":"192.168.100.3/32","Endpoint":"vpn.example.com:51820","PublicKey":"{}","AllowedIPs":"0.0.0.0/0"}}"#, kp["public"].as_str().unwrap())).unwrap();
        let again = fields(r["text"].as_str().unwrap()).unwrap();
        assert_eq!(again["fields"]["Address"], "192.168.100.3/32");
        assert_eq!(public_key("not a key"), None);
    }
}
