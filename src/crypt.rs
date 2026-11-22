//! Profile encryption at rest (the original's "Enable profile encryption",
//! a Pro feature there, free here). Encrypted profiles are `<name>.dapi`.
//!
//! Windows: DPAPI for the current user with no extra entropy, exactly as the
//! original (`ProtectedData.Protect(data, null, CurrentUser)`), so its `.dapi`
//! files open here and the other way round.
//! macOS and Linux: AES-256-GCM with a random key kept in the login keychain
//! (`security`) or the Secret Service (`secret-tool`); without either, in a
//! key file readable only by the user.

pub const ENC_EXT: &str = "dapi";

#[cfg(windows)]
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    dpapi(data, true)
}

#[cfg(windows)]
pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    dpapi(data, false)
}

#[cfg(windows)]
fn dpapi(data: &[u8], protect: bool) -> Result<Vec<u8>, String> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData, CryptUnprotectData};
    unsafe {
        let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
        let mut out = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
        let ok = if protect {
            CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(), std::ptr::null(), 0, &mut out)
        };
        if ok == 0 {
            return Err(if protect { "Could not encrypt the profile" } else { "Could not decrypt the profile (was it encrypted by another Windows user?)" }.into());
        }
        let v = std::slice::from_raw_parts(out.pbData, out.cbData as usize).to_vec();
        LocalFree(out.pbData as _);
        Ok(v)
    }
}

#[cfg(not(windows))]
const MAGIC: &[u8; 4] = b"STE1";

#[cfg(not(windows))]
pub fn encrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use rand_core::{OsRng, RngCore};
    let key = key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ct = cipher.encrypt(Nonce::from_slice(&nonce), data).map_err(|_| "Could not encrypt the profile".to_string())?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(not(windows))]
pub fn decrypt(data: &[u8]) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    if data.len() < 4 + 12 + 16 || &data[..4] != MAGIC {
        return Err("This encrypted profile was not made by this app on this system".into());
    }
    let key = key()?;
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    cipher.decrypt(Nonce::from_slice(&data[4..16]), &data[16..]).map_err(|_| "Could not decrypt the profile (the key has changed)".to_string())
}

#[cfg(not(windows))]
const SERVICE: &str = "SecureTunnel profiles";

/// The profile key: read from the keystore, or made and stored on first use.
#[cfg(not(windows))]
fn key() -> Result<[u8; 32], String> {
    use rand_core::{OsRng, RngCore};
    if let Some(k) = load_key() {
        return Ok(k);
    }
    let mut k = [0u8; 32];
    OsRng.fill_bytes(&mut k);
    store_key(&k)?;
    load_key().ok_or_else(|| "The profile key could not be stored".to_string())
}

#[cfg(not(windows))]
fn hex(k: &[u8]) -> String {
    k.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(not(windows))]
fn unhex(s: &str) -> Option<[u8; 32]> {
    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let mut k = [0u8; 32];
    for i in 0..32 {
        k[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(k)
}

#[cfg(not(windows))]
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn key_file() -> std::path::PathBuf {
    crate::store::base_dir().join("profile.key")
}

#[cfg(target_os = "macos")]
fn load_key() -> Option<[u8; 32]> {
    let o = std::process::Command::new("security").args(["find-generic-password", "-a", "secure-tunnel", "-s", SERVICE, "-w"]).output().ok()?;
    if o.status.success() { unhex(&String::from_utf8_lossy(&o.stdout)) } else { None }
}

#[cfg(target_os = "macos")]
fn store_key(k: &[u8; 32]) -> Result<(), String> {
    let o = std::process::Command::new("security")
        .args(["add-generic-password", "-U", "-a", "secure-tunnel", "-s", SERVICE, "-w", &hex(k)])
        .output()
        .map_err(|e| e.to_string())?;
    if o.status.success() { Ok(()) } else { Err("The login keychain refused to store the profile key".into()) }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn load_key() -> Option<[u8; 32]> {
    if let Ok(o) = std::process::Command::new("secret-tool").args(["lookup", "service", SERVICE]).output() {
        if o.status.success() {
            if let Some(k) = unhex(&String::from_utf8_lossy(&o.stdout)) {
                return Some(k);
            }
        }
    }
    unhex(&std::fs::read_to_string(key_file()).ok()?)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn store_key(k: &[u8; 32]) -> Result<(), String> {
    use std::io::Write;
    // Secret Service first (GNOME Keyring, KWallet); a private key file otherwise.
    if let Ok(mut child) = std::process::Command::new("secret-tool")
        .args(["store", "--label", SERVICE, "service", SERVICE])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(hex(k).as_bytes());
        }
        if child.wait().map(|s| s.success()).unwrap_or(false) {
            return Ok(());
        }
    }
    let f = key_file();
    let _ = std::fs::create_dir_all(crate::store::base_dir());
    std::fs::write(&f, hex(k)).map_err(|e| e.to_string())?;
    crate::store::restrict_permissions(&f);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    #[cfg(windows)]
    fn dpapi_roundtrip() {
        let data = b"[Interface]\nPrivateKey = x\n";
        let enc = super::encrypt(data).unwrap();
        assert_ne!(&enc[..], &data[..]);
        assert_eq!(super::decrypt(&enc).unwrap(), data);
    }
}
