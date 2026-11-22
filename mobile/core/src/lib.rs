//! Tunnel core for the Secure Tunnel phone apps.
//!
//! It compiles the desktop app's own packet path (`src/datapath.rs`), its
//! DPI-protection builders (`src/obfs.rs`), SOCKS5 transport (`src/socks.rs`)
//! and profile parser (`src/profile.rs`) unchanged, so junk packets, the
//! protocol look-alike, I1-I5 packets and AmneziaWG headers behave exactly as
//! on desktop. The phone's VPN service owns the virtual adapter and hands this
//! core its file descriptor:
//!
//! - Android: `VpnService.Builder.establish()`; every socket the core opens is
//!   passed to `VpnService.protect()` first (see `android.rs`).
//! - iOS: the packet tunnel extension's utun descriptor (4-byte address-family
//!   prefix on each packet); see `ffi.rs`.

#[allow(dead_code)]
#[path = "../../../src/datapath.rs"]
mod datapath;
#[allow(dead_code)]
#[path = "../../../src/obfs.rs"]
mod obfs;
#[allow(dead_code)]
#[path = "../../../src/profile.rs"]
mod profile;
#[allow(dead_code)]
#[path = "../../../src/socks.rs"]
mod socks;

/// Per-app routing is applied by the phone's VPN service (Android's allowed /
/// disallowed applications), so profiles with app lists are accepted.
mod apps {
    pub fn enforced() -> bool {
        true
    }
}

pub mod tunnel;

pub mod editor;

pub mod ffi;

#[cfg(target_os = "android")]
mod android;
