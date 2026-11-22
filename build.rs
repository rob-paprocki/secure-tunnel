//! Makes sure the Windows drivers that src/engine.rs and src/winfilter.rs embed
//! are present and match their pinned SHA-256 hashes. They are not kept in git:
//! when one is missing, this runs scripts/fetch_vendor.py, which downloads the
//! official Wintun and WinDivert releases. Other targets need nothing.

use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

/// (path under vendor/, SHA-256). Keep in step with scripts/fetch_vendor.py.
const FILES: &[(&str, &str)] = &[
    ("wintun/amd64/wintun.dll", "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"),
    ("wintun/arm64/wintun.dll", "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"),
    ("wintun/x86/wintun.dll", "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931"),
    ("windivert/amd64/WinDivert.dll", "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"),
    ("windivert/amd64/WinDivert64.sys", "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"),
];

fn bad_files(vendor: &Path) -> Vec<&'static str> {
    FILES
        .iter()
        .filter(|(rel, want)| match std::fs::read(vendor.join(rel)) {
            Ok(data) => format!("{:x}", Sha256::digest(&data)) != *want,
            Err(_) => true,
        })
        .map(|(rel, _)| *rel)
        .collect()
}

/// Icon and version details shown by Explorer, the taskbar and the installer.
fn embed_windows_resources() {
    println!("cargo:rerun-if-changed=packaging/windows/secure-tunnel.ico");
    let version = env!("CARGO_PKG_VERSION");
    println!("cargo:rerun-if-env-changed=WINDRES");
    println!("cargo:rerun-if-env-changed=WINDRES_AR");
    let mut res = winresource::WindowsResource::new();
    // GNU-ABI targets (e.g. aarch64-pc-windows-gnullvm with llvm-mingw) compile the
    // resource with windres; these let a build point at the cross toolchain's copy.
    if let Ok(windres) = std::env::var("WINDRES") {
        res.set_windres_path(&windres);
    }
    if let Ok(ar) = std::env::var("WINDRES_AR") {
        res.set_ar_path(&ar);
    }
    res.set_icon("packaging/windows/secure-tunnel.ico")
        .set("ProductName", "Secure Tunnel")
        .set("FileDescription", "Secure Tunnel")
        .set("InternalName", "secure-tunnel")
        .set("OriginalFilename", "secure-tunnel.exe")
        .set("CompanyName", "Secure Tunnel")
        .set("LegalCopyright", "GPL-3.0-or-later")
        .set("ProductVersion", version)
        .set("FileVersion", version);
    if let Err(e) = res.compile() {
        panic!("could not embed the Windows icon and version resource: {e}");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=scripts/fetch_vendor.py");
    for (rel, _) in FILES {
        println!("cargo:rerun-if-changed=vendor/{rel}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    embed_windows_resources();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let vendor = root.join("vendor");
    if bad_files(&vendor).is_empty() {
        return;
    }
    let script = root.join("scripts").join("fetch_vendor.py");
    let ran = ["python3", "python", "py"].iter().any(|py| {
        Command::new(py)
            .arg("-I")
            .arg(&script)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    });
    let still_bad = bad_files(&vendor);
    if !still_bad.is_empty() {
        panic!(
            "Windows driver files are missing or do not match their pinned SHA-256: {}.\n\
             {}Run `python -I scripts/fetch_vendor.py` (needs internet access), or copy the files \
             from the official Wintun 0.14.1 and WinDivert 2.2.2 releases into vendor/.",
            still_bad.join(", "),
            if ran { "" } else { "Python was not found, so they could not be downloaded automatically. " }
        );
    }
}
