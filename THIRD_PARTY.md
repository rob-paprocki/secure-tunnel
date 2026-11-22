# Open-source parts built into Secure Tunnel

| Part | Version | License | Use |
|---|---|---|---|
| boringtun | 0.7.1 | BSD-3-Clause | WireGuard protocol engine |
| tun-rs | 2.8 | Apache-2.0 | Virtual network adapter |
| Wintun (wintun.dll) | 0.14.1 | Prebuilt Binaries License (see vendor/wintun/LICENSE.txt) | Network adapter driver on Windows, shipped unmodified inside the app |
| WinDivert (WinDivert.dll, WinDivert64.sys) | 2.2.2 | LGPL-3.0 or GPL-2.0 (see vendor/windivert/LICENSE.txt) | Per-app split tunnelling on Windows x64, shipped unmodified |
| egui / eframe | 0.33 | MIT or Apache-2.0 | Window and controls |
| x25519-dalek, aes-gcm, hkdf, sha2 | | BSD-3-Clause / MIT or Apache-2.0 | Keys and QUIC look-alike packets |

wintun.dll comes from the official release (wintun-0.14.1.zip, SHA-256
07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51).

WinDivert comes from the official release (WinDivert-2.2.2-A.zip, SHA-256
63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15); the bundled
files are its x64 WinDivert.dll (SHA-256
c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2) and
WinDivert64.sys (SHA-256
8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2).

Neither driver is stored in this repository. When you build for Windows,
`build.rs` runs `scripts/fetch_vendor.py`, which downloads both zips from the
addresses above and stops if any hash differs.
