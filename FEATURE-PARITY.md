# Feature parity — 1:1 pass against the original

A feature-by-feature comparison of this rebuild against WireSock Secure Connect
3.8.2.1 (the ARM64 original, with its installed x64 build used for screenshots).
Every rule is sourced in `MECHANICS.md`; this file is the checklist view.

**Status legend**
- **Done** — implemented and exercised by a test or a screenshot here.
- **Done\*** — implemented, but not verified against a live tunnel / driver / device.
- **Platform** — implemented, differs per OS (see notes).
- **Dropped** — intentionally not carried over (reason given).

## Main window

| Original feature | Rebuild | Status |
|---|---|---|
| Custom 31 px title bar (#202020, icon, minimize + close) | `style::title_bar`, `app.rs` | Done |
| Big connect/disconnect switch (194×84, grey/green/steel, knob animation) | `app.rs` switch, `style.rs` | Done |
| Status text ("Not connected", "Connecting to…", "Connected to…") | `app.rs` | Done |
| "How to connect" link | `app.rs` | Done |
| Connection statistics (uptime, send/receive rate + totals, ping, loss) | `app.rs::stats`, `stats.rs` | Done\* (real numbers need a live tunnel) |
| Kill-switch bar (armed #A9A9A9 / blocking #CD5C5C) with Unlock | `app.rs`, `netlock.rs` | Done\* |
| Toolbar: Import (+), Logs, Feedback (bug), Preferences (gear) | `app.rs` | Done |

## Preferences — tabs

| Tab | Rebuild | Status |
|---|---|---|
| Profiles | `pages::page_profiles` + `page_editor` | Done |
| General | `pages::page_general` | Done |
| Network | `pages::page_network` | Done |
| Security | `pages::page_security` | Done |
| Advanced | `pages::page_advanced` | Done |
| Logs | `pages::page_logs` | Done |
| Feedback | `pages::page_report` | Done (local report; no online submit — see Dropped) |
| About | `pages::page_about` | Done |

## Profiles

| Feature | Rebuild | Status |
|---|---|---|
| `<name>.conf` files, sorted, `~`-prefixed hidden | `store.rs` ProfileStore | Done |
| Import (.conf), drag-and-drop, file picker | `app.rs`, `pages.rs` | Done |
| New / edit / duplicate / delete, `name(n)` de-dup | `store.rs`, `pages.rs` | Done |
| Forbidden name characters, field validation, ranges | `profile.rs` validate | Done (unit-tested) |
| WireGuard + AmneziaWG fields (Jc/Jmin/Jmax/Jd, S1–S4, H1–H4, I1–I5, Id/Ip/Ib) | `profile.rs` | Done (unit-tested) |
| Export a profile to .conf | `pages.rs` | Done |
| Process picker for per-app lists | `pages.rs` Picker | Done |
| Masking-domain presets, editable | `store.rs`, `pages.rs` | Done |

## Network / engine

| Feature | Rebuild | Status |
|---|---|---|
| WireGuard tunnel (boringtun 0.7.1, vendored Wintun / utun / tun) | `engine.rs`, `datapath.rs` | Done\* |
| DPI protection: junk packets (Jc/Jmin/Jmax/Jd) | `obfs.rs`, `datapath.rs` | Done (unit-tested) |
| Protocol masking look-alikes: QUIC, DNS, SIP, STUN (Id/Ip/Ib) | `obfs.rs` | Done (unit-tested) |
| AmneziaWG S1–S4 padding + H1–H4 headers, I1–I5 packets | `datapath.rs` Awg, `obfs.rs` | Done (unit-tested, incl. masked end-to-end) |
| SOCKS5 UDP ASSOCIATE + RFC 1929 login | `socks.rs` | Done (unit-tested) |
| Kill switch (firewall lock) | `netlock.rs` | Platform: Windows Firewall / nftables / pf. Done\* |
| TCP termination on connect | `tcpkill.rs` | Platform: Windows/Linux only (not macOS). Done\* |
| Bypass LAN, split by AllowedIPs/DisallowedIPs | `profile.rs`, `engine.rs` | Done (unit-tested route maths) |
| Auto-reconnect, connection timeout, retry back-off | `tunnel.rs` | Done\* |
| Virtual-adapter mode | `engine.rs` | Done |

## Per-app split tunnelling

| Platform | Rebuild | Status |
|---|---|---|
| Linux | cgroup v2 + nftables mark + policy routing | Done\* |
| macOS | NETransparentProxyProvider system extension (signed, notarized) | Done\* (extension awaits one-time System Settings approval) |
| Android | VpnService allowed/disallowed applications | Done\* |
| Windows x64 | WinDivert NETWORK-layer filter (owner-table PID lookup, SNAT/DNAT, MSS clamp, DNS redirect) | Done\* (checksum/NAT/MSS/CIDR unit-tested; driver path not runtime-verified) |
| Windows ARM64 | — | Dropped (WinDivert ships no signed ARM64 driver) |

## Settings & UX

| Feature | Rebuild | Status |
|---|---|---|
| Start on sign-in / connect on launch / start minimized | `store.rs`, `boot.rs` | Done\* |
| Confirm disconnect / reconnect / profile removal / unlock / exit | `store.rs`, `app.rs` | Done |
| Theme: System / Light / Dark | `style.rs` | Done (screenshots both themes) |
| Interface scale 80–160 % | `app.rs` | Done |
| Tray / menu bar: close-to-tray, Exit-only-quit, profile submenu, show/hide | `tray.rs` | Done\* (not click-tested on a live desktop) |
| Notifications on connect/disconnect | `tray.rs` | Done\* |
| Log files with rotation, "Open folder" | `tunnel.rs`, `pages.rs` | Done |
| Connect at system startup (service) | `boot.rs` | Platform: scheduled task / systemd / LaunchDaemon. Done\* |

## Former Pro features (free here)

| Feature | Rebuild | Status |
|---|---|---|
| Profile encryption (.dapi DPAPI on Windows; AES-256-GCM elsewhere) | `crypt.rs`, `store.rs` | Done (encryption unit-tested) |
| App view customization (hide buttons, tabs, stats, server name; tooltip style) | `store.rs`, `pages.rs` | Done |

## Dropped on purpose

| Feature | Reason |
|---|---|
| External IP / geo-location display | needs an online lookup service; out of scope for a local client |
| Licensing / Pro gating | all features are free here |
| Auto-update | distribution is out of scope |
| Online feedback submission | the Feedback page writes a local report instead |
| Interface languages other than English | not translated |
| TCP termination on macOS | no supported API |

## Build / platform coverage

| Target | Built | Verified |
|---|---|---|
| Windows x64 | `build/windows/secure-tunnel-x64.exe` | builds, draws; tunnel not live-tested |
| Windows ARM64 | `build/windows/secure-tunnel-arm64.exe` | builds; not run on ARM64 hardware |
| macOS universal (arm64+x86_64) | installed `Secure Tunnel.app` | notarized, installed; extension approval pending |
| Linux x64 / ARM64 | `build/linux/` + 8 packages in `build/linux/packages/` | built; not installed on a live distro |
| Android | `build/android/secure-tunnel-0.1.0.apk` | builds; not run on a device |
| iOS | `mobile/core` static libs (built on the Mac) | core builds; no app planned (see README, "Why there's no iPhone app") |

## Test summary

- `cargo test` (desktop): 33 tests pass.
- `cargo test` (`mobile/core`): 14 tests pass.
- Covered by tests: AmneziaWG wrap/unwrap, masked end-to-end handshake, profile
  parse/validate (WireGuard + AmneziaWG), SOCKS5 header framing, route maths,
  loss estimate, profile encryption, and the Windows per-app NAT/checksum/MSS/CIDR logic.
- Not covered by tests (needs real hardware/network): a live VPN handshake to a
  server, firewall kill switch, the WinDivert driver, the macOS extension, and the
  Android/iOS apps on devices.
