# Mechanics sheet

Rules and numbers taken from the original (WireSock Secure Connect 3.8.2.1, a .NET 10 / WPF app
inside a WiX Burn installer). The installer was unpacked without installing; the managed
assemblies were read with ILSpy and the built-in .NET reader. Sources are given as
`Type.Member (assembly)`. Nothing here was copied as code; this app re-implements the rules.

Evidence ids: installer payload `ev_2dfcfa90…`, `ev_1420c8e5…`, `ev_269cbea0…`;
GUI types `ev_bf9a6055…`; core types `ev_94535d71…`; native engine pseudo-C `ev_30418c5f…`,
`ev_a4b04d09…`, `ev_60c145c2…`, `ev_caf453ba…`, `ev_5d61a5ca…`, `ev_719f4cee…`; constants
`ev_eedf16f7…`, `ev_1ed418d9…`, `ev_165d07db…`.

## What was decompiled

- **The download** (`wiresock-secure-connect-ARM64-3.8.2.1.exe`) is only the WiX Burn stub:
  its entry function `0x140001610` preloads cabinet/msi DLLs and runs the Burn engine. No VPN
  logic lives there (evidence `ev_5779f46a…`, `ev_fff1b4b7…`).
- **The tunnel engine** `wgbooster.dll` (native, x64 copy from the bundled MSI) was opened with
  Ghidra. It is a C++ wrapper around the Rust boringtun WireGuard library (strings
  `boringtun\src\noise\handshake.rs`, Rust `Option::unwrap` panics). The functions below are
  from it, addresses in that DLL.
- **The app and its service** are .NET; their rules were read from the IL (ILSpy).

## Window layout

| Value | Number | Source |
|---|---|---|
| Main window | 390 × 610 | `MainWindow` XAML root grid (WireSockConnect.dll) |
| Main rows | Auto, 0.8*, Auto, 1*, 0.3*, 0.3*, Auto, 1*, Auto, 2*, Auto | `MainWindow` XAML |
| Preferences window | 700 × 700 | `SettingsWindow` XAML |
| Preferences tabs | Profiles, General, Network, Security, Advanced, Logs, Feedback, About | `SettingsWindow` XAML |
| Font sizes | XS 10, S 12, M 16, L 18, XL 22, XXL 28 | `ApplicationSizes` (WireSockConnect.dll) |
| Switch size | 230 × 100 inside the middle 60 % column | `MainWindow` XAML |
| Switch radius | height / 2 | `SwitcherControl.UpdateLayout` |
| Knob | 0.8 × height; spinner 0.6 × knob | `SwitcherControl.UpdateLayout` |
| Knob travel | width − knob − 0.2 × height | `SwitcherControl` |
| Knob animation | 0.2 s, cubic ease in-out | `SwitcherControl.AnimateKnob` |
| Switch colours | Off Gray #808080, On Green #008000, busy SteelBlue #4682B4 | `SwitcherControl.OnStateChanged` |
| Kill switch bar | #A9A9A9 (armed), #CD5C5C (blocking) | `MainWindow` XAML |
| Update text colour | #44AA00 | `MainWindow` XAML |
| Statistics columns | 1* : 1* : 2* | `MainWindow` XAML |
| Statistics visible | only when connected and not hidden | `MainWindowViewModel.IsConnectionStatisticsVisible` |

## Measured from the installed original (checks/original/*.png, UI Automation)

| Item | Value |
|---|---|
| Title bar | custom, 31 px, #202020, 16 px icon, title #ECECEC, caption buttons 40 x 30 (main: minimize + close; preferences: + maximize) |
| Main window | 390 x 610, background #202020, switch 194 x 84 (#808080 off, knob = background, no label), status text #B6B6B6, "How to connect" link #8AD2E4, toolbar 45 px buttons with 38 px icons #919191 (+, LOG, bug, gear) |
| Preferences | 800 x 610; top tab bar of 70 x 70 buttons (32 px icon, 12 px label), selected #2A2A2A with a #3B7695 underline |
| Settings cards | #2B2B2B with #1D1D1D border, 50 px tall, 8 px apart, title 17 px, description 11.5 px, toggle 44 x 20 (#0063B1 on; white with dark knob off), folding chevron |
| Profiles page | 20 px icon toolbar, 199 px tree list ("profile" root, "Import profile..." item), #5E5E5E splitter, large import drop area with a 128 px plus |
| Network page order | DPI protection (On by default), split tunnelling, virtual adapter, Kill Switch, TCP termination, Bypass LAN, reconnect, connection timeout |
| Match (layout, our build vs original) | main window 93 %, Network page 90 % |

## Formats

| Rule | Value | Source |
|---|---|---|
| Speed | bits/s ÷ 1024 per step, units bps/kbps/mbps/gbps/tbps, format `0.#` | `MyStringConverter.ConvertBytesToSpeed` |
| Size | value ÷ 1024 per step, units B/KB/MB/GB/TB, format `0.##` | `MyStringConverter.ConvertBytesToSize` |
| Uptime | `hh:mm:ss`, `Nd hh:mm:ss` past one day | `ConnectionTimeToStringConvertor.Convert` |
| Packet loss | ratio × 100, `0.##`, then ` %` | `EstimatedLossToStringConvertor.Convert`, MainWindow XAML `StringFormat='{0} %'` |
| Ping | `{0} ms` | MainWindow XAML `StringFormat='{0} ms'` |
| Speed source | `(new_bytes − old_bytes) × 8 ÷ seconds` → **bits** per second | `WireSockConnectionManager.GetTunnelStatistics` (wiresock-connect-service.dll) |
| Speed refresh | only when more than 1.0 s passed since the last sample; no rate until the previous counter is non-zero | same |
| Uptime start | reset when the tunnel reports Connected | `WireSockConnectionManager` connection loop |

## Timers

| Timer | Period | Source |
|---|---|---|
| Statistics update | 1 s | `MainWindowViewModel` ctor (`_updateTimer`) |
| Network lock check | 0.5 s | `MainWindowViewModel` (`_networkLockTimer`) — not used here |
| Service reconnect | 10 s | `MainWindowViewModel` (`_serviceConnectionTimer`) — not used here |
| Connection loop tick | 200 ms | `WireSockConnectionManager` connection loop (`_tunnelEvent.WaitOne(200)`) |
| Connect retry back-off | 200 ms after a new error, doubling on repeats, max 5000 ms | same (`Math.Min(num * 2, 5000)`) |
| Connect timeout | counted from the start of the attempt, `> timeout` seconds; 0 = never | same |
| Disconnect limit | 30 s, then forced | same |

## Tunnel engine (wgbooster.dll, native)

| Rule | Value | Function / data |
|---|---|---|
| Statistics record | seconds since last handshake (−1 if none), tx bytes, rx bytes, loss (float), RTT ms (−1 if none) | `wgb_get_tunnel_state` 0x180070110 → 0x180079170 → 0x1800060e0 |
| Loss estimate | weighted mean of `1 − received/expected` over the current and 7 older sessions | 0x180020d00 |
| Loss weights | first 9.0, divided by 3.0 for each older session present; empty sessions skipped | 9.0 @ 0x1801f6220, 3.0 @ 0x1801f6224, 1.0 @ 0x18027f9d0 |
| Connected | when the server's handshake response arrives | strings "Received handshake_response" 0x1801f8bb0, `[TUN]: Handshake response received` 0x18027d330 |
| Liveness probe period | 125,000,000 ns = 0.125 s | 0x1800ef120 (clock 0x18013feb0 returns ns) |
| Liveness trigger | rx bytes unchanged and last handshake older than 109 s (`0x6d`) | 0x1800ef120 |
| After a probe | wait 625,000,000 ns = 0.625 s | 0x1800ef120 |
| Rekey / reject | WireGuard REKEY_AFTER_TIME and REJECT_AFTER_TIME timers | strings 0x1801f8988, 0x1801f89c0 (numeric 120 s / 180 s are the WireGuard protocol values, not read from the binary: estimated) |

### How this build applies them

Standard WireGuard tools don't expose boringtun's session counters, handshake age or RTT, so:

- **Speeds** use the service formula on the interface's byte counters (sysfs on Linux,
  `netstat` on macOS, `Get-NetAdapterStatistics` on Windows), with the same 1.0 s minimum and
  first-sample rule.
- **Connected** is the first received byte, which is the handshake response.
- **Ping** is an ICMP echo to the server (4 packets), taken on connect and then once per
  rekey interval (120 s), because the original's RTT is refreshed by each handshake.
- **Packet loss** feeds each ping round as one (expected, received) sample into the original's
  weighted formula over the last 8 samples. Same maths, different inputs.
- **Liveness**: "last handshake" is approximated by the last time received bytes moved. Past
  109 s idle, one probe goes through the tunnel (to the profile's DNS server) after 0.625 s.
  If nothing has come back after 180 s, the tunnel counts as lost and reconnects when
  auto-reconnect is on. Profiles without a DNS server or keep-alive are never declared lost
  this way, since an idle tunnel can't be told from a dead one.
- **Retries**: network and name-resolution errors are retried with the 200 ms → 5 s back-off
  until the connection timeout; other errors stop at once.

## Profiles

| Rule | Value | Source |
|---|---|---|
| File | `<name>.conf` in one folder, sorted, names starting `~` skipped | `WireSockProfileManager.GetProfiles/Load` (wiresock.core.library.dll) |
| Extension key prefix | `#@ws:` (also accepted without `:`) | `WireSockConfigValidator.TrimAndStripWireSockPrefix` |
| Write order | Interface, scripts, extensions, Amnezia, masking, Peer, peer extensions | `WireSockProfile.SaveToFile` |
| Duplicate name | `name(n)` with n = highest existing + 1, starting at 1 | `WireSockProfileManager.DuplicateProfile` |
| Forbidden name characters | `\ / : * ? " < > \| , ;` | `WireSockProfileView` validation (WireSockConnect.dll) |
| Blank profile AllowedIPs | `0.0.0.0/0, ::/0` | resource `xstrErrorAllowedIPsNotDefined` |

### Field ranges

| Field | Range | Source |
|---|---|---|
| ListenPort | 1–65535 | `WireSockConfigValidator.IsValidValue` |
| MTU | 576–65535 | same |
| PersistentKeepalive | 0–65535 | same |
| ScriptExecTimeout | 0–65535 | same |
| Jc | 0–128 | same |
| Jd | 0–200 | same |
| Jmin, Jmax | 0–1280 | `WireSockProfileView` (UI check; the core allows up to 4294967295) |
| S1–S4 | 0–4294967295 | `WireSockConfigValidator.IsValidValue` |
| H1–H4 | 0–0xFFFFFFFF, decimal or hex, or `min-max` | same (`ValidateIntOrRange`) |
| Keys | base64 of exactly 32 bytes | `WireSockConfigValidator.ValidateKey` |
| Ip (masking protocol) | quic, dns, sip, stun | same |
| Ib (browser) | chrome, firefox, cURL, random | same |
| AmneziaWG | S1, S2, H1–H4 must all be set together | resource `xstrErrorAmneziaParameters` |

## Split tunnelling

| Rule | Value | Source |
|---|---|---|
| Private networks for "Bypass LAN" | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 169.254.0.0/16, 224.0.0.0/24, fd00::/8, ff02::/16, fe80::/10, ff00::/8 | `IpHelper.GetPrivateLocalNetworks` |
| Status text | Not set / On (profile) / On (global) / Off (global) | `MainWindowViewModel.SplitTunnelingStatus` |
| Global vs profile | global wins when "override" is on or the profile has none | same |
| Edit button text | "Setup" when nothing is set, else "Edit" | `MainWindowViewModel.SplitTunnelingEditStatus` |

How it is enforced here (not from the original): DisallowedIPs and the private networks are
subtracted from AllowedIPs before the profile is handed to WireGuard, so the routing table
skips them on every system.

## Settings defaults

| Setting | Default | Source |
|---|---|---|
| Start on sign-in | off | `Settings.AutoStart` |
| Connect on launch | off | `Settings.AutoConnect` |
| Start minimized | off | `Settings.StartMinimized` |
| Confirm disconnect / reconnect / profile removal | on | `Settings.ConfirmDisconnect`, `ConfirmReconnect`, `ConfirmProfileRemoval` |
| Auto reconnect | on | `Settings.Reconnect` |
| Connection timeout | 0 = continuously retry; choices 10 s, 30 s, 1 min, 2 min | `Settings.ConnectionTimeout`, `AppConnectionTimeoutConverter` |
| Log limit | 50 lines | `Settings.LogLimit` |
| Theme | System | `Settings.Theme` |
| Bypass LAN | off | `Settings.BypassLanTraffic` |
| Global junk packets | Jc 3, Jmin 50, Jmax 1000, Jd 0 | service `app.config` (wiresock-connect-service) |
| Kill switch, preserve lock | off | service `app.config` |

## DPI protection: junk packets and protocol masking (wgbooster.dll)

| Rule | Value | Source |
|---|---|---|
| When | before every handshake initiation (WireGuard message type 1, 148 bytes) | log `[MGR]: Configuring pre-handshake with packet count, size min, size max, delay` 0x180279d50 (fns 0x180089d90, 0x18008e2e0); `Sending handshake_initiation` 0x1801f8ca0 |
| Junk packets | `Jc` packets of random bytes, size uniform in [`Jmin`, `Jmax`] | same log string; config 0x1800f7570 |
| Delay | `Jd` ms between junk packets | same log string (`delay: {}ms`) |
| Jc out of range (>128) | becomes 0 | string 0x18026c940 in 0x1800f7570 |
| Jmin/Jmax out of range | defaults 50–1000 | string 0x18026ca60 in 0x1800f7570 |
| Jc set but Jmin = Jmax = 0 | 50 / 1000 (`0x32` / `0x3e8`) | constructor 0x180005820 |
| Jd out of range (>200) | becomes 0 | string 0x18026cad0 in 0x1800f7570 |
| Masking turns on | when `Id` is 1–253 chars of [A-Za-z0-9.-] with no leading/trailing '.' or '-'; otherwise off | strings 0x18026cb90, 0x18026cd30 in 0x1800f7570 |
| Ip | dns, quic, sip, stun; anything else becomes quic | string 0x1802762d0 in 0x180142460 |
| Ib | chrome, firefox, curl, random; anything else becomes curl | string 0x18026cc40 in 0x1800f7570 |
| QUIC look-alike | real QUIC v1 Initial: TLS ClientHello with SNI = Id and ALPN `h3`, keys from HKDF labels `quic key`, `quic iv`, `quic hp` | `boringtun/src/noise/quic/{initial,crypto,tls}.rs`, labels 0x1801f84e1–0x1801f84f0 (fn 0x180015840), `h3` 0x1801f8650 |
| SIP look-alike | INVITE sip:user@Id with Via `;branch=z9hG4bK…`, `Max-Forwards: 70`, From/To/Contact, User-Agent + Allow + Supported of a common phone | strings 0x1801f70a0–0x1801f81d0, user agents 0x1801f7bb0 (fn 0x1800066b0) |
| STUN look-alike | Binding request with SOFTWARE from: libnice 0.1.21, PJSIP 2.13.0, Chromium, Linphone/5.2, Mozilla | `imitation\stun.rs` 0x1801f8250, list 0x1801f8398 |
| DNS look-alike | query for Id | protocol name `dns` 0x1801f6db0 (packet layout estimated: A query with EDNS0) |

How it is done here: like the original, the packets are built inside the tunnel engine. This app
compiles in boringtun 0.7.1 (the same open-source WireGuard code the original's engine is built on,
see `boringtun/src/noise/handshake.rs` strings) and a virtual adapter from tun-rs (Wintun 0.14.1
bundled on Windows, utun on macOS, /dev/net/tun on Linux). It sends the look-alike packet and the
junk right before each handshake initiation, and wraps every packet with AmneziaWG magic headers:
S1–S4 random padding in front, and H1–H4 (a value or a min–max range) in place of the 4-byte
message type. Received packets are matched by padding length and header range, and anything else
(junk, look-alikes) is dropped. Nothing has to be installed.

Estimated (not read from the code): one look-alike packet per handshake, sent before the junk;
which browser shapes the QUIC hello (cipher and extension order, GREASE) only approximates real
browsers; the DNS query layout.

## Built-in engine (this app)

| Rule | Value | Source |
|---|---|---|
| Loss estimate | weighted mean of 1 − received/expected over 8 sessions, weight 9.0 then ÷3.0 | boringtun `Tunn::estimate_loss`, identical to the original's 0x180020d00 |
| Ping | round trip of the last handshake | boringtun `Tunn::stats` (`last_rtt`) |
| Connected | when a handshake has completed (time since last handshake is known) | boringtun `Tunn::stats` |
| Timer tick | 100 ms | this app (estimated; boringtun asks for regular `update_timers` calls) |
| Status report | every 1 s | original's 1 s statistics period |
| Default MTU | 1420 | WireGuard default (estimated) |
| Routes | AllowedIPs minus non-tunneled networks, LAN (if bypassed) and the server's own address; /0 split into two /1 halves | this app |
| Elevation | one administrator prompt per connect (UAC, pkexec or macOS password) | this app |
| Tunnel outlives the window | yes, unless "Disconnect VPN when app closes" is on; the app picks a running tunnel back up on start | matches the original's service behaviour |

## SOCKS5 proxy (wgbooster `proxy::socks5_udp_client`)

| Rule | Value | Source |
|---|---|---|
| Method | RFC 1928 UDP ASSOCIATE; every WireGuard datagram carries a SOCKS5 UDP header naming the server | `associate_to_socks5_proxy` 0x1802704a0, `process_client_to_server_packet` 0x18026e1d0 |
| Login | none, or RFC 1929 username/password (each at most 255 bytes) | strings 0x180270a60–0x180270d80, 0x180270c40 |
| Refusals | proxy that doesn't resolve, or proxy and server in different address families: the profile is refused rather than run unproxied | strings 0x18026a710, 0x18026a790 |
| Proxy loss | association ends when the control connection closes; the tunnel restarts | `liveness probe: restarting failed SOCKS5 proxy` 0x180270218 |
| Connect timeout | 10 s | estimated |
| Socks5ProxyAllTraffic | all WireGuard traffic goes through the proxy either way | estimated (help text only) |

## Kill Switch / network lock

| Rule | Value | Source |
|---|---|---|
| Modes | disabled / enabled | `WgbNetworkLockMode` (wiresock.core.library) |
| Lifted on normal disconnect | unless "Keep network blocked" (preserve) is on | `wgb_drop_tunnel(preserve_network_lock)` |
| Manual reset | Unlock button, with confirmation by default | `wg_reset_network_lock`, setting `ConfirmUnlockNetwork` = true |
| Bar colours | #A9A9A9 armed, #CD5C5C blocking | MainWindow XAML |
| Allowed while locked | tunnel adapter, VPN server (or proxy), loopback, DHCP/DHCPv6, LAN when bypassed | this app (estimated list) |
| How | Windows Firewall default-outbound-block plus allow rules; nftables table on Linux; pf anchor on macOS | this app |

## Per-app split tunnelling

| Rule | Value | Source |
|---|---|---|
| Matching | name with or without .exe, full path, or folder (paths with slashes) | help text `xstrToolTipWgConfigAllowedApplications` |
| Both lists set | tunneled apps take priority | same |
| Linux | cgroup v2 + nftables mark 0x5354 + routing table 0x5354, programs checked every 1 s | this app |
| macOS | Network Extension (transparent proxy, system extension) in Secure Tunnel.app: apps that skip the tunnel are relayed out a physical interface, the rest follow the tunnel's routes. Developer ID signed and notarized; approved once in System Settings | this app (macos/) |
| Android | VpnService allowed / disallowed applications (package names) | this app (mobile/android) |
| Windows (original) | packet filter on its NDISAPI driver `ndiswgc.sys`: each packet's program is found from the IP Helper owner-module tables (GetExtendedTcpTable / GetExtendedUdpTable); tunneled programs' packets are encrypted with address rewriting, the others re-injected on the default adapter; DNS on the default adapter redirected | wgbooster.dll: `iphelper::process_lookup`, `wg_dual_tunnel`, `fdt::rewrite_params`, "inject bypass packet to default adapter" |
| Windows x64 (this app) | WinDivert filter on the NETWORK layer: each packet's program is found from the IP Helper owner tables (GetExtendedTcpTable / GetExtendedUdpTable), matched packets have their source rewritten to the interior address and their TCP MSS clamped before entering the tunnel, replies are rewritten back and injected inbound; tunnelled apps' DNS is redirected to the profile's DNS server. No Wintun adapter or tunnel routes in this mode; the kill switch is not combined with it | `src/winfilter.rs` (WinDivert 2.2.2); checksum/NAT/MSS/CIDR logic unit-tested, driver path not runtime-verified |
| Windows ARM64 (this app) | not applied: WinDivert ships no signed ARM64 driver | — |

## AmneziaWG I1–I5

Tags `<b 0xHEX>`, `<r N>`, `<rc N>`, `<rd N>`, `<t>`, `<c>`; sent in order before each handshake,
after the look-alike packet and before the junk packets (AmneziaWG 1.5 format; order estimated).

## Tray / menu bar

| Rule | Value | Source |
|---|---|---|
| Close button | hides to the tray (menu bar on macOS) when "Minimize to system tray when closed" is on | `Settings.MinimizeToTray` = true |
| Quit | only "Exit" in the tray menu | person's request; original tray menu has Exit |
| Menu | [icon] active profile (connects/disconnects); Profiles submenu (each profile, active one marked; Import profile...); Connect/Disconnect; Preferences; Open app/Hide app; Exit, with separators as in the original | `SysTrayMenu` in NotifyIconResources.xaml; `NotifyIconViewModel` |
| Profile switching from the menu | only while disconnected | `SelectProfileCommand` can-execute |
| Closing the main window with Preferences open | Preferences closes too and both go to the tray (asks first if a profile edit is unsaved); same for "Hide app" | ours: Preferences is drawn by the main window and froze while it was hidden |
| Left click on the tray icon | shows or hides the window; double click opens it (Windows) | `LeftClickCommand`, `DoubleClickCommand` |
| Interface scale | 80-160 % in 10 % steps; applied when the slider is let go; windows are resized one frame later, once the new scale is in effect (sizing in the same frame used the old scale) | ours |
| Notifications | on connect and disconnect | `Settings.ShowTrayNotifications` = true |
| Start minimized | starts hidden in the tray | `Settings.StartMinimized` = false |
| Refresh | 1 s timer on the main thread (Windows, macOS) or the tray thread (Linux) | this app |

## TCP termination on connect

| Rule | Value | Source |
|---|---|---|
| Default | off | `Settings.TCPSocketTermination` |
| What closes | established TCP connections to addresses the tunnel now carries, after the first handshake | help text `xstrTcpSocketTerminationDescFull` |
| How | Windows SetTcpEntry (IPv4), Linux `ss -K`; not possible on macOS | this app |

## macOS approvals

Extension approval is requested on first launch and System Settings opens at the right page;
macOS only allows fully silent approval through MDM (`macos/SecureTunnel-preapproval.mobileconfig`).

## Former Pro features (free here)

| Feature | Rule | Source |
|---|---|---|
| Profile encryption | `<name>.dapi`; Windows DPAPI for the current user with no extra entropy (same as the original, files interchangeable); macOS/Linux AES-256-GCM with a key in the login keychain / Secret Service (key file fallback). Turning it on or off converts every profile | `EncryptedFile.Encrypt/Decrypt`, `WireSockProfileManager.EncryptDecryptProfiles` (wiresock.core.library) |
| App view customization | hide Logs, Feedback and Import buttons, connection statistics, Security/Logs/Feedback/About tabs, server name; plain or detailed tray tooltip | `AdvancedSettingsPage` XAML (ProBadge) |

## Other parity additions

| Feature | Rule | Source |
|---|---|---|
| Connect at system startup | Windows scheduled task at startup as SYSTEM; Linux systemd service; macOS LaunchDaemon; runs the engine with the selected profile; the window picks it up at sign-in | `xstrGeneralAutoConnectService` |
| Confirm disconnect on exit | default on; asked when Exit would disconnect | `Settings.ConfirmDisconnectOnShutdown` = true |
| Log files | `logs/secure-tunnel.log`, moved to `.1.log` past 5 MB; "Open folder" on the Logs page | `xstrOpenFolderWithLogFiles` (size estimated) |
| Select process | running programs with paths; double-click adds the name, "Add path" the full path | `ProcessListWnd` |
| Masking domains | preset list for Id, editable ("Manage combo box domains") | `Settings.PreferredMaskingDomains`, `DomainListDialog` |

## Themes and builds

| Item | Rule | Source |
|---|---|---|
| Dark theme | original's #202020 window and #2B2B2B cards; text raised to #F5F5F5, descriptions #D0D0D0 at 12.5 px (was #DADADA at 11.5 px) for easier reading | original screenshots; readability change is ours |
| Light theme | #F3F3F3 window, white cards, #1A1A1A text, #4A4A4A descriptions; switches off = white with grey outline | estimated (Windows 11 light) |
| Theme choice | System, Light or Dark (General page); follows the OS when System | `Settings.Theme` |
| Windows builds | x64 (MSVC) and ARM64 (aarch64-pc-windows-gnullvm with the open-source llvm-mingw toolchain; needs only Windows' own DLLs); the matching Wintun DLL is built in for each | `build/windows/`, import table checked |
| Linux builds | x86-64 and ARM64, built with cargo-zigbuild against glibc 2.31 (uses symbols up to 2.30); only libc is linked, graphics and desktop libraries load at run time | build setting |
| Linux packages | `packaging/linux/build-packages.py` makes, per CPU: .deb (Debian, Ubuntu, Mint, Kali), .rpm (Fedora, RHEL family, openSUSE; libraries required by file name), Arch .pkg.tar.zst (plus PKGBUILD), and a .tar.gz with install.sh for anything else | build setting |
| Linux run-time tools | ip and ss (iproute2), nft (nftables), pkexec (polkit), sysctl (procps), xdg-open; optional secret-tool, resolvectl | `engine.rs`, `netlock.rs`, `apps.rs`, `tcpkill.rs` |
| macOS build | one universal app: the program, its launcher and the per-app routing extension are each x86_64 + arm64; Developer ID signed, notarized and stapled (Gatekeeper: "Notarized Developer ID") | `lipo -archs`, `spctl -a -vv` on the installed app |
| Shared packet path | `src/datapath.rs`: AmneziaWG headers and padding, junk / look-alike / I-packets, and the adapter-network loops; used by the desktop engine and meant for the phone apps | test `masked_tunnel_end_to_end`: two ends over UDP with Jc 5, S1-S4, H1-H4 ranges and I1 complete a handshake and pass a packet |
| Phone tunnel core | `mobile/core`: compiles the desktop packet path, DPI protection, SOCKS5 and profile files unchanged; C interface (iOS, `include/securetunnel.h`) and JNI (Android, `com.securetunnel.app.TunnelCore`); Android sockets go through `VpnService.protect` first; iOS reads the utun descriptor with its 4-byte family prefix | 14 tests pass on Windows and macOS; builds for aarch64-apple-ios, aarch64-apple-ios-sim; type-checks for Android arm64, armv7, x86_64 |
| Android app | `mobile/android` (Java, no extra libraries): VpnService builds the adapter from the core's plan (addresses, DNS, routes, MTU, AllowedApps/DisallowedApps as package names), then the core runs the tunnel; kill switch = Android's Always-on VPN + "Block connections without VPN" (declared `SUPPORTS_ALWAYS_ON`); import .conf by file picker, "Open with" or share; profile switching only while disconnected | APK `build/android/secure-tunnel-0.1.0.apk`, minSdk 26 (Android 8), targetSdk 36, arm64 / armv7 / x86_64, debug-key signed for sideloading |
| Profile formats | plain WireGuard and AmneziaWG (Jc/Jmin/Jmax, S1-S4, H1-H4 single values or ranges, I1-I5); keys this app doesn't use are ignored | tests `amneziawg_profile_imports_and_masks`, `plain_wireguard_profile_imports` |

## What this version doesn't enforce

Per-app split tunnelling on Windows ARM64 (no signed WinDivert driver; it works on Windows x64),
TCP termination on macOS, interface languages other than English, external IP and location
display, licensing, auto-update and online feedback.
