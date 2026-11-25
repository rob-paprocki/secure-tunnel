# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-11-25

**Upgrading:** nothing to do.

### Changed

- The Mac app's project files now use the real Apple Team ID and bundle IDs. Every signed copy of the app already shows them.
- The README's Releases and Issues links use full GitHub addresses, so they also work when the README is read outside GitHub.

### Fixed

- The repository's own `CONTRIBUTING.md` and `SECURITY.md` were copies of the account-wide ones and are gone, so GitHub now shows the account-wide versions and they stay current.

## [1.0.0] - 2026-11-21

**Upgrading:** nothing to do.

### Added

- First release: a WireGuard and AmneziaWG client for Windows, macOS, Linux and Android.
- Built-in tunnel engine and virtual network adapter, so nothing else needs installing.
- Junk packets and optional I1–I5 packets sent before each handshake. Any WireGuard server ignores them, so they help against deep packet inspection without server changes.
- Protocol masking that makes the first packet look like QUIC, DNS, SIP or STUN traffic. It also works with any WireGuard server.
- AmneziaWG padding and header values (S1–S4, H1–H4) for servers that run AmneziaWG.
- SOCKS5 proxy transport for tunnel traffic, with optional login.
- Kill switch that blocks everything outside the tunnel, even if the tunnel crashes. On Windows it uses the Windows Filtering Platform, so allow rules from other apps can't get around it; Linux uses nftables and macOS uses pf.
- Per-app routing on Linux, macOS, Android and Windows x64.
- Closes open TCP connections on connect (Windows and Linux), so apps reconnect through the tunnel.
- Encrypted profile storage.
- Tray and menu-bar icon, light and dark themes, interface scaling, and connect at startup.
- Android app with a full profile editor, a key generator, split tunnelling by app (system apps included), logs, and settings. Android Auto is left out of the VPN by default.
- Windows installers (`.msi`) and portable `.exe` files for x64 and ARM64.
- A universal macOS app for Apple silicon and Intel, signed and notarized, as a `.dmg` and a `.pkg`.
- Linux packages: `.deb`, `.rpm`, Arch and a portable tarball for x64 and ARM64, plus an AppImage and a Flatpak bundle for x64.
- A signed Android APK for arm64, 32-bit ARM and x86_64 phones.

[Unreleased]: https://github.com/rob-paprocki/secure-tunnel/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/rob-paprocki/secure-tunnel/releases/tag/v1.0.0
