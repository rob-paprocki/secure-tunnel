#!/bin/sh
# Installs Secure Tunnel from this folder on any Linux with glibc 2.30 or later
# (for distributions without a .deb, .rpm or Arch package). Run as root:
#   sudo ./install.sh            install to /usr/local
#   sudo ./install.sh --remove   uninstall
set -e
PREFIX=${PREFIX:-/usr/local}
HERE=$(cd "$(dirname "$0")" && pwd)
if [ "$1" = "--remove" ]; then
    rm -f "$PREFIX/bin/secure-tunnel" "$PREFIX/share/applications/secure-tunnel.desktop"
    for s in 48 128 256; do rm -f "$PREFIX/share/icons/hicolor/${s}x${s}/apps/secure-tunnel.png"; done
    echo "Secure Tunnel removed."
    exit 0
fi
install -Dm755 "$HERE/secure-tunnel" "$PREFIX/bin/secure-tunnel"
install -Dm644 "$HERE/secure-tunnel.desktop" "$PREFIX/share/applications/secure-tunnel.desktop"
for s in 48 128 256; do
    install -Dm644 "$HERE/icons/${s}x${s}/secure-tunnel.png" "$PREFIX/share/icons/hicolor/${s}x${s}/apps/secure-tunnel.png"
done
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q "$PREFIX/share/applications" || true
echo "Secure Tunnel installed. It also needs: ip and ss (iproute2), nft (nftables), pkexec (polkit), xdg-open."
for t in ip ss nft pkexec xdg-open; do
    command -v "$t" >/dev/null 2>&1 || echo "  missing: $t"
done
