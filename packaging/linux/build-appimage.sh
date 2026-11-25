#!/usr/bin/env bash
# Builds dist/linux/secure-tunnel-<version>-x86_64.AppImage from the release binary.
# Runs on Linux x86-64. Build the binary first:
#   cargo zigbuild --release --locked --target x86_64-unknown-linux-gnu.2.31
#
# The graphics and desktop libraries are loaded from the system at run time, as
# with the .deb and .rpm, so the AppImage holds only the program, its icon and
# its desktop entry.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)
TARGET_DIR=${CARGO_TARGET_DIR:-$ROOT/target}
BIN=$TARGET_DIR/x86_64-unknown-linux-gnu/release/secure-tunnel
OUT=$ROOT/dist/linux
WORK=$ROOT/build/appimage
TOOL_URL=https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage
TOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0

[[ -x $BIN ]] || { echo "missing $BIN; build it first (see the top of this file)" >&2; exit 1; }
rm -rf "$WORK" && mkdir -p "$WORK" "$OUT"

TOOL=$WORK/appimagetool
curl -sSfL -o "$TOOL" "$TOOL_URL"
echo "$TOOL_SHA256  $TOOL" | sha256sum -c -
chmod +x "$TOOL"

APPDIR=$WORK/SecureTunnel.AppDir
install -Dm755 "$BIN" "$APPDIR/usr/bin/secure-tunnel"
install -Dm644 "$ROOT/packaging/linux/secure-tunnel.desktop" "$APPDIR/usr/share/applications/secure-tunnel.desktop"
for s in 48 128 256; do
  install -Dm644 "$ROOT/packaging/linux/icons/${s}x${s}/secure-tunnel.png" \
    "$APPDIR/usr/share/icons/hicolor/${s}x${s}/apps/secure-tunnel.png"
done
install -Dm644 "$ROOT/LICENSE" "$APPDIR/usr/share/doc/secure-tunnel/LICENSE"
install -Dm644 "$ROOT/THIRD_PARTY.md" "$APPDIR/usr/share/doc/secure-tunnel/THIRD_PARTY.md"
install -Dm644 "$ROOT/packaging/linux/org.securetunnel.SecureTunnel.metainfo.xml" \
  "$APPDIR/usr/share/metainfo/secure-tunnel.appdata.xml"
cp "$APPDIR/usr/share/applications/secure-tunnel.desktop" "$APPDIR/"
cp "$APPDIR/usr/share/icons/hicolor/256x256/apps/secure-tunnel.png" "$APPDIR/secure-tunnel.png"
ln -s usr/bin/secure-tunnel "$APPDIR/AppRun"

NAME=secure-tunnel-$VERSION-x86_64.AppImage
# --appimage-extract-and-run: CI runners have no FUSE.
ARCH=x86_64 "$TOOL" --appimage-extract-and-run --no-appstream "$APPDIR" "$OUT/$NAME"
echo "built dist/linux/$NAME"
