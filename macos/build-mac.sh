#!/bin/zsh
# Builds the macOS downloads for Secure Tunnel: one universal app (Apple silicon
# and Intel), signed, notarized and stapled, as a .zip, a .dmg and a .pkg.
#
# Run it from a logged-in desktop session (Terminal), not over SSH: signing needs
# the unlocked login keychain, and Xcode must be signed in to the developer account.
#
#   ./macos/build-mac.sh             build everything into dist/macos/
#   ./macos/build-mac.sh --install   ... and copy the app to /Applications
#
# Needs, once per Mac:
#   - "Developer ID Application" and "Developer ID Installer" certificates in the keychain
#   - a notarytool profile for the .dmg and .pkg (the app itself is notarized through Xcode):
#       xcrun notarytool store-credentials secure-tunnel-notary --apple-id <APPLE_ID> --team-id <TEAM_ID>
#     (asks for an app-specific password). Set NOTARY_PROFILE to use another profile name.
set -euo pipefail
ROOT=${0:A:h:h}
OUT=$ROOT/build/mac
DIST=$ROOT/dist/macos
# Optional local settings (e.g. NOTARY_PROFILE=...), kept out of the public copy.
[[ -f $ROOT/private/macos/build.env ]] && source $ROOT/private/macos/build.env
NOTARY_PROFILE=${NOTARY_PROFILE:-secure-tunnel-notary}
NOTARY_PROFILE=${NOTARY_PROFILE%$'\r'}  # a settings file saved with Windows line endings
VERSION=$(tr -d '\r' < $ROOT/Cargo.toml | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Cargo.toml version '$VERSION' isn't X.Y.Z" >&2; exit 1; }
BUILD_NUMBER=${BUILD_NUMBER:-$(date +%Y%m%d%H%M)}
mkdir -p $OUT $DIST

APP_ID=$(security find-identity -v -p codesigning | awk -F'"' '/Developer ID Application/{print $2; exit}')
PKG_ID=$(security find-identity -v -p basic | awk -F'"' '/Developer ID Installer/{print $2; exit}')
[[ -n $APP_ID ]] || { echo "No 'Developer ID Application' certificate in the keychain." >&2; exit 1; }
[[ -n $PKG_ID ]] || { echo "No 'Developer ID Installer' certificate in the keychain." >&2; exit 1; }
xcrun notarytool history --keychain-profile "$NOTARY_PROFILE" >/dev/null 2>&1 || {
  echo "notarytool profile '$NOTARY_PROFILE' is missing or the keychain is locked." >&2
  echo "Create it with: xcrun notarytool store-credentials $NOTARY_PROFILE --apple-id <APPLE_ID> --team-id <TEAM_ID>" >&2
  exit 1
}
echo "Building Secure Tunnel $VERSION (build $BUILD_NUMBER)"

# 1. The Rust window program, for both CPU types, joined into one file.
cd $ROOT
. ~/.cargo/env
rustup target add aarch64-apple-darwin x86_64-apple-darwin >/dev/null
cargo build --release --locked --target aarch64-apple-darwin
cargo build --release --locked --target x86_64-apple-darwin
mkdir -p target/release
lipo -create -output target/release/secure-tunnel \
  target/aarch64-apple-darwin/release/secure-tunnel target/x86_64-apple-darwin/release/secure-tunnel
lipo -info target/release/secure-tunnel

# 2. The app bundle and network extension, archived, then notarized through Xcode.
cd $ROOT/macos
rm -rf $OUT/SecureTunnel.xcarchive $OUT/upload $OUT/notarized
xcodebuild -project SecureTunnel.xcodeproj -scheme SecureTunnel -configuration Release \
  -archivePath $OUT/SecureTunnel.xcarchive -allowProvisioningUpdates \
  MARKETING_VERSION=$VERSION CURRENT_PROJECT_VERSION=$BUILD_NUMBER archive
cat > $OUT/upload.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>method</key><string>developer-id</string>
<key>signingStyle</key><string>automatic</string>
<key>destination</key><string>upload</string>
</dict></plist>
PLIST
xcodebuild -exportArchive -archivePath $OUT/SecureTunnel.xcarchive -exportOptionsPlist $OUT/upload.plist \
  -exportPath $OUT/upload -allowProvisioningUpdates
for i in $(seq 1 90); do
  sleep 20
  if xcodebuild -exportNotarizedApp -archivePath $OUT/SecureTunnel.xcarchive -exportPath $OUT/notarized >/dev/null 2>&1; then
    echo "App notarized."
    break
  fi
done
APP="$OUT/notarized/Secure Tunnel.app"
test -d "$APP"
xcrun stapler validate "$APP"
lipo -info "$APP/Contents/MacOS/secure-tunnel-ui" | grep -q "x86_64 arm64\|arm64 x86_64"
BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$APP/Contents/Info.plist")
NAME=secure-tunnel-$VERSION-macos-universal

notarize() {  # notarize and staple one .dmg or .pkg
  xcrun notarytool submit "$1" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$1"
  xcrun stapler validate "$1"
}

# 3. Zip of the app (for people who just want to drag it into Applications).
rm -f $DIST/$NAME.zip
ditto -c -k --keepParent "$APP" $DIST/$NAME.zip

# 4. Disk image with the app and a link to /Applications.
STAGE=$OUT/dmg
rm -rf $STAGE && mkdir -p $STAGE
ditto "$APP" "$STAGE/Secure Tunnel.app"
ln -s /Applications $STAGE/Applications
rm -f $DIST/$NAME.dmg
hdiutil create -volname "Secure Tunnel $VERSION" -srcfolder $STAGE -ov -format UDZO $DIST/$NAME.dmg
codesign --force --timestamp --sign "$APP_ID" $DIST/$NAME.dmg
notarize $DIST/$NAME.dmg

# 5. Installer package that puts the app in /Applications.
rm -f $OUT/component.pkg $DIST/$NAME.pkg
pkgbuild --component "$APP" --install-location /Applications \
  --identifier "$BUNDLE_ID.pkg" --version $VERSION $OUT/component.pkg
productbuild --package $OUT/component.pkg --sign "$PKG_ID" --timestamp $DIST/$NAME.pkg
notarize $DIST/$NAME.pkg
spctl --assess --type install -vv $DIST/$NAME.pkg

# 6. Checksums.
cd $DIST
shasum -a 256 $NAME.zip $NAME.dmg $NAME.pkg > SHA256SUMS
cat SHA256SUMS

if [[ "${1:-}" == "--install" ]]; then
  rm -rf "/Applications/Secure Tunnel.app"
  ditto "$APP" "/Applications/Secure Tunnel.app"
  echo "Installed in /Applications."
fi
