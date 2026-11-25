"""Builds the Android download: dist/android/secure-tunnel-<version>-android.apk.

    python packaging/android/build-android.py [--debug-key]

Steps: the Rust tunnel core for arm64-v8a, armeabi-v7a and x86_64 (cargo ndk),
then the app (Gradle assembleRelease), signed with the release key, checked
with apksigner.

Needs: the Android SDK (ANDROID_HOME) with build-tools and NDK (ANDROID_NDK_HOME),
JDK 17+ (JAVA_HOME), cargo-ndk, and Rust's Android targets. On the owner's PC
the defaults below find them.

Release key: ST_KEYSTORE (default ~/.android/secure-tunnel-release.jks). Its
password comes from ST_KEYSTORE_PASSWORD or, if that's unset, from the system
credential store via the Python keyring package (service
"secure-tunnel-android-release", user "keystore"). Every release must use the
same key, or updates won't install over the old version. --debug-key builds
with the debug key instead, for testing only.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import site
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ANDROID = ROOT / "mobile" / "android"
CORE = ROOT / "mobile" / "core"
OUT = ROOT / "dist" / "android"
LOCAL = Path(os.environ.get("LOCALAPPDATA", ""))
WINDOWS = os.name == "nt"


def version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8").replace("\r", "")
    v = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)
    if not re.fullmatch(r"\d+\.\d+\.\d+", v):
        sys.exit(f"build-android: Cargo.toml version {v!r} isn't X.Y.Z")
    return v


def first_existing(*candidates: Path) -> str | None:
    for c in candidates:
        if c and c.exists():
            return str(c)
    return None


def toolchain_env() -> dict[str, str]:
    env = dict(os.environ)
    sdk = env.get("ANDROID_HOME") or first_existing(LOCAL / "Android" / "Sdk")
    if not sdk:
        sys.exit("build-android: set ANDROID_HOME to the Android SDK")
    env["ANDROID_HOME"] = sdk
    if not env.get("ANDROID_NDK_HOME"):
        ndks = sorted((Path(sdk) / "ndk").glob("*"))
        if not ndks:
            sys.exit("build-android: no NDK under ANDROID_HOME/ndk; set ANDROID_NDK_HOME")
        env["ANDROID_NDK_HOME"] = str(ndks[-1])
    if not env.get("JAVA_HOME"):
        jdks = sorted((LOCAL / "Programs").glob("jdk-*"))
        if jdks:
            env["JAVA_HOME"] = str(jdks[-1])
    return env


def keystore_password() -> str:
    pw = os.environ.get("ST_KEYSTORE_PASSWORD")
    if pw:
        return pw
    try:
        import keyring
    except ImportError:
        # keyring is usually a per-user install; make sure that folder is searched.
        sys.path.append(site.getusersitepackages())
        try:
            import keyring
        except ImportError:
            sys.exit("build-android: set ST_KEYSTORE_PASSWORD or install keyring (pip install --user keyring)")
    pw = keyring.get_password("secure-tunnel-android-release", "keystore")
    if not pw:
        sys.exit("build-android: no keystore password in the credential store")
    return pw


def run(cmd: list[str], cwd: Path, env: dict[str, str]) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def build_tools(sdk: str) -> Path:
    found = sorted((Path(sdk) / "build-tools").glob("*"))
    if not found:
        sys.exit("build-android: no build-tools in the Android SDK")
    return found[-1]


def main(argv: list[str]) -> int:
    ver = version()
    major, minor, patch = (int(x) for x in ver.split("."))
    env = toolchain_env()
    if not (env.get("CARGO_ENCODED_RUSTFLAGS") or env.get("RUSTFLAGS")):
        # Keep the home and repo folders out of the native library (Rust embeds source paths).
        env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
            [f"--remap-path-prefix={Path.home()}=~", f"--remap-path-prefix={ROOT}=/build/secure-tunnel"])
    env["ST_VERSION_NAME"] = ver
    env["ST_VERSION_CODE"] = str(major * 10000 + minor * 100 + patch)
    if "--debug-key" not in argv:
        ks = Path(os.environ.get("ST_KEYSTORE") or Path.home() / ".android" / "secure-tunnel-release.jks")
        if not ks.is_file():
            sys.exit(f"build-android: release keystore {ks} not found (or pass --debug-key for a test build)")
        env["ST_KEYSTORE"] = str(ks)
        env["ST_KEYSTORE_PASSWORD"] = keystore_password()

    run(["cargo", "ndk", "-t", "arm64-v8a", "-t", "armeabi-v7a", "-t", "x86_64", "-P", "26",
         "-o", str(ANDROID / "app" / "src" / "main" / "jniLibs"), "build", "--release", "--locked"], CORE, env)
    gradlew = str(ANDROID / ("gradlew.bat" if WINDOWS else "gradlew"))
    run([gradlew, "--no-daemon", "clean", "assembleRelease"], ANDROID, env)

    apk_in = ANDROID / "app" / "build" / "outputs" / "apk" / "release" / "app-release.apk"
    OUT.mkdir(parents=True, exist_ok=True)
    apk = OUT / f"secure-tunnel-{ver}-android.apk"
    shutil.copyfile(apk_in, apk)

    apksigner = build_tools(env["ANDROID_HOME"]) / ("apksigner.bat" if WINDOWS else "apksigner")
    res = subprocess.run([str(apksigner), "verify", "--print-certs", str(apk)], env=env,
                         capture_output=True, text=True, check=True)
    for line in res.stdout.splitlines():
        if "SHA-256" in line or "DN:" in line:
            print("  " + line.strip())
    (OUT / "SHA256SUMS").write_text(f"{hashlib.sha256(apk.read_bytes()).hexdigest()}  {apk.name}\n", encoding="utf-8")
    print(f"built {apk.relative_to(ROOT)} ({apk.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
