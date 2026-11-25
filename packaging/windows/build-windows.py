"""Builds the Windows downloads: a portable .exe and an .msi installer for x64 and ARM64.

    python -I packaging/windows/build-windows.py [--arch x64|arm64] [--skip-build]

Needs: Rust with the x86_64-pc-windows-msvc and aarch64-pc-windows-msvc targets,
Visual Studio Build Tools with the x64 and ARM64 C++ libraries, and WiX 5:
    dotnet tool install --global wix --version 5.0.2
    wix extension add -g WixToolset.UI.wixext/5.0.2
Output goes to dist/windows/, with a SHA256SUMS file.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = ROOT / "packaging" / "windows"
OUT = ROOT / "dist" / "windows"
# ARM64 uses the LLVM/MinGW toolchain (llvm-mingw): it cross-compiles from an x64 PC
# without Visual Studio's optional ARM64 build tools, and gives the ring crate the
# clang it needs. Set LLVM_MINGW to its folder, or install it under
# %LOCALAPPDATA%\Programs\llvm-mingw-*.
ARCHES = {"x64": "x86_64-pc-windows-msvc", "arm64": "aarch64-pc-windows-gnullvm"}


def llvm_mingw_env() -> dict[str, str]:
    root = os.environ.get("LLVM_MINGW")
    if not root:
        found = sorted((Path(os.environ.get("LOCALAPPDATA", "")) / "Programs").glob("llvm-mingw-*"))
        if not found:
            sys.exit("build-windows: llvm-mingw not found; set LLVM_MINGW to its folder")
        root = str(found[-1])
    b = Path(root) / "bin"
    return {
        "CC_aarch64_pc_windows_gnullvm": str(b / "aarch64-w64-mingw32-clang.exe"),
        "AR_aarch64_pc_windows_gnullvm": str(b / "llvm-ar.exe"),
        "CARGO_TARGET_AARCH64_PC_WINDOWS_GNULLVM_LINKER": str(b / "aarch64-w64-mingw32-clang.exe"),
        "WINDRES": str(b / "aarch64-w64-mingw32-windres.exe"),
        "WINDRES_AR": str(b / "llvm-ar.exe"),
    }


def version() -> str:
    text = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def find_wix() -> str:
    found = shutil.which("wix")
    if found:
        return found
    candidate = Path.home() / ".dotnet" / "tools" / "wix.exe"
    if candidate.is_file():
        return str(candidate)
    sys.exit("build-windows: WiX not found. Install it with: dotnet tool install --global wix --version 5.0.2")


def remap_flags() -> dict[str, str]:
    """Keeps the home and repo folders out of the binaries (Rust embeds source paths)."""
    if os.environ.get("CARGO_ENCODED_RUSTFLAGS") or os.environ.get("RUSTFLAGS"):
        return {}
    flags = [f"--remap-path-prefix={Path.home()}=~", f"--remap-path-prefix={ROOT}=/build/secure-tunnel"]
    return {"CARGO_ENCODED_RUSTFLAGS": "\x1f".join(flags)}


def run(*cmd: str, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, check=True, cwd=ROOT, env={**os.environ, **(env or {})})


def main(argv: list[str]) -> int:
    arches = [argv[argv.index("--arch") + 1]] if "--arch" in argv else list(ARCHES)
    skip_build = "--skip-build" in argv
    ver = version()
    wix = find_wix()
    target_dir = Path(os.environ.get("CARGO_TARGET_DIR") or ROOT / "target")
    OUT.mkdir(parents=True, exist_ok=True)
    made: list[Path] = []
    for arch in arches:
        triple = ARCHES[arch]
        if not skip_build:
            env = {**remap_flags(), **(llvm_mingw_env() if triple.endswith("gnullvm") else {})}
            run("cargo", "build", "--release", "--locked", "--target", triple, env=env)
        exe = target_dir / triple / "release" / "secure-tunnel.exe"
        portable = OUT / f"secure-tunnel-{ver}-windows-{arch}.exe"
        shutil.copyfile(exe, portable)
        msi = OUT / f"secure-tunnel-{ver}-windows-{arch}.msi"
        run(wix, "build", str(HERE / "secure-tunnel.wxs"), "-arch", arch,
            "-ext", "WixToolset.UI.wixext",
            "-d", f"Version={ver}", "-d", f"ExePath={exe}", "-d", f"RootDir={ROOT}",
            "-d", f"IconPath={HERE / 'secure-tunnel.ico'}", "-d", f"LicenseRtf={HERE / 'license.rtf'}",
            "-o", str(msi))
        pdb = msi.with_suffix(".wixpdb")
        if pdb.exists():
            pdb.unlink()
        made += [portable, msi]
    sums = OUT / "SHA256SUMS"
    existing = {}
    if sums.exists():
        for line in sums.read_text(encoding="utf-8").splitlines():
            digest, name = line.split(None, 1)
            existing[name.strip()] = digest
    for f in made:
        existing[f.name] = hashlib.sha256(f.read_bytes()).hexdigest()
    sums.write_text("".join(f"{d}  {n}\n" for n, d in sorted(existing.items())), encoding="utf-8")
    for f in made:
        print(f"built {f.relative_to(ROOT)} ({f.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
