#!/usr/bin/env python3
"""Download the Windows drivers bundled into Secure Tunnel and verify them.

    python -I scripts/fetch_vendor.py [--check]

Fetches the official Wintun and WinDivert release zips, checks each zip's
SHA-256, extracts only the files the app embeds, checks each file's SHA-256,
and writes them under vendor/. Files that are already present with the right
hash are left alone. With --check, nothing is downloaded: the exit code says
whether every file is present and correct.

build.rs runs this automatically when building for Windows. The pinned hashes
are the same ones listed in THIRD_PARTY.md.
"""
from __future__ import annotations

import hashlib
import io
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENDOR = ROOT / "vendor"

# (zip URL, zip SHA-256, {path inside zip: (path under vendor/, file SHA-256)})
SOURCES = [
    (
        "https://www.wintun.net/builds/wintun-0.14.1.zip",
        "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51",
        {
            "wintun/bin/amd64/wintun.dll": ("wintun/amd64/wintun.dll", "e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce"),
            "wintun/bin/arm64/wintun.dll": ("wintun/arm64/wintun.dll", "f7ba89005544be9d85231a9e0d5f23b2d15b3311667e2dad0debd344918a3f80"),
            "wintun/bin/x86/wintun.dll": ("wintun/x86/wintun.dll", "d694fa46ab4cfebcb2632d094c7aa97278eef2f8052438621766d863ae98a931"),
        },
    ),
    (
        "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip",
        "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15",
        {
            "WinDivert-2.2.2-A/x64/WinDivert.dll": ("windivert/amd64/WinDivert.dll", "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2"),
            "WinDivert-2.2.2-A/x64/WinDivert64.sys": ("windivert/amd64/WinDivert64.sys", "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2"),
        },
    ),
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_current(rel: str, want: str) -> bool:
    path = VENDOR / rel
    return path.is_file() and sha256(path.read_bytes()) == want


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "secure-tunnel-build"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def main(argv: list[str]) -> int:
    check_only = "--check" in argv
    missing = 0
    for url, zip_hash, members in SOURCES:
        todo = {src: dst for src, dst in members.items() if not is_current(*dst)}
        if not todo:
            continue
        if check_only:
            for rel, _ in todo.values():
                print(f"fetch_vendor: missing or wrong hash: vendor/{rel}")
            missing += len(todo)
            continue
        print(f"fetch_vendor: downloading {url}")
        data = download(url)
        if sha256(data) != zip_hash:
            print(f"fetch_vendor: SHA-256 mismatch for {url}; refusing to use it", file=sys.stderr)
            return 1
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for src, (rel, want) in todo.items():
                blob = zf.read(src)
                if sha256(blob) != want:
                    print(f"fetch_vendor: SHA-256 mismatch for {src}; refusing to use it", file=sys.stderr)
                    return 1
                out = VENDOR / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                tmp = out.with_suffix(out.suffix + ".part")
                tmp.write_bytes(blob)
                tmp.replace(out)
                print(f"fetch_vendor: wrote vendor/{rel}")
    if check_only and missing:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
