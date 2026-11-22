"""Writes the macOS app icon (macos/App/AppIcon.icns) from the same drawing as the
Linux and Windows icons, with PNG entries from 16 to 1024 pixels.

    python -I macos/make_icns.py
"""
import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("make_icon", HERE.parent / "packaging" / "linux" / "make_icon.py")
make_icon = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(make_icon)

# ICNS entry type -> pixel size (PNG payloads).
ENTRIES = [
    (b"icp4", 16), (b"icp5", 32), (b"ic11", 32), (b"icp6", 64), (b"ic12", 64),
    (b"ic07", 128), (b"ic08", 256), (b"ic13", 256), (b"ic09", 512), (b"ic14", 512), (b"ic10", 1024),
]


def icns() -> bytes:
    cache: dict[int, bytes] = {}
    body = b""
    for kind, size in ENTRIES:
        png = cache.setdefault(size, make_icon.shield(size))
        body += kind + struct.pack(">I", 8 + len(png)) + png
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


if __name__ == "__main__":
    out = HERE / "App" / "AppIcon.icns"
    out.write_bytes(icns())
    print(f"wrote {out.relative_to(HERE.parent)}")
