"""Writes the Windows icon (packaging/windows/secure-tunnel.ico) from the same
drawing as the Linux icons, with PNG frames from 16 to 256 pixels.

    python -I packaging/windows/make_ico.py
"""
import importlib.util
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("make_icon", HERE.parent / "linux" / "make_icon.py")
make_icon = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(make_icon)

SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def ico(sizes=SIZES) -> bytes:
    frames = [make_icon.shield(n) for n in sizes]
    header = struct.pack("<HHH", 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    entries = b""
    for n, png in zip(sizes, frames):
        dim = 0 if n >= 256 else n  # 0 means 256 in an ICO directory entry
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
    return header + entries + b"".join(frames)


if __name__ == "__main__":
    out = HERE / "secure-tunnel.ico"
    out.write_bytes(ico())
    print(f"wrote {out.relative_to(HERE.parent.parent)}")
