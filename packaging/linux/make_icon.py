"""Draws the app icon (blue shield with a keyhole, as in src/icons.rs) as PNGs.

    python -I make_icon.py <output folder>
"""
import struct
import sys
import zlib
from pathlib import Path


def shield(n: int) -> bytes:
    rows = []
    for y in range(n):
        row = bytearray([0])
        for x in range(n):
            # 4x4 supersampling for smooth edges.
            cov = 0
            hole = 0
            for sy in range(4):
                for sx in range(4):
                    fx = (x + (sx + 0.5) / 4) / n
                    fy = (y + (sy + 0.5) / 4) / n
                    dx = abs(fx - 0.5)
                    inside = 0.06 <= fy <= 0.96 and (dx < 0.42 if fy < 0.55 else dx < 0.42 * (0.96 - fy) / 0.41)
                    if inside:
                        cov += 1
                        if ((fx - 0.5) ** 2 + (fy - 0.44) ** 2) ** 0.5 < 0.12 or (dx < 0.04 and 0.44 <= fy < 0.70):
                            hole += 1
            a = cov / 16
            h = hole / cov if cov else 0
            r = round(0x2B + (255 - 0x2B) * h)
            g = round(0x6C + (255 - 0x6C) * h)
            b = round(0xD6 + (255 - 0xD6) * h)
            row += bytes([r, g, b, round(a * 255)])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(t: bytes, d: bytes) -> bytes:
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", n, n, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b"")
    )


if __name__ == "__main__":
    out = Path(sys.argv[1])
    for size in (48, 128, 256):
        d = out / f"{size}x{size}"
        d.mkdir(parents=True, exist_ok=True)
        (d / "secure-tunnel.png").write_bytes(shield(size))
