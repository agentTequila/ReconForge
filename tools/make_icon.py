"""Generate ReconForge's icon (assets/icon.ico + icon.png).

Run: python tools/make_icon.py   (requires: pip install pillow)
"""

from __future__ import annotations

import math
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "assets"
BG = (13, 17, 23)        # dark slate
RING = (56, 139, 253)    # blue
SWEEP = (57, 255, 20)    # green
DOT = (255, 99, 71)      # red blip


def draw_icon(size: int) -> Image.Image:
    scale = size / 256
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # rounded dark background
    draw.rounded_rectangle([0, 0, size - 1, size - 1],
                           radius=int(48 * scale), fill=BG)

    cx = cy = size / 2
    ring_width = max(2, int(6 * scale))

    # radar rings
    for radius in (96, 64, 32):
        r = radius * scale
        draw.ellipse([cx - r, cy - r, cx + r, cy + r],
                     outline=RING, width=ring_width)

    # crosshair lines
    draw.line([cx, 16 * scale, cx, size - 16 * scale],
              fill=RING, width=max(1, int(3 * scale)))
    draw.line([16 * scale, cy, size - 16 * scale, cy],
              fill=RING, width=max(1, int(3 * scale)))

    # radar sweep (pie slice, 50 degrees)
    bbox = [cx - 96 * scale, cy - 96 * scale, cx + 96 * scale, cy + 96 * scale]
    draw.pieslice(bbox, start=-45, end=5, fill=SWEEP + (110,))
    draw.line([cx, cy, cx + 96 * scale * math.cos(math.radians(-45)),
               cy + 96 * scale * math.sin(math.radians(-45))],
              fill=SWEEP, width=max(2, int(5 * scale)))

    # blip in the sweep sector
    bx = cx + 58 * scale * math.cos(math.radians(-20))
    by = cy + 58 * scale * math.sin(math.radians(-20))
    br = 12 * scale
    draw.ellipse([bx - br, by - br, bx + br, by + br], fill=DOT)

    # center dot
    cr = 7 * scale
    draw.ellipse([cx - cr, cy - cr, cx + cr, cy + cr], fill=(230, 237, 243))
    return img


def save_ico(img: Image.Image, path: Path, sizes: list[int]) -> None:
    """Write an all-PNG-entry ICO.

    Pillow's default ICO writer stores small sizes as BMP frames with a bogus
    AND-mask, so Windows (Explorer, taskbar, Alt+Tab) renders them *without*
    the dark background - only the 256px PNG entry looked right. PNG entries
    carry their own alpha and are rendered correctly at every size.
    """
    import io
    import struct

    blobs: list[bytes] = []
    for s in sizes:
        frame = img if s == img.width else img.resize((s, s), Image.LANCZOS)
        buf = io.BytesIO()
        frame.save(buf, "PNG")
        blobs.append(buf.getvalue())

    count = len(blobs)
    header = struct.pack("<HHH", 0, 1, count)  # reserved, type=icon, count
    offset = 6 + 16 * count
    directory = b""
    for s, blob in zip(sizes, blobs, strict=True):
        dim = 0 if s >= 256 else s  # 0 means 256 in ICO directory
        directory += struct.pack(
            "<BBBBHHII", dim, dim, 0, 0, 1, 32, len(blob), offset
        )
        offset += len(blob)
    path.write_bytes(header + directory + b"".join(blobs))


def main() -> None:
    OUT.mkdir(exist_ok=True)
    base = draw_icon(256)
    base.save(OUT / "icon.png")
    save_ico(base, OUT / "icon.ico", [16, 24, 32, 48, 64, 128, 256])
    print(f"wrote {OUT / 'icon.png'} and {OUT / 'icon.ico'} (all-PNG entries)")


if __name__ == "__main__":
    main()
