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


def main() -> None:
    OUT.mkdir(exist_ok=True)
    base = draw_icon(256)
    base.save(OUT / "icon.png")
    sizes = [16, 24, 32, 48, 64, 128, 256]
    base.save(OUT / "icon.ico", sizes=[(s, s) for s in sizes])
    print(f"wrote {OUT / 'icon.png'} and {OUT / 'icon.ico'}")


if __name__ == "__main__":
    main()
