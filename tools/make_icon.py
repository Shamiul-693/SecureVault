"""Generate resources/icons/securevault.ico and .png (shield with keyhole).

Run: python tools/make_icon.py   (requires Pillow; only needed if you change the icon)
"""
from pathlib import Path

from PIL import Image, ImageDraw

OUT = Path(__file__).resolve().parent.parent / "resources" / "icons"


def draw(size: int = 1024) -> Image.Image:
    s = size
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # rounded-square background with vertical gradient
    bg = Image.new("RGBA", (s, s))
    for y in range(s):
        t = y / s
        r = int(0x2f + (0x1b - 0x2f) * t)
        g = int(0x6f + (0x3f - 0x6f) * t)
        b = int(0xed + (0xb8 - 0xed) * t)
        ImageDraw.Draw(bg).line([(0, y), (s, y)], fill=(r, g, b, 255))
    mask = Image.new("L", (s, s), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, s - 1, s - 1], radius=int(s * 0.22), fill=255)
    img.paste(bg, (0, 0), mask)
    # shield
    cx = s / 2
    top, bottom = s * 0.18, s * 0.86
    w = s * 0.31
    shield = [
        (cx, top), (cx + w, top + s * 0.09), (cx + w, s * 0.50),
        (cx + w * 0.75, s * 0.68), (cx, bottom), (cx - w * 0.75, s * 0.68),
        (cx - w, s * 0.50), (cx - w, top + s * 0.09),
    ]
    d.polygon(shield, fill=(255, 255, 255, 245))
    # keyhole
    kc = (0x1f, 0x4f, 0xc8, 255)
    r = s * 0.075
    ky = s * 0.45
    d.ellipse([cx - r, ky - r, cx + r, ky + r], fill=kc)
    d.polygon([(cx - r * 0.55, ky + r * 0.4), (cx + r * 0.55, ky + r * 0.4),
               (cx + r * 0.8, ky + r * 3.0), (cx - r * 0.8, ky + r * 3.0)], fill=kc)
    return img


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    big = draw()
    big.resize((256, 256), Image.LANCZOS).save(OUT / "securevault.png")
    big.save(OUT / "securevault.ico", sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print("Icons written to", OUT)
