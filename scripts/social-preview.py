#!/usr/bin/env python3
"""Generate the GitHub social preview card for Veil."""
import os
import sys
from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(__file__), "..", ".github", "social-preview.png")
W, H = 1280, 640
BG = (10, 10, 10)
FG = (245, 245, 245)
DIM = (160, 160, 170)
ACCENT = (124, 58, 237)


def load_font(size, bold=False):
    candidates = [
        "/System/Library/Fonts/Helvetica.ttc",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/Library/Fonts/Arial.ttf",
    ]
    for p in candidates:
        if os.path.exists(p):
            try:
                return ImageFont.truetype(p, size)
            except OSError:
                continue
    return ImageFont.load_default()


def main():
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    title_font = load_font(180, bold=True)
    tagline_font = load_font(38)
    small_font = load_font(28)

    title = "Veil"
    tagline = ".gitignore for AI coding agents"
    small = "Keep secrets out of your agent's context — at the network boundary."

    title_w = d.textlength(title, font=title_font)
    d.text(((W - title_w) / 2, 150), title, fill=FG, font=title_font)

    d.line([(W / 2 - 80, 360), (W / 2 + 80, 360)], fill=ACCENT, width=4)

    tagline_w = d.textlength(tagline, font=tagline_font)
    d.text(((W - tagline_w) / 2, 400), tagline, fill=FG, font=tagline_font)

    small_w = d.textlength(small, font=small_font)
    d.text(((W - small_w) / 2, 470), small, fill=DIM, font=small_font)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    img.save(OUT, optimize=True)
    print(f"Wrote {OUT} ({W}x{H})")


if __name__ == "__main__":
    sys.exit(main() or 0)
