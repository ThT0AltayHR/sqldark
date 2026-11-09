#!/usr/bin/env python3
"""Render a captured SQLDark run into an animated terminal GIF for the README.
Usage: python3 scripts/make_demo_gif.py <capture.txt> <out.gif>"""
import sys
from PIL import Image, ImageDraw, ImageFont

CAP = sys.argv[1] if len(sys.argv) > 1 else "/tmp/democap.txt"
OUT = sys.argv[2] if len(sys.argv) > 2 else "assets/demo.gif"

BG = (13, 17, 23); FG = (201, 209, 217)
COLORS = {"[SUCCESS]": (63, 185, 80), "[CRITICAL]": (188, 140, 255),
          "[INFO]": (88, 166, 255), "[WARNING]": (210, 153, 34),
          "[ERROR]": (248, 81, 73)}
PROMPT = (126, 231, 135)

lines = [l.rstrip("\n") for l in open(CAP, encoding="utf-8")]
header = "$ sqldark -u 'http://shop.local/product?id=1' --banner --dump"
lines = [header, ""] + lines

try:
    font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 15)
except Exception:
    font = ImageFont.load_default()

PAD, LH = 14, 21
W = 900
H = PAD * 2 + LH * (len(lines) + 1)


def color_for(line):
    for tag, col in COLORS.items():
        if line.startswith(tag) or line.lstrip().startswith(tag):
            return col
    return FG


def render(n):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    y = PAD
    for i in range(n):
        line = lines[i]
        col = PROMPT if line.startswith("$") else color_for(line)
        d.text((PAD, y), line, font=font, fill=col)
        y += LH
    # cursor
    if n <= len(lines):
        d.rectangle([PAD, y, PAD + 9, y + 15], fill=(88, 166, 255))
    return img

frames = [render(n) for n in range(1, len(lines) + 1)]
frames += [frames[-1]] * 12  # hold the final frame
durs = [120] * (len(lines)) + [120] * 12
durs[0] = 500
frames[0].save(OUT, save_all=True, append_images=frames[1:],
               duration=durs, loop=0, optimize=True)
print("wrote", OUT, "frames:", len(frames), "size:", W, "x", H)
