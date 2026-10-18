#!/usr/bin/env python3
"""Render format-before-after{,-dark}.png from real CLI output.

Usage: render-format-image.py DEMO_SQL FORMATTED_SQL OUT_DIR
Called by build-format-image.sh; requires Pillow.
"""
import sys
from PIL import Image, ImageDraw, ImageFont

W, PAD, RADIUS = 2080, 40, 20
FS, LH, HDR, BODY_PAD = 40, 64, 100, 40

THEMES = {
    "": dict(bg="#ffffff", panel="#f6f8fa", border="#d0d7de", fg="#1f2328", muted="#59636e"),
    "-dark": dict(bg="#0d1117", panel="#161b22", border="#30363d", fg="#e6edf3", muted="#8b949e"),
}


def font(bold=False, size=FS):
    cands = [
        ("/System/Library/Fonts/Menlo.ttc", 1 if bold else 0),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSansMono-Bold.ttf" if bold
         else "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf", 0),
        ("DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf", 0),
    ]
    for path, idx in cands:
        try:
            return ImageFont.truetype(path, size, index=idx)
        except OSError:
            continue
    sys.exit("no monospace font found (install DejaVu Sans Mono)")


def wrap(text, f, max_w, d):
    lines, cur = [], ""
    for word in text.split():
        t = (cur + " " + word).strip()
        if d.textlength(t, font=f) <= max_w or not cur:
            cur = t
        else:
            lines.append(cur)
            cur = word
    return lines + [cur]


def render(before, after, c, out):
    code, bold = font(), font(True)
    probe = ImageDraw.Draw(Image.new("RGB", (1, 1)))
    inner = W - 2 * PAD - 2 * 44
    b_lines = wrap(before, code, inner, probe)
    a_lines = after.split("\n")
    hb = HDR + 2 * BODY_PAD + LH * len(b_lines) - (LH - FS)
    ha = HDR + 2 * BODY_PAD + LH * len(a_lines) - (LH - FS)
    gap = 90
    H = PAD + hb + gap + ha + PAD
    im = Image.new("RGB", (W, H), c["bg"])
    d = ImageDraw.Draw(im)

    def panel(y, h, title, cmd, lines):
        d.rounded_rectangle([PAD, y, W - PAD, y + h], RADIUS, fill=c["panel"], outline=c["border"], width=2)
        d.line([PAD, y + HDR, W - PAD, y + HDR], fill=c["border"], width=2)
        d.text((PAD + 44, y + HDR // 2), title, font=bold, fill=c["fg"], anchor="lm")
        d.text((W - PAD - 44, y + HDR // 2), cmd, font=code, fill=c["muted"], anchor="rm")
        for i, ln in enumerate(lines):
            d.text((PAD + 44, y + HDR + BODY_PAD + i * LH), ln, font=code, fill=c["fg"])

    panel(PAD, hb, "Before", "demo.sql", b_lines)
    ay = PAD + hb + gap
    ax, ay0 = W // 2, PAD + hb + 15
    d.line([ax, ay0, ax, ay - 15], fill=c["muted"], width=4)
    d.line([ax - 14, ay - 30, ax, ay - 15, ax + 14, ay - 30], fill=c["muted"], width=4)
    panel(ay, ha, "After", "gosqlx format demo.sql", a_lines)
    im.save(out, optimize=True)


def main():
    demo, formatted, outdir = sys.argv[1:4]
    before = " ".join(open(demo).read().split())
    after = open(formatted).read().rstrip("\n")
    for suffix, colors in THEMES.items():
        render(before, after, colors, f"{outdir}/format-before-after{suffix}.png")


main()
