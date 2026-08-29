#!/usr/bin/env python3
"""
LAPSlock brand asset generator.

Source geometry lives here, not in a design file. Every asset is reproducible from
this script, which means the icon can be regenerated at any size without hunting for
a .sketch nobody can open.

Concept: the name reads as a keyboard key (LAPS lock / Caps Lock), so the icon is a
keycap with a lock on the keytop. A bare padlock is what every security app on the
App Store already uses; a keycap is an artifact this product's buyers touch all day.

Deliberately NOT in the icon:
  * the wordmark. "LAPSlock" stacked over two lines is unreadable at 60x60 on a home
    screen and worse at 29x29 in Settings. The wordmark is a separate asset for the
    site and docs, generated further down.
  * a keyhole inside a Caps Lock arrow. It was the first idea and it dissolves at
    small sizes. One idea per icon.

Usage:  python3 render-icon.py [outdir]
"""

import sys
import os
from PIL import Image, ImageDraw, ImageFont

# ---------------------------------------------------------------- palette

NAVY = (0x16, 0x23, 0x3A)      # field, and the lock glyph
STEEL = (0x4A, 0x6E, 0x96)     # keycap side walls, and LAPS in the wordmark
CAP = (0xEE, 0xF3, 0xF8)       # keycap top face
INK = (0x1A, 0x1A, 0x1A)       # "lock" in the wordmark
PAPER = (0xFF, 0xFF, 0xFF)

# Supersample factor. PIL has no antialiased vector fill, so everything is drawn
# large and downsampled with LANCZOS.
SS = 4

FONT_BOLD = "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf"


def _rr(draw, box, radius, fill):
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def draw_keyhole(draw, cx, cy, w, color):
    """A keyhole: circle over a tapered slot.

    One shape with one hole is the whole idea. It survives 29x29, where a padlock
    with a separate shackle, body and keyhole turns to mush, and it carries over the
    keyhole motif from the previous icon so the brand does not restart from zero.
    """
    r = w * 0.5
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], fill=color)
    slot_top = cy + r * 0.35
    slot_bot = cy + w * 1.30
    draw.polygon([(cx - r * 0.46, slot_top), (cx + r * 0.46, slot_top),
                  (cx + r * 0.86, slot_bot), (cx - r * 0.86, slot_bot)], fill=color)
    draw.rounded_rectangle([cx - r * 0.86, slot_bot - r * 0.35,
                            cx + r * 0.86, slot_bot], radius=r * 0.18, fill=color)


def draw_padlock(draw, cx, cy, w, color, face=None):
    """Alternate mark: a padlock. Kept for comparison against the keyhole."""
    face = face or CAP
    body_w = w
    body_h = w * 0.72
    body_top = cy - body_h * 0.10
    _rr(draw, [cx - body_w / 2, body_top, cx + body_w / 2, body_top + body_h],
        radius=w * 0.15, fill=color)

    sh_out = w * 0.62
    stroke = w * 0.145
    sh_cy = body_top
    draw.arc([cx - sh_out / 2, sh_cy - sh_out / 2, cx + sh_out / 2, sh_cy + sh_out / 2],
             start=180, end=360, fill=color, width=int(stroke))
    leg_x = sh_out / 2 - stroke / 2
    for sx in (-leg_x, leg_x):
        draw.rectangle([cx + sx - stroke / 2, sh_cy,
                        cx + sx + stroke / 2, body_top + 1], fill=color)

    kh = w * 0.20
    kcy = body_top + body_h * 0.40
    draw.ellipse([cx - kh / 2, kcy - kh / 2, cx + kh / 2, kcy + kh / 2], fill=face)
    draw.polygon([(cx - kh * 0.28, kcy), (cx + kh * 0.28, kcy),
                  (cx + kh * 0.15, kcy + kh * 1.2),
                  (cx - kh * 0.15, kcy + kh * 1.2)], fill=face)


def render_icon(size=1024, mark="keyhole"):
    """The app icon. No alpha channel: the App Store rejects icons with one.

    The keycap is drawn with an asymmetric bevel, thin at the top and thick at the
    bottom, which is what makes it read as a key seen slightly from above rather than
    as a rounded square badge. A uniform border reads as a frame, not a keycap.
    """
    S = size * SS
    img = Image.new("RGB", (S, S), NAVY)
    d = ImageDraw.Draw(img)

    cap_w = S * 0.640
    x0 = (S - cap_w) / 2
    y0 = (S - cap_w) / 2 - cap_w * 0.020
    _rr(d, [x0, y0, x0 + cap_w, y0 + cap_w], radius=cap_w * 0.190, fill=STEEL)

    side = cap_w * 0.070
    top_in = cap_w * 0.055
    bot_in = cap_w * 0.150
    fx0, fy0 = x0 + side, y0 + top_in
    fx1, fy1 = x0 + cap_w - side, y0 + cap_w - bot_in
    _rr(d, [fx0, fy0, fx1, fy1], radius=cap_w * 0.130, fill=CAP)

    face_cx = (fx0 + fx1) / 2
    face_cy = (fy0 + fy1) / 2
    if mark == "keyhole":
        draw_keyhole(d, face_cx, face_cy - cap_w * 0.055, cap_w * 0.205, NAVY)
    else:
        draw_padlock(d, face_cx, face_cy - cap_w * 0.010, cap_w * 0.300, NAVY)

    return img.resize((size, size), Image.LANCZOS)


def render_wordmark(width=1600, stacked=False):
    """Wordmark for the site, README, and App Store screenshots.

    LAPS in steel, lock in ink, matching the concept the family sketched.
    """
    if stacked:
        W, H = width, int(width * 0.62)
    else:
        W, H = width, int(width * 0.30)
    S = (W * 2, H * 2)
    img = Image.new("RGB", S, PAPER)
    d = ImageDraw.Draw(img)

    size = int(S[1] * (0.42 if stacked else 0.55))
    font = ImageFont.truetype(FONT_BOLD, size)

    def measure(t):
        b = d.textbbox((0, 0), t, font=font)
        return b[2] - b[0], b[3] - b[1], b

    if stacked:
        w1, h1, b1 = measure("LAPS")
        w2, h2, b2 = measure("lock")
        total_h = h1 + h2 + size * 0.06
        top = (S[1] - total_h) / 2
        d.text(((S[0] - w1) / 2 - b1[0], top - b1[1]), "LAPS", font=font, fill=STEEL)
        d.text(((S[0] - w2) / 2 - b2[0], top + h1 + size * 0.06 - b2[1]),
               "lock", font=font, fill=INK)
    else:
        w1, h1, b1 = measure("LAPS")
        w2, h2, b2 = measure("lock")
        total = w1 + w2
        left = (S[0] - total) / 2
        base = (S[1] - h1) / 2
        d.text((left - b1[0], base - b1[1]), "LAPS", font=font, fill=STEEL)
        d.text((left + w1 - b2[0], base - b1[1]), "lock", font=font, fill=INK)

    return img.resize((W, H), Image.LANCZOS)


CONTENTS_JSON = """{
  "images" : [
    {
      "filename" : "AppIcon-LAPSlock-1024.png",
      "idiom" : "universal",
      "platform" : "ios",
      "size" : "1024x1024"
    }
  ],
  "info" : {
    "author" : "xcode",
    "version" : 1
  }
}
"""


def emit_appiconset(out, mark="keyhole"):
    """Single-size asset catalog. Xcode 14+ generates every derived size from the
    1024 itself, so shipping one file is correct and one fewer thing to keep in sync."""
    d = os.path.join(out, "AppIcon.appiconset")
    os.makedirs(d, exist_ok=True)
    render_icon(1024, mark).save(os.path.join(d, "AppIcon-LAPSlock-1024.png"))
    with open(os.path.join(d, "Contents.json"), "w") as f:
        f.write(CONTENTS_JSON)


def emit_entra_logo(out, mark="keyhole"):
    """Entra app registration logo: 215x215 PNG, must stay under 100 KB.

    This is the image on the consent screen, which is the moment the product lives or
    dies. An admin granting read access to every local admin password in their tenant
    should not be looking at a default placeholder."""
    render_icon(215, mark).save(os.path.join(out, "entra-logo-215.png"), optimize=True)


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)

    for mark in ("keyhole", "padlock"):
        render_icon(1024, mark).save(os.path.join(out, f"AppIcon-LAPSlock-{mark}-1024.png"))

    # Legibility proofs. These are not shipped; they exist so a human can judge the
    # icon at the sizes iOS actually renders it, instead of only at 1024.
    proof_sizes = [180, 120, 87, 60, 29]
    for mark in ("keyhole", "padlock"):
        strip_w = sum(proof_sizes) + 44 * len(proof_sizes)
        strip = Image.new("RGB", (strip_w, 230), (0xF5, 0xF5, 0xF7))
        x = 22
        for s in proof_sizes:
            strip.paste(render_icon(s, mark), (x, (230 - s) // 2))
            x += s + 44
        strip.save(os.path.join(out, f"proof-strip-{mark}.png"))

    emit_appiconset(out, "keyhole")
    emit_entra_logo(out, "keyhole")

    render_wordmark(1600, stacked=False).save(os.path.join(out, "wordmark-inline.png"))
    render_wordmark(1200, stacked=True).save(os.path.join(out, "wordmark-stacked.png"))
    print("wrote assets to", out)


if __name__ == "__main__":
    main()
