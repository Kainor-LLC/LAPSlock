#!/usr/bin/env python3
"""
TenantKeep On-Call icon: a keep with a keyhole gate and a drawbridge, inside a shield, on
the navy field. Decided 2026-10-25. This script is the source; there is no design file.

Flat geometry only, four colours, no gradients, no shadows: Icon Composer applies the
Liquid Glass material itself, so the layers must stay flat. The geometry was measured
from the chosen candidate at 1024 and is written as coordinates on a 1024 canvas; every
shape is drawn supersampled and downsampled, so it regenerates clean at any size.

Layers, back to front: field, shield, keep (with the keyhole cut out of it so the shield
shows through), drawbridge.

Usage:  python3 keep-icon.py [outdir] [--reference FILE.png]
        --reference prints how far the render is from a reference composite, as the
        fraction of pixels that differ by more than a little. Needs numpy.
Deps:   Pillow (numpy only for --reference)

Judge at 29 px, not at 1024: look at proof-strip-keep.png after any change.
"""
import json
import os
import sys
from PIL import Image, ImageDraw

NAVY = (0x16, 0x23, 0x3A)
STEEL_LIFTED = (0x6E, 0x96, 0xC2)
CAP = (0xEE, 0xF3, 0xF8)

SS = 4  # supersample factor

# ---------------------------------------------------------------- geometry, 1024 canvas

# The shield: a shallow chevron top from (162, 206) to the peak at (520, 114) and down to
# (861, 206), then sides that curve inward to the point at the bottom. The sides are the
# measured edge, every 25 px, which is faithful and regenerates exactly.
SHIELD_LEFT = [(162, 210), (162, 235), (163, 260), (165, 285), (166, 310), (169, 335), (172, 360),
               (176, 385), (180, 410), (185, 435), (190, 460), (196, 485), (203, 510), (210, 535),
               (218, 560), (227, 585), (236, 610), (247, 635), (258, 660), (271, 685), (284, 710),
               (299, 735), (315, 760), (333, 785), (353, 810), (377, 835), (404, 860), (439, 885),
               (505, 910), (512, 912)]
SHIELD_RIGHT = [(861, 210), (861, 235), (860, 260), (858, 285), (857, 310), (854, 335), (851, 360),
                (847, 385), (843, 410), (838, 435), (833, 460), (827, 485), (820, 510), (813, 535),
                (805, 560), (796, 585), (787, 610), (776, 635), (765, 660), (752, 685), (739, 710),
                (724, 735), (708, 760), (690, 785), (670, 810), (646, 835), (619, 860), (584, 885),
                (519, 910), (512, 912)]
SHIELD = [(162, 206), (520, 114), (861, 206)] + SHIELD_RIGHT + list(reversed(SHIELD_LEFT))

# The keep: two tall outer merlons, two shorter inner ones, a body, and a flared base.
MERLONS = [
    (330, 200, 413, 284),   # outer left
    (610, 200, 693, 284),   # outer right
    (433, 242, 500, 284),   # inner left
    (523, 242, 589, 284),   # inner right
]
BODY = (330, 284, 693, 586)
BASE = [(330, 586), (693, 586), (750, 669), (273, 669)]

# The keyhole, cut out of the keep: a circle and a tapering slot that meets the base.
KEYHOLE_CIRCLE = (511.5, 410, 53)                      # cx, cy, r
KEYHOLE_SLOT = [(479, 460), (544, 460), (560, 586), (463, 586)]

# The drawbridge continues the slot downward, in the field colour.
DRAWBRIDGE = [(462, 586), (561, 586), (601, 683), (422, 683)]


def _scale(points, s):
    return [(x * s, y * s) for x, y in points]


def layer_shield(size):
    S = size * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(img).polygon(_scale(SHIELD, S / 1024), fill=STEEL_LIFTED + (255,))
    return img.resize((size, size), Image.LANCZOS)


def layer_keep(size):
    S = size * SS
    k = S / 1024
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    for x0, y0, x1, y1 in MERLONS:
        d.rectangle([x0 * k, y0 * k, x1 * k, y1 * k], fill=CAP + (255,))
    x0, y0, x1, y1 = BODY
    d.rectangle([x0 * k, y0 * k, x1 * k, y1 * k], fill=CAP + (255,))
    d.polygon(_scale(BASE, k), fill=CAP + (255,))
    # The keyhole is a hole, not a paint: erase to transparent so the shield shows through.
    cx, cy, r = KEYHOLE_CIRCLE
    d.ellipse([(cx - r) * k, (cy - r) * k, (cx + r) * k, (cy + r) * k], fill=(0, 0, 0, 0))
    d.polygon(_scale(KEYHOLE_SLOT, k), fill=(0, 0, 0, 0))
    return img.resize((size, size), Image.LANCZOS)


def layer_drawbridge(size):
    S = size * SS
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(img).polygon(_scale(DRAWBRIDGE, S / 1024), fill=NAVY + (255,))
    return img.resize((size, size), Image.LANCZOS)


def compose(size):
    """The flat icon. RGB, no alpha: the App Store rejects an icon with one."""
    img = Image.new("RGBA", (size, size), NAVY + (255,))
    for layer in (layer_shield(size), layer_keep(size), layer_drawbridge(size)):
        img.alpha_composite(layer)
    return img.convert("RGB")


CONTENTS_JSON = json.dumps({
    "images": [{"filename": "AppIcon-TenantKeep-1024.png", "idiom": "universal", "platform": "ios", "size": "1024x1024"}],
    "info": {"author": "xcode", "version": 1},
}, indent=2) + "\n"

PROOF_SIZES = [180, 120, 87, 60, 29]


def emit_appiconset(out):
    d = os.path.join(out, "AppIcon.appiconset")
    os.makedirs(d, exist_ok=True)
    compose(1024).save(os.path.join(d, "AppIcon-TenantKeep-1024.png"))
    with open(os.path.join(d, "Contents.json"), "w") as f:
        f.write(CONTENTS_JSON)


def emit_iconcomposer_layers(out):
    """Transparent 1024 layers for Icon Composer, back to front, flat colour."""
    d = os.path.join(out, "iconcomposer-keep")
    os.makedirs(d, exist_ok=True)
    Image.new("RGB", (1024, 1024), NAVY).save(os.path.join(d, "0-background.png"))
    layer_shield(1024).save(os.path.join(d, "1-shield.png"))
    layer_keep(1024).save(os.path.join(d, "2-keep.png"))
    layer_drawbridge(1024).save(os.path.join(d, "3-drawbridge.png"))


def emit_entra_logo(out):
    """Entra app registration logo, 215 px, under 100 KB."""
    compose(215).save(os.path.join(out, "entra-logo-215.png"), optimize=True)


def emit_proof_strip(out):
    strip_w = sum(PROOF_SIZES) + 44 * len(PROOF_SIZES)
    strip = Image.new("RGB", (strip_w, 230), (0xF5, 0xF5, 0xF7))
    x = 22
    for s in PROOF_SIZES:
        strip.paste(compose(s), (x, (230 - s) // 2))
        x += s + 44
    strip.save(os.path.join(out, "proof-strip-keep.png"))


def compare(reference):
    import numpy as np
    a = np.asarray(compose(1024)).astype(int)
    b = np.asarray(Image.open(reference).convert("RGB").resize((1024, 1024))).astype(int)
    differs = (np.abs(a - b).max(axis=2) > 24)
    return float(differs.mean())


def main():
    out = "./keep-icon-out"
    reference = None
    args = sys.argv[1:]
    while args:
        a = args.pop(0)
        if a == "--reference":
            reference = args.pop(0)
        else:
            out = a
    os.makedirs(out, exist_ok=True)
    emit_appiconset(out)
    emit_iconcomposer_layers(out)
    emit_entra_logo(out)
    emit_proof_strip(out)
    print("wrote", out)
    if reference:
        print("pixels differing from the reference by more than a little: %.3f%%" % (compare(reference) * 100))


if __name__ == "__main__":
    main()
