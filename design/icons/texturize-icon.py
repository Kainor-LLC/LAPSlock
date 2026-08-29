#!/usr/bin/env python3
"""
LAPSlock photoreal tread pipeline.

Takes the clean geometric tread from render-icon.py and makes it read as an actual
tire print: pressure variation, ragged rubber edges, ink starvation, spatter. The
output is still a FLAT-COLOR STENCIL, which is what makes it Liquid Glass
compatible: Icon Composer wants flat layers with no baked shadows/blur/gradients,
and applies the glass material itself. The photorealism lives in the mask's shape,
not in shading.

Two texture sources:
  --synth            synthesize the print (seeded fractal noise; reproducible)
  --source FILE.png  ingest a licensed photo/scan of a real tire track. It is
                     converted to a binary ink mask and modulates the same
                     geometry. Use CC0/public-domain sources only if this ships
                     (stock licenses commonly prohibit logo/trademark use).

Outputs per variant (tread = full ring, skid = broken arcs; navy and light):
  * flat RGB 1024 (App Store marketing icon, no alpha)
  * Icon Composer layers at 1024: background, tread (RGBA), keyhole (RGBA)
  * proof strip 180/120/87/60/29
Plus a combined comparison sheet and an appearance-mode preview sheet
(approximations; ground truth is Icon Composer on the Mac).

Usage:  python3 texturize-icon.py [outdir] [--synth | --source FILE]
Deps:   Pillow, numpy
"""

import importlib.util
import math
import os
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter

_spec = importlib.util.spec_from_file_location(
    "rendericon", os.path.join(os.path.dirname(os.path.abspath(__file__)), "render-icon.py"))
ri = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ri)

NAVY, STEEL, CAP = ri.NAVY, ri.STEEL, ri.CAP
SS = ri.SS
SEED = 31

# ---- shipping configuration -------------------------------------------------
# The icon that ships is the photoreal tread. Decision 2026-08-29: the keycap
# read as one more lock-family security icon; the tread ring is the mark nobody
# else in the category has. Flip these two constants and re-run to change it.
SHIP_BASE = "tread"    # "tread" = full ring | "skid" = broken arcs
SHIP_LIGHT = False     # False = navy field, light tread | True = inverted

# texture tuning, all in supersampled px (canvas = 1024 * SS)
WARP_PX = 15.0        # edge raggedness amplitude
PRESSURE_LO = 0.40    # lightest print pressure for SKID arcs, where breakup is
                      # the aesthetic (below the 0.50 ink threshold = dropout)
TREAD_PRESSURE_FLOOR = 0.62   # floor for the FULL RING: always above the ink
                      # threshold, so light regions print thin and grainy but a
                      # continuous circle never develops accidental gaps
PRESSURE_HI = 1.25
HOLE_THRESH = 0.795   # ink-starvation speckle inside the print

# Edge spatter style:
#   "physical" - flecks only where the print ran heavy (gated by the pressure
#                field), clustered, hugging the band edge. Reads as caused.
#   "uniform"  - evenly sprinkled dots around both edges (the first version).
#   "none"     - clean edges; grain, ragged edges and pressure variation still
#                carry the print feel.
# Invisible at 87px and below either way; this is a 1024/marketing-size choice.
SPATTER_STYLE = "physical"
SPATTER_N = 220       # dot budget for "uniform"; attempt budget for "physical"


def _noise(S, cells, rng):
    g = (rng.random((cells, cells)) * 255).astype(np.uint8)
    img = Image.fromarray(g, "L").resize((S, S), Image.BICUBIC)
    return np.asarray(img, np.float32) / 255.0


def _fractal(S, specs, rng):
    acc = np.zeros((S, S), np.float32)
    for cells, w in specs:
        acc += _noise(S, cells, rng) * w
    acc -= acc.min()
    acc /= max(float(np.ptp(acc)), 1e-6)
    return acc


def geometry_mask(S, base):
    """Clean tread geometry as a float mask (1 = rubber contact)."""
    img = Image.new("L", (S, S), 0)
    d = ImageDraw.Draw(img)
    if base == "tread":
        arcs, fade = [(-90.0, 270.0)], False
    else:
        arcs, fade = [(-140.0, 15.0), (40.0, 190.0)], True
    ri.draw_tread(d, S / 2, S / 2, S, 255, 0, arcs, fade)
    return np.asarray(img, np.float32) / 255.0


def source_ink(S, path):
    """Licensed photo/scan -> ink-density field in [0,1], dark marks = high ink."""
    img = Image.open(path).convert("L").resize((S, S), Image.LANCZOS)
    a = np.asarray(img, np.float32) / 255.0
    a = 1.0 - a                                   # dark print on light paper
    lo, hi = np.percentile(a, 8), np.percentile(a, 92)
    return np.clip((a - lo) / max(hi - lo, 1e-6), 0.0, 1.0)


def stamp_mask(S, base, source=None):
    """Photoreal print mask: geometry modulated by pressure, warp, holes, spatter."""
    rng = np.random.default_rng(SEED)
    geo = geometry_mask(S, base)

    # ragged rubber edges: warp the sampling grid with band-limited noise
    dx = (_fractal(S, [(48, 0.6), (128, 0.4)], rng) - 0.5) * 2 * WARP_PX
    dy = (_fractal(S, [(48, 0.6), (128, 0.4)], rng) - 0.5) * 2 * WARP_PX
    yy, xx = np.mgrid[0:S, 0:S]
    xs = np.clip((xx + dx).astype(np.int32), 0, S - 1)
    ys = np.clip((yy + dy).astype(np.int32), 0, S - 1)
    warped = geo[ys, xs]

    # uneven contact pressure: low-frequency field, some blocks print light/partial
    p_lo = PRESSURE_LO if base == "skid" else TREAD_PRESSURE_FLOOR
    pressure = p_lo + (PRESSURE_HI - p_lo) * _fractal(
        S, [(5, 0.45), (11, 0.35), (23, 0.20)], rng)
    ink = warped * pressure
    if source is not None:
        # licensed texture drives local ink density inside the geometry
        ink = warped * (0.30 + 0.95 * source) * (0.55 + 0.45 * pressure)

    mask = ink > 0.50

    # ink starvation / paper grain inside the print
    holes = (_fractal(S, [(300, 0.55), (900, 0.45)], rng) > HOLE_THRESH)
    mask &= ~holes

    # spatter along the band edges; style is a deliberate choice, see SPATTER_STYLE
    if SPATTER_STYLE != "none":
        spat = Image.new("L", (S, S), 0)
        ds = ImageDraw.Draw(spat)
        r_mid, h0 = S * 0.306, S * 0.066
        # keep spatter out of the skid variant's arc gaps so the gesture stays legible
        gaps = [(15.0, 40.0), (190.0, 220.0)] if base == "skid" else []

        if SPATTER_STYLE == "uniform":
            for _ in range(SPATTER_N):
                ang = rng.uniform(0, 2 * math.pi)
                deg = math.degrees(ang) % 360.0
                if any(g0 - 4 < deg < g1 + 4 for g0, g1 in gaps):
                    continue
                r = r_mid + rng.choice([-1, 1]) * (h0 + rng.uniform(4, 30) * SS / 4)
                cx = S / 2 + r * math.cos(ang)
                cy = S / 2 + r * math.sin(ang)
                rad = rng.uniform(1.0, 3.0) * SS
                ds.ellipse([cx - rad, cy - rad, cx + rad, cy + rad], fill=255)
            spat_a = np.asarray(spat, np.float32) / 255.0
            keep = _fractal(S, [(9, 1.0)], rng) > 0.55
            mask |= (spat_a > 0.5) & keep & (geo < 0.5)
        else:  # physical: clustered flecks only off heavy-pressure contact
            for _ in range(SPATTER_N + 80):
                ang = rng.uniform(0, 2 * math.pi)
                deg = math.degrees(ang) % 360.0
                if any(g0 - 4 < deg < g1 + 4 for g0, g1 in gaps):
                    continue
                r = r_mid + rng.choice([-1, 1]) * (h0 + rng.uniform(3, 16) * SS / 4)
                cx = S / 2 + r * math.cos(ang)
                cy = S / 2 + r * math.sin(ang)
                px = int(min(max(cx, 0), S - 1))
                py = int(min(max(cy, 0), S - 1))
                if pressure[py, px] < 1.02:   # flecks fly where the print ran heavy
                    continue
                for _k in range(int(rng.integers(1, 4))):
                    jx = cx + rng.uniform(-10, 10) * SS / 4
                    jy = cy + rng.uniform(-10, 10) * SS / 4
                    rad = rng.uniform(0.7, 2.2) * SS
                    ds.ellipse([jx - rad, jy - rad, jx + rad, jy + rad], fill=255)
            spat_a = np.asarray(spat, np.float32) / 255.0
            mask |= (spat_a > 0.5) & (geo < 0.5)

    return Image.fromarray((mask * 255).astype(np.uint8), "L")


def keyhole_layer(S, color):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    kw = S * 0.180
    ri.draw_keyhole(d, S / 2, S / 2 - kw * 0.40, kw, color + (255,))
    return img


def compose(size, base, light, source=None, _cache={}):
    """Flat RGB comp. Mask is built once per (base, source) at full supersample."""
    S = 1024 * SS
    key = (base, SPATTER_STYLE, id(source))
    if key not in _cache:
        _cache[key] = stamp_mask(S, base, source)
    field, fg = (CAP, NAVY) if light else (NAVY, CAP)
    img = Image.new("RGB", (S, S), field)
    fg_img = Image.new("RGB", (S, S), fg)
    img.paste(fg_img, (0, 0), _cache[key])
    img.paste(fg_img, (0, 0), keyhole_layer(S, fg).split()[3])
    return img.resize((size, size), Image.LANCZOS)


def emit_iconcomposer_layers(out, base, source=None):
    """Transparent 1024 PNG layers for Icon Composer, back to front. Flat color,
    no baked effects, per Apple's guidance; the system applies the glass."""
    d = os.path.join(out, f"iconcomposer-{base}")
    os.makedirs(d, exist_ok=True)
    S = 1024 * SS
    Image.new("RGB", (1024, 1024), NAVY).save(os.path.join(d, "1-background.png"))
    mask = stamp_mask(S, base, source)
    tread = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    tread.paste(Image.new("RGB", (S, S), CAP), (0, 0), mask)
    tread.resize((1024, 1024), Image.LANCZOS).save(os.path.join(d, "2-tread.png"))
    keyhole_layer(S, CAP).resize((1024, 1024), Image.LANCZOS).save(
        os.path.join(d, "3-keyhole.png"))


def emit_mode_previews(out, base, light):
    """Rough Default / Dark / Tinted / Clear approximations. Judgment aid only;
    the real rendering happens in Icon Composer."""
    sz = 300
    comp = compose(sz, base, light)
    dark = compose(sz, base, light)
    px = np.asarray(dark, np.float32)
    px = np.where(px.sum(2, keepdims=True) < 260, np.array([10, 15, 26], np.float32), px)
    dark = Image.fromarray(px.astype(np.uint8))

    lum = np.asarray(compose(sz, base, light).convert("L"), np.float32) / 255.0
    fg = lum if not light else 1.0 - lum
    tint = np.zeros((sz, sz, 3), np.float32)
    tint[..., 0] = 18 + fg * 150
    tint[..., 1] = 22 + fg * 180
    tint[..., 2] = 30 + fg * 230
    tinted = Image.fromarray(tint.astype(np.uint8))

    clear = Image.new("RGB", (sz, sz), (146, 152, 164))
    white = Image.new("RGB", (sz, sz), (255, 255, 255))
    alpha = Image.fromarray((fg * 205).astype(np.uint8), "L")
    clear.paste(white, (0, 0), alpha)

    pad = 24
    sheet = Image.new("RGB", (4 * sz + 5 * pad, sz + 2 * pad), (0xF5, 0xF5, 0xF7))
    for i, m in enumerate((comp, dark, tinted, clear)):
        sheet.paste(m, (pad + i * (sz + pad), pad))
    sheet.save(os.path.join(out, f"modes-preview-{base}{'-light' if light else ''}.png"))


def emit_appiconset(out):
    """Shipping asset catalog: photoreal tread, single 1024, RGB, no alpha.
    Xcode 14+ derives every size. This overrides render-icon.py's emitter."""
    d = os.path.join(out, "AppIcon.appiconset")
    os.makedirs(d, exist_ok=True)
    compose(1024, SHIP_BASE, SHIP_LIGHT).save(
        os.path.join(d, "AppIcon-LAPSlock-1024.png"))
    with open(os.path.join(d, "Contents.json"), "w") as f:
        f.write(ri.CONTENTS_JSON)


def emit_entra_logo(out):
    """Entra consent-screen logo, 215x215, must stay under 100 KB."""
    compose(215, SHIP_BASE, SHIP_LIGHT).save(
        os.path.join(out, "entra-logo-215.png"), optimize=True)


def emit_ship_proof(out):
    """Proof strip of the shipping variant at the sizes iOS actually renders."""
    sizes = [180, 120, 87, 60, 29]
    strip_w = sum(sizes) + 44 * len(sizes)
    strip = Image.new("RGB", (strip_w, 230), (0xF5, 0xF5, 0xF7))
    x = 22
    for s in sizes:
        strip.paste(compose(s, SHIP_BASE, SHIP_LIGHT), (x, (230 - s) // 2))
        x += s + 44
    strip.save(os.path.join(out, "proof-strip-shipping.png"))


def main():
    args = sys.argv[1:]
    out = args[0] if args and not args[0].startswith("--") else "."
    source = None
    if "--source" in args:
        source = source_ink(1024 * SS, args[args.index("--source") + 1])
    os.makedirs(out, exist_ok=True)

    variants = [("tread", False), ("tread", True), ("skid", False), ("skid", True)]
    for base, light in variants:
        name = f"photo-{base}{'-light' if light else ''}"
        compose(1024, base, light, source).save(os.path.join(out, f"{name}-1024.png"))

    sizes = [180, 120, 87, 60, 29]
    pad = 36
    W = sum(sizes) + pad * (len(sizes) + 1)
    H = (180 + pad) * len(variants) + pad
    sheet = Image.new("RGB", (W, H), (0xF5, 0xF5, 0xF7))
    y = pad
    for base, light in variants:
        x = pad
        for s in sizes:
            sheet.paste(compose(s, base, light, source), (x, y + (180 - s) // 2))
            x += s + pad
        y += 180 + pad
    sheet.save(os.path.join(out, "comparison-sheet-photo.png"))

    emit_iconcomposer_layers(out, "tread", source)
    emit_iconcomposer_layers(out, "skid", source)
    emit_mode_previews(out, "tread", False)
    emit_mode_previews(out, "skid", True)

    emit_appiconset(out)
    emit_entra_logo(out)
    emit_ship_proof(out)
    print("wrote photoreal assets to", out,
          "| shipping:", SHIP_BASE, "light" if SHIP_LIGHT else "navy")


if __name__ == "__main__":
    main()
