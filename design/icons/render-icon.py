#!/usr/bin/env python3
"""
Regenerates the PitLAPS app icons.

The icon is drawn from geometry rather than maintained in a design tool, so this script
is the source of truth. Both colour variants share one geometry function, which means
they cannot drift apart when something changes.

    python3 render-icon.py

Design space is 200x200; everything scales from there. Rendered at 8x and downsampled so
the curves are clean, then flattened to RGB because an app icon must have no alpha
channel (a transparent icon is an App Store rejection).
"""
from PIL import Image, ImageDraw

NAVY = (19, 30, 46, 255)      # #131E2E  pit-wall navy
ORANGE = (217, 72, 15, 255)   # #D9480F  safety orange

SUPERSAMPLE = 8
OUTPUT_PX = 1024
SCALE = (OUTPUT_PX * SUPERSAMPLE) / 200.0


def draw_icon(background, foreground):
    """Draws the icon with the given field and car colours. The keyhole is punched in
    the field colour so it reads as a hole rather than a painted shape."""
    img = Image.new("RGBA", (OUTPUT_PX * SUPERSAMPLE,) * 2, background)
    d = ImageDraw.Draw(img)

    def p(x, y):
        return (x * SCALE, y * SCALE)

    def rrect(x, y, w, h, r, fill=foreground):
        d.rounded_rectangle([p(x, y), p(x + w, y + h)], radius=r * SCALE, fill=fill)

    def poly(pts, fill=foreground):
        d.polygon([p(a, b) for a, b in pts], fill=fill)

    def circ(cx, cy, r, fill=foreground):
        d.ellipse([p(cx - r, cy - r), p(cx + r, cy + r)], fill=fill)

    def quad(p0, p1, p2, n=70):
        """Samples a quadratic bezier; PIL has no curve primitive."""
        out = []
        for i in range(n + 1):
            t = i / n
            mt = 1 - t
            out.append((mt * mt * p0[0] + 2 * mt * t * p1[0] + t * t * p2[0],
                        mt * mt * p0[1] + 2 * mt * t * p1[1] + t * t * p2[1]))
        return out

    # Rear wing. Sits clear of the rear wheels on purpose: when they touched, the two
    # merged into a plinth and the whole icon read as a rocket on a stand.
    rrect(50, 154, 100, 18, 4)

    # Body, tapering toward the nose. The taper is what makes it read as a car rather
    # than a bullet.
    body = []
    body += quad((100, 24), (118, 24), (120, 50))
    body += [(121, 160), (79, 160), (80, 50)]
    body += quad((80, 50), (82, 24), (100, 24))
    poly(body)

    # Wheels. Rear pair is wider and taller, as on a real single-seater.
    rrect(44, 52, 32, 36, 8)
    rrect(124, 52, 32, 36, 8)
    rrect(40, 102, 34, 38, 8)
    rrect(126, 102, 34, 38, 8)

    # Keyhole cockpit. Sized to stay legible down to 40px, which is where the credential
    # meaning is lost first.
    r, cy = 17, 94
    circ(100, cy, r, background)
    poly([(100 - r * 0.45, cy + r * 0.72), (100 + r * 0.45, cy + r * 0.72),
          (100 + r * 0.85, cy + 42), (100 - r * 0.85, cy + 42)], background)

    return img.resize((OUTPUT_PX, OUTPUT_PX), Image.LANCZOS).convert("RGB")


if __name__ == "__main__":
    draw_icon(NAVY, ORANGE).save("AppIcon-J4-navy-1024.png", "PNG")
    draw_icon(ORANGE, NAVY).save("AppIcon-J4-orange-1024.png", "PNG")
    print("wrote AppIcon-J4-navy-1024.png and AppIcon-J4-orange-1024.png")
