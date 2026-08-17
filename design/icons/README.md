# App icon assets

Top-down single-seater with a keyhole cockpit. Navy field is the shipping icon; the
orange field is prepped as an alternate (not wired up yet — see docs/MASTER-TODO.md).

## Files

| File | Use |
|---|---|
| `AppIcon-J4-navy-1024.png` | Shipping icon. Navy `#131E2E` field, orange `#D9480F` car. |
| `AppIcon-J4-orange-1024.png` | Alternate. Colours inverted. |
| `field-comparison.png` | Both shown against light and dark backdrops. |
| `render-icon.py` | Regenerates both PNGs from geometry. |

## Why the geometry is checked in

The icon is drawn programmatically rather than in a design tool, so `render-icon.py` is
the source of truth. If a size or colour needs to change, edit the script and re-run it
instead of editing a PNG. Both variants share one geometry function, so they can never
drift apart.

    python3 render-icon.py

## Design notes

The keyhole is deliberately subordinate to the car. Keyhole-only marks are the norm in
the password-manager category (1Password, Dashlane, NordPass and others), so leading with
the car is what keeps this distinguishable on a crowded App Store shelf — and keeps it
clear of their marks in overall commercial impression.

Observed in testing: the orange field is measurably more legible on BOTH light and dark
wallpapers. Navy was chosen anyway as a deliberate preference, with orange kept as the
alternate.
