# LAPSlock — iOS LAPS administrator client

Native iOS client for viewing Windows and macOS LAPS local administrator passwords
managed by Microsoft Entra ID and Intune. Delegated auth only. No backend in the
credential path — passwords go Microsoft Graph → TLS → device and nowhere else.

**LAPSlock™ is a trademark of Kainor LLC.**

**Source-available, not open source.** The code is published so that security-conscious
administrators can read and verify what an app handling local administrator passwords
actually does. It is licensed under PolyForm Strict 1.0.0 plus an additional permission
that expressly allows commercial organizations to copy and read it for security review.
Redistribution, modification, and publishing builds are not permitted. See `LICENSE`.

> ⚠️ This is the security core (foundation) of the app, built first and on purpose.
> There is no runnable UI yet. What's here is the tested, isolated engine everything
> else stacks on. See `docs/BUILD-SPEC.md` for the full specification this implements.

## Architecture (Build Spec §3.1)

```
AppTarget (SwiftUI — not yet built)
└── LAPSlockKit (SwiftPM)
    ├── AuthKit          AuthManaging protocol + models. NO third-party deps.
    ├── AuthKitMSAL      the ONLY target linking MSAL; tenant pinning (§3.3), BYO (§9)
    ├── InventoryKit     device list/detail; NON-sensitive; may cache   (not yet built)
    ├── CredentialKit    LAPS providers + SensitiveValue   ⚠ ISOLATION BOUNDARY
    │                    depends on: AuthKit + Foundation ONLY (no MSAL, no logging)
    └── PlatformSecurity biometrics, app-switcher redaction   (not yet built)
```

### The critical rule

`CredentialKit` links no logging framework, no analytics SDK, no crash reporter, and
does not import the licensing layer. A developer who tries to send a credential to a
server or a log gets a **compile error**. This is enforced two ways:

1. `Package.swift` — CredentialKit's dependency list is `AuthKit` only.
2. `scripts/isolation-check.sh` — CI/pre-commit guard that greps CredentialKit's
   imports and fails the build on any forbidden module. Proven to catch violations.

## What's implemented

| Piece | File | Status |
|---|---|---|
| SensitiveValue boundary type (§3.2) | `CredentialKit/SensitiveValue.swift` | ✅ + tests |
| Platform provider seam + capabilities | `CredentialKit/LocalAdminCredentialProviding.swift` | ✅ |
| **Windows LAPS reveal** (§2.3, v1.0 GA) | `CredentialKit/WindowsLapsProvider.swift` | ✅ |
| macOS provider (reveal unavailable, see below) | `CredentialKit/MacOSLapsProvider.swift` | ✅ |
| Provider routing | `CredentialKit/CredentialCoordinator.swift` | ✅ |
| Auth protocol seam (§4) | `AuthKit/AuthManaging.swift` | ✅ |
| MSAL implementation + tenant pinning (§3.3, BYO §9) | `AuthKitMSAL/MSALAuthManager.swift` | ⚠️ never compiled |
| Security-core unit tests (§13) | `Tests/CredentialKitTests/` | ✅ (run in Xcode) |
| Isolation CI guard (§13) | `scripts/isolation-check.sh` | ✅ verified working |
| macOS §2.4 verification harness | `tools/Verify-MacOSLapsGraph.ps1` | ✅ run, conclusive |
| macOS 500 diagnostic | `tools/Diagnose-MacOSLaps.ps1` | ✅ run, conclusive |

**New here? Read `QUICKSTART.md`** for the 10-minute first run in Xcode.

## Platform support (§2.4 — settled empirically 2026-08-14)

| | Metadata | Reveal | Rotate |
|---|---|---|---|
| **Windows LAPS** | ✅ v1.0 GA | ✅ **v1.0 GA, documented** | policy-driven (not an app action) |
| **macOS LAPS** | ⚠️ beta API, currently 500s | ❌ **no documented endpoint** | ⚠️ beta, opt-in, off by default |

macOS reveal is off because it is not possible on public Graph today, not as a shortcut:

1. The Entra store used by Windows LAPS returns 200 OK with **no credentials array** for
   ADE-enrolled Macs — macOS passwords aren't kept there.
2. The documented beta function `retrieveDeviceLocalAdminAccountDetail` is specified to
   return only `passwordLastRotationDateTime`. **There is no password field in the contract.**
3. That function also returns **HTTP 500** from Intune's DeviceFE backend on every
   ADE-enrolled, LAPS-managed Mac tested (multiple devices and users in a licensed
   production tenant, 2026-08-14) — while the admin center displays those same passwords,
   i.e. retrieval is portal-internal.

**To enable macOS reveal when Microsoft ships it:** everything needed is documented in a
header block at the top of `CredentialKit/MacOSLapsProvider.swift`. It's four edits in
that one file plus a test update. No UI or other module changes.

## Running the checks

**Isolation guard** (macOS/Linux, no deps):
```bash
./scripts/isolation-check.sh
```

**Unit tests** — open `LAPSlockKit` in Xcode and run the CredentialKitTests target
(these need no Microsoft dependency by design), or on a Mac with the Swift toolchain:
```bash
cd LAPSlockKit && swift test
```
> Note: the full package won't `swift build` on Linux because MSAL is an Apple-platform
> binary. The tests target pure CredentialKit logic and run fine in Xcode.

**macOS LAPS verification** — settles the one open product question (§2.4):
```powershell
# PowerShell 7 on your Mac
Install-Module Microsoft.Graph -Scope CurrentUser   # first time only
./tools/Verify-MacOSLapsGraph.ps1
```
Sign in as an admin holding the custom Intune "View macOS admin password" role. The
script reports whether any documented Graph endpoint returns a macOS password value.
It reads only, never rotates, and never prints a password.

## Before this builds/ships (open items)

- Replace `AuthConfiguration.vendorDefault.clientId` with the real Entra app
  registration client ID (created in the Kainor tenant).
- Confirm MSAL `MSALResult` property names against the resolved MSAL version.
- Run the §2.4 harness and decide macOS reveal in/out per its verdict.
- Confirm `passwordBase64` encoding (UTF-16LE assumed) against a known tenant value.

See `docs/BUILD-SPEC.md` §15 for the complete verification checklist.
