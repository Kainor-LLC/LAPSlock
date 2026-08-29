# LAPSlock — Feature Checklist

Tracks the build spec (`docs/BUILD-SPEC.md`) against what's actually built.
Status as of the device-list/detail/reveal milestone.

Legend: ✅ done & tested · 🟡 partial · ⬜ not started · 🔵 not-code (business/legal/ops)

---

## Core credential handling (Spec §3.2, §3.4, §6)

- ✅ `SensitiveValue` boundary type — plaintext only inside `withValue`, wipes on demand
- ✅ base64 → plaintext decode with UTF-16LE/UTF-8 auto-detect, tested against known vectors
- ✅ Windows LAPS reveal on documented v1.0 Graph (`deviceLocalCredentials`)
- ✅ Password parsed straight into `SensitiveValue`, never into a loggable model
- ✅ Ephemeral URLSession — nothing written to disk, no cookies, no cache
- ✅ Request/response bodies never logged

## Module isolation (Spec §3.1, §13) — the security backbone

- ✅ `CredentialKit` depends on Foundation + AuthKit only
- ✅ Enforced in `Package.swift` AND by `scripts/isolation-check.sh` (fails build on violation)
- ✅ MSAL quarantined in its own `AuthKitMSAL` target
- ✅ CI guard proven to catch forbidden imports (logging, analytics, MSAL, licensing)

## Authentication (Spec §2.1, §4)

- ✅ MSAL interactive sign-in, multi-tenant
- ✅ Silent token acquisition with interactive fallback
- ✅ Tenant pinning — token tid must match the account (cross-tenant guard)
- ✅ Incremental consent — browse scopes at sign-in, reveal scope on first reveal
- ✅ ThisDeviceOnly, non-synced keychain
- ✅ Actor-serialized token access
- ✅ **Verified live against a real tenant** (not just compiled)

## Consent onboarding (Spec §4, §8) — added from your "what if they miss the checkbox" question

- ✅ Sign-in screen explains the org-consent checkbox before the prompt
- ✅ Detects per-user vs org-wide consent failure
- ✅ Shareable admin-approval link with pre-written request message
- ✅ Distinguishes "consent missing" from "role missing" (different fixes)

## Device inventory (Spec §2.2, §2.5, §5.1)

- ✅ Device list from v1.0 `managedDevices`, alphabetical
- ✅ Paging via `$top` + `@odata.nextLink`
- ✅ Client-side search (name, user, serial, model) with prefix/exact ranking
- ✅ Two-identifier handling — Entra + Intune IDs (found to arrive together, no join needed)
- ✅ Entra-join edge cases (absent / empty / all-zeros GUID all normalize correctly)
- ✅ Tenant-scoped cache, cleared on account switch
- ✅ Explicit states: loading, empty, partial (load-more), error

## Device detail (Spec §5.2)

- ✅ Inventory section: name, OS+version, model, manufacturer, user, check-in, compliance
- ✅ LAPS password section — visually distinct, masked, gated
- ✅ LAPS account name as a first-class field (from your feedback), persists after hide
- ✅ Windows release names — "Windows 11 24H2" with build beneath (from your feedback)
- 🟡 Per-device enrichment for null-in-list fields — not yet (list currently returns enough)

## The reveal flow (Spec §6)

- ✅ Explicit intent → biometric gate → fetch → display → auto-hide → wipe, in that order
- ✅ Gate BEFORE fetch (no audit event for an uncompleted reveal)
- ✅ `.deviceOwnerAuthentication` (passcode fallback for locked-out biometrics)
- ✅ Auto-hide countdown with the pit-timer ring
- ✅ Wipe on hide, on leave, on background
- ✅ Copy with `.localOnly` + expiration, clears when the window ends
- ✅ Text selection disabled so copy can't bypass the expiring clipboard

## Screen protections (Spec §6, §12)

- ✅ App-switcher redaction on `scenePhase != .active` (before the snapshot)
- ✅ Screen recording/mirroring detection → revoke + block
- ✅ Screenshot detection → warn, recommend rotation (can't block, tells the truth)
- 🟡 State-restoration disable — needs an explicit flag on credential screens (not yet)

## Tenant switch / sign-out / revocation (Spec §7)

- ✅ Sign-out clears MSAL cache and tenant-scoped data
- ✅ Account switch tears down inventory cache
- ✅ Missing-role message is specific and names the role (not a generic error)
- 🟡 Full keychain-item wipe on sign-out — MSAL clears its own; verify nothing else lingers

## Error & recovery states (Spec §8)

- ✅ 401 / 403 / 404 / 429 (with Retry-After) / 5xx each have distinct copy
- ✅ Consent-not-granted → shareable admin link
- ✅ Role-missing → names Cloud Device Administrator + PIM
- ✅ Device not LAPS-enabled, empty credential set — specific messages
- 🟡 Network-offline detection — currently folds into a generic transport error

## macOS (Spec §2.4) — RESOLVED

- ✅ Verified empirically: no documented Graph endpoint returns the macOS password
- ✅ macOS shows rotation metadata + "open in Intune" handoff instead of reveal
- ✅ Structured so reveal drops in later if Microsoft ships it (4 edits, one file)
- 🔵 Support case filed with Microsoft (the 500) — your action, tracked separately

## Demo mode (App Store Guideline 2.1)

- ✅ Demo inventory + credential providers, 12 devices covering every UI state
- ✅ Obviously-fake passwords (`DEMO-Not-A-Real-Password-NNNN`)
- ✅ Persistent demo banner, non-optional
- ✅ Demo flows through the real reveal path (gate, auto-hide, wipe all exercised)

---

## Your explicitly-named extras (Spec p.11)

- ✅ **Professional, clean look** — native iOS structure, monospaced machine data,
  restrained accent use, the countdown as a signature element
- 🟡 **Dark mode** — SwiftUI semantic colors adapt automatically, BUT the reveal card's
  hardcoded navy and a couple of brand colors need a dark-mode audit. **Not yet verified.**
- 🟡 **Fast** — ephemeral sessions, no over-fetching, client-side search avoids round
  trips. Graph latency is Microsoft's; we minimize our own. No perf pass done yet.
- 🔵 **Low ongoing maintenance** — the architecture is built for this (isolation,
  tests catch regressions, MSAL version pinned), but see the maintenance note below.

---

## Not built yet (Spec §9, §10, §11)

- ⬜ **BYO app registration mode** (§9) — the config seam EXISTS (`AuthConfiguration`
  takes a custom client ID), but there's no settings UI to enter one yet
- ⬜ **Licensing backend / `LicensingKit`** (§10) — free vs paid gating, seat management
- ⬜ **IAP** (individual subscription) (§11)
- ⬜ **Web seat portal** (business tier) (§11)
- ⬜ Free-tier gating (browse + metadata, no reveal)

## Not-code, still required before ship (§11, §15)

- 🔵 Partner Center verification (pending)
- 🔵 Publisher verification → `.well-known/microsoft-identity-association.json`
- 🔵 Privacy + terms pages at kainor.com (app registration already points at them)
- 🔵 Apple $99 + Paid Apps agreement
- 🔵 Design-partner IP agreement in writing
- 🔵 3.1.3(c) Enterprise Services docs for App Store Connect
- 🔵 US external-link rules — verify at submission

---

## On maintenance (your stated concern)

The design already hedges against this becoming a second job:

- **Tests catch regressions** — ~90 of them, so an MSAL update or a refactor that breaks
  something fails loudly instead of silently.
- **MSAL is the main moving dependency** and it's pinned; you update on your schedule,
  not automatically.
- **The macOS provider is structured to absorb Microsoft's eventual fix** without a rewrite.
- **Windows release table** is a one-line edit per new release.

What will still need periodic attention, honestly:
- MSAL major version bumps (a few times a year, usually mechanical)
- iOS SDK changes each September (the screen-protection APIs are the ones to watch)
- Graph API changes (rare on v1.0, more likely on the macOS beta path)
- Apple's shifting payment/external-link rules if you do the paid tiers

None of that is weekly. It's "a focused afternoon a few times a year" if you stay on
current tooling, more if you let it drift. The test suite is what keeps it to an
afternoon instead of a debugging archaeology dig.
