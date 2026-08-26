# PitLAPS — session handoff

Paste or attach this at the start of a new chat. Attach `docs/MASTER-TODO.md` alongside it
for the full backlog; this file is just enough to resume without re-explaining.

---

## What this is

**PitLAPS** — a multi-tenant iOS app for IT administrators to retrieve Windows LAPS local
administrator passwords and BitLocker recovery keys from Microsoft Entra ID and Intune.
Delegated auth only, no backend in the credential path, passwords never touch any server
the vendor operates.

Built by **Kainor LLC** (Kansas, sole member Connor Johnson).

## Immediate context — where we stopped

Mid-way through getting the first **TestFlight** build out, so the app can be tested on a
real iPhone against a real tenant for the first time.

Completed in the current step:
- App ID `com.kainor.pitlaps` registered in the developer portal
- App record created in App Store Connect (name "PitLAPS" was available)
- `NSFaceIDUsageDescription` added (required on real hardware, simulator tolerates absence)
- `ITSAppUsesNonExemptEncryption = NO` added (pre-answers the export compliance prompt;
  basis is HTTPS and Keychain only, no custom crypto)
- iPhone UDID registered as a device (needed because automatic signing refuses to generate
  a profile with zero registered devices)

**Next action:** Xcode → Signing & Capabilities → Try Again, then Product → Archive with
destination "Any iOS Device (arm64)", then Distribute App → TestFlight & App Store.

Expect on first upload: a **missing privacy manifest** warning (`PrivacyInfo.xcprivacy`).
It does not block TestFlight but will block App Store submission later.

## Why TestFlight matters more than it looks

**Every credential reveal to date has been demo data.** The Windows LAPS decode path
(base64 → UTF-16LE detection → BOM stripping) has never processed a real password from
Microsoft Graph. That is the single largest unverified assumption in the project, and it is
exactly the kind of code that passes handwritten test vectors and fails on real input.

The point of getting onto a real device is to reveal one real password and find out.

## Identifiers (all non-secret)

| Thing | Value |
|---|---|
| Entra app client ID | `50c9aa83-4f5c-4203-a3c0-adab54a2ba3a` |
| Kainor tenant ID | `4470dc21-a4b7-4729-a232-56d4c0eedf73` |
| Bundle ID | `com.kainor.pitlaps` |
| Redirect URI | `msauth.com.kainor.pitlaps://auth` |
| Apple Team ID | `72C7PQBP52` |
| Microsoft MPN (global) | `7147713` |
| Repo | `github.com/Kainor-LLC/PitLAPS` (public, source-available) |
| Site | `kainor.com` (GitHub Pages, `docs/` folder) |

Apple ID is `connor@csj.me`; Microsoft work account is `connor@kainor.com`. Three separate
inboxes, easy to miss mail in the wrong one.

## Graph scopes consented

Read-only baseline: `DeviceManagementManagedDevices.Read.All`, `Device.Read.All`,
`DeviceLocalCredential.ReadBasic.All`, `BitLockerKey.ReadBasic.All`.

Requested incrementally on first reveal: `DeviceLocalCredential.Read.All`,
`BitLockerKey.Read.All`.

Requested only if the user enables rotation in Settings:
`DeviceManagementManagedDevices.ReadWrite.All`.

## Architecture, in one screen

Swift package `PitLAPSKit`, six modules:

- **AuthKit** — protocols only, no MSAL dependency
- **AuthKitMSAL** — the only file importing MSAL; tenant pinning
- **CredentialKit** — LAPS + BitLocker providers, `SensitiveValue`. **Isolation boundary:**
  imports Foundation and AuthKit ONLY. No logging, no analytics, no MSAL, no diagnostics.
- **InventoryKit** — device list, paging, search, Windows release naming
- **PlatformSecurity** — biometric gate, reveal window state machine, screen privacy,
  state-restoration suppression, network reachability
- **DiagnosticsKit** — support diagnostics whose types structurally cannot hold a credential

`scripts/isolation-check.sh` enforces the CredentialKit boundary AND that no
credential-shaped value lives in `@AppStorage`/`@SceneStorage`. It has caught real
violations twice, including one the assistant introduced.

`scripts/pre-push-scan.sh` scans the working tree and git history for employer data, PII,
and credential-shaped strings before every push. It has caught leaks the assistant
introduced twice.

~135 tests across five suites, all green.

## Settled decisions worth not relitigating

- **macOS password reveal is impossible**, not pending. Verified empirically: no documented
  Graph endpoint returns it, and the documented beta function returns rotation metadata
  only and currently 500s. Shipping Windows reveal + macOS metadata with a portal handoff.
- **Licence is PolyForm Strict 1.0.0 plus an additional permission** allowing commercial
  organisations to copy and read the source for security review. Source-available, NOT open
  source. The additional grant was necessary because PolyForm Strict alone permits only
  noncommercial purposes, which would have excluded the audit audience.
- **One secret visible at a time.** Revealing a BitLocker key hides the LAPS password.
- **Biometric gate runs BEFORE the Graph call**, not after, so an abandoned reveal does not
  generate an audit event in the customer's tenant.
- **Copy-to-clipboard is a Pro feature.** At the machine you type the password into *their*
  keyboard, so the phone clipboard only helps the secondary workflow.
- **Icon** is a top-down single-seater with a keyhole cockpit, navy field. Source geometry
  is `design/icons/render-icon.py`, not a design file.
- **GitHub Pages is fine until commerce.** Their terms prohibit sites primarily facilitating
  commercial transactions, so the Cloudflare move is a dependency of the Stripe work.

## Working conventions

- **Deliver code as a single zip**, not a stack of individual file cards. Handing over seven
  separate files lost three of them once.
- The sync block on the user's machine:
  ```
  cd ~/Downloads/_pitlaps-incoming
  rm -rf extracted && mkdir extracted
  unzip -q PitLAPS-foundation.zip -d extracted
  S=~/Downloads/_pitlaps-incoming/extracted/PitLAPS
  R=~/Developer/PitLAPS-repo
  cp "$S/App/"*.swift              "$R/App/pitlaps/pitlaps/"
  cp -R "$S/PitLAPSKit/Sources/."  "$R/PitLAPSKit/Sources/"
  cp -R "$S/PitLAPSKit/Tests/."    "$R/PitLAPSKit/Tests/"
  cp "$S/PitLAPSKit/Package.swift" "$R/PitLAPSKit/"
  cp "$S/scripts/"*.sh             "$R/scripts/" && chmod +x "$R/scripts/"*.sh
  ```
- **No comments in shell blocks.** Apostrophes in them ("shouldn't") broke the user's paste
  twice by opening an unterminated quote in zsh. Also avoid em dashes in shell strings.
- **Only one Xcode window at a time** on this project. The app project holds a lock on the
  local package; both open produces "Missing package product" errors. App project for ⌘R,
  Package.swift for ⌘U.
- When `Package.swift` changes, `rm -rf PitLAPSKit/.swiftpm` before reopening, or the test
  targets do not appear.
- The user is a CISSP and very proficient in PowerShell and Entra. Do not over-explain
  identity concepts. Do explain Swift and Xcode.
- Give the plan before commands for anything touching production identity, and stop for
  confirmation before destructive steps.
- Push back directly when something looks wrong. The user has corrected the assistant
  several times and prefers that dynamic.

## Mistakes the assistant made, worth not repeating

- Wrote multi-line Swift strings with backslash continuations, then mangled them with a
  text-processing step, producing literal padding inside a rendered string. Avoid escape
  sequences when generating Swift through Python.
- Attached a SwiftUI `.sheet` to a `Section`, which re-renders on state change and dismissed
  the sheet instantly. Sheets belong on a stable parent.
- Left navigation bars transparent on every screen, so scrolled content read through the
  titles. Fixed with `.toolbarBackground(.visible, for: .navigationBar)`.
- Named the user's employer in documents headed for a public repo. The scanner caught it.
- Timed a network call from before the biometric prompt, so user think-time inflated the
  duration to 4132ms against an actual 617ms.

## What is next after TestFlight

1. **Real-tenant verification** — reveal one real Windows LAPS password on device. Highest
   information value of anything remaining.
2. **Entitlement backend** — Azure Function `/entitlement`, licences table, App Attest.
   The whole revenue path. Deliberately queued after (1); building billing on an unverified
   core is the wrong order.
3. Windows LAPS password history, recents/favourites, biometric app lock
4. PIM role activation from the app (verified v1.0 API; the MFA claims-challenge handling
   makes it a project, not an afternoon)
5. Network transparency doc, trademark filing, attorney pass on the licence wording

Nothing is blocked on Apple or Microsoft any more. Both queues cleared.
