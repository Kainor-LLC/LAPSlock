# LAPSlock — session handoff

Paste or attach this at the start of a new chat. Attach `docs/MASTER-TODO.md` alongside it
for the full backlog; this file is just enough to resume without re-explaining.

Last updated: 2026-08-27.

---

## Renamed from PitLAPS on 2026-08-27

The product was called PitLAPS until the rename. Family feedback: "PitLAPS" reads as
armpit once someone says it, and the old icon read as phallic. **LAPSlock** lands on Caps
Lock, keeps LAPS as a literal App Store keyword, and carries the security meaning in the
name itself.

Done at the cheapest possible moment: nothing published, no customers, no trademark filed,
no backend code written. USPTO and App Store searches were clear. Name clearance is folded
into the attorney pass already on the list, alongside the "LAPS is Microsoft's product
name" question, which is the larger of the two and predates the rename.

Everything below reflects the new name. Anything still saying PitLAPS is stale.

## What this is

**LAPSlock** — a multi-tenant iOS app for IT administrators to retrieve Windows LAPS local
administrator passwords and BitLocker recovery keys from Microsoft Entra ID and Intune.
Delegated auth only, no backend in the credential path, passwords never touch any server
the vendor operates.

Built by **Kainor LLC** (Kansas, sole member Connor Johnson).

## Immediate context — where we stopped

**The app works on real hardware against a real tenant.** Build 3 is uploaded to
TestFlight. Sign-in, device list, paging, search, Face ID gate, and a real Windows LAPS
password reveal have all been exercised on an iPhone against a live tenant.

**The single largest unverified assumption in the project is now verified.** The Windows
LAPS decode path (base64 → UTF-16LE detection → BOM stripping) processed a real password
from Microsoft Graph and produced the correct string. Everything built on top of it is no
longer built on sand.

Also verified on device: Face ID gate fires before the Graph call (so an abandoned reveal
generates no audit event in the customer's tenant), and app-switcher redaction genuinely
hides a revealed credential in the switcher card.

**Next action:** the entitlement backend. Azure infrastructure is provisioned (see below);
the next piece is the API contract and the Function code.

## Entitlement backend — provisioned 2026-08-27

Subscription **Kainor-LAPSlock** `024f01b2-f4b2-459f-84b6-cf7ced419758`, pay-as-you-go,
spending limit OFF, Kainor tenant, `centralus`. Holds promotional credit; when it runs out
billing simply starts rather than resources being deprovisioned.

Two other empty subscriptions exist on the same tenant (`19dd2b0e` free trial, `797ffeb5`
named "LAPSlock"). Neither is used. The one named "LAPSlock" is a trap — the live one is
**Kainor-LAPSlock**.

| Resource | Name |
|---|---|
| Resource group | `kainor-lapslock-prod-rg` |
| Storage | `kainorlapslockprodst` (no hyphens allowed in storage names) |
| Key Vault | `kainor-lapslock-prod-kv` (RBAC, purge protection ON, 90-day retention) |
| Function app | `kainor-lapslock-prod-func` (Flex Consumption, .NET 10 isolated) |
| Managed identity | `90406c76-87bd-4e22-8a5a-636292cd98d4`, Key Vault Crypto User on the vault only |

Still to do: ES256 key in the vault, licences table, API contract, Function code. Full
detail and the reasoning behind each decision is in `MASTER-TODO.md` under "Backend
(Azure)", including why App Attest is deliberately phase 2.

**The load-bearing design decision:** the entitlement request carries a tenant ID and
nothing else. No Graph token, no user identity, no device data. The product's positioning
is that no vendor server sits in the credential path, and an admin with a proxy must be able
to confirm that in ten minutes.

## Build numbers

Builds 1 to 3 belong to the **old PitLAPS App Store Connect record** and are dead. The
LAPSlock record is new, so build numbers start again at 1.

The old PitLAPS App ID and app record still exist and have deliberately not been deleted:
they are the fallback if anything about the new identity turns out to be wrong. Delete
them only once a LAPSlock build has been uploaded and installed from TestFlight. That is
the one irreversible step in the whole migration.

Build numbers are permanently consumed on upload even if the build is deleted.

## Identifiers (all non-secret)

| Thing | Value |
|---|---|
| Entra app client ID | `50c9aa83-4f5c-4203-a3c0-adab54a2ba3a` |
| Kainor tenant ID | `4470dc21-a4b7-4729-a232-56d4c0eedf73` |
| Bundle ID | `com.kainor.lapslock` |
| App Store Connect record | LAPSlock, name reserved 2026-08-27 |
| Redirect URI | `msauth.com.kainor.lapslock://auth` (registered as iOS/macOS platform) |
| Apple Team ID | `72C7PQBP52` |
| Microsoft MPN (global) | `7147713` |
| Repo | `github.com/Kainor-LLC/LAPSlock` (public, source-available) |
| Site | `kainor.com` (GitHub Pages, `docs/` folder) |
| MSAL version | 1.9.0, pinned |

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

Swift package `LAPSlockKit`, six modules:

- **AuthKit** — protocols only, no MSAL dependency
- **AuthKitMSAL** — the only module importing MSAL. `MSALAuthManager` (tenant pinning) and
  `MSALRedirectHandler` (broker redirect entry point, keeps MSAL out of the app target)
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

120 tests across five suites, all green. Run them with `swift test` from `LAPSlockKit/`,
which is faster than the Xcode window dance and catches macOS-only build breaks that a
device build will not.

## Settled decisions worth not relitigating

- **macOS password reveal is impossible**, not pending. Verified empirically: no documented
  Graph endpoint returns it, and the documented beta function returns rotation metadata
  only and currently 500s. Shipping Windows reveal + macOS metadata with a portal handoff.
- **Licence is PolyForm Strict 1.0.0 plus an additional permission** allowing commercial
  organisations to copy and read the source for security review. Source-available, NOT open
  source.
- **One secret visible at a time.** Revealing a BitLocker key hides the LAPS password.
  `clearForNewReveal()` runs before the gate, so no secret is ever on screen while a
  biometric prompt is in flight.
- **Biometric gate runs BEFORE the Graph call**, not after, so an abandoned reveal does not
  generate an audit event in the customer's tenant. Verified on device.
- **Copy-to-clipboard is a Pro feature.**
- **Icon** is a keycap with a keyhole, navy field. The name reads as a keyboard key, so
  the icon is the artifact the buyer touches all day; a bare padlock was built, compared
  at real device sizes, and rejected. Source geometry is `design/icons/render-icon.py`,
  not a design file. See `design/icons/README.md` for the reasoning and the palette.
- **GitHub Pages is fine until commerce.** The Cloudflare move is a dependency of the
  Stripe work.
- **Do not attempt another privacy-cover fix inside `ScreenPrivacy.swift`.** Two attempts
  failed on device by exposing the credential in the app switcher. The design note above
  `PrivacyCoverModifier` explains why, and where the real fix belongs.

## Working conventions

- **Deliver code as a single zip**, not a stack of individual file cards.
- **Deliver whole files, not one-line patches.** If the whole file is not available, ask
  for the missing ranges rather than guessing at the tail.
- The sync block on the user's machine:
  ```
  cd ~/Downloads/_lapslock-incoming
  rm -rf extracted && mkdir extracted
  unzip -q LAPSlock-foundation.zip -d extracted
  S=~/Downloads/_lapslock-incoming/extracted/LAPSlock
  R=~/Developer/LAPSlock-repo
  cp "$S/App/"*.swift              "$R/App/lapslock/lapslock/"
  cp -R "$S/LAPSlockKit/Sources/."  "$R/LAPSlockKit/Sources/"
  cp -R "$S/LAPSlockKit/Tests/."    "$R/LAPSlockKit/Tests/"
  cp "$S/LAPSlockKit/Package.swift" "$R/LAPSlockKit/"
  cp "$S/scripts/"*.sh             "$R/scripts/" && chmod +x "$R/scripts/"*.sh
  ```
- **No comments in shell blocks.** Apostrophes in them ("shouldn't") broke the user's paste
  twice by opening an unterminated quote in zsh. Also avoid em dashes in shell strings.
- **Only one Xcode window at a time** on this project. App project for ⌘R and Archive,
  `Package.swift` for ⌘U. `swift test` from `LAPSlockKit/` works and avoids the window
  dance entirely.
- When `Package.swift` changes, `rm -rf LAPSlockKit/.swiftpm` before reopening.
- The user is a CISSP, very proficient in PowerShell and Entra, and on a Mac. Do not
  over-explain identity concepts. Do explain Swift and Xcode.
- Give the plan before commands for anything touching production identity, and stop for
  confirmation before destructive steps.
- Push back directly when something looks wrong. The user prefers that dynamic.

## Environment notes learned the hard way

- **Xcode 26 has no Build field on the General tab.** Use Build Settings →
  `CURRENT_PROJECT_VERSION`, or `xcrun agvtool new-version -all N` with Xcode closed.
  agvtool prints a spurious `Cannot find ".../YES"` error; harmless.
- **`xcode-select` can point at Command Line Tools** instead of Xcode, which makes every
  `xcodebuild` invocation fail with a confusing message. Fix:
  `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
- **Never pipe `xcodebuild` stderr to /dev/null while debugging.** It hides exactly the
  error that explains the empty output.
- **Developer Mode does not appear in iPhone Settings** until the phone has been connected
  to a Mac running Xcode at least once. Settings → Privacy & Security, at the bottom.
- Archives are re-signed at distribution, so `get-task-allow = true` in an archive's
  entitlements is normal.

## Mistakes the assistant made, worth not repeating

**From 2026-08-27:** added `MSALRedirectHandler.swift` to AuthKitMSAL without the
`#if os(iOS)` guard that `MSALAuthManager.swift` carries and documents. MSAL builds for
macOS but `handleMSALResponse` does not exist there, so the macOS test build broke the
moment that file was added while the iOS app kept working perfectly. It went unnoticed for
a day because the next steps were all device builds. **Run `swift test` after any change to
AuthKitMSAL**, not just after changes that look test-related.

**The big one, from 2026-08-26:** given a device-only failure with a generic error message,
the assistant wrote code twice before reading a log. Both fixes were wrong. The MSAL log,
once captured, named the cause in one line. **For any device-only failure, get the log
first: cable the phone, ⌘R from Xcode, read the console.** A DEBUG-only MSAL logger is now
wired up in `MSALAuthManager` and prints `[MSAL]` lines with PII suppressed.

Others:

- Conflated two independent bugs (off-main MSAL calls, missing redirect handler) because
  both produced the same user-visible error. Fixing one and seeing no change was the clue.
- Shipped a change to app-switcher redaction without testing the case it protects, and the
  regression exposed a credential in the switcher. **Security-relevant changes get tested
  in the direction that matters before anything else.**
- Assumed `@State` written from `.onChange(of: scenePhase)` would be current on the render
  iOS photographs. It is not; change handlers run after that render.
- Widened search without considering cost, shipping a regression the user felt immediately.
  `range(of:options:)` with `.diacriticInsensitive` folds Unicode on every call, and
  calling a ranking function from inside a sort comparator runs it O(n log n) times.
- Wrote multi-line Swift strings with backslash continuations, then mangled them with a
  text-processing step. Avoid escape sequences when generating Swift through Python.
- Attached a SwiftUI `.sheet` to a `Section`, which dismissed the sheet instantly. Sheets
  belong on a stable parent.
- Named the user's employer in documents headed for a public repo. The scanner caught it.
- Timed a network call from before the biometric prompt, inflating 617ms to 4132ms.

## What is next

1. **Entitlement backend — in progress.** Azure infrastructure is provisioned. Next is the
   API contract (published publicly, implementation private), then the ES256 key, the
   licences table, and the Function code. This is the whole revenue path.
2. **Auth diagnostics in the support report** — MSAL/AAD error code, correlation ID, broker
   path flag, allowlisted so no authorization code can ride along in an error description.
   Promoted from nice-to-have to necessary by the broker bug: a customer hitting the same
   failure today gets "check your connection" and no path forward.
3. **Search only covers loaded pages** — a device that exists is not found until the admin
   has scrolled far enough. Correctness bug on any large tenant.
4. **Privacy cover flash on reveal** — cosmetic, but read the design note before touching
   it. The fix belongs in `DeviceDetailModel`, not `ScreenPrivacy`.
5. Windows LAPS password history, recents/favourites, biometric app lock
6. PIM role activation from the app (the MFA claims-challenge handling makes it a project)
7. Network transparency doc, trademark filing, attorney pass on the licence wording

Nothing is blocked on Apple or Microsoft.
