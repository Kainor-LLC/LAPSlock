# LAPSlock

iOS app for IT administrators: retrieves Windows LAPS local administrator passwords and
BitLocker recovery keys from Microsoft Entra ID and Intune. Delegated auth only, no vendor
server in the credential path. Built by Kainor LLC.

**Read `docs/SESSION-HANDOFF.md` first, and `docs/MASTER-TODO.md` for the backlog and the
decided work order.** Those are not imported here on purpose: they are long, and importing
them would load ~1200 lines into every session. Read them when you need them.

This file holds only what you cannot work out from the code.

---

## The rule that must not break

**CredentialKit imports Foundation and AuthKit. Nothing else. Ever.**

It is where credentials live. Adding a licensing module, an analytics SDK or any logging
framework to it must stay a compile error. `LicensingKit` must not import CredentialKit
either, and the guard checks both directions.

```
./scripts/isolation-check.sh     # run after ANY change to CredentialKit or LicensingKit
./scripts/pre-push-scan.sh       # run before EVERY push. Non-negotiable: the repo is public
```

`pre-push-scan.sh` scans for employer data, PII and credential-shaped strings. It has
caught real leaks twice, both introduced by an assistant. Do not push without it.

## Commands

```
cd LAPSlockKit && swift test              # 138 tests, faster than the Xcode window dance
open App/lapslock/lapslock.xcodeproj      # app project, for building and running
```

**Run `swift test` after ANY change to AuthKitMSAL.** MSAL builds for macOS but some of its
API does not exist there, so a missing `#if os(iOS)` breaks the macOS test build while the
iOS app stays perfectly healthy. That shipped once and went unnoticed for a day.

**And `swift test` is NOT sufficient for AuthKitMSAL — build the iOS app too.** The whole
implementation sits inside `#if os(iOS)`, so on macOS it compiles to nothing and the test
suite validates none of it. A wrong MSAL API label passed 262 green tests and failed the
iOS build immediately. The two checks cover opposite halves and neither substitutes for the
other:

```
cd LAPSlockKit && swift test
xcodebuild -project App/lapslock/lapslock.xcodeproj -scheme lapslock \
  -destination 'generic/platform=iOS' -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

## Working with this person

- **They run PowerShell on a Mac.** Bash idioms fail: `VAR=value` assignments, `$VAR`
  expansion, `&&` chaining. Give PowerShell-native commands or full paths with no variables.
- **Deliver whole files, not one-line patches.** If you do not have the whole file, read it
  before editing rather than reconstructing it.
- **Plan before commands for anything touching production identity**, and stop for
  confirmation before anything destructive.
- **Push back directly when something looks wrong.** They prefer that, and have corrected
  the assistant several times.
- CISSP, very strong in PowerShell and Entra. Do not explain identity concepts. Do explain
  Swift and Xcode.
- No comments inside shell blocks. Apostrophes in them have broken pastes.

## The most expensive lesson so far

**For a device-only failure with a generic error message, read the log before writing code.**

Four bugs shipped that were unreachable in the simulator: demo providers reachable from the
live path, MSAL running off the main thread, broker redirects never handled, and a search
performance regression. On the broker bug, two fixes were written and both were wrong; the
MSAL log named the cause in one line as soon as it was captured.

Cable the phone, ⌘R from Xcode, read the console. A DEBUG-only MSAL logger is wired up in
`MSALAuthManager` and prints `[MSAL]` lines with PII suppressed.

## Environment traps, all hit for real

- **`xcode-select` can point at Command Line Tools**, making every `xcodebuild` call fail
  confusingly. Fix: `sudo xcode-select -s /Applications/Xcode.app/Contents/Developer`.
- **Never pipe `xcodebuild` stderr to /dev/null while debugging.** It hides the error that
  explains the empty output.
- **After renaming the repo folder, delete `.build` AND `.swiftpm`.** Both cache absolute
  paths and fail with "XCFramework Info.plist not found" pointing at the old directory.
- **Adding a library to `Package.swift` does not link it to the app target.** Package tests
  pass while the app fails with "Unable to resolve module dependency". Fix in Xcode: target
  → General → Frameworks, Libraries, and Embedded Content → +.
- **A default argument expression is evaluated in a nonisolated context.** Defaulting a
  parameter to a `@MainActor` initializer fails even inside a `@MainActor` class. Default
  to nil and construct in the initializer body.
- **Xcode 26 has no Build field on the General tab.** Use Build Settings →
  `CURRENT_PROJECT_VERSION`, or `xcrun agvtool new-version -all N` with Xcode closed.
- **One Xcode window at a time.** The app project locks the local package.
- **A NavigationStack does not disappear when a detail view is pushed onto it**, so
  `.onAppear` there fires once at launch and never again. Refresh from the detail view's
  `.onDisappear`.
- **`az functionapp show` nests everything under `properties`; `az functionapp list`
  flattens it.** A `--query` written for one silently returns nulls against the other, and
  `--output table` hides null columns rather than showing them empty. Use `--output json`
  when verifying.
- **`httpsOnly` is false when a Flex Consumption function app is created.** Set it
  explicitly and verify. Seen on two separate apps, so it is the default.

## Decisions not to relitigate

- **macOS password reveal is impossible**, not pending. Verified empirically against Graph.
- **Free tier is metered, not crippled.** Reveal stays free because reveal is what a
  sceptical admin needs to verify; convenience is gated. The count lives in the Keychain
  and NEVER on a server — a server counter would mean recording how often each tenant
  retrieves passwords, and the privacy policy says none is collected.
- **The meter is checked BEFORE the biometric gate and charged AFTER the Graph response.**
  Two separate calls. Checking after the gate would make somebody complete Face ID and only
  then learn they are out; charging before the fetch would burn a credit on a cancelled
  prompt.
- **The biometric gate runs BEFORE the Graph call**, so an abandoned reveal generates no
  audit event in the customer's tenant.
- **Do not attempt another privacy-cover fix in `ScreenPrivacy.swift`.** Two attempts failed
  on device by exposing the credential in the app switcher. The design note above
  `PrivacyCoverModifier` explains why and where the real fix belongs.
- **The shipping icon comes from `design/icons/texturize-icon.py`**, not `render-icon.py`.

## Before any commit

```
./scripts/isolation-check.sh
./scripts/pre-push-scan.sh
cd LAPSlockKit && swift test
```

All three green, or do not commit.
