# QUICKSTART — first run in Xcode

Goal for this session: **get the security-core tests to pass.** Nothing else. No app to
launch, no sign-in, no Microsoft connection. Just proof that the foundation compiles and
its logic is correct.

Expected time: 10 minutes. Nothing here touches a tenant or the network.

---

## Before you start

- **Xcode installed** from the Mac App Store (large download; do it ahead of time).
- Open Xcode once and let it install additional components when it asks.

## Step 1 — open the package

1. Unzip the project somewhere permanent, e.g. `~/Developer/PitLAPS`.
2. In Terminal:
   ```bash
   cd ~/Developer/PitLAPS/PitLAPSKit
   open Package.swift
   ```
   That opens the Swift package in Xcode. (Opening `Package.swift` directly is the
   correct move — there is deliberately no `.xcodeproj` yet.)
3. Xcode will resolve dependencies. Watch the top status bar. The MSAL package is fetched
   from GitHub; it belongs to the `AuthKitMSAL` target only. If resolution fails or hangs,
   it does **not** block Step 2 — see Troubleshooting.

## Step 2 — run the tests

1. Leave the destination on **My Mac** (fastest — no simulator to boot). An iPhone
   simulator also works if you prefer.
2. Press **⌘U** (or Product → Test).
3. First run compiles everything, so give it a minute.

### What success looks like

The test navigator (⌘6) shows green checkmarks for roughly 20 tests across two files:

- **SensitiveValueTests** — base64 decoding (UTF-8, UTF-16LE, BOM handling), the
  encoding auto-detect heuristic, and wipe semantics.
- **ProviderCapabilityTests** — platform mapping, Windows declares reveal supported,
  macOS declares reveal *un*supported with a user-facing reason, rotate is off by
  default, and the coordinator refuses reveal on an unsupported platform.

If those are green, the security core is verified: password decoding is correct, the
credential boundary type behaves, and the macOS decision is locked in by test.

## Step 3 — run the isolation guard

In Terminal, from the project root:

```bash
cd ~/Developer/PitLAPS
./scripts/isolation-check.sh
```

Expect: `✅ isolation-check passed: CredentialKit imports only Foundation + AuthKit.`

This is the check that keeps a password from ever reaching a log or a server. Run it
before every commit. To see it work, temporarily add `import OSLog` to any file in
`PitLAPSKit/Sources/CredentialKit/` and run it again — it should fail. Remove the import.

---

## Troubleshooting

**"The package product 'MSAL' requires minimum platform version 10.15 for the macOS
platform"** — fixed in this version of the manifest (macOS 11 is now declared, and the
MSAL implementation is wrapped in `#if os(iOS)`). If you still see it, you're on the old
`Package.swift`; re-download and replace it.

**Errors inside `MSALAuthManager.swift`** — expected, and safe to ignore for now. That
file is the one piece written against an API surface that shifts between MSAL versions,
and it has never been compiled. It lives in its own target (`AuthKitMSAL`) precisely so
it can't block anything else. To get tests running regardless:

- Xcode → scheme selector (top bar) → choose the **CredentialKitTests** scheme, then ⌘U.
  The test target depends only on `CredentialKit` and `AuthKit`, so MSAL never builds.
- Send me the exact error text and I'll correct that file.

**"Missing package product 'MSAL'" or resolution hangs** — network or GitHub issue.
File → Packages → Reset Package Caches, then File → Packages → Resolve Package Versions.
If it still fails, use the CredentialKitTests scheme as above; the tests don't need MSAL.

**"No such module 'AuthKit'"** — you probably opened a single `.swift` file instead of
`Package.swift`. Close and reopen via `open Package.swift`.

**Any compile error in CredentialKit, AuthKit, or the tests** — that's a real bug I
should fix. Copy the full error (file, line, message) and send it over. I could not
compile Swift in the environment where this was written, so a first-compile fix or two
is expected; the logic is what the tests are there to verify.

---

## What you are NOT doing yet

- No app to run — there's no UI target yet, by design.
- No Entra app registration needed.
- No connection to any tenant.
- `AuthConfiguration.vendorDefault.clientId` is still a placeholder string.

Those all come after the foundation is confirmed green.

## Then what

Next build session adds:
1. **InventoryKit** — device list, paging, search, and the two-identifier join that
   Windows reveal depends on (Intune managedDeviceId ↔ Entra azureADDeviceId).
2. **PlatformSecurity** — biometric gate, app-switcher redaction, capture detection.
3. The first SwiftUI screens on top of those.
