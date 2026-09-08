# LAPSlock

LAPSlock is an iOS app for IT administrators. It reads Windows LAPS local administrator
passwords and BitLocker recovery keys from Microsoft Entra ID and Intune, on the phone the
administrator already carries, using the permissions their account already holds.

[Download on the App Store](https://apps.apple.com/us/app/lapslock/id6806470554) ·
[How it works](https://kainor.com/how-it-works/) ·
[Pricing](https://kainor.com/pricing/) ·
[Privacy](https://kainor.com/privacy/)

Built by [Kainor LLC](https://kainor.com). LAPSlock is a trademark of Kainor LLC. Kainor LLC
is not affiliated with, endorsed by, or sponsored by Microsoft Corporation.

## Why the source is published

An app that handles local administrator passwords should not ask for blind trust. The client
source is published so that a security team can read what it does before anyone installs it.

The licence is PolyForm Strict 1.0.0 with an additional permission that expressly allows
commercial organisations to copy and read the code for security review. Redistribution,
modification and publishing builds are not permitted. See [LICENSE](LICENSE).

## Five claims you can check

1. **No vendor server in the credential path.** Passwords travel from Microsoft Graph to the
   device over TLS. Kainor has no server that could see one. The app talks to exactly three
   hosts, and the third only after an organisation activates a licence. The ten-minute proxy
   recipe is in [NETWORK-TRANSPARENCY.md](docs/NETWORK-TRANSPARENCY.md).
2. **Delegated permissions only.** The app can read what the signed-in account can read in
   the admin center, and nothing else. Every reveal appears in the tenant's own Entra audit
   log exactly as a read from the portal would.
3. **Nothing collected.** No analytics, no telemetry, no crash reporting, no account. The
   App Store privacy label says Data Not Collected. The reveal meter for the free tier is
   counted in the device Keychain and never leaves it.
4. **Credential handling is isolated by construction.** The module that touches passwords,
   `CredentialKit`, imports Foundation and the auth protocol and nothing else. Adding a
   logging framework, an analytics SDK or the licensing layer to it is a compile error, and
   `scripts/isolation-check.sh` fails the build if anyone tries.
5. **The licensing backend receives one value.** A tenant ID, roughly monthly, and it returns
   a signed tier. The full request and response contract, including what is and is not
   logged, is [ENTITLEMENT-API.md](docs/ENTITLEMENT-API.md).

If you find a way to make the app leak a credential, [SECURITY.md](SECURITY.md) explains how
to report it.

## What it does

- Search every managed device in the tenant, with background paging.
- Reveal the current Windows LAPS password and the password history Graph returns with it.
- Reveal BitLocker recovery keys per volume.
- Activate a PIM-eligible role from the phone, reading the tenant's own activation policy.
- Switch between customer tenants (MSP plan), with per-tenant favourites and recents.
- Optional biometric app lock and optional user display names, each an explicit choice.

## Platform support

| | Metadata | Reveal |
|---|---|---|
| Windows LAPS | Yes, Graph v1.0 | Yes, Graph v1.0 |
| BitLocker | Yes | Yes |
| macOS LAPS | Rotation date only, Graph beta | No |

macOS passwords cannot be revealed because no Microsoft Graph endpoint returns them. The only
macOS function returns a rotation timestamp and, at the time of writing, fails with HTTP 500
for ADE-enrolled Macs. The evidence and the steps to enable reveal if Microsoft ships an API
are in the header of `LAPSlockKit/Sources/CredentialKit/MacOSLapsProvider.swift`. LAPS
backed up to on-premises Active Directory is out of scope; Entra-backed LAPS only.

## Architecture

```
App/lapslock                      SwiftUI app target
LAPSlockKit/Sources
  AuthKit                         auth protocol and models, no third-party dependencies
  AuthKitMSAL                     the only module that links MSAL
  CredentialKit                   LAPS and BitLocker providers, SensitiveValue   (isolated)
  InventoryKit                    device list, search, paging, favourites
  PrivilegedAccessKit             PIM eligibility and activation
  LicensingKit                    entitlement token verification
  SubscriptionKit                 StoreKit 2 subscriptions
  DiagnosticsKit                  the support report, structurally unable to carry a secret
  PlatformSecurity                biometrics and app-switcher redaction
```

`CredentialKit` depends on `AuthKit` and Foundation only. `LicensingKit` does not import
`CredentialKit`. Both directions are enforced by `scripts/isolation-check.sh`.

## Building and testing

Requires Xcode 26 on macOS.

```
./scripts/isolation-check.sh
cd LAPSlockKit && swift test
open App/lapslock/lapslock.xcodeproj
```

The package tests run on macOS without a tenant or a network connection. The MSAL
implementation is iOS-only, so building the app target is the check that covers it:

```
xcodebuild -project App/lapslock/lapslock.xcodeproj -scheme lapslock \
  -destination 'generic/platform=iOS' -configuration Debug CODE_SIGNING_ALLOWED=NO build
```

Two PowerShell scripts in `tools/` reproduce the macOS LAPS findings against a live tenant
using the Microsoft Graph PowerShell SDK. They read only and never print a password.

## Documents

- [SECURITY.md](SECURITY.md): disclosure policy and the testable design claims.
- [docs/NETWORK-TRANSPARENCY.md](docs/NETWORK-TRANSPARENCY.md): the three hosts, the one
  Kainor request byte for byte, and the proxy recipe.
- [docs/ENTITLEMENT-API.md](docs/ENTITLEMENT-API.md): the licensing contract.
- [docs/SECURITY-ONE-PAGER.md](docs/SECURITY-ONE-PAGER.md): a one-page summary for a
  security team.
- [docs/BUILD-SPEC.md](docs/BUILD-SPEC.md): the design specification the app was built from.
- [CONTRIBUTING.md](CONTRIBUTING.md): issues are welcome; pull requests are not accepted,
  and the file explains why.

## Contact

connor@kainor.com
