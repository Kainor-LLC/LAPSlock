# LAPSlock — security and data handling, on one page

For the person who has to approve this before anyone installs it. Everything here is
checkable; the last section says how. **Kainor LLC · Spring Hill, Kansas, USA ·
connor@kainor.com**

## What it is

An iOS app that lets an administrator retrieve Windows LAPS local administrator passwords
and BitLocker recovery keys from your Microsoft Entra ID / Intune tenant, using their own
Microsoft sign-in. It is a client for Microsoft Graph. There is no Kainor account, no Kainor
database of your devices, and no Kainor server between the administrator and the credential.

## Authorization is Microsoft's, not ours

- **Delegated authentication only**, via Microsoft's MSAL library and your tenant's normal
  sign-in, including Conditional Access, MFA and PIM. The app has no permissions of its own.
- **Least-privilege by default.** Read-only Graph scopes at sign-in; the credential-read
  scope is requested at the first reveal; the one write scope (BitLocker key rotation) is
  requested only if the administrator turns rotation on in Settings.
- **Your audit log, not ours.** Every credential read is a Graph call by the signed-in user
  and appears in your Entra audit log exactly as a read from the admin center would.
- **Face ID or Touch ID gates every reveal**, and the gate runs *before* the Graph call, so
  an abandoned reveal creates no audit event.

## Where data lives, and for how long

| Data | Where | Retention |
|---|---|---|
| Microsoft sign-in tokens | iOS Keychain, device-only, never synced | Until sign-out or Microsoft expiry |
| Device inventory being browsed | App memory | Cleared on sign-out or app close |
| A revealed password or key | App memory only | Destroyed on hide, timeout, backgrounding, or screenshot |
| Clipboard copy (Pro) | Local pasteboard only, no Universal Clipboard | Expires after 90 seconds |
| Free-tier reveal tally | iOS Keychain (count only, no identifiers) | Rolling 30 days |
| Organization license token | iOS Keychain, device-only | Until removed; refreshed about monthly |

**Nothing is written to disk, to a log, to a backup, or to any Kainor system.** The module
that handles credentials links no logging, analytics or crash-reporting framework, and the
build fails if one is added (`scripts/isolation-check.sh`).

## What Kainor receives

For a **free-tier** installation: nothing. The app contacts `login.microsoftonline.com` and
`graph.microsoft.com` only.

For an **organization with a paid license**, after an administrator taps Activate: a request
to one Kainor endpoint containing your Microsoft tenant ID and a version number, about once
a month. No Microsoft token, no user identity, no device data, no usage counts. Our record
of a paying organization is its tenant ID, tier, term and order reference — no names, no
email addresses. Our server does not log tenant IDs. Full specification:
`docs/ENTITLEMENT-API.md`.

**No analytics, telemetry or crash reporting of any kind**, on any tier. Diagnostics exist,
but are assembled on the device only when the administrator asks, are shown in full before
sending, and are structurally incapable of containing a credential, device name or user name.

## Encryption and transport

TLS 1.2+ to Microsoft and to Kainor. Credential-bearing requests use an ephemeral session
with no cache and no cookie store. License statements are ES256-signed and verified against
a public key compiled into the app, so a compromised network can deny a license but not
forge one, and a forged license could not read a credential in any case.

## Regulatory posture, stated carefully

Kainor LLC does not receive your organization's device data or credentials and therefore
does not act as a processor of them; Microsoft remains the processor under your existing
agreement. Kainor holds no personal data about LAPSlock users. A tenant ID identifies an
organization. Kainor LLC is a single-member company and does not currently hold a SOC 2 or
ISO 27001 certification; the controls above are enforced in published source rather than
attested by a third party.

## Verify it

1. Install a TLS-intercepting proxy on a test iPhone and trust its certificate.
2. Sign in to a test tenant and reveal a credential.
3. Observe two hosts, both Microsoft. Search the capture for the credential: it appears once,
   in a Graph response.

Ten minutes. Step-by-step in `docs/NETWORK-TRANSPARENCY.md`. Vulnerability reports:
`SECURITY.md`. Source, published for security review: github.com/Kainor-LLC/LAPSlock.

*LAPSlock is not affiliated with, endorsed by, or sponsored by Microsoft Corporation.*
