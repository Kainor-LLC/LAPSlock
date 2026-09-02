# Security Policy

LAPSlock handles local administrator passwords. If you find a way to make it leak one,
we want to hear about it.

## Reporting a vulnerability

Email **connor@kainor.com** with "LAPSlock security" in the subject.

Please include what you did, what happened, and the app version. If you have a proof of
concept, describe it in words rather than attaching a real credential — we don't want a
password from your tenant in our inbox any more than you do.

**Please don't** open a public GitHub issue for a vulnerability. Use email first.

## What to expect

- Acknowledgement within 3 business days.
- An assessment and a plan, or an explanation of why we think it isn't exploitable, within
  10 business days.
- Credit in the release notes if you want it, or none if you'd rather stay anonymous.

Kainor LLC is a one-person company, so responses come from a human on a normal schedule,
not a 24/7 security operations center. We'd rather tell you that than pretend otherwise.

## Scope

In scope:

- The iOS client in this repository.
- The entitlement/licensing endpoint (once published).
- Anything that causes a credential to be written to disk, a log, a backup, a screenshot,
  the clipboard beyond its expiry, or any network destination other than Microsoft.

Out of scope:

- Microsoft Graph, Microsoft Entra ID, and Intune themselves. Report those to Microsoft.
- The absence of macOS password reveal. That's a Microsoft API limitation, documented in
  `CredentialKit/MacOSLapsProvider.swift`.
- Findings that require an already-compromised device (jailbreak, malicious profile, or a
  device the attacker physically controls and has unlocked).
- Screenshots. iOS does not allow apps to block them. LAPSlock detects them, hides the
  credential, and recommends rotation — that is the best available behavior, not an
  oversight.

## Design claims you're welcome to test

These are the properties the app is built to guarantee. If you can break one, that's a
finding:

1. **No credential reaches any server we control.** The app talks to
   `login.microsoftonline.com`, `graph.microsoft.com`, and — only after an enterprise
   license is activated — our entitlement endpoint. That endpoint receives a tenant ID and
   nothing else: no credential, no Microsoft token, no user or device identity. The full
   wire format, what the server logs, and how to check both are published in
   `docs/ENTITLEMENT-API.md`. Verify with a proxy — this is our strongest claim and the
   easiest to check.
2. **No credential is logged.** `CredentialKit` links no logging framework, analytics SDK,
   or crash reporter. This is enforced at build time by `scripts/isolation-check.sh`, not
   by convention.
3. **No credential is persisted.** Credential-bearing network calls use an ephemeral
   `URLSession` with no cache and no cookie store. Diagnostics are in-memory only and
   structurally incapable of holding a credential (see `DiagnosticsKit`).
4. **A revealed password is destroyed** on hide, on timeout, on backgrounding, and on
   screen-capture detection.
5. **Authorization is Microsoft's, not ours.** The app requests delegated permissions only.
   Without a directory role that can read LAPS passwords, the app can't either.

## Source availability

The source is published for review. It is **not** open source — see `LICENSE`. Commercial
organizations are expressly permitted to copy and read it for security evaluation, which
includes running it in a test tenant.

One honest limitation: iOS does not support practical reproducible builds, so we cannot
cryptographically prove the App Store binary matches this source. Nobody in this category
can. Observed network behavior is the verifiable claim; the source explains it.
