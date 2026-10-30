# Network transparency

LAPSlock handles local administrator passwords, so "trust us" is not an acceptable answer to
"what does it send, and to whom." This document is the answer, and it is written to be
**checked, not believed**: every claim in it is observable with a network proxy in about ten
minutes, and section 4 tells you how.

## 1. The hosts

TenantKeep On-Call talks to exactly these hosts. There is no eighth.

| Host | Operator | When | What crosses the wire |
|---|---|---|---|
| `login.microsoftonline.com` | Microsoft | Sign-in, token refresh | Your Microsoft sign-in, brokered by MSAL. Standard Entra ID delegated auth. |
| `graph.microsoft.com` | Microsoft | Every module that reads your tenant | Graph requests carrying your delegated token; Graph responses carrying your organization's data, including the credential you asked for. |
| `www.cisa.gov` | CISA (US government) | Only when you open the Security module's Digest tab, at most every fifteen minutes unless you pull to refresh, and, if you turn on Threat Digest notifications, when iOS runs the background check | A GET for three public files: the Known Exploited Vulnerabilities catalog and two advisory feeds. No token, no tenant ID, no cookie, no identifier. On a repeat read the request also carries the `ETag` or `Last-Modified` value this server sent for the same file, so an unchanged file is not downloaded again. The files come back, and the last good copy of each is kept in the app's Caches folder on the phone. |
| `api.msrc.microsoft.com` | Microsoft | Only when the Digest is read, on the same schedule | A GET for the public Security Update Guide, filtered to the last thirty days. Same rule: nothing of yours in the request, only the server's own validator on a repeat read, and the last good copy kept in Caches. |
| `isc.sans.edu` | SANS Internet Storm Center | Only when the Digest is read, on the same schedule | A GET for the public diary feed. Same rule: nothing of yours, only the server's own validator on a repeat read, the last good copy in Caches. The diaries are shown in full with SANS's written agreement. |
| `www.bleepingcomputer.com` | BleepingComputer | Only when the Digest is read, on the same schedule | A GET for the public news feed: headlines and short summaries. Same rule. The app never fetches an article page; *Open on the site* hands the link to Safari. Shown with BleepingComputer's written agreement. |
| `kainor-lapslock-prod-func.azurewebsites.net` | Kainor LLC | **Only after you activate an organization license**, then about monthly | A version number and your Microsoft tenant ID. Nothing else. A signed license statement comes back. |

**Relayed alerts add no host to this list.** When an organization turns on relayed alerts,
its own Azure Automation account sends encrypted alerts to `kainor-relay-prod-func.azurewebsites.net`,
which passes them to Apple's push service, and the phone receives them as ordinary notifications
from Apple. The app never makes a request to the relay. What the relay sees and keeps is in
[RELAY-API.md](RELAY-API.md), section 9; its source is under `relay/` in this repository.

**A free-tier installation never contacts Kainor.** It talks to the two Microsoft hosts for
your data, the four public feed hosts for the Digest, and nothing else, and there is no code
path that can change that without a tap on *Activate organization license* in Settings. Demo
mode has no path to Kainor at all.

**The feed hosts cannot receive anything of yours, structurally.** The code that fetches
them is a package target capped at Foundation by the isolation guard in `scripts/isolation-check.sh`:
it cannot import the authentication layer, so it has no way to hold a token or a tenant ID, and
the session it uses sends no cookies and one `Accept` header. The host allowlist is checked on
every URL about to be sent.

## 2. What never leaves the phone to anyone but Microsoft

- Passwords and BitLocker recovery keys. They travel from Microsoft Graph to the app over
  TLS, are held in memory, and are destroyed on hide, timeout, backgrounding or screen
  capture. No Kainor server is in that path, and no Kainor server *could* be: the module
  that handles credentials links no networking to anything but Graph, no logging, and no
  analytics, and the build fails if that changes (`scripts/isolation-check.sh`).
- Your Microsoft tokens. They go to Microsoft and are used against Graph. The Kainor
  endpoint never receives one, which is why it cannot act in your tenant.
- Device names, identifiers, models, compliance states, user names, search terms.
- How many credentials you revealed, which ones, or when. The free-tier meter is a tally
  kept in the phone's Keychain and never transmitted. A server counter would mean recording
  how often each tenant retrieves passwords, and this product does not.

## 3. The one Kainor request, byte for byte

```
POST /entitlement HTTP/1.1
Host: kainor-lapslock-prod-func.azurewebsites.net
Content-Type: application/json; charset=utf-8
Accept: application/json
User-Agent: LAPSlock/<app version> (iOS)

{"version":1,"tenantId":"<your tenant GUID>"}
```

No `Authorization` header. No cookies, the session is ephemeral and refuses them. The
`User-Agent` is set explicitly because URLSession's default would otherwise add the bundle
build and OS version; the one we send names the app and its version and nothing else.

The response is a signed token stating your organization's license tier. The app verifies
the signature against a public key compiled into the app, it never downloads a key, so a
hostile network can deny or downgrade the answer but cannot forge one. The complete
specification, including what our server keeps and what it deliberately does not, is
[`ENTITLEMENT-API.md`](ENTITLEMENT-API.md). Section 8 of that document is the honest account
of server-side retention; the short version is that the tenant ID is not logged, and the
only durable record is one row per *paying* organization.

Why the tenant ID and not something stronger? Because anything stronger would mean sending
your Microsoft token to us, and that would hand a vendor delegated access to your tenant. A
tenant ID is public, any domain's is returned by unauthenticated OIDC discovery, so a
stolen license token is useful only to someone already inside the licensed tenant, who is
already covered by the license. That reasoning is spelled out in the contract, section 9.1.

## 4. Check it yourself, in ten minutes

1. Install a TLS-intercepting proxy, Proxyman, Charles or mitmproxy, and trust its root
   certificate on the iPhone.
2. Sign in to LAPSlock and use it normally: search, open a device, reveal a Windows LAPS
   password, reveal a BitLocker key.
3. Read the capture. You will see `login.microsoftonline.com` and `graph.microsoft.com`.
   **You will not see a Kainor host.** If you open the Security module's Digest tab you will
   also see `www.cisa.gov`, `api.msrc.microsoft.com`, `isc.sans.edu` and
   `www.bleepingcomputer.com`, each a plain GET with no
   `Authorization` header and no cookie. A repeat read adds `If-None-Match` or
   `If-Modified-Since`, carrying back the value that same server sent for that file.
4. If you hold an organization license, tap *Activate organization license* in Settings and
   watch the third host appear once. Confirm the body is
   `{"version":1,"tenantId":"<your tenant>"}` and that nothing further is sent to it while
   you keep using the app.
5. Search the whole capture for the password or key you revealed. It appears exactly once,
   in a Graph response, to Microsoft.

Step 5 is the one that matters. If it fails, that is a security vulnerability; report it as
described in [`SECURITY.md`](../SECURITY.md) and it will be treated as one.

## 5. What this document cannot prove

iOS does not support practical reproducible builds, so we cannot cryptographically prove the
App Store binary matches the published source. Nobody in this category can. That is exactly
why this document is about *observed behavior* rather than about the source: the proxy
capture is evidence about the binary you are actually running, and it does not depend on
trusting us, our build machine, or this page.

The source is published so you can see *why* the capture looks the way it does. The capture
is what tells you that it does.

## 6. If this changes

Adding a host that receives anything of yours, adding a field to the one Kainor request, or
sending anything to a Kainor host in response to a user action other than Activate or
Refresh would each be a breaking change to the entitlement contract, requiring a new version
of it and a note in the release notes. The public feed hosts were added with the Threat
Digest, CISA and Microsoft first and the two news publishers with their agreement on
2026-10-29; they receive a request for a public file and nothing else, and the list in
section 1 says so. If you ever observe otherwise, you have found either a bug or a broken promise, and
we would like to hear about both.

---

*Last updated 2026-09-02. Kainor LLC is not affiliated with, endorsed by, or sponsored by
Microsoft Corporation.*
