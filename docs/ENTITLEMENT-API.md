# LAPSlock entitlement API — version 1

**Status:** frozen for implementation. Nothing here may change without a version bump
except the additive changes listed under [Versioning](#12-versioning-and-compatibility).

**Date:** 2026-09-01
**Operator:** Kainor LLC (Kansas, US)
**Contact:** connor@kainor.com

This document is published; the implementation is not. It exists so that an administrator
evaluating LAPSlock can read what the app sends to a Kainor server, decide whether they
believe it, and then verify it in about ten minutes with a proxy. Section 10 tells them how.

---

## 1. What this endpoint is, and what it deliberately is not

LAPSlock retrieves Windows LAPS passwords and BitLocker recovery keys directly from
Microsoft Graph using delegated access. **No Kainor server sits in that path.** There is
exactly one Kainor-operated endpoint in the whole product, it is this one, and its only job
is to answer a single question:

> Does this Microsoft tenant hold a paid LAPSlock license, and at what tier?

It answers with a signed statement. It never sees a credential, a Graph token, a user
identity, a device name, or a device identifier, because none of those are in the request.

Four constraints shape everything below. They are settled, and the design is downstream of
them rather than the other way around:

1. **The request carries a tenant ID and nothing else.** Sending a customer's Graph token
   to a vendor server would hand that vendor delegated access to the customer's tenant. No
   quantity of "we don't log it" survives an administrator seeing it on the wire.
2. **Reveal counts are never sent anywhere.** The free-tier meter lives in the device
   Keychain. A server-side counter would mean recording how often each tenant retrieves
   administrator passwords, which is usage telemetry, and the privacy policy says none is
   collected.
3. **Failure degrades, never blocks.** If this endpoint is unreachable, slow, hostile, or
   permanently dead, LAPSlock still signs in, still lists devices, and still reveals
   credentials on the free allowance. The revenue path is allowed to fail closed to *free*;
   it is never allowed to fail closed to *unusable*.
4. **Verification is offline.** The signing public keys are compiled into the app. The
   client never fetches a key, so it never trusts the network for anything that decides
   whether it is licensed.

---

## 2. Endpoint

| | |
|---|---|
| Method | `POST` |
| Path | `/entitlement` |
| Host (v1) | `kainor-lapslock-prod-func.azurewebsites.net` |
| Scheme | `https` only. Plain HTTP is refused, not redirected. |
| TLS | Standard public PKI, Azure-managed certificate. No certificate pinning. |
| Authentication | **None.** No API key, no bearer token, no function key. |
| Request content type | `application/json; charset=utf-8` |
| Response content type | `application/json; charset=utf-8` |
| Idempotent | Yes. Repeated identical requests are safe and produce equivalent tokens. |

The host may move to a custom domain later. A host change is not a contract change, but it
is a release-notes change and the network transparency document is updated with it in the
same release, because "the app talks to exactly these hosts" is only a useful claim if the
list is current.

### Why there is no API key

The client is a public, source-available iOS app. Any key compiled into it is readable by
anyone who downloads the source or strings the binary, so it would authenticate nothing
while creating the false impression that the endpoint is authenticated. Abuse is handled
with rate limits (§8), which work whether or not the caller is honest.

### Required and permitted headers

The client sends exactly these, and a proxy should see nothing else that Kainor controls:

```
POST /entitlement HTTP/1.1
Host: kainor-lapslock-prod-func.azurewebsites.net
Content-Type: application/json; charset=utf-8
Accept: application/json
User-Agent: LAPSlock/<app version> (iOS)
Content-Length: <n>
```

- **No `Authorization` header.** Nothing derived from the user's Microsoft session ever
  goes to this host.
- **No cookies.** The request is made on an ephemeral `URLSession` with no cookie store and
  no cache, so there is no persistent client identifier and no cross-request linkage.
- **The `User-Agent` carries the app version and nothing else** — no device model, no OS
  build, no install identifier. It is there so a support ticket can be matched to a
  release. It is documented here rather than left as an accident of the HTTP stack.

Servers MUST ignore request headers not listed here. Clients MUST NOT add any.

---

## 3. Request

```json
{
  "version": 1,
  "tenantId": "c0ffee00-1111-2222-3333-444455556666"
}
```

| Field | Type | Required | Rules |
|---|---|---|---|
| `version` | integer | yes | Request-body version. `1` for this contract. |
| `tenantId` | string | yes | The Entra tenant the user is signed in to. Lowercase canonical GUID, 36 characters with hyphens. |
| `attestation` | string \| null | no | **Reserved, phase 2.** Base64 App Attest attestation object. v1 servers ignore it. |
| `assertion` | string \| null | no | **Reserved, phase 2.** Base64 App Attest assertion. v1 servers ignore it. |

That is the entire request. There is no user object, no device object, no counter, no
timestamp, no telemetry block, and no room for one — a server that starts requiring more
has broken this contract and needs `"version": 2`.

`attestation` and `assertion` are defined now, and specified as ignored now, so that adding
App Attest later is an additive change rather than a breaking one. App Attest is
deliberately phase 2; §9.6 says why.

### Server-side request rules

- Servers MUST accept and ignore unknown fields. A v1 server receiving an `attestation` it
  does not understand answers normally.
- Servers MUST reject a body larger than 4 KiB with `400`.
- Servers MUST reject any `version` they do not implement with `400 unsupported_version`.
- Servers MUST validate `tenantId` as a GUID before it reaches any storage lookup, and MUST
  compare it case-insensitively while storing and signing the lowercase form.

---

## 4. Response

### 4.1 Success — always `200`, always a token

```json
{
  "version": 1,
  "token": "<base64url header>.<base64url payload>.<base64url signature>",
  "refreshAfter": "2026-09-24T00:00:00Z"
}
```

| Field | Type | Meaning |
|---|---|---|
| `version` | integer | Response-body version, `1`. |
| `token` | string | Compact JWS. The only field with any authority. See §5. |
| `refreshAfter` | string | RFC 3339 UTC. **Advisory only.** A hint about when to come back. |

**An unlicensed tenant gets `200` and a valid token with `"tier": "free"`.** It does not get
a `404`, and this is deliberate: a uniform response means the client has exactly one code
path, and it means the endpoint cannot be used as an oracle to discover which tenants are
paying customers.

`refreshAfter` is advisory in the strict sense: the client clamps it into a sane range and
never lets it override a verified `exp`. A server that returns a `refreshAfter` in 1999 or
2099 changes nothing about whether the app is licensed.

### 4.2 Errors

```json
{
  "version": 1,
  "error": "invalid_request",
  "message": "tenantId is not a GUID"
}
```

| Status | `error` | Meaning | Client behavior |
|---|---|---|---|
| `400` | `invalid_request` | Malformed body, oversized body, bad GUID. | Bug. Do not retry. Surface in diagnostics. |
| `400` | `unsupported_version` | Server does not implement this `version`. | Do not retry. Prompt to update the app. |
| `405` | `method_not_allowed` | Not a `POST`. | Do not retry. |
| `429` | `rate_limited` | Too many requests for this tenant or source. | Honor `Retry-After`. Keep the cached token. |
| `500` | `server_error` | Unhandled fault. | Retry once with backoff, then give up quietly. |
| `503` | `signing_unavailable` | Key Vault unreachable or the key is unavailable. | Retry once with backoff, then give up quietly. |

`message` is for a human reading a diagnostic report. It MUST NOT echo the request body and
MUST NOT vary based on whether the tenant holds a license — the difference between "no
license" and "a license" is only ever expressed as a `tier` inside a signed token.

Every error path leaves the app working. §7.6 defines what "give up quietly" means.

---

## 5. The entitlement token

A compact JWS (RFC 7515), ES256, three base64url segments separated by dots.

### 5.1 JOSE header

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "lapslock-ent-2026-09"
}
```

`alg` is always exactly `ES256`. `kid` names one of the public keys compiled into the app.

### 5.2 Claims

```json
{
  "iss": "https://kainor.com/lapslock",
  "aud": "com.kainor.lapslock",
  "sub": "c0ffee00-1111-2222-3333-444455556666",
  "tier": "enterprise",
  "iat": 1788307200,
  "nbf": 1788307140,
  "exp": 1790899200,
  "jti": "9f1d4a2e-0c77-4a35-9b1a-3f2c5d8e7b60"
}
```

| Claim | Type | Value |
|---|---|---|
| `iss` | string | Exactly `https://kainor.com/lapslock`. A **logical** issuer identifier, not a URL the client fetches, so moving the API to another host does not invalidate tokens in the field. |
| `aud` | string | The iOS bundle identifier, `com.kainor.lapslock`. |
| `sub` | string | The licensed tenant GUID, lowercase. Equal to the request's `tenantId`. |
| `tier` | string | One of `free`, `pro`, `msp`, `enterprise`. See §5.3. |
| `iat` | number | Issued-at, seconds since epoch. |
| `nbf` | number | `iat - 60`. One minute of slack for a server clock ahead of the phone. |
| `exp` | number | `iat + 30 days`. See §5.4. |
| `jti` | string | Unique per issued token, a GUID. |

There are no other claims in v1. Clients MUST ignore claims they do not recognize, so that
adding one later is additive; servers MUST NOT add one that changes the meaning of an
existing claim.

**`jti` is honest about its job.** There is no revocation list in v1, so `jti` enforces
nothing today. It exists because a support ticket saying "token `9f1d4a2e…` says free and I
paid" is answerable in one query, and because a future revocation list must not require a
token format change.

### 5.3 Tiers and what they unlock

| `tier` | Sold as | Capabilities |
|---|---|---|
| `free` | — | Metered reveals (5 per rolling 30 days), full search, browse, detail, metadata. |
| `pro` | Individual Pro | Unlimited reveals, copy to clipboard, BitLocker rotation, recents and favorites, biometric app lock. |
| `enterprise` | Enterprise, tenant-keyed | Everything in `pro`, for one tenant. |
| `msp` | MSP org, tenant-keyed | Everything in `pro`, plus tenant switching. See §7.4. |

**An unrecognized `tier` is treated as `free`.** Failing to the metered tier, never to the
unlocked one, is the only safe direction for a value that arrives over a network.

**There is no seat count and no device count in the token, on purpose.** The $299 tier is
sold for up to 500 devices, but enforcing that would mean the app reporting a device count
to a Kainor server, which is exactly the telemetry the product promises not to collect.
Device and seat limits are contract terms, checked against an invoice, not against a token.
The same reasoning that makes App Attest phase 2 applies here: seat undercounting is an
audit problem and no client-side mechanism honestly solves it.

### 5.4 Lifetime, and what a 30-day token actually costs

30 days, so **revocation lags up to 30 days** — a customer who cancels keeps Pro features
until their current token expires, and with the offline grace in §7.5 that stretches to 37.

That is accepted. At $1.99/month and $299/year, a mechanism to shorten it would need
either more frequent check-ins (more of a phone-home for a product whose pitch is that it
barely has one) or a revocation list (server state keyed to tenants, checked often enough
to matter, which reintroduces the check-in). Thirty days of leakage on a canceled
subscription is cheaper than either, and cheaper than the trust cost.

The other half of the trade is the good half: 30 days means a phone with no signal in a
datacenter is still a licensed phone.

---

## 6. Signing keys

- **ES256 (ECDSA on P-256 with SHA-256).** Small signatures, native `CryptoKit` support on
  the client, no third-party JWT library on either side.
- **The key is generated inside Azure Key Vault and never leaves it.** The Function signs by
  calling the vault; it never holds key material.
- **The Function's managed identity holds Key Vault Crypto User, scoped to the one vault.**
  It can sign with an existing key. It cannot create, delete, import, or export one. A
  compromise of the Function lets an attacker mint tokens while they hold that access; it
  does not let them walk away with the key and mint forever.
- **Purge protection is on and cannot be turned off.** Losing the signing key would
  invalidate every entitlement token in the field simultaneously.

### 6.1 Key distribution

The **public** keys are compiled into the app as a keyring — a map from `kid` to a P-256
public key. The client accepts a token whose header `kid` names any key in that ring, and
rejects any token whose `kid` it does not know.

The client **never fetches a key.** A JWKS document may be published for auditors and for
anyone who wants to verify a token by hand, but it is a human-readable artifact, not a
client dependency. Fetching keys from the same server that signs the tokens would mean the
server could hand a compromised client a key of its choosing, and it would break offline
verification, which is the whole point of §1.4.

### 6.2 Rotation

Planned rotation is a three-release dance, and it is slow on purpose:

1. Ship an app release whose keyring contains both the current key and the next one.
2. Wait for that release to reach the field.
3. Switch the Function to sign with the next key. Old tokens stay valid until they expire.

Emergency rotation, after a suspected key compromise, cannot be fast: clients trust only
what is compiled into them, so an attacker with signing access can mint valid tokens until
an app update ships and is installed. This is stated plainly rather than hidden. The
mitigations are that (a) signing access requires ongoing control of the Function's managed
identity, since the key itself cannot be exported, and (b) the worst outcome of a forged
token is unpaid Pro features. **A forged entitlement token cannot read a password.** It
cannot reach Graph, cannot obtain a Graph token, and cannot influence anything in
`CredentialKit`, which by construction has no dependency on licensing at all.

---

## 7. Client behavior (normative)

The wire format is only half a contract. These rules are what make the privacy claims in §1
true, and a client that ships without them breaks the contract even if every byte on the
wire is well-formed.

### 7.1 When the client calls this endpoint

**A free-tier installation never contacts this host at all.**

The call happens only:

1. When the user taps **Activate license** (Settings, and on the upgrade screen as
   "Already purchased?").
2. On the refresh schedule in §7.3, and only once a license has been activated.
3. When the user taps **Refresh license** manually.

The app is therefore in one of two states, and an administrator can tell which from a proxy
in seconds: unactivated, talking to two Microsoft hosts and nothing else; or activated,
talking to those two plus this one, roughly monthly.

> This is a design choice, not a wire-format requirement, and it is reversible without a
> version bump. The alternative — every install checking in on launch — is simpler to build
> and would give Kainor a list of every tenant running the app. That list has no use that
> justifies collecting it, and its existence would be very hard to explain to the same
> administrator we are asking to trust §1.

### 7.2 When the client MUST NOT call it

These are hard prohibitions, because violating any of them turns request timing into the
usage telemetry that §1.2 promises does not exist:

- **Never in response to a reveal**, an attempted reveal, a blocked reveal, or a biometric
  prompt.
- **Never in response to a search, a device list load, a page fetch, or opening a device.**
- **Never on every launch, every foreground, or on a timer shorter than 24 hours.**
- **Never as part of sign-in.** Entitlement resolution is background work that must not
  extend, gate, or fail authentication.

The call rate must remain a function of the calendar, never of what the administrator did.

### 7.3 Refresh schedule

- At most one automatic attempt per 24 hours, per install.
- An attempt is made only when `now >= refreshAfter` (clamped to `[iat + 1 day, exp]`), or
  when the cached token is within 7 days of `exp`, or when there is no cached token and a
  license has been activated.
- Failures back off: one immediate retry, then no further automatic attempt for 24 hours.
- Activation is sticky per tenant. Once activated, the app keeps refreshing on this schedule
  even if the server starts returning `free` — a lapsed renewal that is later paid should
  recover on its own. It stops only when the user signs out of that tenant or taps
  **Remove license**.

### 7.4 Verification, in order

A client MUST perform all of these, in this order, and MUST treat any failure as "no valid
token" — which means `free`, not an error dialog:

1. Split the compact JWS into exactly three segments.
2. Decode the header. **`alg` MUST equal `ES256` exactly.** Reject `none`, reject any RSA
   algorithm, reject a missing `alg`. Never select an algorithm from the token.
3. Look up header `kid` in the compiled-in keyring. Unknown `kid` → reject.
4. Verify the ES256 signature over the ASCII bytes of `header.payload` with that key.
   Only after this step is any claim worth reading.
5. `iss` equals `https://kainor.com/lapslock`, by exact string comparison.
6. `aud` equals the running bundle identifier.
7. `nbf <= now` and `now < exp`, allowing 120 seconds of clock skew in each direction.
8. `sub` equals the tenant the license was activated against, compared lowercase.
   For `free`, `pro`, and `enterprise`, that tenant MUST also be the tenant currently
   signed in. For `msp` it need not be — see below.
9. Map `tier` through §5.3. Anything unrecognized is `free`.

**The `msp` exception.** An MSP signs into their customers' tenants, so requiring
`sub == currently signed-in tenant` would revoke their license the moment they did their job.
An `msp` token is bound to the tenant it was activated against and stays valid across tenant
switches. This is the one place the tenant binding is deliberately loosened, it applies only
to the tier that is sold on an honor-system seat count anyway, and it is written down here
rather than discovered in the code.

### 7.5 Storage and grace

- The token is stored in the **Keychain**, device-only, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
  never synchronized to iCloud. It is not a credential, but it is a bearer statement and it
  does not belong in `UserDefaults`.
- The token is re-verified from scratch on every launch. A token is never trusted because it
  was trusted before.
- **Offline grace: 7 days past `exp`**, and only when the client has actually attempted a
  refresh and failed at the network layer. A token that verifies in every respect except
  freshness keeps working for a week, so a week without signal does not downgrade a paying
  customer mid-job. Grace never applies to a signature failure, an `iss`/`aud`/`sub`
  mismatch, or a successfully received `free` token.
- Clock manipulation defeats the grace window and the expiry both. That is accepted, for the
  same reason the reveal meter accepts it: **this is a nudge, not DRM.** Someone rolling
  their phone's clock back monthly to avoid $1.99 was never a customer, and chasing them
  costs more than they are worth.

### 7.6 Failure behavior

| Condition | Result |
|---|---|
| No network | Cached token, then grace, then `free`. Silent. |
| Endpoint down, 5xx, timeout | Cached token, then grace, then `free`. Silent. |
| DNS hijack, MITM, hostile response | Signature verification fails. `free`. Silent. |
| `429` | Cached token retained. Silent. |
| Malformed or unverifiable token | Discarded. `free`. Recorded in diagnostics, not shown. |
| Endpoint permanently gone | Every install degrades to `free` and the app keeps working. |

"Silent" means no alert, no banner, no interruption. The user finds out where they already
look for it: the license row in Settings. An administrator holding a phone in front of a
broken workstation is never shown a licensing dialog.

### 7.7 Precedence with StoreKit

Individual Pro and MSP Pro are In-App Purchases, entitled by StoreKit on the device. They do
**not** involve this endpoint. Enterprise and MSP org are sold directly and keyed to a
tenant, and those are what this endpoint is for.

```
isPro = storeKitEntitlementActive || verifiedTier != .free
```

The two sources are independent and either is sufficient. StoreKit failing does not consult
this endpoint, and this endpoint failing does not consult StoreKit.

### 7.8 Where this lives in the app

`LicensingKit`, alongside the reveal meter. It imports Foundation, CryptoKit, and Security
only — `URLSession` is Foundation and `CryptoKit.P256.Signing` covers ES256 verification, so
no new dependency and no third-party JWT library is needed. `scripts/isolation-check.sh`
already enforces that allowlist and already enforces, in both directions, that
`LicensingKit` and `CredentialKit` cannot reach each other. **Neither boundary moves for
this work.** If implementing the entitlement client seems to require relaxing either one,
the design is wrong, not the check.

---

## 8. What the server stores and logs

Stated at this level of detail because a claim about what is *not* collected is only
credible next to a complete account of what is.

**Stored, durably — the license table:**

| Field | Why |
|---|---|
| Tenant GUID | The license key itself. |
| Tier | What was sold. |
| Term start and end | When it lapses. |
| Order or invoice reference | Support and accounting. |
| Contact email supplied at purchase | Renewals and license problems. |

A row exists only for a **paying** customer. Nothing creates a row for a free-tier tenant.

**Logged, transiently — request logs, 30-day retention:**

| Field | Why |
|---|---|
| Timestamp | Diagnosis. |
| Tenant GUID from the request | Rate limiting, and spotting a tenant ID being hammered. |
| HTTP status and `jti` issued | Answering "my license says free and I paid". |
| Source IP | Abuse handling. Standard for any HTTP service. |

**Never present in any log or table, because it is never in the request:** any credential,
any Graph token, any user identity, any device identifier, any device name, any device
count, any reveal count, any search term, any App Insights session or user identifier.

**Rate limits:** per tenant GUID and per source IP. A correctly behaving client makes about
12 requests per install per year; the limits are set orders of magnitude above that and
exist to make a scripted tenant-ID sweep expensive.

**On what request logs do and do not reveal.** They show that someone in a licensed tenant
opened LAPSlock roughly monthly. They cannot show how often anyone revealed a password,
which devices were looked at, or who did the looking, because §7.2 forbids the client from
tying a request to any of those and the request body has nowhere to carry them. This is the
difference between knowing a license was checked and knowing how a tool was used, and it is
the line the product refuses to cross.

---

## 9. Threat model

### 9.1 A tenant ID is not a secret, and this design accepts that

Tenant GUIDs are discoverable — they are returned by unauthenticated OIDC discovery for any
domain. Anyone can therefore request an entitlement token for a tenant they do not belong to,
and if that tenant has an enterprise license, they get a valid Pro token.

**This is accepted, and here is the reasoning, because it is the first thing a security
reviewer asks.**

The token is bound to `sub = tid`, and the client requires that tenant to be the one the
user is actually signed in to (§7.4, with the documented `msp` exception). So a stolen
entitlement token is usable only by someone who can already authenticate to that tenant with
an account that holds a directory role permitting LAPS reads. That person is an
administrator of the licensing customer. They are inside the license's scope already, and
the license is per tenant, not per seat.

The realistic abuse is therefore: an employee of a licensed organization uses the app on a
personal phone without asking. The cost of that is zero, because the organization already
paid for the tenant.

The alternative — proving tenant membership — requires the app to send something derived
from the user's Microsoft session to a Kainor server. That would trade a threat that costs
nothing for one that costs the product's entire positioning.

### 9.2 A forged or stolen token cannot read a credential

Worth stating separately because it is the only question that actually matters. An
entitlement token unlocks UI features. It grants no Graph access, carries no Microsoft
authority, and cannot influence `CredentialKit`, which has no licensing dependency and is
prevented at build time from acquiring one. **Every credential read is still authorized by
Microsoft against the signed-in user's delegated permissions.** If that user's directory
role cannot read a LAPS password, no token from this endpoint changes that.

### 9.3 Network attacker

An attacker with full control of the network between the app and this endpoint can:

- **Deny.** Block the call. Result: cached token, then grace, then free tier.
- **Downgrade.** Return a valid-looking failure. Result: free tier.
- **Not forge.** They cannot produce a token that verifies against a compiled-in public key.

The security of the entitlement decision does not rest on TLS. TLS protects the tenant ID in
transit; the signature protects the answer. This is why there is no certificate pinning: it
would add operational fragility against Azure-managed certificate rotation to defend a
channel whose compromise already yields nothing.

### 9.4 Replay

A token is a bearer statement, and replay within its 30 days is possible by design — that
is what makes offline operation work. `sub` binding limits replay to the tenant it was
issued for, and §9.1 covers why that limit is sufficient.

### 9.5 A modified client

The source is public. Anyone can build a copy with the license check removed. Nothing in
this contract prevents that, and nothing could: it is their bundle identifier, their build,
their device.

What such a build cannot do is read a password they were not already entitled to read, for
the reason in §9.2. The people who would compile an iOS app from source to avoid $1.99 a
month are not the buyers, and the enterprise buyers who are cannot deploy an unsigned
sideloaded build through Intune anyway.

### 9.6 Why App Attest is phase 2

App Attest proves a request came from an unmodified build of *this* bundle ID under *this*
team ID on genuine Apple hardware. Against a source-available app it does not stop §9.5,
because the person rebuilding it uses their own bundle ID.

It costs CBOR decoding, X.509 chain validation to Apple's App Attest root, nonce handling,
`rpId` hash checks, per-install public key storage, and a monotonic counter per key for
replay protection — several hundred lines of security-critical code where a subtle error
means believing you are verifying something you are not. It does not exist in the simulator,
so it is another device-only path in a project that has already shipped four bugs which were
unreachable in the simulator.

And it has an expensive failure mode: attestation fails at first launch behind a captive
portal or during an Apple service blip, a paying customer sees "unlicensed", so a soft-fail
path gets written — and a soft-fail path is a bypass.

The request and the contract are shaped for it (§3), so adding it later is additive. The
cheaper interim measures — rate limiting per tenant and watching for anomalous request
counts — are in §8 and ship with v1.

---

## 10. Verify all of this yourself, in ten minutes

Nothing above needs to be taken on faith.

1. Install a TLS-intercepting proxy (Proxyman, Charles, mitmproxy) and trust its root
   certificate on the iPhone.
2. Sign into LAPSlock and use it: search, open a device, reveal a Windows LAPS password,
   reveal a BitLocker key.
3. Read the traffic. You will see two hosts and no others:
   `login.microsoftonline.com` and `graph.microsoft.com`. **A free-tier install never
   contacts a Kainor host** (§7.1).
4. If you hold an enterprise license, tap **Activate license** and watch the third host
   appear. Confirm the request body is exactly `{"version":1,"tenantId":"<your tenant>"}` —
   no token, no user, no device, no counter — and that nothing else is sent to it while you
   keep using the app.
5. Search the entire capture for a password or a recovery key you revealed. It appears only
   in the Graph response, over TLS, to Microsoft.

Steps 3 and 5 are the ones that matter, and they are the reason this document exists: we
would rather tell you how to check than ask you to believe a policy page.

Report anything that contradicts this document to connor@kainor.com — see `SECURITY.md`.

---

## 11. Non-goals for version 1

Named so that their absence reads as a decision rather than an oversight:

| Not in v1 | Where it goes |
|---|---|
| App Attest verification | Phase 2. Fields reserved in §3, reasoning in §9.6. |
| Token revocation list | Deferred. `jti` reserved for it. 30-day lag accepted (§5.4). |
| Seat or device counting | Never here. Contract and audit, not telemetry (§5.3). |
| Reveal counting of any kind | Never, anywhere. §1.2. |
| Stripe webhook | A separate endpoint, separate contract, not client-facing. |
| Domain to tenant GUID resolution | Purchase flow on the website, not this API. |
| User accounts, sign-up, sign-in to Kainor | There is no Kainor account and none is planned. |
| Any analytics or crash reporting on the client | Excluded by the privacy policy and by build-time isolation. |

---

## 12. Versioning and compatibility

`version` in the request body is the contract version. The path is not versioned, because a
body field is enough for a single-endpoint API and it keeps the published host list short.

**Additive, allowed without a version bump.** Clients must tolerate all of these:

- New optional fields in the response body.
- New claims in the token, provided existing claims keep their meaning.
- New `tier` values. An unrecognized tier is `free` (§5.3), so an old client degrades safely
  rather than failing.
- A new `kid` naming a key already distributed in the app's keyring.
- A host change, with the release-note and transparency-doc update required by §2.

**Breaking, requires `version: 2`.** Any of these, at minimum:

- A new required request field.
- Removing or changing the meaning of any claim.
- Changing `alg`, `iss`, or `aud`.
- Any change that makes the client send something not listed in §3.

When v2 exists, the server accepts v1 requests for **at least 12 months** after the first
App Store release that sends v2, because iOS installs update on their own schedule and a
stale client must degrade to `free`, never to broken.

---

## Change log

| Date | Change |
|---|---|
| 2026-09-01 | Version 1. Initial published contract. |
