# TenantKeep alert relay, version 1

**Status:** frozen for implementation, 2026-10-27. Nothing here may change without a version
bump except the additive changes listed under [Versioning](#13-versioning-and-compatibility).
Written before any code, as the entitlement contract was; the open items it listed are
resolved in section 14.

**Date:** 2026-10-27
**Operator:** Kainor LLC (Kansas, US)
**Contact:** connor@kainor.com

This document is published so an administrator can read exactly what a Kainor server sees
when a TenantKeep alert is relayed to a phone, decide whether they believe it, and check it
with a proxy. Section 12 tells them how.

> **Updated 2026-11-15: who sends.** The envelope, the request and the relay are unchanged.
> The sender is now Kainor's own alert service for Instant alerts, described in
> [INSTANT-ALERTS.md](INSTANT-ALERTS.md), instead of TenantKeep Watch in the customer's Azure
> Automation account, which is retired as a route to the phone. Pairing (section 6) happens
> automatically when the phone registers. Sections 1, 6, 9.1 and 11 say what that changes.

> **Updated 2026-11-23: how Kainor's alert service is recognized.** The envelope and the route
> in section 2 are unchanged. The alert service now sends on a second route,
> [section 15](#15-the-alert-services-route), where the relay recognizes it by its own identity
> instead of by each organization's entitlement token. On that route the relay is not told
> which organization an alert is for. Section 15.1 says why it was needed.

---

## 1. What the relay is, and what it deliberately is not

*As first written; see the 2026-11-15 update above.* TenantKeep Watch runs in the customer's own Azure Automation account and already delivers
its alerts to Microsoft Teams and email. TenantKeep On-Call, the phone app, notifies by
polling Microsoft Graph in the background, which iOS schedules on its own budget: minutes
to hours, and never in Low Power Mode. The relay is the third route, for an organization
that wants a Watch alert on the admin's phone within seconds without going through Outlook
or Teams.

It does one thing: it takes an alert that the customer's Automation run has already
encrypted for one phone, and passes it to Apple Push Notification service (APNs) for that
phone, in the same request. **Kainor cannot read the alert.** The phone decrypts it.

Five constraints shape everything below. They are settled:

1. **The request carries a device token, an encrypted envelope, an urgency, and the
   tenant's entitlement token. Nothing else.** No tenant name, no alert kind, no user, no
   title, no text.
2. **The relay retains nothing.** No table, no queue, no blob, no retry store, and no log
   line that contains a device token, an envelope, a tenant ID or an entitlement token. A
   request's data lives for the request and is gone when it ends.
3. **The content is end-to-end encrypted and authenticated** to a key generated in the
   phone's Secure Enclave, from a key the customer's Automation run holds. Kainor holds
   neither private key, so it can neither read an alert nor forge one.
4. **Only a paying tenant can relay, checked offline.** The entitlement token is verified
   against public keys compiled into the relay. The relay never calls the entitlement
   service and keeps no list of tenants.
5. **The relay is additive.** Watch's Teams and email delivery does not depend on it. If
   the relay is down, alerts arrive the way they did before it existed.

It is **not**:

- a store-and-forward service. If APNs refuses or is unreachable, the relay says so to the
  sender and keeps nothing to try again. Retrying is the sender's choice.
- a fan-out service. One request is one phone. A team of five is five requests, made by
  the customer's run, which knows the five phones; the relay never learns that they belong
  together.
- part of On-Call's own notifications. Those stay local to the phone (spec 3.11) and never
  touch this host.
- a way to reach a phone that has not been paired by its owner (section 6).

---

## 2. Endpoint

| | |
|---|---|
| Method | `POST` |
| Path | `/relay` |
| Host (v1, planned) | `kainor-relay-prod-func.azurewebsites.net`, its own function app, separate from the entitlement endpoint |
| Scheme | `https` only. The function app has HTTPS Only set and verified. Senders MUST use `https`; the reference sender hardcodes it. |
| TLS | Standard public PKI, Azure-managed certificate. No pinning. |
| Authentication | The entitlement token in the body (section 4). No API key, no function key. |
| Request content type | `application/json; charset=utf-8` |
| Response content type | `application/json; charset=utf-8` |
| Request body limit | 6 KiB. Larger is refused with `413` before it is parsed. |
| Query string | None is read. A request with one is refused with `400`, so nothing can be smuggled into a URL that a platform log might keep. |

The host may move to a custom domain. That is not a contract change, but it is a
release-notes change, and the privacy page and network transparency document change with
it in the same release.

---

## 3. Request

```json
{
  "v": 1,
  "deviceToken": "7f3c...e91a",
  "environment": "production",
  "urgency": "normal",
  "entitlement": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6...",
  "envelope": {
    "suite": "DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM",
    "mode": "auth",
    "enc": "BPq1...",
    "ct": "8xKz..."
  }
}
```

| Field | Rules |
|---|---|
| `v` | Exactly `1`. |
| `deviceToken` | The phone's APNs device token, lowercase hex, 64 to 200 characters. |
| `environment` | `production` or `sandbox`. Sandbox exists for development builds and is rate limited harder. |
| `urgency` | `normal` or `time-sensitive`. Becomes the notification's interruption level, and its sound: a `time-sensitive` alert plays the default sound and a `normal` one arrives silently, as the app's own alerts do. It is the only fact about the alert the relay can see, and it is there because Apple needs it outside the encryption. Watch sends `time-sensitive` only for a break-glass sign-in. |
| `entitlement` | The tenant's current entitlement token, a compact JWS, exactly as defined in [ENTITLEMENT-API.md section 5](ENTITLEMENT-API.md#5-the-entitlement-token). |
| `envelope.suite` | Exactly the string shown. Any other value is refused. |
| `envelope.mode` | Exactly `auth`. HPKE base mode is refused (section 5.2 says why). |
| `envelope.enc` | The HPKE encapsulated key, base64url, no padding: 65 bytes before encoding. |
| `envelope.ct` | The HPKE ciphertext, base64url, no padding: at most 2,800 bytes before encoding, which keeps the APNs payload under Apple's 4 KB limit. |

Unknown top-level fields are refused with `400`. That is deliberate: a relay that ignored
extra fields would let a sender believe something was being carried, or protected, when it
was not.

### 3.1 How the sender gets the entitlement token

The customer's Automation run calls the entitlement endpoint itself, with its own tenant
ID, exactly as the phone does ([ENTITLEMENT-API.md section 3](ENTITLEMENT-API.md#3-request)),
at most once a day, and reuses the token until two days before it expires. The relay never
issues or refreshes one.

---

## 4. The entitlement check, offline

*This is the check on `POST /relay`. Kainor's alert service is checked as
[section 15](#15-the-alert-services-route) says, and sends no entitlement token.*

In this order, all in memory, before anything is sent to Apple:

1. The token parses as a compact JWS with header `alg` exactly `ES256`.
2. The header `kid` names a key in the keyring compiled into the relay. The relay never
   fetches a key.
3. The signature verifies.
4. `iss` is `https://kainor.com/lapslock` and `aud` is `com.kainor.lapslock`.
5. `nbf` is not in the future and `exp` is not in the past, with five minutes of skew
   allowed either way.
6. `tier` is `pro`, `msp` or `enterprise`. `free`, or anything unrecognized, is refused
   with `402`.

A token that fails any step is refused with `401` and the step is not named, so the
endpoint cannot be used to probe the keyring.

The token's `sub` is the tenant ID. The relay reads it during the request, for the
per-tenant rate limit, and for nothing else. **This means the relay can see which tenant
sent an alert.** That is the price of checking payment without a database, and it is said
here and on the privacy page rather than hidden.

---

## 5. The envelope

### 5.1 Cryptography

HPKE, RFC 9180, **authenticated mode** (`mode_auth`):

| | |
|---|---|
| KEM | DHKEM(P-256, HKDF-SHA256), `0x0010` |
| KDF | HKDF-SHA256, `0x0001` |
| AEAD | AES-256-GCM, `0x0002` |
| `info` | the ASCII bytes `TenantKeep relay v1` |
| AAD | the ASCII bytes of the lowercase `deviceToken` |
| Recipient key | P-256, generated in the phone's Secure Enclave, not exportable, available after first unlock so the notification extension can use it while the phone is locked |
| Sender key | P-256, generated once by the customer's Automation setup and kept as an encrypted Automation variable |

Binding the device token as AAD means a ciphertext made for one phone fails on any other
phone, even one paired to the same sender.

### 5.2 Why authenticated mode, and not base mode

Base mode only keeps an alert private. Anyone who held a phone's pairing data (its public
key and device token, section 6) and any Pro entitlement token, from any tenant, could then
encrypt a convincing fake alert, "Break-glass sign-in, tap to review", and the phone would
show it. That is a phishing channel onto an administrator's lock screen. In authenticated
mode the phone accepts only what was encrypted with the private key of the sender it was
paired with. The relay cannot forge one, and neither can someone who stole the pairing data.

### 5.3 Plaintext

UTF-8 JSON, at most 2,700 bytes:

```json
{
  "v": 1,
  "id": "6b1d2c4e-0f8a-4f3e-9d6b-2a7c1e5f9b30",
  "at": 1793066400,
  "tenant": "c0ffee00-1111-2222-3333-444455556666",
  "kind": "breakGlassSignIn",
  "title": "Break-glass sign-in",
  "body": "bg-admin@contoso.com signed in from 203.0.113.7",
  "link": "tenantkeep://people?upn=bg-admin%40contoso.com"
}
```

| Field | Rules |
|---|---|
| `id` | A GUID, unique per alert, for de-duplication on the phone. |
| `at` | When Watch raised it, seconds since epoch. |
| `tenant` | The tenant GUID the alert is about. |
| `kind` | One of the alert kinds the phone knows; an unknown kind is shown as a generic Watch alert. |
| `title`, `body` | At most 80 and 400 characters. Shown as given. |
| `link` | Optional. A `tenantkeep://` link into On-Call. Any other scheme is dropped. |

---

## 6. Pairing, owned by the customer

*Since 2026-11-15, Instant alerts pair automatically: the phone sends its push token and
public key when it registers, and receives the alert service's sender key, which it pins for
the organization ([INSTANT-ALERTS.md](INSTANT-ALERTS.md) section 4). The manual pairing below
is how the retired self-hosted route worked.*

Pairing is two-way and happens between the phone and the customer's own Automation account.
Kainor is not involved in it and is never told it happened.

1. **Phone to Automation.** In On-Call, Settings, Notifications, Relay, the admin turns the
   relay on (Pro only). The phone generates its Secure Enclave key and shows a QR code and a
   copyable text holding `v`, `deviceToken`, `environment` and the public key (X9.63,
   base64url). The admin puts it in the Automation account as an encrypted variable.
2. **Automation to phone.** Watch's setup generates the sender key once and prints its
   public key as a QR code and text. The admin scans it on the phone, which pins it for
   that tenant.

A phone can pin one sender per tenant. Re-pairing replaces the pin.

The pairing data is not a secret in the way a password is: it cannot read anything, and
without the sender's private key it cannot be used to make the phone show an alert. It is
still kept as an encrypted variable, because it identifies a phone.

---

## 7. Response

### 7.1 Success, `202`

```json
{ "apnsId": "1f3a2b4c-5d6e-7f80-91a2-b3c4d5e6f708" }
```

`202` means Apple accepted the notification. It does not mean the phone has shown it; APNs
delivers when it can, and the relay is not told.

### 7.2 Errors

```json
{ "error": "device_unregistered", "message": "Apple no longer recognizes this device token. Pair the phone again." }
```

| Status | `error` | When |
|---|---|---|
| `400` | `bad_request` | The body is not valid JSON, a field is missing, unknown or out of range, or a query string was sent. |
| `401` | `entitlement_invalid` | Any step 1 to 5 in section 4 failed. |
| `401` | `service_token_invalid` | Section 15's route only: the caller is not Kainor's alert service. |
| `402` | `entitlement_tier` | The token is valid but the tier cannot relay. |
| `410` | `device_unregistered` | APNs answered 410: the app was removed or the token changed. Pair again. |
| `413` | `too_large` | The body is over 6 KiB, or the ciphertext over its limit. |
| `429` | `rate_limited` | Section 8. `Retry-After` says when. |
| `502` | `apns_rejected` | APNs refused for another reason. `message` carries Apple's own reason string, such as `BadDeviceToken`, and nothing from the request. |
| `503` | `apns_unavailable` | APNs did not answer in time, or the relay is shedding load. Nothing was kept; try again later. |
| `503` | `keys_unavailable` | Section 15's route only: Microsoft's signing keys could not be fetched, so the caller could not be checked. Nothing was kept; try again shortly. |

No response ever echoes a device token, an envelope, a tenant ID, an entitlement token or
the alert service's token.

---

## 8. Rate limits, in memory only

| Key | Limit |
|---|---|
| Per tenant (`sub`) | 120 requests a minute |
| Per device token | 30 requests a minute |
| Per source address | 240 requests a minute |
| Sandbox, per tenant | 10 requests a minute |

Counters live in the process's memory, keyed by an HMAC of the value under a random key
made when the process starts, so even a memory dump does not hold a device token or a
tenant ID in the clear. They vanish when the process recycles, and each instance counts on
its own, so the limits are approximate and generous on purpose. They exist to keep one
misconfigured run from spending the shared APNs budget, not to meter anyone.

These are the limits on `POST /relay`. The alert service's route has its own, in section 15.4.

---

## 9. What the relay sees, and what it keeps

| What | Seen | Kept |
|---|---|---|
| Alert content | Never. Ciphertext only. | No |
| Device token | During the request, to address APNs | No |
| Tenant ID | On `POST /relay`, during the request, inside the entitlement token. On the alert service's route (section 15), never: nothing sent there names an organization | No |
| The alert service's token | On the alert service's route, during the request. It identifies Kainor's own service and carries nothing about a customer | No |
| Urgency | During the request | No |
| Source IP address | During the request, at the platform's edge | Masked to `0.0.0.0` in telemetry, Application Insights' default, which stays on |
| That a relay request happened, its status and duration | Yes | Platform request telemetry: timestamp, path `/relay`, status, duration. No body, no headers, no query, no custom properties. 30-day retention, ingestion capped at 0.1 GB a day |

Configuration that makes this true, and that a release checklist verifies: request and
response body collection off; web server logging and failed request tracing off; no custom
telemetry in the function's code; logging level such that no exception message can carry a
request field; the function never writes a request field to any sink.

Apple sees what it always sees for a push: the device token, the app's topic, and the
payload, which here is ciphertext.

### 9.1 What the privacy page says, in the same release

*Since 2026-11-15 the privacy page's "Instant alerts" section and network paragraph replace the
paragraph below. The relay still keeps nothing; the alert service keeps identifiers
([INSTANT-ALERTS.md](INSTANT-ALERTS.md) section 5), so the app's App Privacy answers change with
Instant alerts.*

The privacy page and the network transparency document change in the release that ships
the relay, with this paragraph, word for word:

> **Alert relay (Pro, off by default).** If your organization turns on relayed alerts,
> TenantKeep Watch in your own Azure Automation account encrypts each alert for your phone
> and sends it through `kainor-relay-prod-func.azurewebsites.net`, which passes it to Apple
> for delivery. Kainor cannot read these alerts and keeps nothing: the relay has no
> database and writes no log line containing your phone's device token, your tenant ID or
> the alert. While a request is in flight the relay can see your tenant ID (to check your
> plan), your phone's device token (to address Apple), whether the alert is time-sensitive,
> and the sending address, which our telemetry masks. Turning the relay off in the app
> discards the phone's key, after which nothing sent to it can be read.

App Privacy label: Apple counts data as collected when it is retained beyond servicing the
request in real time. The relay retains nothing beyond the request, so the relay itself adds
nothing to the label. Instant alerts, the hosted service that sends through it, keeps a
registration for each phone; the privacy policy says what it holds, and the label follows it.

---

## 10. The phone (normative)

- **Key.** Generated in the Secure Enclave when the admin turns the relay on. Not
  exportable, `afterFirstUnlockThisDeviceOnly`, no biometric condition so the notification
  extension can use it while the phone is locked. The key is not one of the app's five
  Keychain items for credentials or settings; it is the Enclave's, and the Keychain holds
  only its reference. It is the sixth item under the rule, decided 2026-10-27.
- **Notification Service Extension.** Every relayed push carries `mutable-content` and a
  neutral placeholder, "TenantKeep alert". The extension verifies and decrypts with the
  Enclave key and the pinned sender key, checks the plaintext's `v`, drops it as a
  duplicate if its `id` was seen in the last 24 hours, and rewrites the notification with
  `title`, `body` and the tenant's name if the phone knows it.
- **Anything that fails** (wrong sender, wrong phone, tampering, a ciphertext from before
  the key was rotated, a duplicate) is shown as "TenantKeep: an alert could not be verified
  and was discarded", with no content. The extension cannot silence a notification without
  an entitlement Apple grants on request, which Kainor applies for.
- **Nothing decrypted is written down** except the `id` list for de-duplication, in the
  app group container, holding ids only, at most a day old.
- **The kill switch.** Turning the relay off deletes the Enclave key and the sender pins.
  Anything sent afterwards fails verification. Turning it on again makes a new key, which
  needs pairing again.
- **Pro.** The switch is disabled on the free tier with the plan named. A phone whose plan
  has lapsed stops checking in with the alert service, which removes a phone 30 days after
  its last check-in. On `POST /relay` the relay's entitlement check enforces the plan as
  well; on the alert service's route the plan is checked on the phone, where the App Store
  subscription is known (section 15.5).

---

## 11. Threat model

| Threat | Outcome |
|---|---|
| Kainor, or anyone controlling the relay, wants to read alerts | The relay cannot: it holds neither private key. Kainor's alert service creates each alert, so it knows its kind, organization and time while sending it, and keeps none of that. |
| They want to forge an alert | The relay alone cannot make one the phone accepts. Since 2026-11-15 Kainor's alert service holds the sender key, so Kainor can make an alert the phone accepts; someone who stole that key could too (next rows). |
| They want to know who gets alerts | Can see, during a request, a tenant ID and a device token. The design keeps neither. This is the trust the relay asks for, and it is why it is off by default and stated on the privacy page. |
| They drop or delay alerts | Possible. Watch's Teams and email delivery is unaffected; the relay is additive. |
| Someone steals a phone's pairing data | Cannot read or forge. Can attempt sends, which the phone discards with the generic notice, at the cost of their own Pro entitlement and within the rate limits. |
| Someone steals the alert service's sender key | Can make registered phones show alerts naming any organization they are registered for. The key is a Key Vault secret only the service's managed identity can read. Replacing it makes every phone register again to pin the new one. |
| Replay of a captured request | The phone drops a repeated `id` for 24 hours, and the plaintext carries its time, which the phone shows. |
| Kainor's APNs signing key is stolen | The thief can push to any device token they know, but only the placeholder: they cannot produce a payload the extension accepts. The key is held in Key Vault, non-exportable, used by the function's managed identity. |
| A stolen entitlement token | Lets someone use the relay at Kainor's cost until the token expires. It exposes nothing about the tenant. |
| The alert service's token is stolen | The same, until the token expires, within a day: pushes to device tokens the thief already knows, which show only the "could not be verified" notice, because the thief does not have the sender key. The token is issued to a managed identity, so there is no stored secret to copy; it exists in the service's memory. It is good for the relay and nothing else. |
| Denial of service | Rate limits per tenant, device and address; consumption-plan scaling; a budget alert. Nothing the attacker does is stored. |

---

## 12. Verify this yourself

1. Put a proxy you control, such as mitmproxy, between the Automation run (or a copy of the
   reference sender run from your workstation) and the internet.
2. Send one alert. The request to the relay host carries exactly the fields in section 3.
   The envelope's `ct` is opaque bytes; nothing readable is in it.
3. The response carries an `apnsId` or one of the errors in section 7.2, and never your
   token, tenant or envelope.
4. On the phone, turn the relay off and send again. The alert arrives as "could not be
   verified", which shows the phone, not the relay, was doing the decrypting.

---

## 13. Versioning and compatibility

Additive changes that do not need a version bump: a new `error` code; a new optional
response field; a new `urgency` value, which an older relay refuses with `400`; a new
plaintext field, which an older phone ignores. Anything else, including any new request
field, a new suite, or a change to what the relay sees or keeps, is version 2, a new path,
and a privacy page change in the same release.

## 14. Resolved before freezing

- **CryptoKit, authenticated mode, Secure Enclave recipient:** works. Checked on Apple silicon
  with a real Enclave key: a round trip, an impostor sender rejected, another phone's AAD
  rejected, and the key reference restored from its data representation.
- **The sender on .NET:** `relay/sender/Hpke.cs` implements RFC 9180 for this suite. It
  matches the CFRG test vectors for authenticated mode with AES-128-GCM and AES-256-GCM, all
  514 encryptions sealed and opened (`relay/sender/Test-Hpke.ps1`), and CryptoKit opens what
  it seals.
- **The Enclave key reference is the app's sixth Keychain item,** shared with the
  notification extension, this device only, after first unlock. Decided by Kainor.
- **Apple's notification filtering entitlement:** Kainor applies for it. Until it is
  granted, a failed alert shows the generic notice in section 10; after, it is dropped.
- **The relay function's source is published,** in this repository under `relay/`, so
  section 9 can be checked against the code as well as a proxy.
- **Still at submission:** the App Privacy label definitions, section 9.1.

## 15. The alert service's route

| | |
|---|---|
| Method | `POST` |
| Path | `/relay/service` |
| For | Kainor's own alert service ([INSTANT-ALERTS.md](INSTANT-ALERTS.md)), and no one else |
| Authentication | `Authorization: Bearer`, a token Microsoft Entra ID issued to the alert service's managed identity, for the relay |
| Body | Section 3's, without `entitlement`. A body that carries one is refused with `400`, as any unknown field is |
| Everything else | As section 2: `https` only, 6 KiB, no query string, the envelope of section 5, the answers of section 7 |

A second path, as section 13 requires for anything that changes what the relay sees.
`POST /relay` is as it was.

### 15.1 Why it exists

The entitlement token of section 4 is issued for an organization license, by tenant ID. A
Pro subscription bought in the app belongs to an Apple account and is known only to the
phone: the entitlement service is never told who subscribes, on purpose. So when the sender
became Kainor's alert service (2026-11-15), it had no token the relay would accept for an
organization whose administrators subscribe in the app, and their alerts were refused with
`402`. Found in review on 2026-11-23, before release.

Teaching a server about App Store purchases would have meant keeping a record of who
subscribes. Instead the relay recognizes the one sender it is run for.

### 15.2 The check

In this order, in memory, before the body is parsed:

1. The token is signed by one of Microsoft Entra ID's published keys for Kainor's tenant.
   The relay fetches those keys from Microsoft over `https` and caches them. They are
   Microsoft's public keys, the same for everyone; fetching them tells Microsoft nothing
   about a request.
2. Its issuer and its `tid` are Kainor's tenant. A token from any other tenant is refused,
   whatever it carries.
3. Its audience is the relay's own app registration, "TenantKeep Relay", which holds no
   permission to anything. A token for anything else is refused here, and a token for the
   relay is useless anywhere else.
4. It is in date, with two minutes of skew allowed.
5. It is an application's own token, not a person's, and carries the role `Alerts.Send`.
   The registration requires assignment, and the role is assigned to one identity: the
   alert service's function app.
6. It is that identity's: its `oid` is the alert service's managed identity, which the
   relay's settings name. So an identity in Kainor's tenant that is given the role by
   mistake is still refused.

A token that fails any step is refused with `401` and the step is not named. If Microsoft's
keys cannot be fetched the answer is `503 keys_unavailable`, so the alert service tries
again instead of taking it for a refusal.

There is no secret to steal. The alert service's identity is an Azure managed identity:
Azure issues its tokens to the running service, and no key or password for it exists to be
copied.

### 15.3 What the relay sees on this route

The token names Kainor's alert service and carries nothing about a customer. The body
carries no tenant ID and no entitlement token. So on this route the relay sees a device
token, an urgency and ciphertext, and **cannot tell which organization an alert is for**:
less than on `POST /relay`, where the entitlement token names the tenant. It keeps nothing,
as section 9 says.

### 15.4 Rate limits

| Key | Limit |
|---|---|
| Per device token | 30 requests a minute |
| The whole service | 3,000 requests a minute |
| Sandbox, the whole service | 120 requests a minute |

Counted as section 8 describes. There is no limit per tenant, because none is seen, and
none per source address, because the alert service's few addresses carry every
organization's alerts.

### 15.5 Where the plan is checked

On the phone, where it is known. The app offers the Instant alerts switch only with Pro or
an organization license, and stops checking in with the alert service once the plan has
lapsed, after which the service removes the phone (30 days after its last check-in). The
relay delivers only to the On-Call app's own push topic, under Kainor's key, so nothing but
the app from the App Store receives what it sends.

## Change log

- 2026-10-27, draft 1. Written from the 2026-10-25 decision for route D'. One change from
  that decision: HPKE authenticated mode with a sender key the phone pins, instead of base
  mode, so pairing data alone cannot be used to show a fake alert.
- 2026-10-27, draft 1 accepted in substance. Kainor approved authenticated mode and two-way
  pairing.
- 2026-10-27, frozen. Open items resolved (section 14).
- 2026-11-15, the sender changes to Kainor's alert service (INSTANT-ALERTS.md); pairing is
  automatic. Envelope, request and relay unchanged, so no version change. Sections 1, 6, 9.1
  and 11 annotated.
- 2026-11-23, a second route, `POST /relay/service`, for Kainor's alert service, recognized
  by its own identity (section 15). A new path, as section 13 requires. `POST /relay`, the
  envelope and what the relay keeps are unchanged; on the new route the relay no longer sees
  a tenant ID.
- 2026-11-24, section 15.2, step 6: the relay can be told the alert service's identity, and
  then accepts no other identity in Kainor's tenant that holds the role. A setting, so the
  route is unchanged until it is set.
