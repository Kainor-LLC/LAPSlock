# TenantKeep alert relay, version 1

**Status:** draft contract, phase 3 step I. It becomes frozen for implementation when Kainor
approves it, and from then nothing here may change without a version bump except the
additive changes listed under [Versioning](#13-versioning-and-compatibility). No code exists
yet; by decision the contract comes first, as the entitlement contract did.

**Date:** 2026-10-27
**Operator:** Kainor LLC (Kansas, US)
**Contact:** connor@kainor.com

This document is published so an administrator can read exactly what a Kainor server sees
when a TenantKeep alert is relayed to a phone, decide whether they believe it, and check it
with a proxy. Section 12 tells them how.

---

## 1. What the relay is, and what it deliberately is not

TenantKeep Watch runs in the customer's own Azure Automation account and already delivers
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
| `urgency` | `normal` or `time-sensitive`. Becomes the notification's interruption level. It is the only fact about the alert the relay can see, and it is there because Apple needs it outside the encryption. Watch sends `time-sensitive` only for a break-glass sign-in. |
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
| `402` | `entitlement_tier` | The token is valid but the tier cannot relay. |
| `410` | `device_unregistered` | APNs answered 410: the app was removed or the token changed. Pair again. |
| `413` | `too_large` | The body is over 6 KiB, or the ciphertext over its limit. |
| `429` | `rate_limited` | Section 8. `Retry-After` says when. |
| `502` | `apns_rejected` | APNs refused for another reason. `message` carries Apple's own reason string, such as `BadDeviceToken`, and nothing from the request. |
| `503` | `apns_unavailable` | APNs did not answer in time, or the relay is shedding load. Nothing was kept; try again later. |

No response ever echoes a device token, an envelope, a tenant ID or an entitlement token.

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

---

## 9. What the relay sees, and what it keeps

| What | Seen | Kept |
|---|---|---|
| Alert content | Never. Ciphertext only. | No |
| Device token | During the request, to address APNs | No |
| Tenant ID | During the request, inside the entitlement token | No |
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
request in real time. The relay retains nothing beyond the request, so the label stays
"Data Not Collected". (verify) against Apple's definitions again at submission.

---

## 10. The phone (normative)

- **Key.** Generated in the Secure Enclave when the admin turns the relay on. Not
  exportable, `afterFirstUnlockThisDeviceOnly`, no biometric condition so the notification
  extension can use it while the phone is locked. The key is not one of the app's five
  Keychain items for credentials or settings; it is the Enclave's, and the Keychain holds
  only its reference. (verify) this counts as a sixth item under the rule, and decide.
- **Notification Service Extension.** Every relayed push carries `mutable-content` and a
  neutral placeholder, "TenantKeep alert". The extension verifies and decrypts with the
  Enclave key and the pinned sender key, checks the plaintext's `v`, drops it as a
  duplicate if its `id` was seen in the last 24 hours, and rewrites the notification with
  `title`, `body` and the tenant's name if the phone knows it.
- **Anything that fails** (wrong sender, wrong phone, tampering, a ciphertext from before
  the key was rotated, a duplicate) is shown as "TenantKeep: an alert could not be verified
  and was discarded", with no content. The extension cannot silence a notification without
  an entitlement Apple grants on request; (verify) whether to apply for it.
- **Nothing decrypted is written down** except the `id` list for de-duplication, in the
  app group container, holding ids only, at most a day old.
- **The kill switch.** Turning the relay off deletes the Enclave key and the sender pins.
  Anything sent afterwards fails verification. Turning it on again makes a new key, which
  needs pairing again.
- **Pro.** The switch is disabled on the free tier with the plan named. The relay's
  entitlement check is what actually enforces it.

---

## 11. Threat model

| Threat | Outcome |
|---|---|
| Kainor, or anyone controlling the relay, wants to read alerts | Cannot. Holds neither private key. |
| They want to forge an alert | Cannot make one the phone accepts: no sender key. The most they can do is cause the "could not be verified" notice. |
| They want to know who gets alerts | Can see, during a request, a tenant ID and a device token. The design keeps neither. This is the trust the relay asks for, and it is why it is off by default and stated on the privacy page. |
| They drop or delay alerts | Possible. Watch's Teams and email delivery is unaffected; the relay is additive. |
| Someone steals a phone's pairing data | Cannot read or forge. Can attempt sends, which the phone discards with the generic notice, at the cost of their own Pro entitlement and within the rate limits. |
| Someone steals the Automation's sender key | Can make one paired phone show alerts. Rotate the sender key in Watch's setup and re-pin on the phone. The Automation variable is encrypted and held in the customer's own subscription. |
| Replay of a captured request | The phone drops a repeated `id` for 24 hours, and the plaintext carries its time, which the phone shows. |
| Kainor's APNs signing key is stolen | The thief can push to any device token they know, but only the placeholder: they cannot produce a payload the extension accepts. The key is held in Key Vault, non-exportable, used by the function's managed identity. |
| A stolen entitlement token | Lets someone use the relay at Kainor's cost until the token expires. It exposes nothing about the tenant. |
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

## 14. Open items before this is frozen

Each is marked (verify) where it appears, and none changes what the relay sees:

- CryptoKit HPKE in authenticated mode with a Secure Enclave recipient key on iOS 17.
- An RFC 9180 implementation for the PowerShell sender on .NET, which has ECDH, HKDF and
  AES-GCM but no HPKE type, checked against the RFC's test vectors.
- Whether the Enclave key reference is a sixth Keychain item under the rule.
- Whether to apply for Apple's notification filtering entitlement, so a failed alert can be
  silenced instead of shown as a notice.
- Whether to publish the relay function's source alongside this contract. It is small, and
  publishing it would let an administrator check section 9 against the code, not only
  against a proxy.
- The App Privacy label definitions at submission.

## Change log

- 2026-10-27, draft 1. Written from the 2026-10-25 decision for route D'. One change from
  that decision: HPKE authenticated mode with a sender key the phone pins, instead of base
  mode, so pairing data alone cannot be used to show a fake alert.
- 2026-10-27, draft 1 accepted in substance. Kainor approved authenticated mode and two-way
  pairing. Freezing waits on the open items in section 14.
