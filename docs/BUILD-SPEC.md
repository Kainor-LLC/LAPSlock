# Build-Ready Specification — Entra/Intune LAPS Administrator Client (iOS)

**Version:** 1.0
**Status:** Design complete for Windows LAPS; macOS LAPS retrieval blocked on a verification item (see §2.4).
**Audience:** A development-oriented session that will construct the application from this document alone.

This spec is self-contained. It intentionally restates architecture and permissions so no external context is required.

---

## 0. Product definition and hard constraints

**What it is:** A native iOS administrator client for Microsoft Entra/Intune tenants that use Windows LAPS and macOS LAPS. It lets an authenticated, authorized administrator browse managed devices and, where Microsoft authorizes it for that administrator, reveal and (optionally) rotate a device's LAPS-managed local administrator password.

**What it is NOT:** A credential collection service. There is no developer-controlled service through which any LAPS password passes.

**Non-negotiable constraints (enforce in code, not just policy):**

1. The developer/vendor must never receive, store, proxy, log, analyze, or handle any LAPS password.
2. LAPS values are fetched on-device with the administrator's own delegated Microsoft Graph token and displayed only to that administrator.
3. No LAPS value is persisted anywhere: not in storage, Keychain, databases, analytics, crash reports, logs, telemetry, or UI state restoration.
4. Any vendor backend is limited to licensing/entitlement and non-sensitive operational telemetry. It must be structurally incapable of receiving credential data.
5. Do not add any mechanism to bypass tenant authorization, obtain credentials without authorization, circumvent Microsoft security controls, or access tenants that have not consented.

---

## 1. Platform and technology decisions

- **Language:** Swift 5.9+ (Swift 6 concurrency where practical).
- **UI:** SwiftUI as primary. Use UIKit interop (`UIViewControllerRepresentable`) only where SwiftUI lacks a control — notably for robust app-switcher/screenshot handling and for the MSAL web session host.
- **Min iOS:** iOS 16.0 (for `ASWebAuthenticationSession`, modern SwiftUI navigation, `LAContext` maturity). iOS 17+ features used behind availability checks.
- **Auth library:** MSAL for iOS (`MSAL`, the official Microsoft Authentication Library). Do not hand-roll OAuth.
- **Networking:** `URLSession` with async/await. No third-party networking SDK in the credential path.
- **Concurrency:** async/await throughout; actors for the token/session store.
- **Dependency management:** Swift Package Manager only. Minimize dependencies; the credential module has zero third-party dependencies.
- **Persistence:** Keychain for tokens only. A lightweight cache (Core Data or a plain file-backed store) for **non-sensitive** device metadata only.
- **Crash/analytics:** optional, and **linked only outside the credential module** (see §6). Prefer no third-party crash SDK; if used, disable in credential-handling scope.

---

## 2. Microsoft Graph integration (verified facts and verification flags)

> Everything marked **VERIFIED** was confirmed against Microsoft Learn / the Graph docs repo as of 2026-08. Everything marked **VERIFY** must be re-confirmed in a real tenant before you build on it. Do not invent endpoints or permission names.

### 2.1 Authentication model — VERIFIED direction

- Use **delegated** permissions only. Do **not** request application (app-only) permissions for anything credential-adjacent; app-only credential read would let a background service read passwords with no user present, violating constraint #1.
- Authority: the administrator's own tenant. After the account is selected, use the tenant-specific authority for silent token acquisition. Use `/common` (or `/organizations`) only for the initial account-selection interactive sign-in.
- Use **incremental consent**: request browse scopes first; request the credential-read scope only at the moment the admin first attempts a reveal.

### 2.2 Device inventory — VERIFIED

- **Intune managed devices:** `GET /deviceManagement/managedDevices`
  - Permission (delegated): `DeviceManagementManagedDevices.Read.All`. Requires admin consent. Tenant-wide.
  - Supports OData `$top` and `@odata.nextLink` paging, `$select`, and some `$filter`. **Many properties are null in the list response** (e.g. `ethernetMacAddress`, `notes`, and in some tenants the primary user's `userPrincipalName`) and only populate on a per-device `GET .../managedDevices/{id}?$select=...`. Design around this.
  - `$search` is **not** supported on many properties. Prefer client-side search over a cached window (see §5).
- **Entra devices:** `GET /devices`
  - Permission (delegated): `Device.Read.All`. Requires admin consent. Tenant-wide.
  - Needed to obtain the **Entra deviceId** used by the Windows LAPS read (§2.3). Evaluate whether you need both `/devices` and `/deviceManagement/managedDevices`, or can satisfy the UI from one plus targeted per-device calls.

### 2.3 Windows LAPS — VERIFIED (v1.0)

- **List metadata (no password):** `GET /directory/deviceLocalCredentials`
  - Least-privileged permission: `DeviceLocalCredential.ReadBasic.All` (delegated or application). Admin consent required. Tenant-wide.
  - Returns `deviceLocalCredentialInfo` objects **excluding** the `credentials` property: `id`, `deviceName`, `lastBackupDateTime`, `refreshDateTime`.
  - Supports `$select`, `$filter`, `$search`, `$orderby`, `$top`, `$count`, `$skiptoken`.
- **Reveal password:** `GET /directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials`
  - Permission: **`DeviceLocalCredential.Read.All`** (delegated). `DeviceLocalCredential.ReadBasic.All` is insufficient for the password.
  - In delegated scenarios the signed-in user must also hold a supporting **Entra directory role**. For the `credentials` (password) property specifically, the supported least-privileged roles are **Cloud Device Administrator** and **Intune Service Administrator**. (Broader metadata-only reads also allow Helpdesk Administrator, Security Administrator, Security Reader, Global Reader.)
  - Response `credentials[]` is a `deviceLocalCredential` with: `accountName`, `accountSid`, `backupDateTime`, `passwordBase64`.
  - **`passwordBase64` is base64-encoded.** Decode it to recover the string. Windows LAPS values are typically **UTF-16LE** once base64-decoded — verify decoding against a known value in your tenant. The response may contain multiple entries (password history); the most recent `backupDateTime` is the current password.
  - The `{entraDeviceId}` path segment is the **Entra directory device id**, not the Intune `managedDeviceId`.

### 2.4 macOS LAPS — PARTIALLY VERIFIED; **read is BLOCKED on verification**

- **Context (VERIFIED):** macOS LAPS shipped in Intune service release **2507 (July 2025)**. Requirements: macOS 12+, devices synced from Apple Business/School Manager, enrolled via **Automated Device Enrollment (ADE) after a factory reset**. Password is 15 chars. Auto-rotates every 180 days; a configurable rotation period of 1–180 days is also supported.
- **Retrieval today (VERIFIED):** Microsoft documents viewing the macOS LAPS password **only through the Intune admin center** (Devices → macOS → device → **Passwords and keys**). Viewing/rotating requires a **custom Intune RBAC role** (category **Enrollment programs** → **View macOS admin password** = Yes, **Rotate macOS admin password** = Yes). These permissions are **not** in any built-in Intune role, nor in the Entra "Intune Administrator" role. Audit events are `Get AdminAccountDto` (view) and `rotateLocalAdminPassword ManagedDevice` (rotate).
- **⚠️ VERIFY — the product-defining item:** There is **no confirmed documented public Microsoft Graph endpoint that returns the macOS LAPS password value.** Sources conflict on where it's stored (Microsoft's official doc: "stored and encrypted by Intune"; a third-party writeup: "stored with the Entra ID device object" like Windows, which would imply `deviceLocalCredentials` might surface it). **Before building macOS LAPS reveal:** in a real tenant with a custom Intune role granted, test (a) whether `GET /directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials` returns the macOS account, and (b) whether any Intune `managedDevices` endpoint exposes it. If neither returns the password via documented Graph, **macOS LAPS reveal is not buildable on public Graph** and must be deferred. Do not ship a macOS reveal feature on an undocumented/internal endpoint.
- **Rotate (VERIFIED but BETA):** `POST /deviceManagement/managedDevices/{managedDeviceId}/rotateLocalAdminPassword`
  - Permission (delegated): `DeviceManagementConfiguration.Read.All` **or** `DeviceManagementManagedDevices.Read.All`. Also requires the custom Intune "Rotate macOS admin password" role.
  - **Beta only** — Microsoft states beta APIs are subject to change and not supported for production. Ship rotate as optional, off by default, with a clear "beta API" note, and re-check for a v1.0 promotion.
  - The `{managedDeviceId}` here is the **Intune managed device id**.

### 2.5 The two-identifier join — REQUIRED

Carry both identifiers on every device model:
- **Entra deviceId** — used for Windows LAPS reveal (`/directory/deviceLocalCredentials/{entraDeviceId}`).
- **Intune managedDeviceId** — used for macOS rotate (`/deviceManagement/managedDevices/{managedDeviceId}/rotateLocalAdminPassword`).

Map between them using the `azureADDeviceId`/`deviceId` linkage on the Intune `managedDevice` and the Entra device object. Handle the case where only one identifier exists (unmanaged-but-directory-joined, or Intune-managed-but-not-directory-joined).

---

## 3. Application architecture

### 3.1 Module map (enforce boundaries at the module/target level)

```
AppTarget
├── FeatureUI            (SwiftUI views, navigation)   ── depends on: FeatureViewModels
├── FeatureViewModels    (Observable state, orchestration)
│      ├── depends on: AuthKit, InventoryKit, CredentialKit, LicensingKit
├── AuthKit              (MSAL wrapper, token/session actor, tenant pinning)
├── InventoryKit         (device list/detail; NON-sensitive; may cache)
├── CredentialKit        (LAPS reveal/rotate; SensitiveValue)   ⚠ isolation boundary
│      ├── depends on: AuthKit, Foundation ONLY
│      ├── MUST NOT depend on: LicensingKit, any analytics, any logging module
├── LicensingKit         (entitlement checks against vendor backend; NON-sensitive)
└── PlatformSecurity     (biometrics, app-switcher redaction, screenshot detection)
```

**The critical rule:** `CredentialKit` links no logging framework, no analytics SDK, no crash reporter, and does not import `LicensingKit`. A developer who tries to send a credential to the backend or a log gets a **compile error**. This is the primary defense against accidental exfiltration and must survive refactors.

### 3.2 The SensitiveValue boundary type

```swift
// In CredentialKit. Deliberately not Codable, not Equatable-on-value,
// no value-exposing description. The only way out is `withValue`.
public final class SensitiveValue {
    private var storage: [UInt8]          // backing bytes
    private var consumed = false

    public init(bytes: [UInt8]) { self.storage = bytes }

    /// Convenience for a decoded string; caller must not retain the String.
    public convenience init?(base64: String, encoding: SensitiveEncoding) {
        guard let data = Data(base64Encoded: base64) else { return nil }
        self.init(bytes: [UInt8](data))
        self.declaredEncoding = encoding
    }
    private var declaredEncoding: SensitiveEncoding = .utf16LE

    /// Access the plaintext only within a scoped closure. Never return it.
    public func withValue<R>(_ body: (String) -> R) -> R {
        let s: String
        switch declaredEncoding {
        case .utf16LE: s = String(decoding: Data(storage), as: UTF16.self) // verify BOM/endianness
        case .utf8:    s = String(decoding: storage, as: UTF8.self)
        }
        return body(s)
    }

    /// Overwrite backing bytes. Call on view dismissal.
    public func wipe() {
        for i in storage.indices { storage[i] = 0 }
        storage.removeAll(keepingCapacity: false)
        consumed = true
    }

    // Prevent leakage via string interpolation / logging.
    // (No custom description that returns the value; default is fine because
    //  storage is private. Do NOT add CustomStringConvertible returning value.)
    deinit { wipe() }
}

public enum SensitiveEncoding { case utf16LE, utf8 }
```

Rules for `SensitiveValue`:
- Never store it in a persistent `@State`/`@AppStorage`/scene-restoration graph.
- Never pass it to `print`, `os_log`, `Logger`, analytics, or `URLRequest` bodies.
- The view holds it weakly-scoped and calls `wipe()` in `onDisappear` and on `scenePhase != .active`.

### 3.3 Tenant isolation

- One authoritative `tenantId` per signed-in `MSALAccount`, resolved from the ID token.
- Every cache partition, Keychain item key, and in-memory store namespace includes `tenantId`.
- **Account/tenant switch = full teardown and rebuild** of `InventoryKit` caches and any in-memory state. No shared, un-namespaced store exists. Cross-tenant leakage is prevented by construction.
- On switch, also clear the MSAL token cache entries for the departing account if the user chose "sign out" (vs. "switch"), per §7.

### 3.4 GraphService design

- A single `GraphClient` in `AuthKit`/`InventoryKit` for non-sensitive calls with request/response logging permitted (metadata only).
- A **separate** credential-fetch function inside `CredentialKit` that: acquires the delegated token, performs the `deviceLocalCredentials` GET, parses `passwordBase64` directly into a `SensitiveValue`, and **never logs the request or response body**. This function returns `SensitiveValue`, not `String`, not a `Codable` model containing the value.

---

## 4. Authentication and session management

- MSAL interactive sign-in via `ASWebAuthenticationSession`. Configure the redirect URI per your registration (or the customer's, in BYO mode — §9).
- Silent token acquisition (`acquireTokenSilent`) for subsequent calls; fall back to interactive on `interaction_required`.
- Store tokens in Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. **Disable iCloud Keychain sync** for these items. Never store refresh tokens on any backend.
- Token/session store is an `actor` to serialize refreshes.
- **Incremental consent:** browse scopes at sign-in; `DeviceLocalCredential.Read.All` requested at first reveal attempt with an in-app explanation that it is tenant-wide and admin-gated.

---

## 5. Device list and detail

### 5.1 List
- Default sort: alphabetical by device name.
- Paging: `$top` (e.g. 50–100) + follow `@odata.nextLink`. Never attempt to load an entire large tenant into memory.
- **Search:** primary strategy is client-side filtering over the currently loaded/cached window, because server-side `$search`/`$filter` support is inconsistent across managedDevice properties. Offer server-side `$filter` only for fields known to support it in your tenant testing.
- Cache **non-sensitive** metadata only (name, OS, model, manufacturer, ownership, primary user UPN, last-sync). Cache is `tenantId`-scoped and cleared on switch/sign-out.
- Explicit states: **loading**, **empty** (no devices / none authorized), **partial** (more pages available / some per-device fields unfetched), **error** (with the recovery affordance from §8).

### 5.2 Detail
- Inventory section: name, OS + version, model, manufacturer, ownership/management state, primary user, last check-in, compliance state (if available under granted scopes).
- Per-device enrichment: fetch null-in-list fields via `GET .../managedDevices/{id}?$select=...` on demand.
- **Local administrator password section:** visually distinct, locked, masked. Never shows a value without the §6 reveal flow. Shows metadata (account name, last backup/rotation time) from the metadata call without needing the high-privilege scope.

---

## 6. Protected credential reveal workflow

Order of operations:
1. **Explicit intent:** admin taps "Reveal password" in the locked section.
2. **Biometric/passcode gate:** `LAContext.evaluatePolicy(.deviceOwnerAuthentication)`. On failure, abort; do not fetch.
3. **Fetch:** `CredentialKit` acquires the delegated token (requesting `DeviceLocalCredential.Read.All` consent if not yet granted), calls `GET /directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials`, and parses the most-recent `passwordBase64` into a `SensitiveValue`. Request/response bodies are never logged.
4. **Display:** masked by default (dots). Tap-to-reveal shows plaintext via `SensitiveValue.withValue`.
5. **Auto re-mask:** after ~20–30s, re-mask automatically. A visible countdown is acceptable.
6. **Cleanup:** on re-mask, `onDisappear`, and `scenePhase` change away from `.active`, call `wipe()`.

**Clipboard (recommended: default OFF; opt-in only):**
- If offered, copy using `UIPasteboard.general.setItems(_:options:)` with `.expirationDate` (~30–60s) and `.localOnly = true` to suppress Universal Clipboard.
- Warn the user the value was copied and will auto-clear.
- Consider making copy a paid-tier-only affordance. Reveal-only is the safer default; full-screen reveal is acceptable **only** with the redaction controls below active.

**Screenshot / recording / app-switcher protections:**
- **App switcher:** on `scenePhase == .inactive/.background`, overlay a blank/branded view so the reveal is not captured in the snapshot. (UIKit: swap the window's root snapshot or add a cover view in `sceneWillResignActive`.)
- **Screen recording / mirroring:** observe `UIScreen.capturedDidChangeNotification`; if `isCaptured`, force re-mask and block reveal.
- **Screenshots:** observe `UIApplication.userDidTakeScreenshotNotification`; warn and audit (cannot block, but can respond).
- **State restoration:** disable UI state restoration for any screen that can hold a credential, so it is never serialized to disk.

---

## 7. Sign-out, tenant switch, revocation, permission change

- **Sign out:** clear MSAL cache for the account, wipe all `tenantId`-scoped caches and Keychain items, drop all in-memory state, return to onboarding.
- **Switch tenant/account:** full data-layer teardown/rebuild (§3.3); no residual data from the prior tenant.
- **Consent revoked / token invalid:** on `401`/`invalid_grant`/`interaction_required`, present the recovery flow (re-consent or re-auth) without exposing stale data.
- **Missing role (esp. macOS custom Intune role, or Entra role for Windows credential read):** detect the authorization failure on reveal and show a specific, actionable message ("Your account can sign in but isn't authorized to view LAPS passwords. An administrator must grant [Cloud Device Administrator / Intune Service Administrator], or the custom Intune 'View macOS admin password' role."). Do not present this as a generic error.

---

## 8. Error and authorization-recovery states

Enumerate and design each: network offline; Graph 5xx; throttling (429 — honor `Retry-After`); token expired; consent not granted; consent revoked mid-session; role missing; device not LAPS-enabled; no credentials returned; beta-API failure (macOS rotate). Each has a distinct message and, where possible, a one-tap recovery (retry, re-consent, re-auth, contact-admin copy).

---

## 9. Enterprise "bring your own app registration" (BYO) mode

- **Recommended as the default for security-conscious customers.** The customer registers the application in **their** Entra tenant, owns the client ID, configures the redirect URI, and consents to the scopes they can inspect. This removes the vendor from the consent relationship and makes the "we can't see your credentials" claim customer-verifiable.
- The app must support configuring a custom client ID + authority at runtime (via MDM-delivered app config / managed app configuration, or a settings entry).
- Vendor multi-tenant registration remains the convenience default for smaller customers.
- **Tradeoffs:** BYO shifts registration/consent burden to the customer's IT (higher setup cost) in exchange for maximal trust and auditability. Support both; document BYO as the enterprise recommendation.

---

## 10. Backend boundary (licensing only)

- **May receive:** app install identity, license/seat identity, subscription/entitlement state, purchase receipts (for IAP validation), and non-sensitive operational telemetry (crash-free rate, feature-usage counts with **no** device or credential data).
- **Must never receive:** any LAPS password, any Graph credential response, device names tied to credentials, tenant credential data, Microsoft access/refresh tokens.
- **Enforcement:** `LicensingKit` has no reference to `CredentialKit`. Backend request builders live in `LicensingKit` only. There is no code path from a `SensitiveValue` to any backend call.
- **Is the backend necessary?** Only for business/seat licensing and (optionally) individual subscription validation beyond on-device receipt checks. Individual IAP can be validated largely on-device; the backend earns its place with seat management (§11). Keep it minimal to reduce identity/privacy surface.

---

## 11. Business model and licensing (implementation notes)

- **Free tier:** device browse + Windows LAPS metadata; no reveal.
- **Individual paid (IAP, auto-renewing):** reveal + rotate + copy-with-expiry. Monthly and annual; lead with annual. Apple fee 15% (Small Business Program) or 30%.
- **Business/seat licensing via web portal (Stripe/Paddle), NOT IAP:** org accounts, buy N seats, invite/assign by UPN, **reassign seats on employee departure**, billing-owner and admin roles, invoicing. The iOS app checks entitlement against the licensing backend using app/license identity only.
- **Apple rule basis:** Guideline **3.1.3(c) Enterprise Services** permits non-IAP payment for org-only sales; consumer/single-user/family sales must use IAP. Document the org-only nature of the business tier in App Store Connect; expect possible App Review back-and-forth (apps have been flagged under 3.1.1/3.1.3 despite qualifying).
- **US external-link rules are recent and unevenly enforced — VERIFY at submission.** Exact external-link placement and disclosure UI must be confirmed against current App Store Connect guidance; budget for rejection rounds.
- **Lifetime purchase: not recommended** for a security tool with ongoing Graph/OS-compat maintenance and security liability.
- **ABM/VPP:** consider for managed enterprise distribution; it is a distribution mechanism, not a billing one.

---

## 12. Threat model and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Malicious vendor/developer | Client-only credential handling; **BYO app registration** removes vendor from consent; verifiable/reproducible builds; published egress allowlist | Low if BYO used; medium if vendor registration + closed binary |
| Compromised vendor backend | Backend never holds credentials/tokens; `CredentialKit` isolated from `LicensingKit` | Low for credentials; licensing data exposure possible |
| Compromised iOS device (malware/jailbreak) | Assume client is readable; it holds only the user's own delegated access; biometric gate; no persisted credentials | Medium — a fully compromised device can capture a revealed value on screen |
| Lost/stolen unlocked device | Biometric gate on reveal; auto-remask; short session; no persistence; `ThisDeviceOnly` keychain | Low-medium |
| Malicious/compromised tenant admin | Out of app's control — Microsoft RBAC governs; app adds Microsoft-side audit (`Get AdminAccountDto`, LAPS read audit) | Inherent to admin trust; unchanged by app |
| Cross-tenant authorization mistake | `tenantId`-scoped everything; full teardown on switch; authority pinned per account | Very low |
| Token theft | `ThisDeviceOnly` non-synced keychain; short-lived tokens; no refresh token on backend; actor-serialized refresh | Low |
| Clipboard exposure | Copy default-off/opt-in; `.expirationDate` + `.localOnly`; user warning | Low if configured; do not ship unconditional copy |
| Logging/telemetry leakage | Credential module links no logger/analytics; Graph credential bodies never logged | Very low if module boundary holds |
| Crash-report leakage | No crash SDK in `CredentialKit`; credentials never in `@State`/restoration | Very low |
| Supply-chain/dependency compromise | SPM only; zero third-party deps in `CredentialKit`; pin versions; review | Low for credential path |
| Reverse engineering of the app | Acceptable — client holds no secrets, only user's delegated access | Low (by design) |
| Screenshots / UI-state disclosure | App-switcher redaction; screen-capture detection; screenshot warning; state-restoration disabled | Medium (screenshots not fully blockable) |
| Backend compromise | Minimal backend; no credential/token data; standard hardening | Low for credentials |

---

## 13. Testing

- **Unit:** `SensitiveValue` wipe/scoping; base64→plaintext decode against known vectors; tenant-scoping key generation; two-identifier join logic; entitlement checks.
- **Integration:** MSAL flows against a test tenant; paging over `managedDevices`; Windows LAPS metadata + reveal; **macOS LAPS retrieval verification harness (§2.4)**; 401/403/429 handling.
- **UI:** reveal gate → mask → auto-remask → wipe; app-switcher overlay present; copy expiry; account switch teardown (assert no prior-tenant data).
- **Security-focused:** static check/CI rule asserting `CredentialKit` imports neither `LicensingKit` nor any logging/analytics module (fail the build if violated).

---

## 14. Build order (roadmap)

1. **MVP:** MSAL auth + tenant pinning; device list (paging + client-side search); Windows LAPS metadata; Windows LAPS reveal behind biometric gate; **module isolation from day one**.
2. **Hardening:** app-switcher redaction; screen-capture detection; clipboard expiry; state-restoration disable; logging scrub; keychain hardening; BYO registration mode.
3. **Beta (TestFlight):** licensing backend + entitlement; free/paid gating; error/recovery flows; **run the macOS LAPS Graph-read verification (§2.4)**.
4. **Production:** individual IAP; web seat portal; App Store submission with Enterprise Services documentation.
5. **macOS + rotate:** ship macOS reveal **only if** §2.4 confirms a documented Graph path; ship rotate only when it exits beta.

---

## 15. Open verification checklist (do these before/at build)

- [ ] **§2.4 macOS LAPS read via Graph** — confirm a documented public endpoint returns the macOS password, or defer the feature.
- [ ] Windows LAPS `passwordBase64` decoding (confirm UTF-16LE vs other) against a known tenant value.
- [ ] Exact `$filter`/`$search` support on `managedDevices` in your target tenants.
- [ ] Entra device role requirements for the `credentials` property in delegated mode (Cloud Device Administrator / Intune Service Administrator) as of build date.
- [ ] macOS rotate API v1.0 promotion status (currently beta).
- [ ] App Store external-link / disclosure UI rules for the US storefront at submission time.
- [ ] 3.1.3(c) Enterprise Services acceptance for the business tier (prepare App Store Connect documentation).


Other Features forgotten to be asked:

Darkmode

Probably already mentioned but I hate apps that look like crap, I need this to look professional and clean. Also fast (as fast as you can get calling graph api, I know microsoft can be slow)

I’m also pretty concerned about ongoing maintenance. Vulnerability patches, bug fixes, etc. I don’t have time to make this a second full time job
