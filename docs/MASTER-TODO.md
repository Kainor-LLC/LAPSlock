# PitLAPS — Master TODO

Consolidates the build spec, the implementation checklist, and the business/pricing plan
from the separate planning conversation.

Legend: ✅ done · 🟡 partial · ⬜ not started · 🔵 not-code · ⚠️ needs a decision

---

# ⚠️ READ FIRST — three conflicts between the plans

## 1. ✅ RESOLVED — relicensed to PolyForm Strict + security-review permission

The plan calls for **PolyForm Strict** (source-available, no redistribution). But today we
committed **Apache-2.0** and pushed it to a public repo. Apache-2.0 is a true open source
license: it grants redistribution and modification, which is exactly what PolyForm Strict
is meant to deny.

**What relicensing can and can't do.** As sole copyright holder you can relicense all
future versions freely. What you cannot do is retroactively revoke Apache-2.0 rights from
anyone who already obtained the code — that grant is irrevocable for the versions
published under it. In practice the repo has been public for hours with essentially no
audience, so the real-world risk is close to zero. But "close to zero" is not "zero," and
the fix gets harder every day the repo sits there.

**Decide now, not later:**
- **Option A — relicense to PolyForm Strict.** Do it before any further commits. Also
  drop the "open source" language from the README and site and say **"source-available for
  security review."** Marketing note: your buyers care that they can *read* the code, not
  that they can fork it, so you lose nothing with this audience.
- **Option B — stay Apache-2.0.** Accept that a competitor may legally fork and publish.
  Your protection becomes trademark plus first-mover plus App Attest.

**DECIDED: Option A.** Relicensed to PolyForm Strict 1.0.0 plus an explicit additional
permission allowing commercial organizations to copy and read the code for security
review. That additional grant was necessary: PolyForm Strict alone permits only
noncommercial purposes, which would have excluded a for-profit security team auditing the
repo — the exact audience the code is published for.

The LICENSE also documents the brief Apache-2.0 period honestly rather than pretending it
didn't happen. README and site copy now say "source-available," not "open source."

Remaining: 🔵 attorney review of the additional-permission wording before it appears in an
enterprise agreement or an enforcement action.

## 2. Website hosting: GitHub Pages now, Cloudflare when commerce lands

GitHub's Pages terms prohibit using it to run an online business or a site **primarily
directed at facilitating commercial transactions**. A marketing-and-docs site for a paid
app is ordinary Pages usage; putting Stripe checkout on it is what crosses the line.

**So the move is a dependency of the Stripe work, not a standalone task.** It is listed
under Payments below. Do not move it before then, and specifically not now:

The plan recommends Cloudflare Pages for the marketing site. Reasonable in the abstract —
but kainor.com is currently on GitHub Pages, working, with HTTPS, **and Apple is actively
reviewing that site as part of the Developer Program enrollment.** Changing DNS or
hosting mid-review risks a failed check and another rejection cycle.

**Defer until Apple enrollment completes.** Revisit then, and only if GitHub Pages is
actually causing a problem. The GitHub ToS "commerce" concern is real but doesn't bite
until you sell directly from the site.

## 3. macOS reveal is impossible, not pending

The plan treats macOS as a normal roadmap item. We proved today it isn't: no documented
Graph endpoint returns a macOS LAPS password, and the documented beta function returns
rotation metadata only *and* currently 500s. Any pricing or listing copy must not imply
macOS password retrieval.

---

# App features

## Done and tested

- ✅ MSAL auth, multi-tenant, tenant pinning, incremental consent — **verified live**
- ✅ Delegated scopes: `DeviceManagementManagedDevices.Read.All`, `Device.Read.All`,
  `DeviceLocalCredential.ReadBasic.All`, `DeviceLocalCredential.Read.All`
  (the plan listed only two; four are registered and consented)
- ✅ Device search (name, user, serial, model) with prefix/exact ranking
- ✅ **Search widened 2026-08-27** — added `userDisplayName`, `emailAddress`, and
  `managedDeviceName` to both `$select` and the matcher. Admins working a ticket have a
  person's name far more often than a device name. `rank()` is now field-aware: match
  strength (exact / prefix / substring) is evaluated across all fields, with device name
  winning ties, so an exact hit on a user's name no longer sorts below an incidental
  substring in a model string. Also normalised empty strings to nil at the parse boundary,
  because Graph returns `""` for user fields on shared devices and an empty string is a
  substring of every query.
- ✅ Windows password reveal, expiry/rotation date display
- ✅ Copy to clipboard with auto-clear — **built, currently free**, see pricing conflict below
- ✅ Face ID gate before every reveal
- ✅ Auto-hide window, wipe on background/recording/screenshot
- ✅ App-switcher redaction
- ✅ Zero analytics/telemetry (enforced by the isolation guard, not just policy)
- ✅ Demo mode for App Store review
- ✅ Consent-onboarding explainer + shareable admin approval link
- ✅ Windows release names ("Windows 11 24H2" + build)
- ✅ Support diagnostics that structurally cannot capture credentials
- ✅ **TestFlight** — first build uploaded 2026-08-26. Build 1 (1.0) archived, validated,
  uploaded. **Build 3 uploaded 2026-08-27 and is the first build where sign-in actually
  works on a device with Microsoft Authenticator installed** — builds 1 and 2 are both
  broken in the broker path. Internal testing only; no Beta App Review needed. Export
  compliance pre-answered via `ITSAppUsesNonExemptEncryption`.
- ✅ **Search latency fixed 2026-08-27.** The widened search shipped a performance
  regression, found in use on device. Three compounding causes: `range(of:options:)` with
  `.diacriticInsensitive` performs full Unicode folding on every call; `rank()` was called
  from inside the sort comparator, so it evaluated O(n log n) times rather than once per
  device; and `visibleDevices` was a computed property that `deviceList` read twice per
  body evaluation, so every keystroke ran the whole filter and sort at least twice. Fixed
  by folding each field once and comparing with plain string ops, scoring in a single pass,
  and storing `visibleDevices` behind a 180ms debounce. Note for future work: Release
  configuration made no perceptible difference, which is what pointed at redundant passes
  rather than at raw compute.
- ✅ **Four device-only bugs found and fixed 2026-08-26/27**, none reachable in the
  simulator. The first two are described below; the third (privacy cover flash) is still
  open and has its own entry; the fourth was the search latency regression above.
  1. **Demo fallback in the live path.** `AppRootView`'s `.live` branch coalesced nil
     providers into `DemoLapsProvider`/`DemoBitLockerService` while still passing
     `isDemo: false`, so a fake credential could have rendered with no banner. Root cause
     was `detailBuilder: (ManagedDeviceSummary) -> DeviceDetailView` not being a
     `@ViewBuilder`, so the closure could not branch on nil and the author reached for the
     nearest conforming type. Fixed by hoisting the check into a `LiveSession` value whose
     accessors are non-optional, so there is no optional left to coalesce. Nil now routes
     to the existing recover-to-signed-out path.
  2. **Broker redirect never handled.** With Microsoft Authenticator installed, MSAL
     delegates auth to it and the result returns as a URL open on
     `msauth.com.kainor.pitlaps://auth`. Nothing was listening, so the interactive request
     never completed and MSAL reported "application did not receive response from broker"
     (MSALErrorDomain -50000), which surfaced as the generic sign-in error. Fixed with
     `MSALRedirect.handle` in AuthKitMSAL plus `.onOpenURL` on the root view. NOT the app
     delegate: this app is scene-based, SwiftUI installs its own scene delegate, and iOS
     therefore routes URL opens to `scene(_:openURLContexts:)` and never calls
     `application(_:open:options:)`. `sourceApplication` is nil on the SwiftUI path, which
     is fine because MSAL validates broker responses with a nonce (V2-broker-nonce).
     The URL scheme, `msauthv2`/`msauthv3` query schemes, keychain access group, and the
     Entra iOS/macOS redirect registration were all already correct.
  3. **MSAL interactive calls ran off the main thread.** `MSALAuthManager` is an actor, so
     `application.acquireToken` was invoked from the cooperative thread pool. MSAL
     dereferences the presenting view controller INSIDE `acquireToken`, not only while
     building `MSALWebviewParameters`, so it read `UIViewController.view` and
     `UIView.window` off-main. Main Thread Checker flagged it. Building the parameters on
     the main actor, which the code already did, is necessary but not sufficient. Fixed by
     dispatching `acquireToken` and `signout` to the main thread. Note this was a real
     defect but was NOT the cause of the sign-in failure; the two were conflated during
     diagnosis.

## Next up — code

- ✅ **BitLocker recovery key read** — built and tested (service + UI)
  - `GET /v1.0/informationProtection/bitlocker/recoveryKeys?$filter=deviceId eq '{entraDeviceId}'`
  - `GET /v1.0/informationProtection/bitlocker/recoveryKeys/{id}?$select=key`
  - Scope: `BitLockerKey.Read.All` (delegated; **application not supported** — matches our model)
  - Roles already held by your users: Cloud Device Admin, Helpdesk Admin, Intune Service
    Admin, Security Admin, Security Reader, Global Reader
  - `$select=key` triggers an Entra audit entry — same auditability story
  - Uses the Entra device ID we already carry. Same screen, same gate, same reveal window.
  - Competitors' users are explicitly asking for this; neither competitor covers Entra/Intune.

- ✅ **Settings screen** — appearance, BitLocker rotation, macOS status, diagnostics, about
- ✅ **BitLocker rotate** — behind the settings toggle, requests
  `DeviceManagementManagedDevices.ReadWrite.All` at toggle time
- ⬜ **PIM role activation from the app** ← closes the most annoying gap in the workflow

  The scenario: an admin needs a LAPS password, but their Cloud Device Administrator role
  is PIM-*eligible*, not active. Today that means leaving the phone, opening the portal on
  a desktop, activating, and coming back. Doing it in-app closes the loop, and it pairs
  naturally with the `notAuthorized` error we already surface — "your role is not active,
  activate it here" instead of "you lack permission".

  **API (verified, v1.0 GA):**
  - List what the user is eligible for:
    `GET /v1.0/roleManagement/directory/roleEligibilitySchedules?$filter=principalId eq '{id}'`
    Scope: `RoleEligibilitySchedule.Read.Directory`
  - Activate:
    `POST /v1.0/roleManagement/directory/roleAssignmentScheduleRequests`
    with `action: selfActivate`, `principalId`, `roleDefinitionId`, `directoryScopeId`,
    `justification`, `scheduleInfo` (e.g. `expiration.duration: PT5H`), optional `ticketInfo`.
    Scope: `RoleAssignmentSchedule.ReadWrite.Directory` (least privileged of the options)

  **Three things to design around, in order of how much they will hurt:**

  1. **MFA must be satisfied in-session.** Microsoft requires the caller to have been
     challenged for MFA in the current session for self-service operations. In practice
     Graph may return a claims challenge that MSAL has to handle and re-authenticate
     against. That is real work and it is the main reason this is not a quick feature.
     It is also correct behaviour: it means the app cannot quietly escalate privilege.
  2. **Approval workflows.** If the tenant requires approval for that role, `selfActivate`
     creates a *pending* request rather than granting. The UI must show "requested, waiting
     for approval" and never imply the role is active.
  3. **Consent optics.** `RoleAssignmentSchedule.ReadWrite.Directory` lets the app request
     role activation. That is a heavier ask than reading passwords and belongs behind an
     opt-in Settings toggle with incremental consent, exactly like BitLocker rotation.
     Customers who leave it off never see it on their consent screen.

  Mild uncertainty worth checking during implementation: the docs list Privileged Role
  Administrator for *write* operations on this endpoint, but that applies to managing other
  people's assignments. Self-activating your own existing eligibility should not require
  it, or PIM would be self-defeating. Verify against a real tenant before promising it.

  **Priority: after real-tenant verification and the entitlement backend.** High value, but
  the MFA claims-challenge work makes it a genuine project rather than an afternoon.

- ⬜ Windows LAPS password history (`credentials` returns multiple; we take newest.
  History matters when a device hasn't checked in and still has an older password)
- ⬜ **Auth diagnostics in the support report** ← proven necessary on 2026-08-26

  `signIn()` collapses every failure that isn't consent, cancellation, or tenant mismatch
  into one message: "Sign-in didn't complete. Check your connection and try again." Correct
  for users, who should never see MSAL internals. Useless for support, and it cost real
  time on the first device build: a missing broker redirect handler presented as a
  connection problem, and the only way to identify it was a cabled Mac and Console.app.
  A customer cannot do that, so without this the support path for the single most likely
  failure category is "reinstall and hope."

  Broker failures will be the most common support category this app has. Every customer
  with Microsoft Authenticator installed takes that path, and it depends on four things
  being correct on a device you cannot inspect.

  **Fields to capture** (all non-secret, all from `AuthError`/`NSError` userInfo):
  - MSAL error domain and code, plus the internal error code where present
  - The AAD/STS error code (`AADSTS…`). The single most useful field for a support case
    or a web search, and the one that names the actual cause.
  - OAuth error and error description (`invalid_grant`, `interaction_required`, etc.)
  - Correlation ID — what Microsoft support asks for first
  - HTTP status where the failure came from a token endpoint
  - **Whether the broker path was taken**, and whether a redirect was ever received.
    A single boolean would have identified the 2026-08-26 bug immediately.
  - Broker app version if MSAL exposes it
  - The redirect URI the app actually used, so a mismatch is visible without the portal

  **Design constraint, and this one matters:** allowlist specific userInfo keys. Do not
  serialise the whole dictionary. MSAL error descriptions can contain a full redirect URL,
  and a redirect URL can carry an authorization code — credential-shaped, and exactly the
  thing DiagnosticsKit's types exist to make unrepresentable. An allowlist keeps that
  guarantee structural rather than a matter of care. `pre-push-scan.sh` catches
  credential-shaped strings in the tree, not at runtime, so it will not save us here.

  Pairs with the Graph `request-id` work already done: that covers Graph call failures,
  this covers the auth failures that happen before any Graph call. Same report, same
  Settings screen, same no-credentials guarantee.

- ⬜ **Reveal shows a privacy placeholder first** ← observed on device 2026-08-27

  Tapping reveal on either a LAPS password or a BitLocker key shows the "item is hidden"
  privacy screen for roughly two seconds, then replaces it with the credential. Both
  credential types, so it is in the shared reveal path rather than either provider.

  Cause is confirmed, not guessed. `PrivacyCoverModifier.shouldCover` is
  `isProtected && scenePhase != .active`, and the reveal order (§6, deliberate) is:
  clear existing secret → biometric gate (Face ID takes the scene to `.inactive`) →
  Graph call → publish secret (`isProtected` flips true while the scene is STILL
  `.inactive`) → scene returns to `.active` and the cover finally clears. The cover is
  correct about its own condition; the condition is asking the wrong question.

  Not a security hole (it errs toward hiding), but it works against what the reveal window
  is for. An admin standing at a machine reads a hidden-state screen as failure and taps
  again, and every extra tap is another audit event in the customer's tenant.

  **Two fixes were tried on device and BOTH FAILED, in the dangerous direction** (the
  credential appeared in the app-switcher card). Details are in the design note now sitting
  above `PrivacyCoverModifier`. In short: qualifying the `.inactive` case on "was a
  credential on screen while active" is right in principle, but every way of recording that
  inside the modifier was either one render stale (`@State` written from
  `.onChange(of: scenePhase)`, since change handlers run after the render iOS photographs)
  or otherwise failed the switcher test. Reverted to the original condition.

  **Do not attempt a third fix inside ScreenPrivacy.** The right change is in
  `DeviceDetailModel`: hold the fetched secret and publish it only once `scenePhase` is
  `.active`. Then `isProtected` is simply false during the inactive tail, the cover
  condition needs no qualification at all, and there is no render-timing hazard to get
  wrong. It also stops the 60-second reveal window from starting while the credential is
  still behind a cover, which is a second small bug in the same area.

  Verify ON DEVICE, in this order, and treat the second as blocking:
  (1) reveal shows no flash, (2) credential up, swipe to the app switcher, the card shows
  "Hidden".

- ✅ **App-switcher redaction verified on device 2026-08-27.** Reveal a credential, swipe to
  the switcher, the card shows "Hidden". Previously only assumed, since it had likely only
  ever been checked in the simulator where scenePhase timing differs. It holds, which
  matters because the sign-in screen makes this claim to users directly.

- ⬜ **Search only covers loaded pages** ← correctness bug, not a feature gap

  `DeviceSearch.filter` runs over `cachedDevices()`, which is the pages fetched so far.
  On a tenant large enough that the admin has not scrolled to the end, searching for a
  device that exists returns nothing. That does not read as "still loading", it reads as
  "this app cannot find my machine", and it gets worse the bigger the customer is.

  Graph will not solve this: `managedDevices` supports `$filter` with `eq` and some
  `startswith`, but not substring `contains`, and `$search` is not supported on the
  resource at all. So the answer is client-side over a complete set, not a server query.

  `loadAll(maxPages:)` already exists and nothing calls it. Suggested shape: filter
  locally for instant feedback, and when the query is non-empty and `hasMore()` is true,
  page to completion in the background and re-filter as results arrive. Show that it is
  still loading rather than showing an empty state, since an empty state during a partial
  load is exactly the lie being fixed.

  Worth measuring before choosing a design: 100 devices per page against a few thousand
  devices is tens of requests, which is fine once but wasteful on every keystroke.

- ⬜ Device row shows the raw UPN. Now that search matches `userDisplayName` and
  `emailAddress`, a result can match on a field the row never displays, which looks like a
  phantom hit. `ManagedDeviceSummary.primaryUserLabel` exists for this; swap
  `DeviceListView` line ~301 over to it.

- ⬜ Recents / favorites
- ⬜ Biometric app lock (distinct from the per-reveal gate)
- ⬜ Tenant switcher (MSP tiers)
- ⬜ "Copy your tenant ID" button (feeds the org purchase flow)
- ⬜ BYO app registration UI (the config seam already exists)
- ⬜ Entitlement check: call `/entitlement`, cache signed JWT, 14–30 day offline grace
- ⬜ **App Attest gating** on `/entitlement` — the real anti-sideload teeth

## App icon

- ✅ **Shipping icon** — top-down single-seater with a keyhole cockpit, navy field.
  Source geometry is checked in at `design/icons/render-icon.py` rather than kept in a
  design tool, so the icon is reproducible and both colour variants share one geometry
  function and cannot drift apart.
- ⬜ **Alternate icon picker (orange field)** — the orange asset is rendered and committed,
  but not wired up. Implementation is native and small:
  1. Add a second icon set `AppIconOrange` to `Assets.xcassets`
  2. Build settings: `ASSETCATALOG_COMPILER_ALTERNATE_APPICON_NAMES = AppIconOrange` and
     `ASSETCATALOG_COMPILER_INCLUDE_ALL_APPICON_ASSETS = YES`
  3. Settings row calling `UIApplication.shared.setAlternateIconName("AppIconOrange")`

  Roughly 30-45 minutes including the Xcode settings. **Two things to know before
  building it:** iOS shows an unsuppressable system alert on every icon change ("You have
  changed the icon for PitLAPS"), so it is two taps for a preference set once; and icon
  variants cannot appear in App Store screenshots, so nobody discovers the feature until
  they open Settings.

  **Priority: after the entitlement backend.** It is a delight feature for an audience
  that will open Settings once to enable BitLocker rotation and rarely again.

  Observed in testing and worth recording: the orange field is measurably more legible on
  BOTH light and dark wallpapers. Navy ships as a deliberate preference, not because it
  tested better.

- ⬜ iOS 18 dark and tinted icon variants. Currently derived automatically by iOS, which
  is acceptable. Hand-authored versions would give more control.

## Loose ends from the build spec

- 🟡 **Dark mode audit** — semantic colors adapt, but the reveal card's hardcoded navy
  needs verifying. You named this explicitly; it's cheap and worth doing with the toggle.
- 🟡 State-restoration disable on credential screens (real §6 gap)
- 🟡 Network-offline detection (currently folds into a generic transport error)
- 🟡 Per-device enrichment for fields that are null in list responses

---

# Settings screen — your three toggles

## Design note: not on the main page

You said "toggles on the main page." I'd put them behind a **gear icon in the device list
toolbar → Settings sheet** instead. The device list's job is find-a-device-fast; toggles
on that surface compete with the search field for attention and get tapped by accident.
One tap away is the right distance for settings you change rarely.

## ⬜ Toggle 1 — BitLocker key rotation (requests write access)

Your instinct is exactly right, and the honest labeling is the valuable part. Proposed copy:

> **Allow BitLocker key rotation**
> Off by default. Turning this on asks Microsoft Entra ID for permission to **modify**
> devices in your tenant (`DeviceManagementManagedDevices.ReadWrite.All`), not just read
> them. Your administrator may need to approve it. Rotation is queued and applies the next
> time the device checks in with Intune.

Two things this buys you: customers who don't want it **never see a write permission on
their consent screen**, which is a real selling point — and it's a natural paid-feature
line, matching how your competitor gates password reset behind its paid tier.

## ⬜ Toggle 2 — Appearance

Make it **three-way (System / Light / Dark), defaulting to System.** That's the iOS
convention, and a two-way toggle forces a choice the OS already made correctly for most
people. Cheap to build once the dark-mode audit above is done.

## ⬜ Toggle 3 — macOS support

Small improvement on your idea: **don't hide it — show it disabled with the reason.** A
hidden toggle is dead code nobody remembers, and an admin wondering "why can't I see Mac
passwords?" gets silence. Instead:

> **macOS local admin passwords** *(unavailable)*
> Microsoft doesn't currently offer an API for reading macOS local administrator
> passwords. Intune keeps them encrypted on its own service, and only the admin center can
> display them. PitLAPS will enable this automatically if Microsoft ships an API.

That turns an absence into an answer, and it's honest about whose limitation it is. The
provider already reports this; the toggle just surfaces it.

---

# ✅ Pricing — copy-to-clipboard IS behind Pro

I raised this as a concern and was wrong. The correcting insight: when you're standing at
the end user's machine, the password is on your phone and you type it into *their*
keyboard. The phone clipboard doesn't help with that at all. Copy only matters for the
secondary workflow — pasting into an RDP/SSH client on the phone, or sending it to a
colleague — which is genuinely a convenience feature, not core function.

So gating copy is defensible, matches the competitor's precedent, and the free tier
remains fully useful for the primary use case (walk up, reveal, type).

⬜ TODO: make copy-to-clipboard gated once entitlement checking exists. It is currently
built and ungated.

## Pricing plan as written (for reference)

- ⬜ Free: search, reveal, expiry date, copy-tenant-ID button
- ⬜ Individual Pro IAP: $1.99/mo · $19.99/yr
- ⬜ MSP Pro IAP (per tech): $49.99/yr
- ⬜ Enterprise direct (tenant-keyed): $299/yr ≤500 devices · $599/yr unlimited
- ⬜ MSP org direct: $999/yr
- ✅ Apple Small Business Program — submitted (15% commission)

---

# Backend (Azure)

- ⬜ Azure subscription for the backend. You already have one attached to the Kainor
  tenant; verify it suffices before creating another, since a second tenant means a
  second identity to manage.
- ⬜ Resource group, storage, licenses table
- ⬜ Function app (Consumption): `/entitlement` — tid in → signed JWT out
- ⬜ App Attest verification on `/entitlement`
- ⬜ Later: `/stripe-webhook` to auto-insert license rows
- ⬜ Custom domain for the API (~$10–15/yr; expect <$2/mo Azure spend)
- ⬜ **Private repo** for the Function, JWT signing keys, Stripe webhook. Publish only the
  API contract. Clones can't stand up a working entitlement backend.

---

# Payments

- ✅ Business bank account (LLC, linked to Apple)
- ⬜ **Move the marketing site to Cloudflare Pages** — required before adding checkout,
  because GitHub Pages prohibits sites primarily facilitating commercial transactions.
  Small lift: connect the repo, point DNS, done. Blocked until Apple finishes reviewing
  kainor.com, since a DNS change mid-review risks another rejection.
- ⬜ Stripe account on the LLC + EIN + bank
- ⬜ Payment Link with a domain/tenant-ID custom field
- ⬜ Stripe Invoicing (ACH, PO numbers, net-30) for enterprise/MSP
- ⬜ Stripe Tax on
- ⬜ Domain → tenant GUID resolution via OIDC discovery
- ⬜ Revisit Paddle/Lemon Squeezy as merchant of record if international orders appear

---

# Legal & business

- ✅ LLC (Kansas, Business ID 10077333)
- ✅ EIN
- ✅ Business bank account (LLC, linked to Apple)
- ✅ **Apple Developer Program** — enrolled as Kainor LLC, $99 paid. Team ID 72C7PQBP52.
- ✅ **Partner Center verification** — Authorized
- 🔵 **Employer/design-partner IP agreement in writing** ← still the highest-value item
  on this list. A prospective customer who is also an employer needs the ownership
  question documented before money moves.
- ✅ **Publisher verification** — MPN 7147713 associated, "Kainor LLC" shows with the verified badge
- ✅ **Privacy + terms pages** — live at kainor.com/privacy/ and /terms/, linked from the
  app registration, the site nav, and the in-app Settings screen
- 🟡 "Not affiliated with Microsoft" disclaimer — in Settings and both legal pages;
  still needed on the marketing site
- ⬜ One-page security/data-handling doc
- ⬜ Enterprise license agreement draft (attorney pass before the first real deal)
- ⬜ W-9 PDF ready
- ⬜ Trademark filing — USPTO, Class 9, ~$350 (verify current fee). Owner = the LLC,
  intent-to-use basis, pick goods wording from the ID Manual to avoid the custom-text
  surcharge.
- ✅ **License decision** — PolyForm Strict + security-review permission
- 🔵 Attorney review of the additional-permission wording

---

# App Store & launch

- ⬜ Free app + IAP subscription products in App Store Connect
- ✅ Paid Apps agreement — accepted, bank and tax details in place
- ⬜ Org purchasing on the website only, never linked in-app (verify current 3.1.3 text)
- ⬜ 3.1.3(c) Enterprise Services documentation
- ⬜ Listing copy leads with security posture
- ⬜ Privacy manifest + "Data Not Collected" nutrition label
- ✅ SECURITY.md with a disclosure policy and the five testable design claims
- ⬜ Tag a source release per App Store version
- ⬜ **Network transparency doc** — the app talks to exactly three hosts
  (login.microsoftonline.com, graph.microsoft.com, your entitlement domain). Any admin can
  verify in ten minutes with a proxy. For this audience, observed behavior beats any badge.
  **This is your strongest trust artifact.**
- ⬜ Contributions policy: issues on, pull requests off (sole copyright holder = you can
  relicense and enforce without hunting contributors)
- 🔵 Launch posts: r/Intune, r/msp, Intune blog circuit
- 🔵 File the Microsoft support case for the macOS 500 (request ID
  `d4576653-30f5-44ae-8790-06fff930667f`) — the only path to macOS ever working

---

# Competitive intel (from research)

Two iOS competitors exist, **both for on-prem AD LAPS, neither for Entra/Intune**:

- **LAPSSignify** — free with IAP; paid tier gates clipboard copy and password reset.
  Users request: search by AD description, share via email/SMS, scheduling.
- **LAPS mobile** — requires self-hosting a WebLAPS portal. Users request: multiple
  passwords during AD replication lag, **and extra device attributes including BitLocker
  keys**.

Takeaways: your Entra/Intune positioning is genuinely unoccupied, gating rotation has
precedent, and BitLocker read is the most-requested adjacent feature in the category.

---

# What to work on next

Reprioritized with Apple pending, no dev tenant available, and the Microsoft side finished.

## Tier 1 — ✅ DONE

These are hours, not days, and two of them are things I said mattered and then did not do.

1. ✅ **State-restoration disable on credential screens.** Was a real §6 requirement. Without it, iOS can serialize a view containing a revealed credential to
   disk during state preservation. This is the only open item that is an actual security
   hole rather than a polish issue, so it goes first.
2. ✅ **Graph `request-id` in diagnostics.** I called it the single most useful
   field for a Microsoft support case and then shipped a report without it, because the
   services do not surface it on their typed errors. Small refactor, and it is the
   difference between a useful support report and a vague one.
3. ✅ **Network-offline detection.** Currently folds into a generic transport error, so
   "you are on a captive portal" reads as "something went wrong". §8 asks for it
   specifically and admins hit it constantly in server rooms.
4. ✅ **Copy tenant ID button.** Ten minutes, and it is the first step of the enterprise
   purchase flow. Cheap to do before the flow exists.

## Tier 2 — ✅ DONE 2026-08-27

5. ✅ **Verified against a real tenant.** On a TestFlight/device build, signed in to a live
   tenant, listed real devices, scrolled through multiple pages, and revealed a real
   Windows LAPS password on a Cloud PC. **The password was correct.** The decode path
   (base64 → UTF-16LE detection → BOM stripping) has now processed real Graph output
   rather than handwritten test vectors, which was the largest unverified assumption in
   the project. Face ID gate fired before the Graph call as designed. Paging works against
   real data.

   Everything above this line is no longer built on sand.

## Tier 3 — genuine product value, no tenant required

6. **Auth diagnostics in the support report.** Moved to the top of this tier because the
   first real device build proved it necessary rather than nice. MSAL/AAD error code,
   correlation ID, and a broker-path flag, allowlisted so no authorization code can ride
   along in an error description. Full detail under "Next up — code".
7. **Windows LAPS password history.** `credentials` returns multiple entries and we take
   the newest. History matters when a device has not checked in and is still running an
   older password — a real support scenario where the current app gives the wrong answer.
8. **Recents / favourites.** The daily-use improvement with the highest ratio of value to
   effort. An admin looking after the same twenty machines should not search every time.
9. **Biometric app lock**, distinct from the per-reveal gate.

## Tier 4 — the revenue path (largest remaining chunk)

Partially unblocked: the backend does not need Apple, but IAP and App Attest do.

10. Azure Function `/entitlement`, licences table, private repo for the signing keys
11. Stripe (waiting on the business bank account)
12. App Attest gating — needs a real device and the Apple account, so blocked
13. IAP products and free-tier gating — needs App Store Connect, so blocked

## Tier 5 — cheap trust and legal work, do while waiting

14. **Network transparency doc.** Three hosts, verifiable with a proxy in ten minutes.
    Already identified as the strongest trust artifact and it costs an afternoon.
15. **Trademark filing.** USPTO Class 9, intent-to-use, ~$350. Actionable today, and the
    icon can be cleared at the same time (a design-mark search, separate from the wordmark
    search already done).
16. Attorney pass on the licence additional-permission wording and the liability cap.
17. "Not affiliated with Microsoft" on the marketing site.

## Nothing is blocked any more

The Apple and Microsoft queues are both cleared. Every remaining item is work, not waiting.

Deliberately deferred, not blocked:
- Alternate icon picker, iOS 18 icon variants — behind the entitlement work
- PIM activation — behind real-tenant verification and the entitlement backend

## Recommended next session

Tier 1 in one pass, then Tier 2. Tier 1 closes a genuine security gap and two things I
flagged and left undone; Tier 2 tells you whether the core actually works. Doing Tier 3
or 4 before Tier 2 means building more on unverified foundations.
