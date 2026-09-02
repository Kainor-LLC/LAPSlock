# LAPSlock — Master TODO

Consolidates the build spec, the implementation checklist, and the business/pricing plan
from the separate planning conversation.

Legend: ✅ done · 🟡 partial · ⬜ not started · 🔵 not-code · ⚠️ needs a decision

---

# For Connor when back — 2026-09-02 autonomous session

Items below either need a decision, a device, or an account only you hold. Everything else
from this session is committed (not pushed) with all three checks green.

## Found during the 2026-09-02 device test
- ✅ **Cross-tenant license state was wrong, fixed on the spot.** `isActivated` meant only
  "a record exists", so activating in one organization and then signing into another showed
  the activated branch with a Refresh button that would have fetched for the wrong tenant and
  no way to activate the one on screen. `EntitlementManager.isBoundToAnotherTenant` now makes
  the distinction and Settings gains a third branch: "Free here" plus "Activate for this
  organization". `msp` is exempt. Six tests, suite at 199.
- ✅ **Activate now names the organization it will license.** Found by asking what an MSP
  would experience: nothing on the button said which tenant it bound to, so an MSP who
  installed the app, signed into a customer first, and tapped Activate would silently
  license the wrong organization. The button reads "Activate license for contoso.com", from
  the UPN domain rather than the tenant GUID, which an administrator recognises instantly.
  Both footers now also say that an MSP should activate against their own organization,
  because an MSP license travels and needs no re-activation.
- ✅ **Automatic activation on tenant switch: considered and REJECTED**, recorded in the
  contract at §7.1. It violates §7.2 by making sign-in reach the network, but the deciding
  argument is worse than the rule: for an MSP it would send Kainor the identifier of every
  customer tenant they sign into, building a list of that MSP's customers. Not ours to have.
  The MSP tier already solves it by binding one license to the MSP's own tenant.
- ✅ **There was no way to sign out. Fixed 2026-09-02.** `signOut()` existed on the root
  model and was reachable only from an error-recovery path, so no button anywhere ended a
  session. For a tool that reveals administrator passwords that is not a missing
  convenience: you could not hand the phone back, and an MSP could not change tenants
  without force-quitting. Settings now has a destructive Sign out in live mode and Leave
  demo in demo, both calling the same method, which already handled either state. The
  license is deliberately kept — it is tenant-bound and re-verified, so returning to the
  same organization keeps it and a different one shows "Free here".
- ⬜ **Device rows show the UPN because Intune returns no `userDisplayName`.** Not a code
  bug: `userDisplayName` is in the `$select` and is decoded, and `primaryUserLabel` prefers
  it. The Kainor tenant simply returns it empty, which is common depending on how the
  primary user was assigned. **This is the 🟡 "per-device enrichment" item**, and it costs a
  Graph call per device or a directory lookup per user, which is why it was deferred. Decide
  whether display names are worth that.
- ⬜ **`broker=yes` means the broker ANSWERED, not that it was opened.** Observed on device:
  launching Authenticator and abandoning it reported `broker=no`, because
  `MSALBrokerVersionKey` is only set on a broker response. Defensible, but it could mislead
  during exactly the diagnosis the flag exists for. Consider a three-state value, or rename
  it to `broker-responded`.
- ⬜ **Settings is unreachable while signed out.** Found on device: after a failed sign-in
  the only route to the diagnostics report is via demo mode. `rotationSection` and
  `macOSSection` are not conditional, so this is not a matter of passing nils — the sections
  need gating before a signed-out Settings can exist. Small, worth doing.
- ✅ **Accent color fixed 2026-09-02, and measuring it changed the answer.** Steel `#4A6E96`
  from the mark was the obvious replacement for the orange and **it fails**: 2.97:1 against
  the navy credential card, below WCAG's 3.0 floor for a UI component, and that card is where
  the countdown ring and reveal timer live. Lifting steel enough for the card takes it to
  3.09:1 on white. No single value serves both surfaces; orange only appeared to because it
  is unusually forgiving.

  So the accent is now two tokens, both steel. `Brand.accent` is **adaptive** — steel as
  drawn in light appearance, lifted `#6E96C2` in dark — for buttons, tints, list rows and
  banners, which follow the system appearance. `Brand.accentOnField` is the lifted value
  fixed, for the credential card, which is navy in both appearances. All 12 call sites
  migrated; the compiler enforced it because the old token was removed rather than
  deprecated.

  Also: `pitWall` became `field` and took the icon's actual navy `#16233A` rather than the
  near-miss `#131E2E`, and the palette now stores **hex** instead of fractional component
  triples. That last one matters more than it sounds — fractional triples cannot be compared
  by eye against `design/icons/README.md`, which is part of how the accent drifted out of the
  identity without anyone noticing. The icon README now documents the derivation and the
  contrast floor.

  **Worth an eyeball on device in both appearances**, since it is 12 call sites of colour I
  cannot see. The reveal card and the countdown ring are the ones to look at.
- ~~⬜ The app's accent color is not in the icon.~~ `Brand.signal` safety orange `#D9480F`
  tints every action, the Face ID glyph and the countdown ring, but the shipping mark is
  navy `#16233A`, steel `#4A6E96` and cap `#EEF3F8` with no orange anywhere. `Brand.pitWall`
  `#131E2E` is also a near-miss against the icon navy. The palette and its names (`pitWall`,
  `signal`, "pit-lane language") are PitLAPS-era leftovers that the rename swept in code but
  not in identity. **Steel is the obvious replacement since it is already in the mark, but it
  reads calmer than orange on a reveal action, so it is a founder call.** This was never in
  this file, but it should have been noticed from `design/icons/README.md`.

## MSP tier: switcher VERIFIED on device 2026-09-02

Everything testable without a customer tenant now works on hardware. With the license row
temporarily set to `msp`: Settings read Plan MSP, the building icon appeared on the device
list, the picker listed Kainor's own organization with its GUID, and both resolver failure
paths gave their intended messages — an unresolvable domain and a path-traversal attempt.
Flipping the row back to `enterprise` and refreshing made the icon disappear again, which
also exercised the Refresh license path properly for the first time.

**Still unproven, and it needs a customer:** an actual switch into a tenant the account can
reach. That requires a second tenant that has invited the Kainor account, or a GDAP
relationship. The compensations for that are in place — `SwitchFailure` explains all ten
error cases on screen, and `DiagnosticOperation.tenantSwitch` carries the AADSTS code and
correlation ID into the support report.

## Device test PASSED 2026-09-02

Everything built without hardware has now run on a phone.

- **Entitlement, end to end.** Activate returned Enterprise from the live Function, survived
  a force-quit, survived sign-out and back in without re-activating, and Remove returned to
  the metered tier. Signing into a second tenant dropped to free — the tenant binding.
- **Auth diagnostics.** An abandoned Authenticator sign-in produced an MSAL code and, most
  importantly, **no URL and no error text anywhere in the report**.
- **Regressions all clean.** Face ID prompts before the fetch, a cancelled prompt reveals
  nothing and charges nothing, the switcher card reads Hidden, and revealing a BitLocker key
  hides the LAPS password.
- **Copy tenant ID** works. **Sign out** works and the license survives it.

Three bugs were found and fixed during the test, none of which the 262 tests had caught:
cross-tenant license state, no sign-out button anywhere, and the Activate button not naming
the organization it would bind to. Worth remembering the next time a green suite feels like
proof.

## Needs a decision
- **Search only covers loaded pages** (the #3 item in the decided order). This is a design
  call, so I did not touch it. Three shapes, with a recommendation:
  1. *Fetch every page first, then search locally.* Simplest; correct; Graph pages are 1000
     devices, so a 10k-device tenant is ten calls at sign-in. Cost is the initial wait and
     memory on the largest tenants. Search stays instant and diacritic-insensitive as today.
  2. *Server-side `$filter` on `deviceName` / user fields per keystroke.* No wait at
     sign-in, but Intune's `managedDevices` `$filter` support is narrow (startswith on a
     few properties, no `$search`), so it would REGRESS the current matching on display
     name, email and diacritics — the thing that was just fixed.
  3. *Hybrid.* Local search over loaded pages as now, plus paging continues in the
     background after the first page so the working set fills within seconds, with a
     "still loading N of M" indicator until it does. Search results are complete once
     loading finishes and are labelled honestly until then.
  **Recommendation: 3**, with 1 as the fallback if background paging proves awkward. It
  keeps today's matching, removes the phantom-miss without a per-keystroke network call,
  and the indicator turns "search found nothing" into "search is still filling" — the
  actual bug is that the empty state lies.
- **Guideline 3.1.3 stance** — please read `docs/APP-STORE-3-1-3.md` once. It records why
  the Settings license section must never grow a price or a link, and the blocked-reveal
  message must never mention the website. Those are now compliance constraints, not copy.
- **Push timing for `docs/`.** The privacy policy and the transparency doc are committed with
  today's date and name the azurewebsites host. Pushing `docs/` publishes both. They are true
  today, but they describe an Activate button that is not in the shipped app yet.
- **Copy in the license section** — one read from you. It is deliberately a status readout
  with no pitch and no price, same rule as the reveals section.

## Not attempted, and why
- Dark mode audit, state-restoration disable on credential screens, offline detection, and
  per-device enrichment (the four 🟡 items). Each needs either a device with the toggle in
  hand, a change on the credential screen that has bitten this project twice when shipped
  untested, or a Graph design decision. Left for a session with a phone.
- Gating copy, rotation, favourites and app lock behind Pro. Decided policy, mechanical
  gate, but it is the reveal screen and I cannot see it. Recommend: show the control, and on
  free tier route a tap to the same one-line message style the meter uses. Small, worth
  doing with the phone next to you.
- Windows LAPS password history, recents/favourites, biometric app lock, tenant switcher,
  BYO registration UI, PIM: features with design in them.

## Done this session (details in each section)
- Auth diagnostics in the support report (decided-order item 2).
- Contribution policy with issue forms and the PR-closing workflow.
- Privacy manifest; site footer disclaimer; Copy tenant ID in Settings.
- App Store review notes, listing copy, and the 3.1.3 compliance note — all drafts for you.
- Security one-pager.
- Entitlement client half built and tested; `isPro` wired; app compiles.
- Privacy policy updated for the third host and the license record.
- Network transparency doc written and linked from `SECURITY.md`.
- Public roadmap / feedback design captured as a TODO section.

# ⚠️ READ FIRST — three conflicts between the plans (two now resolved)

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
     `msauth.com.kainor.lapslock://auth`. Nothing was listening, so the interactive request
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
- ✅ **Auth diagnostics in the support report — DONE and VERIFIED ON DEVICE 2026-09-02.**
  Abandoning an Authenticator sign-in produced `signIn unknown` with an MSAL code and no URL
  or error text anywhere in the report. The allowlist holds.
  `AuthFailureDetail` (AuthKit) is an allowlist: MSAL error code (Int), `AADSTS` code
  extracted by regex from the description and stored WITHOUT the description, OAuth error
  string by shape, correlation ID by GUID shape, HTTP status, and a broker-path flag from the
  presence of `MSALBrokerVersionKey`. There is no description field and the tests assert a
  hostile description contributes nothing to the report. `MSALAuthManager` reduces the raw
  NSError on the actor via a private `MSALFailure` wrapper so the raw error never leaves the
  file. Sign-in failures are recorded as `DiagnosticEvent`s with the new fields, which
  `DiagnosticEvent` re-sanitizes itself; the export appends the latest failure so silent
  token failures during browsing are covered with one hook. **Device test:** force a broker
  failure (Authenticator installed, wrong tenant) and confirm the report shows codes and no
  URL.

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

- ✅ Device row shows the raw UPN — **fixed 2026-09-02**, `DeviceRow` now uses
  `primaryUserLabel` (display name, then UPN, then email). Build verified; eyeball on device.
  Original note: Now that search matches `userDisplayName` and
  `emailAddress`, a result can match on a field the row never displays, which looks like a
  phantom hit. `ManagedDeviceSummary.primaryUserLabel` exists for this; swap `DeviceRow`
  in `DeviceListView.swift` over to it. (No line number: the file has shifted twice since
  this was written, which is the argument for naming the type instead.)

- ✅ **`LicensingKit` — Keychain-backed reveal meter. DONE 2026-08-29.** Rolling 30-day
  window, 5 free reveals, LAPS and BitLocker sharing one allowance, re-revealing the same
  device inside an hour free. All three open questions resolved:

  1. Checked BEFORE the biometric gate, charged AFTER a successful Graph response. Two
     separate calls so a blocked reveal costs no Face ID prompt and a cancelled or failed
     one costs no credit. Verified on device across six cases including the cancel path.
  2. **Keychain survival across app deletion VERIFIED on device.** The count carries over
     a delete and reinstall. The design assumption holds.
  3. Timestamps, not a counter, so the window genuinely rolls.

  Also: device identifiers are stored as salted SHA-256, because the ledger outlives
  sign-out and tenant switches and a readable list of *which devices had their admin
  password revealed* is reconnaissance. The meter fails open — a Keychain error loses a
  count rather than blocking anybody. Demo mode has its own in-memory meter so a reviewer
  exercises the countdown and the blocked state without burning real credits.
  `isolation-check.sh` now enforces the boundary in both directions and has been verified
  to fail on an injected violation.

- ✅ **Remaining-reveals count in the device list and the detail screen, DONE 2026-08-29.**
  Shown before the tap, as a quiet line that scrolls away with the list rather than a
  pinned banner. Turns orange at zero. Hidden entirely for Pro. The list refreshes from
  the detail view's `onDisappear`, not the list's `onAppear` — a NavigationStack does not
  disappear when a detail is pushed onto it, so `onAppear` there fires once at launch and
  never again.
- ✅ **Read-only allowance section in Settings, DONE 2026-08-29.** Reveals left, and when
  the next one frees up. Deliberately not a sales surface: no upgrade button and no price,
  because this is where a confused customer looks and where support asks them to read
  from. The footer states the privacy claim while it explains the count — the tally is
  local, and no server records what is retrieved or how often.
- ✅ **DEBUG-only reveal meter reset, DONE 2026-08-29.** Inside `#if DEBUG`, not behind a
  runtime flag, so it cannot reach a Release build. Needed because the ledger survives app
  deletion by design, so there was otherwise no way to test metering short of waiting out
  a 30 day window.

- ⬜ Blocked-state copy currently says "Pro removes the limit" with no price. Deliberate:
  App Store pricing is per-storefront and must come from StoreKit at runtime, never a
  hardcoded string. Add the upgrade action once IAP products exist.
- ⬜ `isPro` is hardcoded false with a TODO pointing at `/entitlement`. Everyone is metered
  until entitlement exists, which is the safe direction — nobody is accidentally given Pro.
- ⬜ StoreKit subscription products and free trial (7 or 14 days) configuration
- ⬜ Gate copy-to-clipboard, BitLocker rotation, favourites, and app lock behind Pro
- ⬜ Recents / favorites
- ⬜ Biometric app lock (distinct from the per-reveal gate)
- 🟡 **Tenant switcher — AUTH LAYER DONE 2026-09-02, UI still to build.**

  The §3.3 tenant guard was the obstacle, and it was re-pointed rather than removed. It used
  to compare a returned token's `tid` against the signed-in account's OWN tenant, which is
  right for a single-organization admin and wrong for an MSP. Deleting the comparison would
  have removed the only thing stopping a token for one organization being used against
  another. So the expectation became explicit instead: `TenantPin` in AuthKit holds the
  tenant we deliberately selected, builds the authority URL from it, and refuses any token
  whose `tid` is not that value. **The authority we ASK and the tenant we ACCEPT are now the
  same value**, which is what makes the guard mean anything.

  It lives in AuthKit, not AuthKitMSAL, because AuthKitMSAL is `#if os(iOS)` and MSALResult
  cannot be built on macOS — so the most security-relevant comparison in the auth path was
  previously impossible to unit test. It now has 7 tests, verified to fail on the two
  classic defects: treating a missing `tid` as acceptable, and allowing `common` to be
  pinned.

  `MSALAuthManager.setActiveTenant(_:)` switches tenants and **validates before committing**
  — it acquires a token for the target first and rolls back on failure, so a switch never
  leaves the app pointed at a directory the user cannot read. The active tenant is
  deliberately NOT persisted: a switch lasts one session, and reopening the app returns you
  to your own tenant, because somebody handed an unlocked phone should not find it already
  aimed at a customer's directory. Sign-in and sign-out both reset it.

  `TenantDirectory` resolves a customer domain to a tenant GUID via unauthenticated OIDC
  discovery against `login.microsoftonline.com` — a host already in the transparency doc, so
  **no new network destination and no privacy policy change**. A GUID passes through with no
  round trip. 11 tests, including path-traversal rejection since the domain is interpolated
  into a URL.

  **⚠️ THE SALES-RELEVANT FINDING: app consent is per-tenant.** An MSP cannot self-serve
  their way into a customer tenant. Each customer's Entra administrator must approve
  LAPSlock in their own tenant before a partner account can get a token for it, so expect
  `consentRequired` on first switch. `AdminConsentLink.url(clientId:tenant:)` already builds
  the right link per tenant, so the flow exists — but the MSP onboarding story is "ask each
  customer's admin to click this once", not "add a tenant and go". That has to be said at
  the point of sale.

  **UI BUILT 2026-09-02.** `TenantSwitcherView`, reached from a building icon on the device
  list toolbar that appears **only for the `msp` tier** — passing nil rather than disabling a
  visible control, so a single-organization admin never sees chrome for a feature that does
  not apply. The customer list is `KeychainTenantStore` in AuthKit,
  `WhenUnlockedThisDeviceOnly`, with `TenantList` handling recency ordering, de-duplication
  by tenant ID and a 50-entry cap (7 tests). Switching resets the inventory, and because
  `setActiveTenant` validates before committing there is nothing to clean up on failure.

  **The design rule for that screen, given it cannot be tested here: every failure names what
  happened and what to do next, on screen, with no reference to anything outside it.** The
  first person to exercise it is a paying customer with no support channel. So
  `SwitchFailure` translates all seven `AuthError` cases and all three
  `TenantDirectoryError` cases into a title and an explanation in the user's terms — and the
  consent case, which is the one an MSP cannot self-serve, gets a full explanation plus a
  ShareLink and an open-in-Safari for the per-tenant approval URL. `tenantMismatch` says
  explicitly that a safety check refused a wrong-organization token and nothing changed,
  because otherwise it reads as a bug.

  The saved-list footer says the list never leaves the device. That is the client-side half
  of §7.1 and worth keeping honest.

  ✅ **Tenant banner added 2026-09-02.** `TenantBanner` sits at the top of the device list in
  the live path, always, not only when switched. Quiet secondary text for your own
  organization; the orange warning treatment and "Working in contoso.com" when away from
  home. Absence of a banner is easy to miss, a differently coloured one is not — and for a
  credential tool, "whose directory am I looking at" is the question to answer before a
  reveal, not after.

  ✅ **Tenant-switch failures now reach the support report.** `DiagnosticOperation.tenantSwitch`,
  carrying the AADSTS code, correlation ID and broker flag through the same allowlist as
  sign-in failures. This is the compensation for a feature the vendor cannot test: the
  on-screen `SwitchFailure` explanation handles the common cases, and when it does not, the
  report carries what Microsoft support actually needs. **The target tenant is deliberately
  NOT recorded** — it identifies one of the MSP's customers and a support report is a thing
  people email; the correlation ID lets Microsoft find the request, tenant included, without
  a customer's directory ID landing in Kainor's inbox.

  **Still to build:** switching does not yet destroy a credential already on screen. In practice the
  switcher is reached from the list rather than the detail view, so the case may be
  unreachable, but "may be unreachable" is not the standard this project holds for credential
  lifetime — verify or handle it.

  **⚠️ CANNOT BE FULLY TESTED HERE, and manufacturing a test tenant was investigated and
  abandoned 2026-09-02.** Every route costs something that a single test does not justify:

  * *Microsoft 365 Developer Program* — no longer eligible; it now requires a Visual Studio
    subscription.
  * *A plain workforce tenant* — the Azure portal no longer offers one. The choices are
    **governed workforce** or **external**, and legacy has been retired from that flow.
  * *Governed workforce* — creation is free and the governed tenant needs no licenses, but
    **cross-tenant delegated administration requires Entra P1, P2 or ID Governance**, which
    the Kainor tenant does not have (Entra ID Free comes with a pay-as-you-go subscription).
    Worth attempting, since creation may succeed with the governance relationship simply
    inert, giving a usable second directory. **Abort if it asks to buy or trial a license.**
  * *External* — wrong product. Entra External ID is a CIAM directory for customer-facing
    apps, not an organization.
  * *An M365 Business trial* — creates a tenant, but auto-renews and risks a bill, which is
    not a trade worth making for one test.

  **So the first real test of an MSP tenant switch is a customer, and that was the design
  assumption rather than a surprise.** It is why `SwitchFailure` explains all ten error cases
  on screen and why `DiagnosticOperation.tenantSwitch` carries the AADSTS code and
  correlation ID into the support report. If an early MSP prospect appears, ask them to
  invite the Kainor account as a guest in a sandbox of theirs — that is a ten-minute favour
  and it closes this gap properly.

  Original note: Guest/B2B needs a second tenant that has invited the
  Kainor account; GDAP needs a real partner relationship. The auth layer is unit tested and
  the guard is covered, but the end-to-end MSP path needs a customer tenant to prove.

- ~~⚠️ Tenant switcher — reclassified 2026-09-02 from a convenience to a PREREQUISITE for
  selling the MSP tier.** Verified in `MSALAuthManager`: tokens are only ever requested for
  `account.tenantId`, the signed-in account's own home tenant. There is no code path to any
  other tenant. That means the three ways MSPs actually reach customer tenants divide
  sharply:
  * **A dedicated admin account in each customer tenant** (`admin@customer.com`) — works
    today. The account's home tenant IS the customer tenant, so signing out and back in with
    the other account just works, and an `msp` license travels because that tier is exempt
    from the signed-in-tenant check.
  * **Guest / B2B**, where `tech@msp.com` is invited into the customer tenant — **does not
    work.** The ID token's `tid` is the MSP's own tenant, so the app lists the MSP's devices
    and there is no way to reach the customer's.
  * **GDAP / Partner Center delegated admin** — **does not work**, same reason.

  Microsoft pushed partners off legacy DAP onto GDAP, so the second and third cases are
  probably where most MSPs live. **Selling MSP org at $999/yr before this exists would mean
  selling a tier the app cannot serve for most buyers.** Either build the switcher before
  offering the MSP tiers, or scope the MSP pricing explicitly to the dedicated-account model
  and say so at the point of sale.

  Note this was only reachable at all once Sign out existed (same day) — before that an MSP
  could not change accounts without force-quitting.
- ✅ "Copy your tenant ID" — Settings → About, live mode only, 2026-09-02. Plain pasteboard,
  deliberately not the expiring credential one: a tenant ID is public.
- ⬜ BYO app registration UI (the config seam already exists)
- ⬜ Entitlement check: call `/entitlement`, cache signed JWT, 14–30 day offline grace
- ⬜ **App Attest gating** on `/entitlement` — **phase 2, and NOT "the real anti-sideload
  teeth" as this line used to claim.** Against a source-available app there are no teeth,
  only friction: App Attest proves a request came from *your* bundle ID, and anyone
  building from the public source has their own. See "Why App Attest is phase 2, not v1"
  in the Backend section for the full cost/benefit.

## App icon

- ✅ **Shipping icon, 2026-08-29** — a keyhole inside a photoreal tire tread ring, navy
  field. Comes from `design/icons/texturize-icon.py` (`SHIP_BASE` / `SHIP_LIGHT` there are
  authoritative), which imports geometry from `render-icon.py` and adds the print
  treatment. `render-icon.py` no longer emits shipping assets — it used to, and running it
  silently overwrote the icon with the earlier keycap.

  Full reasoning, palette, and the tread patterns that FAILED (poker chip, camera shutter,
  recycle glyph, and sparse blocks turning to noise below 87px) are in
  `design/icons/README.md`.

- ⬜ **Alternate icon picker** — deferred, and the premise changed. The orange asset this
  item assumed no longer exists: `AppIcon-J4-orange-1024.png` was deleted in the rename,
  and the new mark has no orange variant. Reviving this means designing a second variant
  first, which is a design decision, not a 45-minute wiring job.

  If it is ever built, two things learned earlier still hold: iOS shows an unsuppressable
  system alert on every icon change, so it is two taps for a preference set once; and icon
  variants cannot appear in App Store screenshots, so nobody discovers the feature unless
  they open Settings. Low priority for an audience that opens Settings once and rarely
  again.

- ⬜ **Hand-authored dark and tinted icon variants.** iOS derives them automatically today,
  which is acceptable. Note that `texturize-icon.py` already emits Icon Composer layers
  (background / tread / keyhole) for Liquid Glass, and **nothing consumes them yet** — the
  shipping icon is still a flat 1024. That is the real open thread here: the layers exist
  without an `.icon` file.

## Loose ends from the build spec

- 🟡 **Dark mode audit** — semantic colors adapt, but the reveal card's hardcoded navy
  needs verifying. You named this explicitly; it's cheap and worth doing with the toggle.
- 🟡 State-restoration disable on credential screens (real §6 gap)
- 🟡 Network-offline detection (currently folds into a generic transport error)
- 🟡 Per-device enrichment for fields that are null in list responses

---

# ✅ Settings screen — BUILT. Retained for the reasoning, not as work.

All three toggles ship, plus two sections added later: a read-only free-tier allowance
readout and a DEBUG-only reveal-meter reset. See `SettingsView.swift`.

## ✅ Design note: not on the main page — settled

The original ask was "toggles on the main page." They live behind a **gear icon in the
device list toolbar → Settings sheet** instead. The device list's job is
find-a-device-fast; toggles on that surface compete with the search field and get tapped by
accident. One tap away is the right distance for settings changed rarely.

## ✅ Toggle 1 — BitLocker key rotation (requests write access)

Your instinct is exactly right, and the honest labeling is the valuable part. Proposed copy:

> **Allow BitLocker key rotation**
> Off by default. Turning this on asks Microsoft Entra ID for permission to **modify**
> devices in your tenant (`DeviceManagementManagedDevices.ReadWrite.All`), not just read
> them. Your administrator may need to approve it. Rotation is queued and applies the next
> time the device checks in with Intune.

Two things this buys you: customers who don't want it **never see a write permission on
their consent screen**, which is a real selling point — and it's a natural paid-feature
line, matching how your competitor gates password reset behind its paid tier.

## ✅ Toggle 2 — Appearance

Make it **three-way (System / Light / Dark), defaulting to System.** That's the iOS
convention, and a two-way toggle forces a choice the OS already made correctly for most
people. Cheap to build once the dark-mode audit above is done.

## ✅ Toggle 3 — macOS support

Small improvement on your idea: **don't hide it — show it disabled with the reason.** A
hidden toggle is dead code nobody remembers, and an admin wondering "why can't I see Mac
passwords?" gets silence. Instead:

> **macOS local admin passwords** *(unavailable)*
> Microsoft doesn't currently offer an API for reading macOS local administrator
> passwords. Intune keeps them encrypted on its own service, and only the admin center can
> display them. LAPSlock will enable this automatically if Microsoft ships an API.

That turns an absence into an answer, and it's honest about whose limitation it is. The
provider already reports this; the toggle just surfaces it.

---

# ✅ Pricing — metered reveals, decided 2026-08-27

Supersedes the earlier pricing plan. The reframe behind it: "free gets traction" is a
consumer-app belief that does not transfer. No network effects, no ad revenue, no viral
loop, and the buyer already pays for Intune. **Price is not the adoption friction, trust
is.** For this category specifically, free is mildly suspicious — a free app that reads
every local admin password in a tenant invites "so how are you making money?" A modest
price answers that cleanly. The price tag is a trust signal.

**The free tier is for evaluation, not traction.** Nobody buys a credential tool without
testing it against their own tenant. So reveal must be free, because reveal is the thing
being verified — an admin needs to search a device, reveal a password, and watch the read
appear in their own Entra audit log. Gate convenience instead.

## The model

**Free, forever:**
- Unlimited device search, browse, detail
- Rotation dates and expiry
- BitLocker key *metadata* (which volumes have keys, when they were backed up)
- **5 credential reveals per rolling 30 days**, LAPS and BitLocker combined
- Copy tenant ID

**Pro:** unlimited reveals, copy to clipboard, BitLocker rotation, recents/favourites,
biometric app lock, tenant switching.

**Why five.** Evaluation takes roughly three reveals, so someone proving it works never
hits the wall, and someone doing real work hits it in week one. It also keeps the app
installed for the light user who needs it twice a month — that person was never going to
pay and is worth more as a recommender than as a blocked user who deletes it.

**Pair with a StoreKit free trial** (7 or 14 days, platform-level, no custom code). Trial
gives depth, the meter is the permanent floor. Do both.

## The architectural decision that matters most: count locally

**Never count reveals on the server.** Server-side counting is the obvious implementation
and it would quietly destroy the best claim the product has: a server counter means learning
how often each tenant retrieves passwords, which is usage telemetry, and the published
privacy policy says none is collected. "We count your reveals" is a worse sentence than
anything unbeatable enforcement buys.

Count in the **Keychain**, not `UserDefaults`, so a reinstall does not reset the meter. A
device wipe or a new phone does, and that is acceptable. State it plainly in the code
comments: **this is a nudge, not DRM.** Someone willing to wipe their phone monthly to dodge
$20 was never a customer, and chasing them costs the privacy claim that wins enterprise
deals.

## Prices

| Tier | Price | Notes |
|---|---|---|
| Free | $0 | 5 reveals / 30 days |
| Individual Pro (IAP) | $1.99/mo or $19.99/yr | |
| MSP Pro (IAP, per technician) | $49.99/yr | adds tenant switching |
| Enterprise (direct, tenant-keyed) | $299/yr ≤500 devices · $599/yr unlimited | |
| MSP org (direct) | $999/yr | ⚠️ see below |

$299 and $599 sit deliberately below the procurement line. Above roughly $1,000 an
enterprise purchase triggers vendor onboarding, security questionnaires, and a PO. Below it,
a manager expenses it. Staying under that line is worth more than the extra revenue.

- ⚠️ **MSP org at $999 crosses back over that line.** Either drop to $899 to stay under, or
  accept that MSPs are less bureaucratic about it. Founder's call, still open.
- ✅ Apple Small Business Program — enrolled, 15% commission on IAP

## Two UX rules

**Never surprise someone at the machine.** Show remaining reveals in the device list and on
the detail screen *before* they tap. Discovering you are blocked while standing at a broken
workstation generates one-star reviews and permanent ill will.

**Ask once, then stop.** At zero, one clear message with the price. Not a nag on every
screen. This audience is unusually allergic to being sold to.

## ✅ Three things to resolve before building the meter — ALL RESOLVED 2026-08-29

Kept because the reasoning still applies to any future change to the reveal path. Outcomes:
(1) implemented as described, verified on device including the cancelled-prompt case;
(2) **Keychain survival across app deletion VERIFIED on hardware** — the count carries over
a delete and reinstall; (3) timestamps, as described.

1. **Check the meter BEFORE the biometric gate, not after.** The decisions doc says "after
   the biometric gate, before the Graph call". That ordering makes a blocked user complete
   Face ID and *then* get told they are out of reveals, which is exactly the
   surprise-at-the-machine failure the UX rules exist to prevent. Checking and decrementing
   are separable: **check** before the gate so a blocked reveal fails fast with no prompt,
   and **decrement** only after a successful Graph response, so an abandoned or failed
   reveal does not burn a credit either. Strictly better on both counts.
2. **Verify Keychain survival across app deletion ON DEVICE.** Keychain items persisting
   after uninstall is long-standing iOS behaviour but it is not a documented guarantee, and
   Apple has changed it before (briefly in an iOS 10.3 beta, then reverted). The entire
   anti-reset property of the meter rests on it. Four device-only assumptions have already
   shipped broken in this project — do not make this the fifth. Also confirm the interaction
   with `ThisDeviceOnly` accessibility, which the MSAL cache already uses.
3. **A rolling 30-day window needs timestamps, not a counter.** Store the last five reveal
   timestamps and expire them individually. Note that device clock changes can reset the
   window; consistent with "nudge, not DRM", so worth one line of comment and no code.

---

# Backend (Azure)

## ✅ Infrastructure provisioned 2026-08-27, rebuilt under LAPSlock names 2026-08-28

Subscription `024f01b2-f4b2-459f-84b6-cf7ced419758`, pay-as-you-go, spending limit OFF (so
credit exhaustion starts billing rather than deprovisioning resources), Kainor tenant,
region `centralus`. **Select it by ID, never by name** — see the handoff for why the names
in this repo were wrong until 2026-09-01.

**Subscription cleanup, 2026-09-01.** The live subscription was still named `Kainor-PitLAPS`
and was renamed to `Kainor-LAPSlock`. The two unused subscriptions, both verified empty,
were cancelled: `19dd2b0e` (free trial) and `797ffeb5` (`PitLAPS`). Cancelled subscriptions
remain visible for roughly 30 to 90 days before Azure removes them and can be restored with
`az account subscription enable` inside that window, so their continued appearance in an
`az login` list is expected. The soft-deleted `kainor-pitlaps-prod-kv` was unaffected — it
lives in the live subscription, purge date 2026-11-27.

| Resource | Name | Notes |
|---|---|---|
| Resource group | `kainor-lapslock-prod-rg` | centralus |
| Storage | `kainorlapslockprodst` | Standard_LRS, TLS 1.2 min, no public blob access, HTTPS only |
| Key Vault | `kainor-lapslock-prod-kv` | RBAC authorization, purge protection ON, 90-day retention |
| Function app | `kainor-lapslock-prod-func` | Flex Consumption, .NET 10 isolated, Linux, httpsOnly true |
| App Insights | `kainor-lapslock-prod-func` | auto-created, name matches the function app |
| Managed identity | `e4c41c72-583a-4941-b822-73628fbba6df` | system-assigned |
| Role assignment | Key Vault Crypto User | scoped to the vault ONLY |

Decisions worth not relitigating:

- **Flex Consumption, not Consumption.** Consumption is now documented as a legacy plan and
  Flex is the recommended serverless option. Flex does not support the C# in-process model,
  which is fine since in-process reaches end of support 2026-11-10 anyway.
- **Purge protection is ON and cannot be turned off.** Deliberate: losing the signing key
  invalidates every entitlement JWT in the field at once, with no recovery except reissuing
  to every customer.
- **Crypto User, not Crypto Officer,** for the app identity. It can sign and verify with an
  existing key but cannot create, delete, import, or export one. A compromise of the
  Function lets an attacker mint tokens while they hold access; it does not let them
  exfiltrate the key and mint forever.
- **Sign through Key Vault rather than holding key material in the app.** Costs a round trip
  per issued JWT, irrelevant at a few requests per install per month.
- **`httpsOnly` is false on creation** for Flex Consumption and must be set explicitly.
  Seen on both the PitLAPS and LAPSlock function apps, so it is the default, not a fluke.
  Always verify it after `az functionapp create`.
- **Rebuilt under LAPSlock names on 2026-08-28.** Nothing had been deployed, so recreating
  was cheaper than renaming, and the old group was deleted. Its vault lingers as a
  soft-deleted entry for 90 days: purge protection cannot be waived, which is the whole
  point of enabling it.

CLI gotcha: `az functionapp show` nests everything under `properties`, while
`az functionapp list` flattens it. A `--query` written for one silently returns nulls
against the other, and `--output table` hides null columns rather than showing them empty.
Use `--output json` when verifying.

## ✅ API contract written 2026-09-01 — `docs/ENTITLEMENT-API.md`

Version 1, frozen for implementation. Published in the public repo; the Function stays
private. **Read it before writing any Function code** — it is normative for both halves,
and §7 is normative for the client, not advisory.

Everything previously decided survived unchanged: tid and nothing else in the request,
`attestation`/`assertion` reserved, ES256 signed through Key Vault, public key embedded,
claims `iss`/`aud`/`sub`/`tier`/`iat`/`nbf`/`exp`/`jti`, 30-day lifetime.

Decided *by* the contract, because the implementation needed an answer:

- **A free-tier install never contacts the endpoint.** The call happens on Activate
  license, on the refresh schedule afterwards, and on a manual refresh. Nothing else. The
  alternative — every install checking in on launch — would build a list of every tenant
  running the app, and that list has no use worth the explaining it would cost. Reversible
  without a version bump if it turns out to generate support tickets.
- **Hard prohibitions on when the client may call**, so request timing never becomes usage
  telemetry: never on a reveal, a search, a device open, a launch, or as part of sign-in.
- **Always `200` with a signed token, `tier: free` for unlicensed tenants.** No 404, so the
  endpoint is not an oracle for who is paying.
- **Unrecognized tier → free.** Fail to metered, never to unlocked.
- `isPro = storeKitEntitlementActive || verifiedTier != .free`. IAP tiers never touch this
  endpoint; it exists for the tenant-keyed direct sales.
- **7-day offline grace past `exp`**, network-failure only, taking worst-case revocation lag
  to 37 days. Buys a week in a datacenter with no signal.
- **`msp` tokens are bound to the activating tenant, not the signed-in one.** An MSP signs
  into customer tenants; the strict binding would revoke their license for doing their job.
  The one deliberate loosening, on the tier that is honour-system on seats anyway.
- **Keyring of `kid` → public key compiled into the app; the client never fetches a key.**
  A JWKS document is for auditors and hand-verification only. Rotation is a three-release
  dance and emergency rotation is honestly documented as slow.
- **No seat or device count in the token**, ever. Enforcing the ≤500-device tier would mean
  the app reporting a device count to a Kainor server. Contract and invoice, not telemetry.
- Client lives in `LicensingKit` — Foundation + CryptoKit + Security already covers
  URLSession and ES256 verification, so no new dependency and neither isolation boundary
  moves.

## Remaining

- ✅ **ES256 signing key created 2026-09-02.** `lapslock-ent-2026-09` in
  `kainor-lapslock-prod-kv`, in-vault, `exportable: false`, sign and verify ops only.
  Public key published at `docs/entitlement-jwks.json`, point verified against the P-256
  curve equation. Vault version `ec4ca7dc7a284a19865eb9ea3a3806ec` — **pin it in Function
  config**, since a new version would otherwise take over signing while `kid` stayed the
  same and break every client in the field.
- ✅ Key Vault Crypto Officer removed from the human account 2026-09-02. The vault has
  exactly one assignment: the Function identity as Crypto User.
- ✅ **Licenses table created 2026-09-02.** `licenses` in `kainorlapslockprodst`. Named with
  the American spelling to match `LICENSE`, `SECURITY.md`, the privacy policy, the terms, and
  the entitlement contract — Kainor LLC is a US company and every public-facing document
  already reads that way. It was first created as `licences`, then recreated while empty,
  because Azure tables cannot be renamed and doing it after the first customer row would
  have been a migration. The published terms page at `docs/terms/index.html` still uses
  British `licence` in seven places; that is live legal text and belongs to the attorney
  pass, not to a spelling sweep.
  PartitionKey is the lowercase tenant GUID, RowKey is `current` (leaving room for dated
  history rows later without changing the lookup), plus `Tier`, `TermStart`, `TermEnd`,
  `OrderRef`. **No purchaser name or email** — the order reference resolves to those in
  Stripe, which holds them as a billing record anyway, so no personal data lands in Azure.
  A row exists only for a PAYING tenant.
- ✅ **Table roles granted 2026-09-02, scoped to the TABLE and not the storage account.**
  Recreated at the `licenses` scope during the rename, and the two assignments orphaned on
  the deleted `licences` path were removed. **Azure keeps role assignments that point at
  deleted resources.** They do not error and they do not clean themselves up, so they sit in
  an access review looking legitimate and would silently take effect again if anything ever
  recreated a table by that name. Check for orphans after deleting any scoped resource.
  The human account has Storage Table Data Contributor, for inserting license rows by hand
  until Stripe exists. The Function identity has **Storage Table Data Reader** — read-only,
  because the entitlement endpoint never writes a license row. A compromise of the Function
  can see who holds a license; it cannot grant one. Same reasoning as Crypto User over
  Crypto Officer. **When the Stripe webhook needs write, grant it separately and ideally to
  a separate identity**, so the read path and the write path never share a credential.
- ⚠️ **The storage account key is in the Function app settings.** `AzureWebJobsStorage` and
  `DEPLOYMENT_STORAGE_CONNECTION_STRING` are both connection strings containing an account
  key, which grants full read/write over the whole storage account — **including the
  licenses table**, bypassing the carefully scoped Reader role above. Inconsistent with
  giving the identity Crypto User so it can sign but not exfiltrate the signing key. Fix is
  identity-based storage (`AzureWebJobsStorage__accountName` plus blob roles; Flex
  Consumption supports identity-based deployment storage). **Do it as its own deliberate
  step before go-live, never alongside new Function code** — getting `AzureWebJobsStorage`
  wrong stops the app starting, and debugging that at the same time as new code is how a
  bad evening happens.
- ✅ **Cost guards set 2026-09-02. The bill is now bounded by configuration, not by trust.**

  | Guard | Value | Why that number |
  |---|---|---|
  | Log Analytics daily ingestion cap | **0.1 GB/day** | 0.1 x 31 = 3.1 GB/month, which sits UNDER the 5 GB/month free grant. The ingestion ceiling is therefore effectively zero, not merely small. Resets 14:00 UTC. |
  | `maximumInstanceCount` | **20**, was 100 | The endpoint is anonymous by design, so a flood is possible. Rate limiting bounds the logic; this bounds the money. 20 is still far more than this workload can consume. |
  | `alwaysReady` | **[]** — already zero | Always-ready instances stay provisioned and are billed continuously whether or not a request arrives. For a background call made monthly, paying to avoid a cold start is pure waste. |
  | Subscription budget | **$10/month**, `lapslock-monthly-guard` | Alerts to connor@kainor.com at 50% actual, 90% actual, and 100% forecast. Expected spend is under $2, so 50% fires around $5 — early, and a false alarm is the point. |
  | Cap-reached alert | `lapslock-ingestion-cap-hit` | **The cap makes the budget alert silent.** If something floods the logs, the cap holds the bill near zero, so the $10 budget never fires and nothing tells you anything is wrong. This rule is the only signal. Queries `_LogOperation` for `OverQuota` once a day and emails the `lapslock-alerts` action group. Stateless (`autoMitigate` false), because hitting a cap is an event rather than a condition that clears — and Azure refuses a stateful rule at frequencies above 12 hours anyway. |

  A log alert rule is itself billed per rule per evaluation interval. Daily is the cheapest
  tier, which is why it is daily; the exact rate was not verifiable from the pricing page.
  Tightening it to hourly costs more and buys little before there are customers.

  **The `Ingestion Volume` workspace metric was considered and rejected.** A metric alert
  would be cheaper and would warn on the way up rather than after the fact, but the metric
  reports unit `Count` with only `Count` aggregation, which cannot be interpreted confidently
  as bytes. A cost guard built on a threshold nobody can explain is worse than none.

  The daily cap trades telemetry for money: when it is hit, ingestion stops until the reset.
  That is the intended direction — fail to no-data rather than to a bill.

  Still to do on App Insights before the Function goes live: failures and platform metrics
  only, and confirm request/response body collection stays off. The cap bounds the cost; it
  does not stop a body containing a tenant ID being written, which section 8.2 forbids.
- ✅ Rate limiting per §8.3 shipped in the Function 2026-09-02: source IP plus an HMAC of
  the tid under a per-process random key, in memory, absolute expiry inside the window,
  nothing persisted. Per-instance and therefore approximate, which is documented.
- ✅ **Function written, tested and deployed 2026-09-02.** Live at
  `https://kainor-lapslock-prod-func.azurewebsites.net/entitlement`, .NET 10 isolated, 69
  tests verified to fail on injected defects. A live token verifies against the published
  JWKS and a tampered payload fails, so the chain is proven rather than assumed.
- ✅ **Pre-live hardening done 2026-09-02.** No app setting is secret-shaped: storage moved
  to `AzureWebJobsStorage__accountName` with SystemAssignedIdentity deployment auth, so the
  account key that granted blob AND table read/write over the whole account — quietly
  defeating the scoped read-only table role — is gone. Logging down to Warning with
  `Host.Results` at Error. App Insights retention 30 days. FTP disabled. TLS 1.2.
- ✅ **Client half built and VERIFIED ON DEVICE 2026-09-02.** Activate against the live
  endpoint returned Enterprise, it survived a force-quit and a sign-out/sign-in cycle, and
  Remove returned to the metered tier. Signing into a second tenant correctly dropped to
  free, which is the tenant binding working. `EntitlementClient`,
  `EntitlementStore` (Keychain, AfterFirstUnlockThisDeviceOnly), `EntitlementManager`
  (every section 7 rule), all in `LicensingKit`, which still imports Foundation + CryptoKit +
  Security only. 45 new tests, suite at 183, both the verifier and the manager verified to
  fail on injected defects. `isPro` is wired in `LAPSlockApp.swift`; Settings has an
  Organization license section with Activate, Refresh and Remove; the app target compiles.
  **What only a phone can verify:** Activate against the live endpoint with Kainor's own
  license row, the Settings row reading Enterprise, Remove returning to free, and that a fresh
  install shows no Kainor host in a proxy capture. Note `isPro` today lifts only the
  meter — gating copy, rotation, favourites and app lock behind it is a separate item.
- ✅ **Privacy policy updated 2026-09-02** — two hosts always, a third only after a license
  is activated, plus a license-token row in the storage table and a section on what Kainor
  keeps for a paying organization. The wording is true both before and after the client
  ships. **Pushing `docs/` publishes it with the new effective date**, so push it alongside
  the app release rather than ahead of it.
- ✅ Client half built 2026-09-02 — see the entry above.
- ⚠️ **Privacy policy says "exactly two hosts" and must say three in the same release that
  ships activation.** `docs/privacy/index.html`, "Network connections". The wording should
  keep the distinction the contract makes: two hosts always, a third only after a license is
  activated. Shipping the endpoint without this makes a published policy false.
- ⬜ App Attest verification — **phase 2, deliberately.** See the reasoning below.
- ⬜ Later: `/stripe-webhook` to auto-insert license rows
- ⬜ Custom domain for the API (~$10–15/yr; expect <$2/mo Azure spend). Note that App Service
  managed certificates may not be available on Flex Consumption — verify before committing
  to an approach.
- ✅ **Private repo created 2026-09-02: `Kainor-LLC/LAPSlock-backend`**, verified private.
  Scaffolded with a README that names the public contract as authoritative, a `.gitignore`
  leading with `local.settings.json`, and its own `pre-push-scan.sh` tuned to what this repo
  can leak — storage keys and connection strings, Stripe live and webhook secrets, JWTs, a
  tracked `local.settings.json`, and files whose names suggest a customer data export.
  Verified to FAIL on injected violations, not merely to pass. No Function code yet.

## Why App Attest is phase 2, not v1

The TODO previously called it "the real anti-sideload teeth." Against a source-available
app there are no teeth, only friction, and it should not gate the revenue path shipping.

It proves a request came from an unmodified build of *your* bundle ID under *your* team ID
on genuine Apple hardware. It does not stop someone building from the public source with the
check removed, because that is their bundle ID.

Cost: CBOR decoding, X.509 chain validation to Apple's App Attest root, nonce handling,
`rpId` hash checks, per-install public key storage, and a monotonic counter per key for
replay protection — a few hundred lines of security-critical code where a subtle error means
you believe you are verifying something you are not. Client side it needs key generation,
keychain persistence, and a re-attestation path after reinstall or restore. **It does not
exist in the simulator**, so it would be yet another device-only path, and four of those
shipped broken in this project already.

The failure mode that costs money: attestation fails at first launch on a captive portal or
during an Apple service blip, and a paying customer sees "unlicensed". So you write a
soft-fail path, and a soft-fail path is a bypass.

Who is actually buying: enterprises at $299–999/yr with compliance obligations, and
individuals at $1.99/mo. Neither pirates at scale. The genuinely abusable tier is MSP
per-tech pricing, where the risk is seat undercounting — which App Attest does nothing about.
That is an audit and contract problem.

Cheaper interim measures worth doing instead: rate-limit per tenant ID, and count entitlement
requests per `tid` so anomalies surface. Revisit if that data shows abuse.

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
- ✅ "Not affiliated with Microsoft" disclaimer — in Settings, both legal pages, and as of
  2026-09-02 the marketing site footer, with the Microsoft trademark line.
  still needed on the marketing site
- ✅ **One-page security/data-handling doc written 2026-09-02** — `docs/SECURITY-ONE-PAGER.md`.
  For the approver, not the engineer: auth model, the storage table, what Kainor receives on
  each tier, transport, and a carefully worded regulatory paragraph that says plainly there
  is no SOC 2 / ISO 27001 and why the controls are in published source instead.
- ⬜ Enterprise license agreement draft (attorney pass before the first real deal)
- ⬜ W-9 PDF ready
- ⬜ Trademark filing — USPTO, Class 9, ~$350 (verify current fee). Owner = the LLC,
  intent-to-use basis, pick goods wording from the ID Manual to avoid the custom-text
  surcharge.
- ✅ **License decision** — PolyForm Strict + security-review permission
- 🔵 Attorney review of the additional-permission wording

---

# App Store & launch

- ⬜ Free app + IAP subscription products in App Store Connect, plus a 7 or 14 day StoreKit
  free trial. Free tier is metered (5 reveals / 30 days), not feature-crippled — see Pricing.
- 🟡 **Review notes drafted 2026-09-02** — `docs/APP-STORE-REVIEW-NOTES.md`, for your
  approval. Covers demo mode, the meter as designed behavior, Activate-is-not-a-purchase,
  Data Not Collected with the proxy link, Face ID before fetch, switcher behavior. **Flags a
  gap:** a reviewer cannot exercise Pro features until IAP exists (sandbox) — your call
  whether to accept that on first submission or add a compiled-out reviewer path.
- ✅ Paid Apps agreement — accepted, bank and tax details in place
- ✅ Org purchasing on the website only, never linked in-app — **3.1.3 text verified
  2026-09-02**, see `docs/APP-STORE-3-1-3.md`. The constraint that matters: the app must not
  directly or indirectly steer iOS users to a non-IAP purchase. Activate sells nothing, the
  blocked-reveal message offers only the IAP path, and Copy tenant ID stays a plain utility.
- ✅ 3.1.3(c) Enterprise Services documentation — `docs/APP-STORE-3-1-3.md`, 2026-09-02.
  The pricing table mapped onto the guideline, what the app must keep doing to stay inside
  the line, and the paragraph for a review response.
- 🟡 **Listing copy drafted 2026-09-02** — `docs/APP-STORE-LISTING.md`, for your approval.
  Name, subtitle, promo text, description leading with the four testable claims, keywords
  at 96/100, macOS stated as a limitation up front.
- ✅ **Privacy manifest added 2026-09-02** — `App/lapslock/lapslock/PrivacyInfo.xcprivacy`,
  picked up automatically by the synchronized root group. Tracking false, no collected data
  types, one required-reason API (UserDefaults, CA92.1, for the app's own settings). The
  reasoning is in the file's comment so the label can be defended. MSAL carries its own
  manifest. **"Data Not Collected" in App Store Connect is still a checkbox for you to tick.**
- ✅ SECURITY.md with a disclosure policy and the five testable design claims
- ⬜ Tag a source release per App Store version
- ✅ **Network transparency doc written 2026-09-02** — `docs/NETWORK-TRANSPARENCY.md`, linked
  from `SECURITY.md`. Three hosts, the one Kainor request byte for byte, the ten-minute proxy
  recipe, and an honest section on what it cannot prove (no reproducible builds on iOS).
  Names the azurewebsites host, so it changes when a custom domain lands.
- ~~⬜ Network transparency doc~~ — the app talks to exactly three hosts
  (login.microsoftonline.com, graph.microsoft.com, your entitlement domain). Any admin can
  verify in ten minutes with a proxy. For this audience, observed behavior beats any badge.
  **This is your strongest trust artifact.**
- ✅ **Contributions policy written 2026-09-02.** `CONTRIBUTING.md`, issue forms for bugs and
  features (each with a required "no credentials or identifiers" checkbox), blank issues
  off, and a workflow that closes pull requests with a polite explanation. GitHub cannot
  disable PRs on a public repo, so the workflow is the mechanism; it uses
  `pull_request_target` with `pull-requests: write` only and never checks out PR code.
- ~~⬜ Contributions policy: issues on, pull requests off~~ (sole copyright holder = you can
  relicense and enforce without hunting contributors)
- 🔵 Launch posts: r/Intune, r/msp, Intune blog circuit
- 🔵 File the Microsoft support case for the macOS 500 (request ID
  `d4576653-30f5-44ae-8790-06fff930667f`) — the only path to macOS ever working

---

# Public roadmap and user feedback — ⬜ not started, design not settled

**The goal:** a way for real users to send feedback, and a public roadmap on kainor.com that
Connor curates. Automatic intake, manual approval, nothing user-written reaches the public
page without a deliberate step.

## The constraint that shapes the whole thing

**A feedback channel must not become a data collection channel.** The privacy policy says no
analytics and no telemetry, and that claim is the product's strongest asset. So no in-app
feedback widget that phones home, no session replay, no "how are we doing?" prompt that
reports anything on its own.

The pattern already exists in this codebase and should be reused: `DiagnosticsKit` assembles
a report, shows the user the whole thing, and sends nothing until they tap. Feedback works
the same way — composed locally, displayed in full, transmitted only by explicit action.

## Intake, in order of preference

1. **GitHub Issues on the public repo.** Costs nothing, is already the plan (issues on, pull
   requests off), and suits the audience: this buyer already lives on GitHub. An issue form
   template gives structure without a server.
2. **An in-app "Send feedback" that opens the mail composer**, prefilled with app and iOS
   version and nothing else. No network call, no third-party SDK, no identifiers. For the
   admin who will never open GitHub.
3. **A form on the marketing site**, only if 1 and 2 prove insufficient. It needs a
   third-party form service, which is a new data processor to name in the privacy policy —
   a real cost, so do not reach for it first.

## Curation and publication

**A file in the repo is the source of truth, and the commit is the approval step.** Something
like `docs/roadmap.json`, hand-edited, rendered into `docs/roadmap/index.html`. That gives
review, history, and a diff for free, with no admin UI to build or secure.

Three rules for what gets published:

- **Never identify who asked.** No names, no employers, no tenants, no "requested by a large
  insurance customer". The buyer is enterprise IT and their roadmap requests reveal what they
  do not have yet. Describe the item in the abstract, always.
- **No dates, ever.** Status only — considered, planned, in progress, shipped. A public
  roadmap with dates becomes a commitment in a procurement conversation, and a missed one is
  worse than never having published.
- **Shipped items stay.** The archive is the evidence the roadmap is real, and it is the
  cheapest possible proof that a one-person company actually delivers.

Consider publishing "declined, and why" as well. It is unusual, it is honest, and for this
audience an explained no builds more trust than silence — the macOS reveal finding is
already the model for that.

## Sequencing

Not before there are users, and specifically not before the first paying customer: an empty
public roadmap advertises that nobody is asking for anything. GitHub Issues can be switched
on immediately at zero cost, which starts collecting the raw material. The rendered page
waits until there is something on it worth reading.

---

# Marketing — decided 2026-08-27

## The strongest asset is already built, and it is not the app

⬜ **Write up the macOS LAPS finding.** Empirically proved that Microsoft has no working API
for retrieving macOS local administrator passwords: the Entra store returns an empty
credentials array, and the documented beta function
`retrieveDeviceLocalAdminAccountDetail` returns rotation metadata only and currently throws
HTTP 500 on ADE-enrolled LAPS-managed Macs. There are reproducible tests and Graph request
IDs behind it.

**Nobody has published this.** Every admin searching "Intune macOS LAPS API" or
"retrieveDeviceLocalAdminAccountDetail 500" hits a wall right now, and they are exactly the
buyer at exactly the moment they are frustrated. The post ranks indefinitely, costs an
evening, and markets nothing directly — it establishes domain authority, and the tool
mention at the bottom is almost incidental.

Pairs with 🔵 filing the Microsoft support case for the macOS 500 (request ID
`d4576653-30f5-44ae-8790-06fff930667f`). Do the support case first: "I reported this to
Microsoft and here is what happened" is a stronger post than "this is broken".

## The rest, in order of value

1. ⬜ **The Intune blogging community.** Small and tight — Call4Cloud, Modern Endpoint, the
   MVPs. One mention from someone respected there beats any paid promotion.
2. 🔵 **r/Intune and r/sysadmin.** Self-promotion rules are strict and enforced. The way in
   is answering LAPS questions genuinely for a while first; the macOS post gives you
   something to link that is not an advertisement.
3. ⬜ **App Store keywords:** Intune, LAPS, Entra, BitLocker. Almost no competition.
4. 🔵 **r/msp separately.** MSPs buy differently, and per-technician pricing targets them.
5. ⚠️ **First reference customer.** "Used in production by an insurance company" is worth a
   great deal to the next buyer. **But this is downstream of the employer/design-partner IP
   agreement, which is still unsigned and is already flagged as the highest-value item on
   the legal list.** Do not approach this as a marketing task until the ownership question
   is documented. Reference permission is a second, separate written agreement, and note
   that even naming the industry may be identifying — the pre-push scanner exists because
   employer data leaked into this repo once already.

## Skip

Paid advertising (audience too small for CAC to work), general tech press, anything
resembling growth hacking. This market is won by being the person who obviously knows the
subject.

## The highest-value marketing artifact is a security document

⬜ **The network transparency doc.** The app talks to exactly three hosts
(`login.microsoftonline.com`, `graph.microsoft.com`, the entitlement endpoint), verifiable
with a proxy in ten minutes. Competitors cannot make that claim. Filed under marketing
rather than engineering because that is what it actually is.

## What actually threatens this product

Not price, not marketing. It is an administrator looking at the consent screen, seeing a
request to read every local administrator password in their tenant, and closing it.

Publisher verification, source availability, the audit trail, and having no server in the
credential path all exist to survive that single moment. **Measure every marketing decision
against whether it helps or hurts there.**

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

## Tier 3 — genuine product value, no tenant and no backend required

6. **Auth diagnostics in the support report.** Moved to the top of this tier because the
   first real device build proved it necessary rather than nice. MSAL/AAD error code,
   correlation ID, and a broker-path flag, allowlisted so no authorization code can ride
   along in an error description. Full detail under "Next up — code".
7. ✅ **`LicensingKit` reveal meter — DONE 2026-08-29.** The client half of the revenue
   path is shipped and verified on device. What remains is the server half (Tier 4) and
   the StoreKit products.
8. **Windows LAPS password history.** `credentials` returns multiple entries and we take
   the newest. History matters when a device has not checked in and is still running an
   older password — a real support scenario where the current app gives the wrong answer.
9. **Recents / favourites.** The daily-use improvement with the highest ratio of value to
   effort. An admin looking after the same twenty machines should not search every time.
10. **Biometric app lock**, distinct from the per-reveal gate.

## Tier 4 — the revenue path. The CLIENT half is done; this is the server half.

Backend infrastructure is provisioned (see "Backend (Azure)"). The free-tier meter and all
gating UI shipped 2026-08-29. IAP and App Attest need Apple; the Function does not.

11. `/entitlement` Function: API contract, ES256 key, licenses table, code
12. Stripe
13. IAP products and the StoreKit trial. Note the gating itself is BUILT — what is missing
    is products to sell and an entitlement check to set `isPro`, which is currently
    hardcoded false.
14. App Attest gating — **phase 2, deliberately.** Reasoning in the Backend section.

## Tier 5 — cheap trust and marketing work, high leverage

15. **The macOS LAPS write-up.** Reclassified from "nice to have" to near the top by the
    marketing decisions: nobody has published this finding, it ranks indefinitely, and it
    reaches the buyer at the moment of frustration. File the Microsoft support case first
    so the post can say what Microsoft's response was.
16. **Network transparency doc.** Three hosts, verifiable with a proxy in ten minutes.
    Already identified as the strongest trust artifact and it costs an afternoon.
17. **Trademark filing.** USPTO Class 9, intent-to-use, ~$350. Actionable today, and the
    icon can be cleared at the same time (a design-mark search, separate from the wordmark
    search already done).
18. Attorney pass on the license additional-permission wording and the liability cap.
19. "Not affiliated with Microsoft" on the marketing site.

## Nothing is blocked any more

The Apple and Microsoft queues are both cleared. Every remaining item is work, not waiting.

Deliberately deferred, not blocked:
- Alternate icon picker — and the premise changed; there is no second variant to pick any
  more. Icon Composer / Liquid Glass layers exist but nothing consumes them.
- PIM activation — real-tenant verification is done, so this now sits behind the
  entitlement backend only. The MFA claims-challenge handling makes it a project rather
  than an afternoon.

## DECIDED ORDER, 2026-08-29. Do not re-argue this each session.

1. ~~**`/entitlement` API contract**~~ — DONE 2026-09-01, `docs/ENTITLEMENT-API.md`.
   Next: the ES256 key, the licenses table, then the Function, then the client half
   (fetch, verify, Activate license UI, `isPro`). The privacy policy host list has to
   change in the same release as the client work. The infrastructure is provisioned and
   nothing blocks any of it.
2. **Auth diagnostics in the support report.** Becomes urgent the moment there is a
   customer, and not before. Tonight proved it is needed: diagnosing the broker bug took a
   cable, Xcode and Console.app, and a customer hitting the same failure gets "check your
   connection" with no path forward.
3. **Search only covers loaded pages.** Bites the first large customer. Also a design
   question rather than a mechanical fix, so it wants thought, not haste.

Everything else waits. The reasoning for this order: 2 and 3 are both insurance against
problems that cannot occur until there are customers, and there is no way to get customers
without the thing in 1.

## Cheap items worth doing alongside the above

Neither is on the critical path, both are small:

- **File the Microsoft support case for the macOS LAPS 500** (request ID
  `d4576653-30f5-44ae-8790-06fff930667f`). Do this before the write-up so the post can say
  what Microsoft's response was, which is a stronger article than "this is broken".
- **Register nothing else.** `lapslock.com` and `.app` are done, USPTO and App Store
  searches are clear, and the trademark filing waits for the attorney pass so name
  clearance and the "LAPS is Microsoft's product name" question get handled together.
