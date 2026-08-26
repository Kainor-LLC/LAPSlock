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

## Tier 2 — the biggest unknown risk in the project

5. **Verify against a real tenant.** Every reveal you have ever seen was demo data. The
   Windows LAPS decode path (base64, UTF-16LE detection, BOM stripping) has never touched
   a real password from Graph, and that is exactly the kind of code that works on
   handwritten test vectors and fails on real input. Now that the IP question is settled,
   consenting in the design-partner tenant and revealing one real password is the single
   most informative thing left to do. If something is broken, everything above is built on
   sand — better to know now.

## Tier 3 — genuine product value, no tenant required

6. **Windows LAPS password history.** `credentials` returns multiple entries and we take
   the newest. History matters when a device has not checked in and is still running an
   older password — a real support scenario where the current app gives the wrong answer.
7. **Recents / favourites.** The daily-use improvement with the highest ratio of value to
   effort. An admin looking after the same twenty machines should not search every time.
8. **Biometric app lock**, distinct from the per-reveal gate.

## Tier 4 — the revenue path (largest remaining chunk)

Partially unblocked: the backend does not need Apple, but IAP and App Attest do.

9. Azure Function `/entitlement`, licences table, private repo for the signing keys
10. Stripe (waiting on the business bank account)
11. App Attest gating — needs a real device and the Apple account, so blocked
12. IAP products and free-tier gating — needs App Store Connect, so blocked

## Tier 5 — cheap trust and legal work, do while waiting

13. **Network transparency doc.** Three hosts, verifiable with a proxy in ten minutes.
    Already identified as the strongest trust artifact and it costs an afternoon.
14. **Trademark filing.** USPTO Class 9, intent-to-use, ~$350. Actionable today, and the
    icon can be cleared at the same time (a design-mark search, separate from the wordmark
    search already done).
15. Attorney pass on the licence additional-permission wording and the liability cap.
16. "Not affiliated with Microsoft" on the marketing site.

## Nothing is blocked any more

The Apple and Microsoft queues are both cleared. Every remaining item is work, not waiting.

Deliberately deferred, not blocked:
- Alternate icon picker, iOS 18 icon variants — behind the entitlement work
- PIM activation — behind real-tenant verification and the entitlement backend

## Recommended next session

Tier 1 in one pass, then Tier 2. Tier 1 closes a genuine security gap and two things I
flagged and left undone; Tier 2 tells you whether the core actually works. Doing Tier 3
or 4 before Tier 2 means building more on unverified foundations.
