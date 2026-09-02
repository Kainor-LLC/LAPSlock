# App Store review notes

Text for the "Notes" field in App Store Connect, and the reasoning behind each paragraph so
it can be maintained. **Status: draft for founder approval before first submission.**

Review notes are read by a reviewer who has never heard of Windows LAPS, probably has no
Microsoft tenant, and has about ten minutes. The goal is to stop the three predictable
misreadings: "the app does nothing" (no tenant), "the app is broken" (the meter), and "the
app collects data" (it does not, and that has to be verifiable rather than asserted).

---

## Paste into App Store Connect

LAPSlock is a tool for IT administrators. It retrieves Windows LAPS local administrator
passwords and BitLocker recovery keys from an organization's Microsoft Entra ID / Intune
tenant, using the administrator's own Microsoft sign-in. It has no accounts of its own and
no server of ours in the path of any password.

REVIEWING WITHOUT A MICROSOFT TENANT: tap "Try the demo" on the sign-in screen. Demo mode
uses fabricated devices and obviously fake credentials (repeated digits, "DEMO-Not-A-Real-
Password"), exercises every screen, and makes no network requests. Everything below can be
seen in demo mode.

THE FREE TIER IS METERED, NOT BROKEN: free use allows 5 credential reveals per rolling 30
days. After the fifth, the reveal button shows a clear message and the app continues to
work for everything else (search, device details, key metadata). This is intentional and
disclosed in the app before the limit is reached — the remaining count is shown on the
device list and in Settings. If you exhaust it while reviewing, that is the designed
behavior, not a defect.

SETTINGS → ORGANIZATION LICENSE: "Activate" checks whether the signed-in organization holds
a license purchased directly from us (outside the App Store, for organizations). It sends
our server the organization's Microsoft tenant identifier and nothing else, and receives a
signed statement of the license tier. No purchase can be made in this flow, and it is not
available in demo mode. Individual subscriptions are sold through In-App Purchase.

PRIVACY: the app collects no analytics, telemetry, or crash data, and the "Data Not
Collected" label is accurate. The only network hosts contacted are login.microsoftonline.com,
graph.microsoft.com, and — only after an organization activates a license — our license
server, which receives a tenant identifier only. This is documented for verification with a
network proxy at https://github.com/Kainor-LLC/LAPSlock/blob/main/docs/NETWORK-TRANSPARENCY.md.

FACE ID: used to gate each credential reveal. The prompt appears before the credential is
fetched, so cancelling it fetches nothing.

SCREENSHOTS AND THE APP SWITCHER: revealed credentials are hidden in the app switcher and
the app clears a revealed value if a screenshot is detected. This is deliberate protective
behavior for a credential viewer.

---

## Why each paragraph is there

- **Demo mode first.** A reviewer without a tenant sees a sign-in screen and nothing else.
  If the notes do not point at the demo in the first screenful, the review fails on "we
  could not access the app's features."
- **The meter, stated as designed behavior.** A reviewer who reveals six demo credentials
  hits the wall and files it as a bug unless told otherwise. Saying "disclosed before the
  limit" matters: guideline reviewers look for surprise paywalls.
- **Activate is not a purchase.** Guideline 3.1.1 is about in-app purchases bypassing IAP.
  Activate checks an existing organizational license; it sells nothing, links to no
  checkout, and mentions no price. Saying so plainly heads off the question. Individual
  subscriptions go through IAP, which is the compliant path for individuals.
- **Data Not Collected, with a way to check.** Reviewers do spot-check the nutrition label
  against observed traffic. Naming the three hosts and linking the proxy recipe turns a
  claim into an invitation.
- **Face ID before fetch.** Explains why cancelling the biometric prompt shows nothing.
- **Switcher and screenshot behavior.** Otherwise reads as a rendering bug.

## Known gap to resolve before submission

**A reviewer cannot exercise Pro features.** Demo mode is metered like the free tier, the
organization license is not available in demo, and there is no IAP yet. Once IAP products
exist, the App Store sandbox lets a reviewer subscribe without paying, which is the usual
answer. Until then, either accept that Pro features are not reviewable on first submission
(they mostly remove limits rather than add screens) or add a DEBUG-style reviewer path —
which would have to be compiled out of Release, the same way the meter reset is. Founder's
call; recorded in `MASTER-TODO.md`.
