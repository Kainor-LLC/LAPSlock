# Guideline 3.1.3 and how LAPSlock's pricing complies

Reference for a review response, and a check on the pricing model. **Checked against
Apple's published guidelines on 2026-09-02**; re-verify the text before each submission,
because this section changes.

## What the guideline says

**3.1.3(c) Enterprise Services:** if an app is sold directly by the developer to
organizations or groups for their employees or students (professional databases, classroom
management tools are Apple's examples), enterprise users may be allowed to access
previously-purchased content or subscriptions. Consumer, single-user, or family sales must
use in-app purchase.

**3.1.3(b) Multiplatform Services** additionally permits access to things bought on other
platforms or the developer's website, *provided those items are also available as in-app
purchases*, and with a constraint that governs everything else here: **the app must not
directly or indirectly target iOS users toward a purchase method other than in-app
purchase, and general communications must not discourage IAP.**

## How LAPSlock's model maps onto it

| Sale | Buyer | Channel | Guideline basis |
|---|---|---|---|
| Individual Pro | one administrator | In-app purchase | required for single-user sales |
| MSP Pro (per technician) | one technician | In-app purchase | single-user sale |
| Enterprise (tenant-keyed) | an organization | Direct, from Kainor | 3.1.3(c) |
| MSP org (tenant-keyed) | an organization | Direct, from Kainor | 3.1.3(c) |

This is the shape 3.1.3(c) describes: individuals buy through IAP, organizations buy
directly and their users "access previously-purchased" entitlement.

## What the app does, and must keep doing, to stay inside the line

- **Settings → Organization license → Activate checks an existing license. It sells
  nothing.** No price, no link to a checkout, no "buy a license" button, no mention of the
  website as a place to purchase. It sends a tenant ID and receives a signed tier. That is
  "access previously-purchased," and nothing more.
- **The blocked-reveal message says Pro removes the limit and offers the IAP path.** It does
  not mention organization licensing or the website. A message at the moment of friction
  that steered toward the direct channel would be exactly the "indirectly target" case.
- **Organization purchasing lives on the website only**, never linked from the app. This
  was already the decision; the guideline text confirms it is the right one.
- **Copy tenant ID in Settings is a utility, not a purchase step.** It is labelled as an
  identifier, with no text about buying. Keep it that way — the moment it says "paste this
  at checkout" it becomes steering.
- **Listing copy and review notes say "organizations can license by tenant directly from
  Kainor"** once, factually, alongside the IAP description. That is a general
  communication that does not discourage IAP.

## Why not route organizations through IAP too

Because organizations cannot: App Store purchases are tied to an Apple ID, and an enterprise
license is tied to a tenant with dozens of administrators who come and go. Volume Purchase
does not cover consumable-style subscriptions per tenant. This is the exact situation
3.1.3(c) exists for, and it is worth saying so plainly in a review response if asked.

## If a reviewer pushes back

Point at the table above and at the Settings screen: Activate has no price and no link.
Individuals have a complete IAP path. The direct channel exists only for organizations, per
3.1.3(c), and the app never steers anyone to it.

Sources, checked 2026-09-02:
- https://developer.apple.com/app-store/review/guidelines/
- https://developer.apple.com/news/?id=xqk627qu
