# App Store listing copy

**Status: draft for founder approval.** Written to lead with security posture, per the
decision in `MASTER-TODO.md`. Character limits are App Store Connect's: name 30, subtitle
30, promotional text 170, description 4000, keywords 100 total (comma-separated, no spaces
needed after commas).

## Name (30)

LAPSlock

## Subtitle (30)

LAPS & BitLocker keys, on your phone

*(29 characters.)*

## Promotional text (170) — editable without a new build

Retrieve Windows LAPS passwords and BitLocker recovery keys from Entra ID and Intune. Your
sign-in, your tenant's audit log, no vendor server in the path.

## Description

LAPSlock retrieves Windows LAPS local administrator passwords and BitLocker recovery keys
from Microsoft Entra ID and Intune — at the helpdesk bench, in the server room, and
everywhere the admin center is not.

BUILT FOR PEOPLE WHO ARE PAID TO BE SUSPICIOUS

• Your sign-in, not ours. LAPSlock uses Microsoft delegated authentication. It can only
  read what your account can already read, and every retrieval lands in your own tenant's
  audit log exactly as it would from the admin center.
• No vendor server in the credential path. Passwords travel from Microsoft Graph to your
  device over TLS. Kainor never sees them and has no way to.
• Nothing collected. No analytics, no telemetry, no crash reporting, no account to create.
  The app talks to Microsoft and, only if your organization activates a license, to one
  license endpoint that receives your tenant ID and nothing else.
• Verifiable, not just promised. The source is published for security review, and a
  ten-minute proxy check confirms every claim above. We would rather you looked than
  trusted.

WHAT IT DOES

• Search your fleet by device name, serial, model, or the person using it — matching real
  names and email addresses, because a ticket names a person more often than a machine.
• Reveal a Windows LAPS password behind Face ID or Touch ID, with the managed account name
  and the backup date.
• See previous LAPS passwords where your tenant kept them. A device that stopped checking
  in is still using an older one, and that is usually the machine you are standing at.
• Reveal BitLocker recovery keys per volume, each labelled with the key identifier the
  locked machine is asking for, so you pick the right one instead of guessing.
• Activate a PIM-eligible role without leaving the bench. LAPSlock reads your
  organization's own policy first, offers only the durations it permits, and tells you up
  front if a ticket number or extra verification is required.
• Switch between customer organizations, for managed service providers. Which organization
  you are working in is on screen at all times.
• Pin the devices you keep coming back to, and see the last few you opened.
• Lock the whole app behind Face ID, separately from the check before each reveal.

WHAT IT DELIBERATELY DOES NOT DO

• Store credentials. A revealed value lives in memory and is destroyed when hidden, on
  timeout, when the app leaves the foreground, or if a screenshot is detected.
• Show credentials in the app switcher.
• Ask for write access unless you turn it on. BitLocker key rotation and role activation
  are opt-in switches; leave them off and LAPSlock only ever requests read permissions.
• Read Windows LAPS backed up to Active Directory. LAPSlock reads Entra-backed LAPS.
  Entra-joined and hybrid-joined devices both work when the policy backs up to Entra ID —
  a policy targeting Windows Server AD is not readable by any Graph API.
• Retrieve macOS local admin passwords. Microsoft does not expose them through any working
  API; LAPSlock shows the metadata and links you to the portal rather than pretending.

FREE AND PAID

Free includes unlimited search and browsing, all metadata, password history, BitLocker
keys, copying, role activation, app lock, and five credential reveals per rolling 30 days —
enough to prove it works against your own tenant and watch the reads appear in your audit
log. A subscription removes the reveal limit. The MSP plan adds switching between customer
organizations. Organizations can license by tenant directly from Kainor.

Requires a Microsoft Entra ID account with a directory role permitted to read Windows LAPS
passwords or BitLocker keys, and devices managed in Intune or joined to Entra ID.

LAPSlock is an independent product of Kainor LLC and is not affiliated with, endorsed by,
or sponsored by Microsoft Corporation. Microsoft, Microsoft Entra, Microsoft Intune,
Windows, and BitLocker are trademarks of Microsoft Corporation.

## Keywords (100)

intune,entra,laps,bitlocker,recovery key,local admin,password,azure ad,helpdesk,msp,pim

*(87 characters.) Changes from the first draft: dropped `sysadmin`, which overlaps
`helpdesk` and is a word people describe themselves with rather than search with. Added
`msp`, which is how that whole buyer segment self-identifies and is now a real tier, and
`pim`, which nothing else in this category does from a phone. "LAPS" is repeated from the
name because matching on the name is not guaranteed to be exact.*

## Notes on choices

- **Security posture leads** because price is not the adoption friction for this buyer;
  trust is. The first four bullets are the four testable claims from `SECURITY.md`.
- **"Paid to be suspicious"** is the one line of personality. It names the reader
  accurately and signals that the rest of the copy will not be marketing.
- **macOS is stated as a limitation, in the listing.** A buyer who discovers it after
  purchase writes a one-star review; one who reads it here trusts everything else more.
- **No prices in the description.** They change; the IAP sheet shows them.
- **The disclaimer is in the description**, not only in Settings, because Apple has
  rejected apps for implied affiliation and because the same sentence is on the website.
- **Two limitations are stated in the listing, not buried.** macOS reveal is impossible,
  and AD-backed LAPS is unreadable. Both cost a few installs from people the app cannot
  help — and save the one-star review from someone who bought first and found out after.
  The AD one was added 2026-09-03 after checking the Graph surface properly.
- **Revised 2026-09-03** for everything that landed after the first draft: password
  history, PIM activation, tenant switching, favourites and app lock. The Free/Paid
  section was also rewritten — copy to clipboard and BitLocker rotation are NOT gated any
  more, so claiming them as paid features would have been false advertising in the
  listing itself.
