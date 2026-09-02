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

• Search your device inventory by name, serial, or the assigned user.
• Reveal a Windows LAPS password behind Face ID or Touch ID, with the account name and
  the next rotation date.
• Reveal BitLocker recovery keys per volume, with backup dates, so you pick the right one.
• See rotation and expiry so you know what you are looking at.
• Copy with a clipboard that expires and never syncs to other devices.

WHAT IT DELIBERATELY DOES NOT DO

• Store credentials. A revealed value lives in memory and is destroyed when hidden, on
  timeout, when the app leaves the foreground, or if a screenshot is detected.
• Show credentials in the app switcher.
• Retrieve macOS local admin passwords. Microsoft does not expose them through any working
  API; LAPSlock shows the metadata and links you to the portal rather than pretending.

FREE AND PRO

Free includes unlimited search and browsing, all metadata, and five credential reveals per
rolling 30 days — enough to prove it works against your own tenant and watch the reads
appear in your audit log. Pro removes the limit and adds copy to clipboard and BitLocker
key rotation. Organizations can license by tenant directly from Kainor.

Requires a Microsoft Entra ID account with a directory role permitted to read Windows LAPS
passwords or BitLocker keys, and devices managed in Intune or joined to Entra ID.

LAPSlock is an independent product of Kainor LLC and is not affiliated with, endorsed by,
or sponsored by Microsoft Corporation. Microsoft, Microsoft Entra, Microsoft Intune,
Windows, and BitLocker are trademarks of Microsoft Corporation.

## Keywords (100)

intune,entra,laps,bitlocker,recovery key,local admin,password,azure ad,helpdesk,sysadmin

*(96 characters. "LAPS" is already in the name and is indexed from there; it is repeated
because keyword matching on the name is not guaranteed to be exact.)*

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
