# Launch posts

Drafts for founder approval. **Do not post any of these until App Review approves 1.0** — a
post pointing at an app that is not yet on the store is worse than no post.

Written to the marketing philosophy already recorded in `MASTER-TODO.md`: this market is won
by being the person who obviously knows the subject. No growth hacking, no "excited to
announce", no feature list as a wall of bullets. Each post leads with something the reader
can *check*, discloses the commercial interest in the first paragraph, and invites scrutiny
of the code rather than trust.

**Two rules that override everything below:**

1. **Never name or hint at the employer.** Not the company, not the industry, not the device
   count, not "the tenant I administer day to day". The pre-push scanner exists because
   employer data leaked into this repo once. "Used in production at an insurance company" is
   identifying and is not yours to disclose. Speak as Kainor, about a product.
2. **Disclose that it is yours, in the first paragraph, every time.** Reddit removes
   undisclosed self-promotion and remembers who did it. Disclosed, technical, and useful is
   the only shape that survives moderation on these subreddits.

---

## Post 1 — r/Intune

**Post first here.** Smallest audience, most on-topic, and the moderators tolerate a
disclosed tool post if it is substantive. Text post, no link in the title.

### Title

> I built an iOS app that reads Windows LAPS passwords and BitLocker keys from Entra/Intune. Here is how to verify it never sees them.

### Body

> Disclosure up front: this is my app, it has a paid tier, and I am the developer. If that is
> not what you want to read on a Tuesday, no hard feelings.
>
> **The problem it solves.** You are at a machine that will not log in. The LAPS password is
> in Entra. The admin center is on a laptop somewhere else. LAPSlock reads Windows LAPS local
> administrator passwords and BitLocker recovery keys from Entra ID and Intune, on your phone,
> behind Face ID, with the same delegated permissions your account already has.
>
> **The part I actually care about you checking.** A phone app that handles local admin
> passwords should make every sysadmin's teeth itch, so the design decision was: there is no
> vendor server in the credential path, and you should not have to take my word for it.
>
> - It uses Microsoft delegated auth via MSAL. It can read exactly what your account can read
>   in the admin center, and nothing else. Every reveal appears in *your* Entra audit log,
>   exactly as a read from the portal would.
> - Passwords go from Graph to your device over TLS. Kainor (my company) never sees them and
>   has no server that could.
> - No analytics, no telemetry, no crash reporting, no account to create. The App Store
>   privacy label says "Data Not Collected" and it means it.
> - The source is public for security review. The credential-handling module is
>   structurally isolated — a build script fails if it ever imports anything it should not.
> - You can confirm the network claim yourself in about ten minutes with a proxy. There is a
>   walkthrough in the repo (`NETWORK-TRANSPARENCY.md`): the app talks to
>   `login.microsoftonline.com`, `graph.microsoft.com`, and — only after an organization
>   activates a licence — one Kainor endpoint that receives a tenant ID and nothing else.
>
> **What it does not do**, because finding out later is worse:
>
> - It cannot read LAPS backed up to on-prem AD. Entra-backed only. Hybrid-joined is fine if
>   the policy targets Entra.
> - It cannot reveal macOS local admin passwords. There is no Graph API that returns them,
>   and the one beta endpoint that should return metadata currently 500s on every
>   ADE-enrolled Mac I have tested. I have a support case open with Microsoft about it and
>   will write that up separately.
> - It cannot grant you access you do not have. No permission it requests escalates anyone.
>
> **Things that turned out to matter more than I expected:**
>
> - LAPS password *history* comes back in the same Graph response as the current password.
>   A device that stopped checking in is still on the old one — and that is exactly the
>   machine you are standing at.
> - If your role is PIM-eligible rather than active, it can request activation from the
>   phone. It reads your tenant's PIM policy first, so it only offers durations your policy
>   allows and tells you up front if a ticket number is required. Turned out the
>   authentication-context requirement arrives as an HTTP 400 with the claim buried in the
>   error message, not as a 401 challenge, which cost me a day.
>
> **Pricing, since someone will ask.** Free tier is fully functional with five reveals per
> rolling 30 days, counted on the device and nowhere else. Subscriptions remove the limit.
> Org licensing by tenant is available directly from us.
>
> Repo: github.com/Kainor-LLC/LAPSlock — the permissions table in `how-it-works` is probably
> the page a security team wants first. Happy to answer anything about the Graph surface; the
> LAPS endpoints are underdocumented and I have notes.

### Why it is shaped this way

- Disclosure in sentence one, with permission to leave. That earns the rest of the post.
- The first substantive section is *how to verify*, not *what it does*. This audience trusts
  a claim they can check and distrusts one they cannot.
- Limitations stated plainly, including the macOS one that competitors would hide. Stating
  limits is the single most credibility-building thing a vendor can do in r/Intune.
- The "things that turned out to matter" section is the actual value to a reader who never
  installs the app. It is also what makes the post something other than an advertisement,
  which is what keeps it up.
- The pricing paragraph is short and un-sold. Nobody in this subreddit wants to be pitched.

---

## Post 2 — r/msp

Different buyer, different post. **Post a few days after r/Intune**, not the same day — two
simultaneous posts across subreddits reads as a campaign. Text post.

### Title

> For MSPs running Intune across customer tenants: a phone app for LAPS/BitLocker with proper tenant switching. Built it, disclosing it, here is the consent model.

### Body

> I am the developer, this is a paid product, disclosure done.
>
> LAPSlock reads Windows LAPS passwords and BitLocker recovery keys from Entra/Intune on an
> iPhone. The individual version has been in r/Intune; this post is about the MSP side,
> because the multi-tenant part has a consent model worth understanding before you consider
> it, and it is not a LAPSlock design — it is Microsoft's.
>
> **How switching between customers works.** You sign in once with your own account. To work
> in a customer tenant you add it by domain or tenant ID and switch. Which organization you
> are operating in is on screen at all times, the device list is cleared on every switch, and
> any credential on screen is discarded. The app returns to your own tenant on relaunch,
> deliberately — operating inside a customer should be a decision made now, not inherited
> from last week.
>
> **The consent model, which is the part that matters.** Each customer's Entra administrator
> has to consent to LAPSlock in *their* tenant once before you can work in it. That is
> incremental delegated consent, not a LAPSlock account system. There is a shareable
> admin-consent link for exactly this. Your access in their tenant is whatever your
> guest/GDAP/dedicated account can already do — the app adds nothing.
>
> Per-customer state stays per-customer: pinned devices are keyed to the tenant you are
> operating in, so customer A's favourites never appear while you are in customer B. The
> list of which customers you work with is stored on the phone only and is never sent to us;
> who your customers are is your business.
>
> **What it will not do for you.** It does not aggregate across tenants, it does not report,
> and it will not hand a technician access their account does not hold. It also cannot read
> LAPS backed up to on-prem AD, which for some of your customers will be the whole estate —
> Entra-backed LAPS only.
>
> **Security posture, briefly, because your customers will ask you.** Delegated auth only,
> no vendor server in the credential path, no analytics or telemetry, source published for
> review, and the network claims are verifiable with a proxy in ten minutes. There is a
> one-page security summary in the repo written for exactly the "our client's security team
> wants to know" conversation.
>
> **Pricing.** MSP plan is per technician, yearly, and is what unlocks tenant switching.
> Organization licensing for a whole MSP is available directly from us, and yes, that
> includes invoicing and a PO if procurement needs one.
>
> Repo: github.com/Kainor-LLC/LAPSlock. I would genuinely like to hear how your technicians
> actually move between customer tenants day to day — the switcher was designed from
> Microsoft's docs and a two-tenant test lab, not from watching an MSP work.

### Why it is shaped this way

- The MSP buyer's first question is never "what does it do", it is "what does it mean for
  our customers' consent and our liability". So the consent model is the body of the post.
- "Not a LAPSlock design — it is Microsoft's" is doing real work: it says the app has not
  invented a trust relationship, only surfaced the existing one.
- The closing question is sincere and is also the best possible source of 1.1 requirements.
  The TODO notes the switcher was built without watching an MSP use it.

---

## Post 3 — the macOS LAPS write-up (technical, not promotional)

**This is the post that gets shared.** It is useful to people who will never install the
app, it links to the repo as a source rather than a pitch, and it is the thing the TODO
identified as the way into r/Intune and r/sysadmin: *"the macOS post gives you something to
link that is not an advertisement."*

**Blocked on one thing: file the Microsoft support case first** (request ID recorded in
`MASTER-TODO.md`). "I reported this to Microsoft and here is what happened" is a materially
stronger post than "this is broken", and it may also get the endpoint fixed.

### Title

> The Graph API for macOS LAPS passwords returns HTTP 500 on every device I have tested. Here is what I found and what Microsoft said.

### Skeleton (fill in after the support case resolves)

1. **What Windows LAPS on Graph looks like and why it works** —
   `deviceLocalCredentials/{id}?$select=credentials`, GA, documented, returns the password
   and its history. Two lines of praise; it is genuinely well done.
2. **What macOS gets instead** — the beta `retrieveDeviceLocalAdminAccountDetail`
   function, specified to return only `passwordLastRotationDateTime` (no password field at
   all), and in practice returning 500 from Intune's DeviceFE backend on every ADE-enrolled,
   LAPS-managed Mac tested.
3. **Reproduction** — the exact request, the exact response, the request ID. Redact tenant
   and device identifiers; the request ID is the one identifier Microsoft *wants* published.
4. **What this means for anyone building on it** — there is currently no supported way to
   retrieve a macOS local admin password outside the admin center. Anyone claiming otherwise
   is either using an undocumented endpoint or not telling the truth.
5. **What Microsoft said** — the support case outcome, quoted.
6. **What I did about it in LAPSlock** — one paragraph, at the end, disclosed: shows the
   metadata that does work, hands off to the portal, and will use an API if one appears.
   This is the only paragraph about the product, and it is last on purpose.

Post to r/Intune and r/sysadmin; r/sysadmin tolerates this one because it is a bug report
about Microsoft, not a product post. Link to the repo only in the final paragraph.

---

## Not doing

- **r/sysadmin for Post 1 or 2.** Removes most self-promotion regardless of disclosure. Post 3
  is the way in.
- **Simultaneous posting.** Space them by days. A cluster reads as a campaign.
- **Paid promotion, general tech press, growth mechanics.** Per the TODO: the audience is too
  small for acquisition spend to work, and this market is won by evident expertise.
- **Any reference to the employer, its industry, or its estate.** See rule 1.

## Sequence

1. App Review approves 1.0 →
2. Post 1 (r/Intune) the same or next day →
3. Answer every comment for 48 hours, including the hostile ones, technically →
4. Post 2 (r/msp) three or four days later →
5. File the Microsoft support case if not already done; Post 3 when it resolves →
6. Approach the Intune blogging community (Call4Cloud, Modern Endpoint, MVPs) with Post 3,
   not with the product — per the TODO, one mention from someone respected there beats any
   promotion.
