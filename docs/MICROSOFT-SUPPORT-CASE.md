# Microsoft support case — macOS LAPS on Microsoft Graph

Draft of the case Kainor LLC files with Microsoft about retrieving macOS local administrator
passwords through Microsoft Graph. Written 2026-09-08. The write-up in `LAUNCH-POSTS.md`
(Post 3) waits for the outcome of this case.

---

## Read before filing

**1. Kainor files this as Kainor. Not through an employer, a licensing partner, or a CSP.**
A partner-submitted ticket is filed against the partner's customer tenant and under that
customer's agreement. It would attach Kainor's product research to an unrelated organisation
in Microsoft's records, and any request ID quoted in it is resolved by Microsoft to the tenant
that made the request. Both of those cross the one line this repository exists to hold
(`scripts/pre-push-scan.sh`). File from the Kainor tenant, as Kainor LLC, from a kainor.com
address.

**2. Only cite request IDs that came from the Kainor tenant.** A Graph `request-id` is opaque
to us but not to Microsoft: it identifies the tenant, the user and the device behind the call.
The 2026-08-14 verification ran in a different tenant, so its request IDs are not Kainor's to
cite and were removed from this repository on 2026-09-08. Kainor files Variant B.

**2a. Two tracks, and they never reference each other.** The tenant that owns the Macs may
file its own defect ticket, through its own support channel, with its own reproduction — that
is that organisation's ticket about that organisation's problem, and it is the one most likely
to get the 500 fixed. Kainor's track is the public question below. Kainor never quotes,
numbers, or alludes to the other ticket; Post 3 draws only on Kainor's own thread. A fix that
lands because of someone else's ticket benefits Kainor the way it benefits every customer.

**3. Two variants, pick by what Kainor can reproduce today.**

| | Variant A — full reproduction | Variant B — API surface question |
|---|---|---|
| Kainor tenant has an ADE-enrolled, LAPS-managed Mac | Yes | No |
| Includes the HTTP 500 with request ID and timestamp | Yes | No — describes it as observed, offers to reproduce if Microsoft provides a path |
| Core ask | Fix the 500, and confirm whether a password-returning API exists or is planned | Confirm whether a password-returning API exists or is planned; document the function's contract |

Variant B is still worth filing. The central finding needs no reproduction at all: the
**documented contract** of the only macOS function has no password property.

**4. Where to file, in order of usefulness.**

1. **Intune admin center → Tenant administration → Help and support → new support request**,
   signed in to the Kainor tenant. This is a real product support case with an SLA. It
   requires an Intune licence in the Kainor tenant; one Microsoft 365 Business Premium or
   Intune Plan 1 seat is enough. Category: Microsoft Intune → Device management → macOS.
2. **Microsoft Q&A** (learn.microsoft.com/answers), tags `microsoft-graph` and
   `microsoft-intune`. Public, free, answered by Microsoft engineers, and the thread itself
   becomes citable in Post 3.
3. **GitHub issue on `microsoftgraph/microsoft-graph-docs-contrib`** against the function's
   reference page, for the documentation half only: the page should state plainly that the
   password value is not returned by any API.
4. Paid per-incident developer support for Microsoft Graph, if 1 is unavailable and 2 stalls.

Do 1 (or 2) and 3 together. They ask different teams different questions.

---

## The case

### Title

> macOS LAPS: `retrieveDeviceLocalAdminAccountDetail` (beta) returns HTTP 500 for ADE-enrolled Macs, and no Graph API returns the macOS local administrator password

### Summary

Kainor LLC builds LAPSlock, an iOS administrator client for Microsoft Entra ID and Intune
tenants that use Windows LAPS and macOS LAPS. It uses delegated permissions only, through
public, documented Microsoft Graph endpoints. Windows LAPS works exactly as documented through
`GET /v1.0/directory/deviceLocalCredentials/{id}?$select=credentials`.

For macOS LAPS, shipped in Intune service release 2507, we have found:

1. **No documented Microsoft Graph endpoint returns the macOS local administrator password.**
   The only macOS-specific function, `retrieveDeviceLocalAdminAccountDetail` (beta), returns
   a `deviceLocalAdminAccountDetail`, concretely `microsoft.graph.macOSDeviceLocalAdminAccountDetail`,
   whose documented response carries exactly one property, `passwordLastRotationDateTime`
   (reference page, checked 2026-09-08:
   https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-retrievedevicelocaladminaccountdetail?view=graph-rest-beta).
   There is no password property in the contract.
2. **The Entra device-credential store used by Windows LAPS does not hold macOS passwords.**
   `deviceLocalCredentials/{entraDeviceId}?$select=credentials` returns `200 OK` with no
   `credentials` array for ADE-enrolled Macs. This is consistent with the macOS LAPS
   documentation ("stored and encrypted by Intune") and is not itself a defect.
3. **The beta function returns HTTP 500** for every ADE-enrolled, LAPS-managed Mac we tested
   (Variant A: details below), so even the documented metadata is not retrievable.

The Intune admin center displays and rotates these passwords (Devices → macOS → device →
Passwords and keys, gated by the custom RBAC permissions **View macOS admin password** and
**Rotate macOS admin password** under *Enrollment programs*). Retrieval therefore exists as a
service capability but is portal-internal. We will not build on undocumented or internal
endpoints.

### What we are asking

1. **Is there a supported Microsoft Graph API, now or planned, that returns the macOS LAPS
   local administrator password to an authorised delegated caller**, equivalent to
   `deviceLocalCredentials` for Windows? If planned, a public roadmap reference or the
   Graph changelog entry would let us and other customers plan against it.
2. **Please fix the HTTP 500** from `retrieveDeviceLocalAdminAccountDetail` for ADE-enrolled
   Macs, or state the precondition it requires that our devices do not meet. The function is
   documented without preconditions beyond the permission and a valid managed device ID.
3. **Please make the function's reference page explicit** that the password value is not
   returned. Administrators searching for a macOS LAPS API currently find this function,
   assume it is the equivalent of the Windows one, and discover otherwise only by calling it.

### Environment

- Tenant: Kainor LLC (tenant ID and domain provided in the case form, not repeated here).
- Caller: delegated user token acquired through MSAL (iOS) and, for reproduction, through
  the Microsoft Graph PowerShell SDK (`Invoke-MgGraphRequest`) on macOS.
- Permissions consented: `DeviceManagementManagedDevices.Read.All` (delegated). The signed-in
  user holds an Intune custom role granting **View macOS admin password** and **Rotate macOS
  admin password**, and can view the password in the admin center for the same devices.
- Devices: macOS, synced from Apple Business Manager, enrolled through Automated Device
  Enrollment after a factory reset, LAPS enabled through the Intune enrollment profile. The
  admin center shows a current password and rotation date for each.
- Graph API versions exercised: `v1.0` and `beta`.

### Reproduction — the three requests

All three use the same delegated token. `{entraDeviceId}` is the device's Entra object ID
(`azureADDeviceId` on the managed device). `{managedDeviceId}` is the Intune managed device ID.

**Request A — the Windows LAPS store, to confirm macOS passwords are not there**

```
GET https://graph.microsoft.com/v1.0/directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials
```

Observed for every Mac: `200 OK`, body contains `id`, `deviceName`, `lastBackupDateTime`
absent, and **no `credentials` property**. For a Windows LAPS device in the same tenant the
identical request returns the `credentials` array with the password and its history.

**Request B — the documented macOS function**

```
GET https://graph.microsoft.com/beta/deviceManagement/managedDevices/{managedDeviceId}/retrieveDeviceLocalAdminAccountDetail
```

Expected, per the reference page's own example: `200 OK` and
`{"value":{"@odata.type":"microsoft.graph.macOSDeviceLocalAdminAccountDetail","passwordLastRotationDateTime":"…"}}`.
The page lists no precondition beyond `DeviceManagementManagedDevices.Read.All` and an active
Intune licence for the tenant.

Observed for every ADE-enrolled, LAPS-managed Mac: **`500 Internal Server Error`**. The
response is the standard Graph error envelope; the `innerError` identifies the Intune device
front-end service. Details per attempt (fill from the verification run; Variant A only):

| Attempt | UTC timestamp | `request-id` | `client-request-id` | HTTP |
|---|---|---|---|---|
| 1 | `<yyyy-mm-ddThh:mm:ssZ>` | `<from response>` | `<from response>` | 500 |
| 2 | | | | 500 |
| 3 | | | | 500 |

The same user, in the same session, can open the same device in the Intune admin center and
view the password. The failure is specific to the Graph function, not to authorisation.

**Request C — property scan, to rule out an undocumented property**

```
GET https://graph.microsoft.com/v1.0/deviceManagement/managedDevices/{managedDeviceId}
GET https://graph.microsoft.com/beta/deviceManagement/managedDevices/{managedDeviceId}
```

Observed: `200 OK` on both; no property on the managed device object carries a local
administrator password or a reference to one.

A reproduction script that performs A, B and C and prints the outcome of each is published:
`tools/Verify-MacOSLapsGraph.ps1` in https://github.com/Kainor-LLC/LAPSlock. It requires
only the Graph PowerShell SDK and a delegated sign-in.

### Impact

Administrators who need a macOS local administrator password away from a desk have no
supported path except the admin center in a browser. Any third party claiming macOS LAPS
password retrieval through an API is either using an internal endpoint or overstating.
LAPSlock ships macOS as "rotation metadata only, password unavailable, open the admin
center" and says so in the App Store listing, because that is the truth of the API today.
A supported endpoint would let us, and anyone else building on Graph, do for macOS what
Windows LAPS already permits.

### What we are not asking

We are not asking for access to an internal or undocumented endpoint, and we will not use one
if offered. We are asking what the supported surface is and when it will exist.

---

## Variant B substitutions

If the Kainor tenant has no ADE-enrolled Mac, replace the "Reproduction" section's Request B
paragraph with:

> We have observed this function return `500 Internal Server Error` for ADE-enrolled,
> LAPS-managed Macs in a production tenant during evaluation, consistently across devices and
> users, while the same users could view the password in the admin center. We cannot
> reproduce it in the Kainor tenant today because it holds no ADE-enrolled Mac. If Microsoft
> can confirm the function is expected to work for such devices, we will arrange a
> reproduction environment and supply request IDs.

and delete the attempts table. Keep Requests A and C, the contract finding, and all three
asks. Ask 1 and ask 3 need no reproduction at all.

---

## Kainor's filing, ready to paste — Microsoft Q&A (Variant B)

Sign in to https://learn.microsoft.com/answers with a kainor.com account → **Ask a question**.
Tags: *Microsoft Graph*, *Microsoft Intune*. Public, so the redaction checklist below applies.

**Title**

> Is there a supported Microsoft Graph API that returns the macOS LAPS local administrator password? The only macOS function returns rotation metadata and 500s

**Body**

> I build tooling on Microsoft Graph for Intune tenants that use Windows LAPS and macOS LAPS, delegated permissions only, documented endpoints only. Disclosure: I'm the developer of a commercial admin app in this space; the question is about the API surface, not the app.
>
> **Windows LAPS** works as documented: `GET /v1.0/directory/deviceLocalCredentials/{id}?$select=credentials` returns the password and history to an authorised caller.
>
> **macOS LAPS** (Intune service release 2507) appears to have no equivalent:
>
> 1. The only macOS-specific function, `GET /beta/deviceManagement/managedDevices/{id}/retrieveDeviceLocalAdminAccountDetail`, is documented to return a `microsoft.graph.macOSDeviceLocalAdminAccountDetail` with a single property, `passwordLastRotationDateTime`. There is no password property in the contract. (Reference: https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-retrievedevicelocaladminaccountdetail?view=graph-rest-beta)
> 2. `deviceLocalCredentials/{entraDeviceId}?$select=credentials` returns `200 OK` with no `credentials` property for ADE-enrolled Macs, consistent with the docs saying macOS passwords are "stored and encrypted by Intune" rather than in the Entra store.
> 3. In practice I have also seen the beta function return `500 Internal Server Error` for ADE-enrolled, LAPS-managed Macs where the same user can view the password in the admin center. I can't reproduce that in my own tenant today (no ADE-enrolled Mac), so I'm not asking for that to be debugged here — noting it in case it's known.
>
> The admin center can display and rotate these passwords (custom RBAC: *View macOS admin password* / *Rotate macOS admin password* under Enrollment programs), so the capability exists server-side.
>
> **Questions**
>
> 1. Is there a supported Graph API, now or on the roadmap, that returns the macOS LAPS password to an authorised delegated caller, the way `deviceLocalCredentials` does for Windows?
> 2. If not planned, could the `retrieveDeviceLocalAdminAccountDetail` reference page state explicitly that the password value is not returned by any API? People find this function, assume it's the macOS equivalent of the Windows one, and only learn otherwise by calling it.
>
> I'm not looking for an internal or undocumented endpoint and wouldn't use one. Just the supported surface, or confirmation that there isn't one yet.

**Docs issue, filed the same day** — https://github.com/microsoftgraph/microsoft-graph-docs-contrib
→ Issues → New issue. Title: *retrieveDeviceLocalAdminAccountDetail: state that the password
value is not returned*. Body: two sentences pointing at
`api-reference/beta/api/intune-devices-manageddevice-retrievedevicelocaladminaccountdetail.md`,
quoting the single-property response, and asking for a note that no API returns the macOS
password. Link the Q&A thread.

## Redaction checklist before submitting anywhere public (Q&A, GitHub, Post 3)

- No tenant ID, tenant domain other than kainor.com, device name, serial number, user name or
  UPN. Graph request IDs and timestamps are the identifiers Microsoft wants and are safe to
  publish; a request ID cannot be resolved by anyone outside Microsoft.
- No mention of any organisation other than Kainor LLC, its industry, its device count, or
  where the devices are.
- Run `./scripts/pre-push-scan.sh` before committing any version of this file that contains
  real values from a case.

## Filed

- **2026-09-08 — Microsoft Q&A, Kainor's track:**
  https://learn.microsoft.com/en-us/answers/questions/5997863/is-there-a-supported-graph-api-that-returns-the-ma
  Tag: Microsoft Security → Microsoft Intune. This is the only Microsoft thread Post 3 quotes.
- Docs issue on `microsoftgraph/microsoft-graph-docs-contrib`: ⬜ file next, linking the thread
  above. Title: *retrieveDeviceLocalAdminAccountDetail: state that the password value is not
  returned by any API.*

## After the outcome

Record Microsoft's answer verbatim in this file under a new "Outcome" heading with the date
and the case number, then write Post 3 from the skeleton in `LAUNCH-POSTS.md`. If a supported
endpoint appears, `MacOSLapsProvider.swift` carries the step list to enable reveal.
