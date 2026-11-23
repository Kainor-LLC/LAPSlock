# TenantKeep Instant Alerts, version 1

Instant alerts are the one part of TenantKeep On-Call that runs on a server Kainor operates, and only for an organization that turns them on. This page is the contract: what the service reads, what it keeps, what the phone sends it, and how to stop it. The service's source is in this repository under `watch/`; the alert envelope is the relay's ([RELAY-API.md](RELAY-API.md)).

## 1. What It Does

TenantKeep On-Call's own notifications are made on the phone, when iOS lets the app check, which can take minutes or hours. Instant alerts are for three events where minutes matter:

| Alert | Checked | Opens |
|---|---|---|
| A sign-in by an account the organization names as a break-glass account | Every minute | People |
| A Conditional Access policy added, changed or deleted | Every five minutes | Conditional Access |
| A security incident that is new, or rose in severity, at medium or above, and still open | Every five minutes | Security |

Microsoft writes sign-ins and audit entries to its logs a few minutes after they happen, so an alert usually arrives two to six minutes after the event.

An alert names the kind of event and the organization, for example "Contoso: break-glass sign-in". It never names a person, a policy or an incident. Tapping it opens the module, where the app reads the detail itself, from Microsoft, as the administrator.

## 2. Turning It On

1. An administrator turns on Instant alerts in TenantKeep On-Call (Settings, Notifications). The app says what follows, and asks to go ahead.
2. The organization approves the **TenantKeep Watch** application in Microsoft Entra ID, once. Only a Global Administrator or Privileged Role Administrator can. The app shows the approval link and can send it to one.
3. The phone registers with the service (section 4) and starts receiving alerts.

Instant alerts are part of Pro and organization licenses.

## 3. What the Service Reads

TenantKeep Watch is a multi-tenant Entra application, separate from the On-Call app, with these Microsoft Graph **application** permissions and no others:

| Permission | Why |
|---|---|
| `AuditLog.Read.All` | Sign-ins of the named break-glass accounts; Conditional Access entries in the directory audit log |
| `Directory.Read.All` | Reading sign-ins as an application needs it; resolving the named accounts' object IDs; the organization's name; the registering administrator's active roles |
| `Policy.Read.All` | Conditional Access policy changes |
| `SecurityIncident.Read.All` | Security incidents |

Each sign-in query is limited to the accounts the organization named. The service cannot change anything: it has no write permission. It cannot read local administrator passwords, BitLocker recovery keys, mail, files or messages, because those permissions are never requested. Adding a permission is a published change to this page.

TenantKeep Watch signs in to Microsoft with a federated credential bound to the service's own Azure managed identity. There is no client secret or certificate to steal.

## 4. What the Phone Sends

`POST https://kainor-watch-prod-func.azurewebsites.net/api/v1/devices`, when the administrator turns Instant alerts on, then about once a day and whenever the phone's push address changes:

```json
{
  "deviceToken": "a694...1513",
  "environment": "production",
  "publicKey": "BFYY...0SQ",
  "breakGlass": ["bg-admin@contoso.com"]
}
```

| Field | Meaning |
|---|---|
| `deviceToken` | The phone's Apple push token |
| `environment` | `production`, or `sandbox` for development builds |
| `publicKey` | The phone's public key, made in its Secure Enclave, X9.63, base64url |
| `breakGlass` | The break-glass accounts set for the organization in the app. Applied only from an active Global Administrator or Security Administrator |

The request carries a Microsoft token issued for the `Alerts.Register` scope of the TenantKeep Alerts app registration, which holds no Microsoft Graph permission. The service checks its signature, lifetime, issuer and scope, takes the organization from it, and allows registration only for an account with an active Global Administrator, Security Administrator, Security Operator, Security Reader or Global Reader role. That token cannot read anything from Microsoft. No Microsoft Graph token ever reaches the service.

The answer carries the service's public sender key, which the phone keeps for that organization so it can open, and authenticate, what the service sends. `DELETE` on the same address, with the push token, removes the phone.

## 5. What the Service Keeps

For each organization: its tenant ID; its name, which alerts carry; the object IDs of the named break-glass accounts; whether the approval is in place; and, for each kind of alert, the time and opaque identifiers of the last events seen, so nothing is announced twice.

For each phone: its push token, its public key, the registering administrator's object ID, and when it last checked in.

It does not keep the sign-ins, audit entries or incidents it reads. Each is examined in memory to decide whether to alert, and discarded. It keeps no names, email addresses, IP addresses or locations. Its telemetry records counts and durations, never a tenant ID, push token, object ID or anything read from a tenant.

| Data | Deleted |
|---|---|
| A phone | When Instant alerts are turned off on it, or 30 days after it last checked in |
| Everything for an organization | Within a day of the organization removing TenantKeep Watch from Entra ID |

The service runs in Microsoft Azure, Central US. Its sub-processors are Microsoft (Azure) and Apple (Apple Push Notification service, which sees the push token and an encrypted alert it cannot read).

## 6. The Alert

Each alert is a relay envelope ([RELAY-API.md](RELAY-API.md) section 5): HPKE in authenticated mode, from the service's sender key to the phone's Secure Enclave key, bound to the phone's push token, sent through Kainor's relay to Apple. Kainor's service necessarily knows that an alert of a given kind happened in an organization at a given time, because it creates the alert; it does not keep that fact once the alert is sent.

## 7. Stopping It

- **One phone:** turn Instant alerts off in the app. The phone is removed from the service and its key is deleted.
- **The whole organization:** delete TenantKeep Watch in Microsoft Entra ID, Enterprise applications. The service can no longer read anything from that moment, and deletes what it holds within a day.

## 8. Verify This Yourself

- The permissions TenantKeep Watch holds are visible in your tenant: Entra ID, Enterprise applications, TenantKeep Watch, Permissions.
- Every read appears in your tenant's logs as TenantKeep Watch, as with any application.
- A proxy on the phone shows the requests in section 4, to the one host, only with Instant alerts on.
- The source is in `watch/` in this repository.

## Change Log

- 2026-11-15: version 1. Break-glass sign-ins, Conditional Access changes and security incidents.
