# TenantKeep Watch, Hosted by Kainor

The service behind Instant alerts: it watches an organization that has approved it, with
read-only Microsoft Graph application permissions, and sends encrypted alerts to the phones
its administrators register, through the relay (`relay/`). The plan, the permission list and
what it keeps are in the private repo's `HOSTED-WATCH-PLAN.md`; the privacy terms are in the
privacy policy once it ships.

Status: in service for Kainor's own tenant since 2026-11-15. Its only endpoints are the two a
phone calls, with its administrator's Microsoft token, to register and to unregister
(`/api/v1/devices`). Nothing is reachable with a function key: the four setup endpoints the
first test used were removed on 2026-11-23.

## What It Runs On

`watch/infra/main.bicep`, one resource group in Central US:

| Resource | Why |
|---|---|
| Function app, Flex Consumption, .NET 10 isolated, system identity, HTTPS only | The watcher and the registration API |
| Storage account, identity only (shared keys off) | Tables for organizations, cursors and phones; the deployment package |
| Key Vault, RBAC, purge protection | The alert sender's private key, readable by the function's identity alone |
| Log Analytics capped at 0.1 GB a day, Application Insights | Counts and durations only |
| A $10 monthly budget | Email at 80 percent spent and at a forecast over 100 |

The function's identity holds Storage Blob Data Owner, Queue Data Contributor and Table Data
Contributor on its own storage account, and Key Vault Secrets User on its own vault, and
nothing else. It reads customer tenants as the TenantKeep Watch app, through a federated
credential that trusts this identity, so there is no secret to steal.

Expected cost at a few dozen organizations: a few dollars a month. One timer run a minute
covers every organization, the Flex Consumption free monthly grant covers that many runs
(verify in Cost Management after the first month), storage and Key Vault cost cents, and
logs are capped.

## Setting It Up

In Kainor's tenant, from the repository root. Each step prints what the next one needs.

1. Sign in and pick the subscription.

```
az login --tenant kainor.com
az account set --subscription KainorLLC
```

2. The resources. Note `functionPrincipalId` and `vaultName` from the output. This first deployment is the only one that passes `none`: nothing it names exists yet.

```
az group create --name kainor-watch-prod-rg --location centralus
az deployment group create --resource-group kainor-watch-prod-rg --template-file watch/infra/main.bicep --parameters budgetEmail=connor@kainor.com watchClientId=none alertsApiAudience=none relayServiceAudience=none noLocationRuleId=none
```

3. The Entra app. Read the plan it prints, then run it again with `-Apply`. It prints `watchClientId` and `alertsApiAudience`, which is TenantKeep Alerts' client ID, bare. Phones present tokens for that registration, which `tools/setup/New-OnCallApps.ps1` makes.

```
pwsh ./watch/infra/New-WatchApps.ps1 -FunctionPrincipalId <functionPrincipalId>
pwsh ./watch/infra/New-WatchApps.ps1 -FunctionPrincipalId <functionPrincipalId> -Apply
```

4. The resources again, with the two values.

```
az deployment group create --resource-group kainor-watch-prod-rg --template-file watch/infra/main.bicep --parameters budgetEmail=connor@kainor.com watchClientId=<watchClientId> alertsApiAudience=<alertsApiAudience> relayServiceAudience=none noLocationRuleId=none
```

5. The sender key. Give yourself Key Vault Secrets Officer on the vault for this step only, then take it away.

```
az role assignment create --role "Key Vault Secrets Officer" --assignee connor@kainor.com --scope /subscriptions/<subscription id>/resourceGroups/kainor-watch-prod-rg/providers/Microsoft.KeyVault/vaults/kainor-watch-prod-kv
pwsh ./watch/infra/New-WatchSenderKey.ps1 -VaultName kainor-watch-prod-kv
az role assignment delete --role "Key Vault Secrets Officer" --assignee connor@kainor.com --scope /subscriptions/<subscription id>/resourceGroups/kainor-watch-prod-rg/providers/Microsoft.KeyVault/vaults/kainor-watch-prod-kv
```

6. The relay's trust in this service. Read the plan it prints, then run it again with `-Apply`. It makes the "TenantKeep Relay" registration, gives this function's identity the `Alerts.Send` role on it, and sets the relay's two settings. It sets this function's `RELAY_SERVICE_AUDIENCE` only once the relay answers on `/relay/service`, so publish the relay first and run it once more. It prints `relayAudience`.

```
pwsh ./watch/infra/New-RelayServiceTrust.ps1
pwsh ./watch/infra/New-RelayServiceTrust.ps1 -Apply
```

7. The rule that keeps locations out of the log: `pwsh ./watch/infra/Set-LogLocationBlanking.ps1 -ResourceGroup kainor-watch-prod-rg -Workspace kainor-watch-prod-law`. It prints nothing to keep; the rule's ID is read below.

Every later deployment of `main.bicep` passes all four of its app parameters, as they are now. The template writes every setting, and since 2026-11-24 it refuses to run without them: one left out was written empty, which stopped the service, or sent its alerts to a route that refuses them, or dropped the log rule. Read the values first:

```
az functionapp config appsettings list --name kainor-watch-prod-func --resource-group kainor-watch-prod-rg --query "[?name=='WATCH_CLIENT_ID' || name=='ALERTS_API_AUDIENCE' || name=='RELAY_SERVICE_AUDIENCE']" --output table
az monitor log-analytics workspace show --resource-group kainor-watch-prod-rg --workspace-name kainor-watch-prod-law --query defaultDataCollectionRuleResourceId --output tsv
```

`ALERTS_API_AUDIENCE` holds bare client IDs, comma separated. A token's audience is the bare client ID of the registration it was issued for, so an `api://` form there refuses every phone.

## Publishing the Code

From `watch/function`, signed in as above. Publishing replaces every function in the app,
so a function removed from the code is removed from the service.

```
func azure functionapp publish kainor-watch-prod-func --dotnet-isolated
```

## Checking It

The service has no endpoint that reports its state. Its log has one line a minute holding
counts only, and this prints how many runs there were, when the last one was, each run
that sent an alert or had a failure, and each phone the service refused to register:

```
pwsh ./watch/infra/Get-WatchRuns.ps1
```

`notSent=403x1` on a line means one alert was answered 403 by the relay; `0` is a request
that got no answer. `outcomes=` says what became of every alert in the run:
`202 production x1, 502 BadDeviceToken sandbox x2; newest 202 production` is one alert
Apple took for a production address and two Apple refused, with Apple's own word for why,
for addresses registered as sandbox. `newest` is the outcome for the phone that registered
or checked in last, which answers "it says registered and nothing arrived" for the phone
in your hand. `BadDeviceToken` is an address that is not valid for the service it was
registered for: an old address, or a development build's address registered as production
or the reverse. The service drops such an address after the one refusal, as it does an
address Apple answers 410 for, and a phone still in use registers again at its next
check-in. `RegisterDevice refused reason=Expired` is a phone whose Microsoft
sign-in the service would not accept, which the phone shows as "answered 401". The reason
is the kind of refusal only (Expired, InvalidAudience, InvalidIssuer, noScope, noToken).
The log keeps no place. Azure Application Insights works out a city and country from the
address each request arrives from and stores them on the log row; nothing in a function
app's settings turns that off. `watch/infra/Set-LogLocationBlanking.ps1` puts a rule on the
log workspace that empties those columns as rows arrive, and `-Check` shows whether any
row of the last hour still carries one. Run it again after anything that redeploys the
workspace, `main.bicep` included, because a redeploy may drop the link to the rule.

To test the whole path, sign in with a break-glass account the organization has named and
expect the alert within about five minutes. The phone has to allow notifications from
TenantKeep: iOS gives an app no push address until it may show them, so turning Instant
alerts on asks first.

## Before Customers See It

- **Publisher verification** for the TenantKeep Watch app, so the approval screen shows Kainor as a verified publisher. It needs a Microsoft AI Cloud Partner Program ID (verify). Organizations that block unverified multi-tenant apps cannot approve it without this.
- The federated credential trusting a managed identity, used to sign in to other tenants: confirm it works against the lab tenant before relying on it (verify).
