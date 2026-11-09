# TenantKeep Watch, Hosted by Kainor

The service behind Instant alerts: it watches an organization that has approved it, with
read-only Microsoft Graph application permissions, and sends encrypted alerts to the phones
its administrators register, through the relay (`relay/`). The plan, the permission list and
what it keeps are in the private repo's `HOSTED-WATCH-PLAN.md`; the privacy terms are in the
privacy policy once it ships.

Status: step H1, the Azure side. The service's code (H2, H3) is not written yet.

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

2. The resources. Note `functionPrincipalId` and `vaultName` from the output.

```
az group create --name kainor-watch-prod-rg --location centralus
az deployment group create --resource-group kainor-watch-prod-rg --template-file watch/infra/main.bicep --parameters budgetEmail=connor@kainor.com
```

3. The two Entra apps and the On-Call app's new permission. Read the plan it prints, then run it again with `-Apply`. It prints `watchClientId` and `alertsApiAudience`.

```
pwsh ./watch/infra/New-WatchApps.ps1 -FunctionPrincipalId <functionPrincipalId>
pwsh ./watch/infra/New-WatchApps.ps1 -FunctionPrincipalId <functionPrincipalId> -Apply
```

4. The resources again, with the two values.

```
az deployment group create --resource-group kainor-watch-prod-rg --template-file watch/infra/main.bicep --parameters budgetEmail=connor@kainor.com watchClientId=<watchClientId> alertsApiAudience=<alertsApiAudience>
```

5. The sender key. Give yourself Key Vault Secrets Officer on the vault for this step only, then take it away.

```
az role assignment create --role "Key Vault Secrets Officer" --assignee connor@kainor.com --scope /subscriptions/<subscription id>/resourceGroups/kainor-watch-prod-rg/providers/Microsoft.KeyVault/vaults/kainor-watch-prod-kv
pwsh ./watch/infra/New-WatchSenderKey.ps1 -VaultName kainor-watch-prod-kv
az role assignment delete --role "Key Vault Secrets Officer" --assignee connor@kainor.com --scope /subscriptions/<subscription id>/resourceGroups/kainor-watch-prod-rg/providers/Microsoft.KeyVault/vaults/kainor-watch-prod-kv
```

Nothing runs until the function code is published (step H3), so these resources cost
almost nothing before then.

## Before Customers See It

- **Publisher verification** for the TenantKeep Watch app, so the approval screen shows Kainor as a verified publisher. It needs a Microsoft AI Cloud Partner Program ID (verify). Organizations that block unverified multi-tenant apps cannot approve it without this.
- The federated credential trusting a managed identity, used to sign in to other tenants: confirm it works against the lab tenant before relying on it (verify).
