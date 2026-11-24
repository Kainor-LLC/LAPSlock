#Requires -Version 7.4
<#
.SYNOPSIS
    Lets the relay accept alerts from Kainor's alert service by the service's own identity
    (docs/RELAY-API.md, section 15).

.DESCRIPTION
    Run in Kainor's tenant, signed in with the Azure CLI (az login --tenant kainor.com), by an
    account that can create app registrations, assign app roles, and change the two function
    apps' settings. Without -Apply it only prints what it would do. Safe to run again: it
    finds what exists, and changes only what differs.

    1. "TenantKeep Relay": an app registration in Kainor's tenant only. It holds no
       permission to anything. It exists so a token can be issued for the relay and nothing
       else, and it defines one application role, Alerts.Send.
    2. Its enterprise application requires assignment, so Microsoft Entra ID issues a token
       for the relay only to an identity that has been given the role.
    3. The alert service's function app identity is given Alerts.Send. Nothing else is.
    4. The relay's settings name Kainor's tenant and the registration (SERVICE_TENANT_ID,
       SERVICE_CLIENT_ID), which turns its /relay/service route on, and the alert service's
       identity (SERVICE_CALLER_ID, its object ID), so that no other identity given the
       role is accepted. A relay published before SERVICE_CALLER_ID existed ignores it.
    5. Once the relay answers on that route, the alert service's setting names the audience
       (RELAY_SERVICE_AUDIENCE), which moves its alerts onto it. Before that this step is
       skipped, so the order of publishing cannot lose an alert: publish the relay, run this
       again, publish the alert service.

    No secret is created anywhere: the alert service proves itself with its managed identity.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.
#>
[CmdletBinding()]
param(
    [string] $WatchFunction = 'kainor-watch-prod-func',
    [string] $WatchResourceGroup = 'kainor-watch-prod-rg',
    [string] $RelayFunction = 'kainor-relay-prod-func',
    [string] $RelayResourceGroup = 'kainor-relay-prod-rg',
    [string] $RelayHost = 'kainor-relay-prod-func.azurewebsites.net',
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$appName = 'TenantKeep Relay'
$roleValue = 'Alerts.Send'
$graph = 'https://graph.microsoft.com/v1.0'

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

function Invoke-Az {
    $out = & az @args --only-show-errors
    if ($LASTEXITCODE -ne 0) { throw "az $($args[0..2] -join ' ') failed." }
    $out
}

function Read-Az {
    $text = Invoke-Az @args --output json
    if ($text) { ($text -join "`n") | ConvertFrom-Json -Depth 20 }
}

function Send-Graph([string] $Method, [string] $Uri, [hashtable] $Body) {
    $file = New-TemporaryFile
    try {
        $Body | ConvertTo-Json -Depth 10 | Set-Content -Path $file.FullName -Encoding utf8
        Invoke-Az rest --method $Method --uri $Uri --headers 'Content-Type=application/json' --body "@$($file.FullName)" --output none
    } finally {
        Remove-Item $file.FullName -ErrorAction SilentlyContinue
    }
}

$account = Read-Az account show
$tenantId = $account.tenantId
Write-Information "Tenant $tenantId, signed in as $($account.user.name)" -InformationAction Continue

# 1. The registration
$app = Read-Az ad app list --display-name $appName --query '[0]'
if (-not $app) {
    Write-Step "Create app '$appName' (this tenant only, no permissions) with the application role $roleValue"
    if ($Apply) {
        $roles = New-TemporaryFile
        try {
            ConvertTo-Json -Depth 5 -InputObject @(@{
                allowedMemberTypes = @('Application')
                description        = "Send an encrypted alert through the relay as Kainor's alert service."
                displayName        = 'Send alerts'
                id                 = [guid]::NewGuid().ToString()
                isEnabled          = $true
                value              = $roleValue
            }) | Set-Content -Path $roles.FullName -Encoding utf8
            Invoke-Az ad app create --display-name $appName --sign-in-audience AzureADMyOrg --app-roles "@$($roles.FullName)" --output none
        } finally {
            Remove-Item $roles.FullName -ErrorAction SilentlyContinue
        }
        $app = Read-Az ad app list --display-name $appName --query '[0]'
    }
}
if ($app) {
    $role = $app.appRoles | Where-Object { $_.value -eq $roleValue -and $_.isEnabled }
    if (-not $role) { throw "'$appName' exists without the role $roleValue. Add it by hand, or delete the registration and run this again." }
    if ($app.signInAudience -ne 'AzureADMyOrg') { throw "'$appName' accepts other tenants ($($app.signInAudience)). It must be this tenant only." }
    $uri = "api://$($app.appId)"
    if ($app.identifierUris -notcontains $uri -or $app.api.requestedAccessTokenVersion -ne 2) {
        Write-Step "Give '$appName' the address $uri and version 2 tokens"
        if ($Apply) {
            Send-Graph PATCH "$graph/applications/$($app.id)" @{ identifierUris = @($uri); api = @{ requestedAccessTokenVersion = 2 } }
        }
    }
}

# 2. Its enterprise application, which requires assignment
$sp = if ($app) { Read-Az ad sp list --filter "appId eq '$($app.appId)'" --query '[0]' }
if ($app -and -not $sp) {
    Write-Step "Create the enterprise application for '$appName'"
    if ($Apply) {
        Invoke-Az ad sp create --id $app.appId --output none
        $sp = Read-Az ad sp list --filter "appId eq '$($app.appId)'" --query '[0]'
    }
}
if ($sp -and -not $sp.appRoleAssignmentRequired) {
    Write-Step "Require assignment on '$appName', so only an identity given $roleValue gets a token for it"
    if ($Apply) { Send-Graph PATCH "$graph/servicePrincipals/$($sp.id)" @{ appRoleAssignmentRequired = $true } }
}

# 3. The alert service's identity gets the role
$principal = (Invoke-Az functionapp identity show --name $WatchFunction --resource-group $WatchResourceGroup --query principalId --output tsv)
if (-not $principal) { throw "$WatchFunction has no managed identity." }
if ($sp) {
    $held = Read-Az rest --method GET --uri "$graph/servicePrincipals/$($sp.id)/appRoleAssignedTo"
    $others = @($held.value | Where-Object { $_.principalId -ne $principal })
    if ($others.Count -gt 0) {
        Write-Warning "$($others.Count) other identity holds a role on '$appName': $(($others | ForEach-Object { $_.principalDisplayName }) -join ', '). Only $WatchFunction should."
    }
    if (-not ($held.value | Where-Object { $_.principalId -eq $principal -and $_.appRoleId -eq $role.id })) {
        Write-Step "Give $WatchFunction's identity ($principal) the role $roleValue on '$appName'"
        if ($Apply) {
            Send-Graph POST "$graph/servicePrincipals/$($sp.id)/appRoleAssignedTo" @{ principalId = $principal; resourceId = $sp.id; appRoleId = $role.id }
        }
    }
} else {
    Write-Step "Give $WatchFunction's identity ($principal) the role $roleValue on '$appName'"
}

# 4. The relay's settings
$relayNow = @{}
foreach ($setting in (Read-Az functionapp config appsettings list --name $RelayFunction --resource-group $RelayResourceGroup --query "[?name=='SERVICE_TENANT_ID' || name=='SERVICE_CLIENT_ID' || name=='SERVICE_CALLER_ID']")) { $relayNow[$setting.name] = $setting.value }
$clientId = if ($app) { $app.appId } else { '<the new client ID>' }
if ($relayNow['SERVICE_TENANT_ID'] -ne $tenantId -or $relayNow['SERVICE_CLIENT_ID'] -ne $clientId -or $relayNow['SERVICE_CALLER_ID'] -ne $principal) {
    Write-Step "Set SERVICE_TENANT_ID=$tenantId, SERVICE_CLIENT_ID=$clientId and SERVICE_CALLER_ID=$principal on $RelayFunction"
    if ($Apply) {
        Invoke-Az functionapp config appsettings set --name $RelayFunction --resource-group $RelayResourceGroup --settings "SERVICE_TENANT_ID=$tenantId" "SERVICE_CLIENT_ID=$clientId" "SERVICE_CALLER_ID=$principal" --output none
    }
}

# 5. The alert service's setting, only once the relay answers on the new route
$audience = "api://$clientId"
$watchNow = Read-Az functionapp config appsettings list --name $WatchFunction --resource-group $WatchResourceGroup --query "[?name=='RELAY_SERVICE_AUDIENCE'] | [0]"
$status = try {
    [int](Invoke-WebRequest -Method Post -Uri "https://$RelayHost/relay/service" -Body '{}' -ContentType 'application/json' -SkipHttpErrorCheck -TimeoutSec 30).StatusCode
} catch { 0 }
if ($watchNow -and $watchNow.value -eq $audience) {
    Write-Information "$WatchFunction already sends as the alert service." -InformationAction Continue
} elseif ($status -eq 401) {
    Write-Step "Set RELAY_SERVICE_AUDIENCE=$audience on $WatchFunction"
    if ($Apply) {
        Invoke-Az functionapp config appsettings set --name $WatchFunction --resource-group $WatchResourceGroup --settings "RELAY_SERVICE_AUDIENCE=$audience" --output none
    }
} else {
    Write-Information "SKIP The relay answered $status on /relay/service, not 401: its new code is not published yet. Publish the relay, then run this again to move $WatchFunction onto it." -InformationAction Continue
}

Write-Information '' -InformationAction Continue
Write-Information "relayClientId    $clientId" -InformationAction Continue
Write-Information "relayAudience    $audience" -InformationAction Continue
if (-not $Apply) { Write-Information 'Nothing was changed. Run again with -Apply.' -InformationAction Continue }
