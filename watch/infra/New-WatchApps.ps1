#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Creates the Entra app for TenantKeep Watch, hosted by Kainor (HOSTED-WATCH-PLAN.md, H1).

.DESCRIPTION
    Run in Kainor's tenant, after main.bicep, by an account that can create app registrations
    (Application Administrator or Global Administrator). Without -Apply it only prints what
    it would do. Safe to run again: it finds what exists by name.

    "TenantKeep Watch": multi-tenant, application permissions only, read-only, the fixed
    list in the plan's section 3 (v1: break-glass, Conditional Access, incidents). No secret
    and no certificate: a federated identity credential trusts the function app's managed
    identity instead. Its permissions are set to exactly the list, so running this again
    after the list shrinks takes the dropped permission off the registration. Organizations
    that already approved it keep that grant until they remove it.

    Phones register with the scope Alerts.Register of "TenantKeep Alerts", which
    tools/setup/New-OnCallApps.ps1 makes. This script made an earlier "TenantKeep Alerts API"
    and added its scope to the original On-Call registration; since the second review (R2-15,
    2026-11-24) it does neither, because following its output on a redeploy set the service
    to accept that API's tokens only, and every phone's check-in failed.

.PARAMETER FunctionPrincipalId
    The function app's managed identity object ID: main.bicep's functionPrincipalId output.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [guid] $FunctionPrincipalId,
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphAppId = '00000003-0000-0000-c000-000000000000'
# The fixed list. Adding to it is a decision recorded in HOSTED-WATCH-PLAN.md, not an edit here.
# Policy.Read.All was on it and nothing used it: Conditional Access changes come from the
# directory audit log, which AuditLog.Read.All covers (second review, R2-14, 2026-11-24).
$watchPermissions = @('AuditLog.Read.All', 'Directory.Read.All', 'SecurityIncident.Read.All')
# TenantKeep Alerts, made by tools/setup/New-OnCallApps.ps1: the registration whose token a
# phone presents. ALERTS_API_AUDIENCE takes bare client IDs.
$alertsClientId = 'd7c387b7-8e67-4957-bc67-4b71824a60ea'

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

Connect-MgGraph -Scopes 'Application.ReadWrite.All' -NoWelcome
$tenantId = (Get-MgContext).TenantId

$graph = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
$roleIds = foreach ($name in $watchPermissions) {
    $role = $graph.AppRoles | Where-Object { $_.Value -eq $name -and $_.AllowedMemberTypes -contains 'Application' }
    if (-not $role) { throw "Microsoft Graph has no application permission named $name." }
    $role.Id
}

# 1. TenantKeep Watch
$watch = Get-MgApplication -Filter "displayName eq 'TenantKeep Watch'" | Select-Object -First 1
$access = @{
    ResourceAppId  = $graphAppId
    ResourceAccess = @($roleIds | ForEach-Object { @{ Id = $_; Type = 'Role' } })
}
if (-not $watch) {
    Write-Step "Create app 'TenantKeep Watch' (multi-tenant) with $($watchPermissions -join ', ') as application permissions"
    if ($Apply) {
        $watch = New-MgApplication -DisplayName 'TenantKeep Watch' -SignInAudience 'AzureADMultipleOrgs' `
            -RequiredResourceAccess @($access) -Notes 'TenantKeep Instant alerts. Read-only. HOSTED-WATCH-PLAN.md.'
    }
} else {
    Write-Step "Set the permissions of 'TenantKeep Watch' ($($watch.AppId)) to exactly $($watchPermissions -join ', ')"
    if ($Apply) { Update-MgApplication -ApplicationId $watch.Id -RequiredResourceAccess @($access) }
}

if ($watch) {
    $fic = Get-MgApplicationFederatedIdentityCredential -ApplicationId $watch.Id |
        Where-Object { $_.Subject -eq "$FunctionPrincipalId" }
    if (-not $fic) {
        Write-Step "Trust the function app's identity $FunctionPrincipalId as the Watch app's credential"
        if ($Apply) {
            New-MgApplicationFederatedIdentityCredential -ApplicationId $watch.Id -Name 'watch-function-identity' `
                -Issuer "https://login.microsoftonline.com/$tenantId/v2.0" -Subject "$FunctionPrincipalId" `
                -Audiences @('api://AzureADTokenExchange') | Out-Null
        }
    }
} else {
    Write-Step "Trust the function app's identity $FunctionPrincipalId as the Watch app's credential"
}

if ($Apply) {
    Write-Information '' -InformationAction Continue
    Write-Information "watchClientId     = $($watch.AppId)" -InformationAction Continue
    Write-Information "alertsApiAudience = $alertsClientId" -InformationAction Continue
    Write-Information 'Run main.bicep again with those, as watch/README.md says.' -InformationAction Continue
} else {
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}
