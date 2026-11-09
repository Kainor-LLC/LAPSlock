#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Creates the two Entra apps for TenantKeep Watch, hosted by Kainor (HOSTED-WATCH-PLAN.md, H1).

.DESCRIPTION
    Run in Kainor's tenant, after main.bicep, by an account that can create app registrations
    and edit the On-Call app (Application Administrator or Global Administrator). Without
    -Apply it only prints what it would do. Safe to run again: it finds what exists by name.

    1. "TenantKeep Watch": multi-tenant, application permissions only, read-only, the fixed
       list in the plan's section 3 (v1: break-glass, Conditional Access, incidents). No
       secret and no certificate: a federated identity credential trusts the function app's
       managed identity instead.
    2. "TenantKeep Alerts API": multi-tenant, exposes one delegated scope, Alerts.Register,
       pre-authorized for the On-Call app so registering a phone asks for no extra consent.
    3. On the existing On-Call app: the delegated permission Alerts.Register, so the phone can
       get a token for the Alerts API.

.PARAMETER FunctionPrincipalId
    The function app's managed identity object ID: main.bicep's functionPrincipalId output.

.PARAMETER OnCallAppId
    The On-Call app's client ID. The default is the shipping one.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [guid] $FunctionPrincipalId,
    [guid] $OnCallAppId = '50c9aa83-4f5c-4203-a3c0-adab54a2ba3a',
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphAppId = '00000003-0000-0000-c000-000000000000'
# The fixed list. Adding to it is a decision recorded in HOSTED-WATCH-PLAN.md, not an edit here.
$watchPermissions = @('AuditLog.Read.All', 'Directory.Read.All', 'Policy.Read.All', 'SecurityIncident.Read.All')
$scopeName = 'Alerts.Register'

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

# 2. TenantKeep Alerts API
$api = Get-MgApplication -Filter "displayName eq 'TenantKeep Alerts API'" | Select-Object -First 1
if (-not $api) {
    Write-Step "Create app 'TenantKeep Alerts API' (multi-tenant) exposing the delegated scope $scopeName"
    if ($Apply) {
        $api = New-MgApplication -DisplayName 'TenantKeep Alerts API' -SignInAudience 'AzureADMultipleOrgs' `
            -Notes 'Registers phones for TenantKeep Instant alerts. HOSTED-WATCH-PLAN.md.'
        $scopeId = [guid]::NewGuid()
        Update-MgApplication -ApplicationId $api.Id -IdentifierUris @("api://$($api.AppId)") -Api @{
            RequestedAccessTokenVersion = 2
            Oauth2PermissionScopes      = @(@{
                Id                      = $scopeId
                Value                   = $scopeName
                Type                    = 'User'
                IsEnabled               = $true
                AdminConsentDisplayName = 'Register phones for TenantKeep Instant alerts'
                AdminConsentDescription = 'Lets an administrator register their phone to receive TenantKeep Instant alerts for this organization.'
                UserConsentDisplayName  = 'Register your phone for TenantKeep Instant alerts'
                UserConsentDescription  = 'Lets TenantKeep register this phone to receive Instant alerts for your organization.'
            })
        }
        Update-MgApplication -ApplicationId $api.Id -Api @{
            RequestedAccessTokenVersion = 2
            PreAuthorizedApplications   = @(@{ AppId = "$OnCallAppId"; DelegatedPermissionIds = @("$scopeId") })
        }
        $api = Get-MgApplication -ApplicationId $api.Id
    }
}

# 3. The On-Call app asks for Alerts.Register
if ($api) {
    $scope = $api.Api.Oauth2PermissionScopes | Where-Object Value -eq $scopeName
    $onCall = Get-MgApplication -Filter "appId eq '$OnCallAppId'"
    if (-not $onCall) { throw "No app with client ID $OnCallAppId in this tenant." }
    $existing = @($onCall.RequiredResourceAccess)
    if (-not ($existing | Where-Object ResourceAppId -eq $api.AppId)) {
        Write-Step "Add the delegated permission $scopeName to the On-Call app ($OnCallAppId), keeping its $($existing.Count) existing resource entries"
        if ($Apply) {
            $updated = @($existing | ForEach-Object {
                    @{ ResourceAppId = $_.ResourceAppId; ResourceAccess = @($_.ResourceAccess | ForEach-Object { @{ Id = $_.Id; Type = $_.Type } }) }
                }) + @(@{ ResourceAppId = $api.AppId; ResourceAccess = @(@{ Id = $scope.Id; Type = 'Scope' }) })
            Update-MgApplication -ApplicationId $onCall.Id -RequiredResourceAccess $updated
        }
    }
} else {
    Write-Step "Add the delegated permission $scopeName to the On-Call app ($OnCallAppId)"
}

if ($Apply) {
    Write-Information '' -InformationAction Continue
    Write-Information "watchClientId     = $($watch.AppId)" -InformationAction Continue
    Write-Information "alertsApiAudience = api://$($api.AppId)" -InformationAction Continue
    Write-Information 'Run main.bicep again with those two parameters.' -InformationAction Continue
} else {
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}
