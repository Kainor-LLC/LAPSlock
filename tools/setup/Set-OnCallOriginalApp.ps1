#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Prepares the original TenantKeep On-Call app registration to be TenantKeep Actions: the
    one app an organization can approve for every write.

.DESCRIPTION
    The original registration is the one every build before the split signed in with. It
    stays, as the single app that holds every write permission, beside the separate app for
    each kind of action that tools/setup/New-OnCallApps.ps1 creates.

    This script only adds. It:

      1. Adds the consent page as a web redirect URI, so an admin consent link for this
         app has somewhere to return. Every redirect URI already there is kept.
      2. Adds any write permission from docs/app-registrations.json (the entry with key
         "actions") that the registration does not list yet. Every permission already
         listed is kept, the read permissions included: the App Store build from before
         the split still asks this registration for them.
      3. With -Rename, sets the display name to "TenantKeep Actions". Leave this until the
         build that uses the split is the one on the App Store: until then the earlier
         build reads through this registration, and its consent screen would carry a name
         that says Actions.

    Without -Apply it only prints what it would do. Safe to run again.

    It removes nothing, grants no consent in any tenant, and does not touch the scope the
    registration exposes for Instant alerts.

.PARAMETER TenantId
    Kainor's tenant, to sign in there directly. Optional.

.PARAMETER ConsentPage
    The page admin consent returns to.

.PARAMETER Rename
    Also set the display name to "TenantKeep Actions".

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.

.EXAMPLE
    pwsh ./tools/setup/Set-OnCallOriginalApp.ps1

    Prints the plan and changes nothing.

.EXAMPLE
    pwsh ./tools/setup/Set-OnCallOriginalApp.ps1 -Apply
#>
[CmdletBinding()]
param(
    [string] $TenantId,
    [string] $ConsentPage = 'https://tenantkeep.app/consent/',
    [switch] $Rename,
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphAppId = '00000003-0000-0000-c000-000000000000'

# The definition is the published list, so this script cannot drift from the app.
$listPath = Join-Path $PSScriptRoot '../../docs/app-registrations.json'
$actions = (Get-Content -Raw -Path $listPath | ConvertFrom-Json).registrations | Where-Object { $_.key -eq 'actions' }
if (-not $actions) { throw "docs/app-registrations.json has no registration with key 'actions'." }
$appId = $actions.clientId
$wanted = @($actions.scopes)

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

$connectScope = if ($Apply) { 'Application.ReadWrite.All' } else { 'Application.Read.All' }
$connect = @{ Scopes = $connectScope; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$context = Get-MgContext
Write-Information "Signed in as $($context.Account) in tenant $($context.TenantId)" -InformationAction Continue

$app = Get-MgApplication -Filter "appId eq '$appId'" | Select-Object -First 1
if (-not $app) { throw "This tenant does not own the registration $appId. Sign in to Kainor's tenant, or pass -TenantId." }
Write-Information "Registration: '$($app.DisplayName)' ($appId)" -InformationAction Continue

# 1. The consent page
$webNow = @()
if ($app.Web) { $webNow = @($app.Web.RedirectUris | Where-Object { $_ }) }
if ($webNow -contains $ConsentPage) {
    Write-Information "     The consent page is already a web redirect URI." -InformationAction Continue
} else {
    Write-Step "Add the web redirect URI $ConsentPage, keeping $($webNow.Count) already there"
    if ($Apply) { Update-MgApplication -ApplicationId $app.Id -Web @{ RedirectUris = @($webNow + $ConsentPage) } }
}

# 2. The write permissions
$graph = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
$delegated = @($graph.Oauth2PermissionScopes)
$wantedIds = foreach ($scopeName in $wanted) {
    $scope = $delegated | Where-Object { $_.Value -eq $scopeName } | Select-Object -First 1
    if (-not $scope) { throw "Microsoft Graph has no delegated permission named $scopeName." }
    [pscustomobject]@{ Name = $scopeName; Id = "$($scope.Id)" }
}

$existing = @($app.RequiredResourceAccess | Where-Object { $_ })
$graphEntry = $existing | Where-Object { $_.ResourceAppId -eq $graphAppId } | Select-Object -First 1
$listedIds = @()
if ($graphEntry) { $listedIds = @($graphEntry.ResourceAccess | ForEach-Object { "$($_.Id)" }) }
$missing = @($wantedIds | Where-Object { $listedIds -notcontains $_.Id })

if ($missing.Count -eq 0) {
    Write-Information "     Every write permission is already listed ($($wanted.Count) of $($wanted.Count))." -InformationAction Continue
} else {
    Write-Step "Add $($missing.Count) permission(s), keeping the $($listedIds.Count) Microsoft Graph permission(s) already listed: $(($missing | ForEach-Object Name) -join ', ')"
    if ($Apply) {
        $graphAccess = @()
        if ($graphEntry) { $graphAccess = @($graphEntry.ResourceAccess | ForEach-Object { @{ Id = "$($_.Id)"; Type = $_.Type } }) }
        $graphAccess += @($missing | ForEach-Object { @{ Id = $_.Id; Type = 'Scope' } })
        $others = @($existing | Where-Object { $_.ResourceAppId -ne $graphAppId } | ForEach-Object {
                @{ ResourceAppId = $_.ResourceAppId; ResourceAccess = @($_.ResourceAccess | ForEach-Object { @{ Id = "$($_.Id)"; Type = $_.Type } }) }
            })
        $updated = @(@{ ResourceAppId = $graphAppId; ResourceAccess = $graphAccess }) + $others
        Update-MgApplication -ApplicationId $app.Id -RequiredResourceAccess $updated
    }
}

# 3. The name, only when asked
if ($Rename) {
    if ($app.DisplayName -eq $actions.name) {
        Write-Information "     Already named '$($actions.name)'." -InformationAction Continue
    } else {
        Write-Step "Rename '$($app.DisplayName)' to '$($actions.name)'"
        if ($Apply) { Update-MgApplication -ApplicationId $app.Id -DisplayName $actions.name }
    }
} else {
    Write-Information "     Name left as '$($app.DisplayName)'. Pass -Rename when the split build is the one on the App Store." -InformationAction Continue
}

Write-Information '' -InformationAction Continue
if ($Apply) {
    Write-Information 'Done. Nothing was removed and no consent was granted.' -InformationAction Continue
} else {
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
