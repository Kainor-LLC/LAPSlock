#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Creates TenantKeep On-Call's write app registrations in Kainor's tenant.

.DESCRIPTION
    TenantKeep On-Call signs in through one read-only app registration, shared with
    TenantKeep Posture, and through one separate registration for each kind of write. An
    organization that approves only the read app has given TenantKeep nothing that can
    change its tenant, and a write is possible only through the app whose switch it turned
    on.

    This script creates the four write apps that do not exist yet:

      TenantKeep Device Actions     sync, restart, remote lock, retire, wipe, locate,
                                    key and password rotation, and reading a Mac's admin
                                    password (Microsoft files that read under the same
                                    permission as remote actions)
      TenantKeep User Actions       revoke sessions, block or unblock sign-in, confirm
                                    compromised or dismiss risk
      TenantKeep Account Recovery   remove sign-in methods, issue a Temporary Access Pass
      TenantKeep Group Membership   add or remove a group member

    Role activation keeps the existing On-Call registration, which this script does not
    touch. The shared read app belongs to the TenantKeep Posture repository.

    Each app is multi-tenant, a public client with no secret and no certificate, and holds
    delegated Microsoft Graph permissions only. It carries the iPhone and iPad redirect
    URI, and the approval page as a web redirect so an admin consent link has somewhere to
    return.

    Without -Apply it only prints what it would do, after checking that every permission
    name exists. Safe to run again: it finds what exists by name and sets it to exactly
    this definition.

    It does not create service principals, grant consent in any tenant, or change the
    existing On-Call registration or the shared read app.

.PARAMETER TenantId
    Kainor's tenant, to sign in there directly. Optional.

.PARAMETER ApprovalPage
    The page admin consent returns to. Registered as a web redirect URI on each app.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.

.EXAMPLE
    pwsh ./tools/setup/New-OnCallWriteApps.ps1

    Prints the plan and changes nothing.

.EXAMPLE
    pwsh ./tools/setup/New-OnCallWriteApps.ps1 -Apply

    Creates or updates the four apps and prints their client IDs.
#>
[CmdletBinding()]
param(
    [string] $TenantId,
    [string] $ApprovalPage = 'https://kainor.com/approve/',
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphAppId = '00000003-0000-0000-c000-000000000000'
# The registration every shipped build signs in with. It must live in the tenant this
# script runs in: that is the check against creating these apps in the wrong tenant.
$onCallAppId = '50c9aa83-4f5c-4203-a3c0-adab54a2ba3a'
# The iPhone and iPad app. The Mac menu bar app performs none of these writes.
$iosRedirect = 'msauth.com.kainor.lapslock://auth'

# The definition. A change here is a change to what an organization is asked to approve:
# keep it in step with the scope table in LAPSlockKit and the permissions page on the site.
$definitions = @(
    @{
        Name   = 'TenantKeep Device Actions'
        Scopes = @(
            'DeviceManagementManagedDevices.PrivilegedOperations.All'
            'DeviceManagementManagedDevices.ReadWrite.All'
        )
        Notes  = 'TenantKeep On-Call: device actions and Mac admin password reveal. Delegated only, no secret.'
    }
    @{
        Name   = 'TenantKeep User Actions'
        Scopes = @(
            'User.RevokeSessions.All'
            'User.EnableDisableAccount.All'
            # Graph requires this on the same token as User.EnableDisableAccount.All.
            'User.Read.All'
            'IdentityRiskyUser.ReadWrite.All'
        )
        Notes  = 'TenantKeep On-Call: revoke sessions, block sign-in, risk. Delegated only, no secret.'
    }
    @{
        Name   = 'TenantKeep Account Recovery'
        Scopes = @(
            'UserAuthenticationMethod.ReadWrite.All'
            'UserAuthMethod-TAP.ReadWrite.All'
        )
        Notes  = 'TenantKeep On-Call: sign-in methods and Temporary Access Pass. Delegated only, no secret.'
    }
    @{
        Name   = 'TenantKeep Group Membership'
        Scopes = @('GroupMember.ReadWrite.All')
        Notes  = 'TenantKeep On-Call: group membership. Delegated only, no secret.'
    }
)

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

# A dry run only reads.
$connectScope = if ($Apply) { 'Application.ReadWrite.All' } else { 'Application.Read.All' }
$connect = @{ Scopes = $connectScope; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$context = Get-MgContext
Write-Information "Signed in as $($context.Account) in tenant $($context.TenantId)" -InformationAction Continue

$onCall = Get-MgApplication -Filter "appId eq '$onCallAppId'" | Select-Object -First 1
if (-not $onCall) {
    throw "This tenant does not own the On-Call registration ($onCallAppId). Sign in to Kainor's tenant, or pass -TenantId."
}

$graph = Get-MgServicePrincipal -Filter "appId eq '$graphAppId'"
$delegated = @($graph.Oauth2PermissionScopes)

$results = foreach ($definition in $definitions) {
    $name = $definition.Name
    $scopeIds = foreach ($scopeName in $definition.Scopes) {
        $scope = $delegated | Where-Object { $_.Value -eq $scopeName } | Select-Object -First 1
        if (-not $scope) { throw "Microsoft Graph has no delegated permission named $scopeName (wanted by $name)." }
        $scope.Id
    }
    $access = @{
        ResourceAppId  = $graphAppId
        ResourceAccess = @($scopeIds | ForEach-Object { @{ Id = $_; Type = 'Scope' } })
    }
    $settings = @{
        SignInAudience         = 'AzureADMultipleOrgs'
        IsFallbackPublicClient = $true
        PublicClient           = @{ RedirectUris = @($iosRedirect) }
        Web                    = @{ RedirectUris = @($ApprovalPage) }
        RequiredResourceAccess = @($access)
        Notes                  = $definition.Notes
    }

    $app = Get-MgApplication -Filter "displayName eq '$name'" | Select-Object -First 1
    if (-not $app) {
        Write-Step "Create '$name' (multi-tenant, public client, no secret) with $($definition.Scopes -join ', ')"
        Write-Step "  redirects: $iosRedirect and $ApprovalPage"
        if ($Apply) { $app = New-MgApplication -DisplayName $name @settings }
    } else {
        Write-Step "Set '$name' ($($app.AppId)) to exactly $($definition.Scopes -join ', ')"
        Write-Step "  redirects: $iosRedirect and $ApprovalPage"
        if ($Apply) { Update-MgApplication -ApplicationId $app.Id @settings }
    }
    if ($app) { [pscustomobject]@{ App = $name; ClientId = $app.AppId } }
}

Write-Information '' -InformationAction Continue
if ($results) { Write-Information ($results | Format-Table -AutoSize | Out-String) -InformationAction Continue }
if ($Apply) {
    Write-Information 'Done. The client IDs above go into the On-Call code and the approval page.' -InformationAction Continue
    Write-Information 'Still to do by hand for each app: verified publisher, and its ID in docs/.well-known/microsoft-identity-association.json.' -InformationAction Continue
} else {
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
