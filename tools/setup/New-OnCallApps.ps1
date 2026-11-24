#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Applications
<#
.SYNOPSIS
    Creates TenantKeep On-Call's app registrations in Kainor's tenant: one for each kind of
    write, one for Instant alerts, and one for Intune app protection.

.DESCRIPTION
    TenantKeep On-Call signs in through one read-only app registration, shared with
    TenantKeep Posture, and writes through separate registrations. An organization that
    approves only the read app has given TenantKeep nothing that can change its tenant.

    For writes an organization chooses one of two routes:

      A separate app for each kind of action, which this script creates:

        TenantKeep Role Activation    activate a role or group membership, approve or deny
        TenantKeep Device Actions     sync, restart, remote lock, retire, wipe, locate,
                                      key and password rotation, and reading a Mac's admin
                                      password (Microsoft files that read under the same
                                      permission as remote actions)
        TenantKeep User Actions       revoke sessions, block or unblock sign-in, confirm
                                      compromised or dismiss risk
        TenantKeep Account Recovery   remove sign-in methods, issue a Temporary Access Pass
        TenantKeep Group Membership   add or remove a group member

      One app for every action: the original On-Call registration, which this script does
      not touch.

    It also creates TenantKeep Alerts, which holds no Microsoft Graph permission at all. It
    defines one scope of its own, Alerts.Register, which a phone presents to Kainor's
    Instant alerts service, and it is its own client for that scope.

    And it creates TenantKeep App Protection, which holds no Microsoft Graph permission
    either. It holds the one permission Microsoft's Intune App SDK needs to enrol the app
    for a person whose organization targets it with an app protection policy:
    DeviceManagementManagedApps.ReadWrite on Microsoft Mobile Application Management, which
    reads and writes that person's own app management record and nothing in the tenant.
    The permission is on a registration of its own because its name is not a read, and the
    sign-in registration holds reads only. An organization that does not use app protection
    never approves it.

    Each app is multi-tenant, a public client with no secret and no certificate. The write
    apps hold delegated Microsoft Graph permissions only. Each carries the redirect URI of
    the app that signs into it, and the consent page as a web redirect so an admin consent
    link has somewhere to return.

    Without -Apply it only prints what it would do, after checking that every permission
    name exists. Safe to run again: it finds what exists by name and sets it to exactly
    this definition.

    It does not create service principals, grant consent in any tenant, or change the
    original On-Call registration or the shared read app.

.PARAMETER TenantId
    Kainor's tenant, to sign in there directly. Optional.

.PARAMETER ConsentPage
    The page admin consent returns to. Registered as the web redirect URI on each app.

.PARAMETER PublisherId
    Kainor's Microsoft partner ID, to mark each app as coming from a verified publisher, so
    its consent screen does not say "unverified". The same ID the shared read app carries.
    Optional. Needs an account that is also an administrator in Partner Center, signed in
    with multifactor authentication.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.

.EXAMPLE
    pwsh ./tools/setup/New-OnCallApps.ps1

    Prints the plan and changes nothing.

.EXAMPLE
    pwsh ./tools/setup/New-OnCallApps.ps1 -Apply

    Creates or updates the seven apps and prints their client IDs.
#>
[CmdletBinding()]
param(
    [string] $TenantId,
    [string] $ConsentPage = 'https://tenantkeep.app/consent/',
    [string] $PublisherId,
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$graphAppId = '00000003-0000-0000-c000-000000000000'
# The registration every shipped build signs in with. It must live in the tenant this
# script runs in: that is the check against creating these apps in the wrong tenant.
$onCallAppId = '50c9aa83-4f5c-4203-a3c0-adab54a2ba3a'
# The iPhone and iPad app, and the Mac menu bar app. The Mac app activates roles and
# performs no other write.
$iosRedirect = 'msauth.com.kainor.lapslock://auth'
$macRedirect = 'msauth.com.kainor.tenantkeep.menubar://auth'

# The definition. A change here is a change to what an organization is asked to approve:
# keep it in step with AppRegistration in LAPSlockKit and docs/app-registrations.json.
$definitions = @(
    @{
        Name      = 'TenantKeep Role Activation'
        Scopes    = @(
            'RoleAssignmentSchedule.ReadWrite.Directory'
            'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup'
        )
        Redirects = @($iosRedirect, $macRedirect)
        Notes     = 'TenantKeep On-Call: role and group activation, approvals. Delegated only, no secret.'
    }
    @{
        Name      = 'TenantKeep Device Actions'
        Scopes    = @(
            'DeviceManagementManagedDevices.PrivilegedOperations.All'
            'DeviceManagementManagedDevices.ReadWrite.All'
        )
        Redirects = @($iosRedirect)
        Notes     = 'TenantKeep On-Call: device actions and Mac admin password reveal. Delegated only, no secret.'
    }
    @{
        Name      = 'TenantKeep User Actions'
        Scopes    = @(
            'User.RevokeSessions.All'
            'User.EnableDisableAccount.All'
            # Graph requires this on the same token as User.EnableDisableAccount.All.
            'User.Read.All'
            'IdentityRiskyUser.ReadWrite.All'
        )
        Redirects = @($iosRedirect)
        Notes     = 'TenantKeep On-Call: revoke sessions, block sign-in, risk. Delegated only, no secret.'
    }
    @{
        Name      = 'TenantKeep Account Recovery'
        Scopes    = @(
            'UserAuthenticationMethod.ReadWrite.All'
            'UserAuthMethod-TAP.ReadWrite.All'
        )
        Redirects = @($iosRedirect)
        Notes     = 'TenantKeep On-Call: sign-in methods and Temporary Access Pass. Delegated only, no secret.'
    }
    @{
        Name      = 'TenantKeep Group Membership'
        Scopes    = @('GroupMember.ReadWrite.All')
        Redirects = @($iosRedirect)
        Notes     = 'TenantKeep On-Call: group membership. Delegated only, no secret.'
    }
)

$alertsName = 'TenantKeep Alerts'
$alertsScope = 'Alerts.Register'

# Intune app protection. The permission is on Microsoft's Mobile Application Management
# service, not on Microsoft Graph, so it is looked up there. The service is found by the
# name Microsoft documents and exists only in a tenant that has Intune.
$protectionName = 'TenantKeep App Protection'
$protectionService = 'Microsoft Mobile Application Management'
$protectionScope = 'DeviceManagementManagedApps.ReadWrite'

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

# Marks an app as from the verified publisher, when an ID was given and it is not already.
# A refusal is a warning: the app works without it, and Microsoft's reasons (no Partner
# Center role, no multifactor sign-in, a publisher domain that does not match) are the
# caller's to fix, not this script's.
function Set-Publisher($App, [string] $Name) {
    if (-not $PublisherId) { return }
    if (-not $App) { Write-Step "Mark '$Name' as from the verified publisher $PublisherId"; return }
    $current = if ($App.VerifiedPublisher) { $App.VerifiedPublisher.VerifiedPublisherId } else { $null }
    if ($current -eq $PublisherId) {
        Write-Information "     '$Name' is already from the verified publisher." -InformationAction Continue
        return
    }
    Write-Step "Mark '$Name' as from the verified publisher $PublisherId"
    if ($Apply) {
        try {
            Set-MgApplicationVerifiedPublisher -ApplicationId $App.Id -VerifiedPublisherId $PublisherId
        } catch {
            Write-Warning "Could not set the verified publisher on '$Name': $($_.Exception.Message)"
        }
    }
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

# 1. The write apps
$results = @(foreach ($definition in $definitions) {
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
        PublicClient           = @{ RedirectUris = @($definition.Redirects) }
        Web                    = @{ RedirectUris = @($ConsentPage) }
        RequiredResourceAccess = @($access)
        Notes                  = $definition.Notes
    }

    $app = Get-MgApplication -Filter "displayName eq '$name'" | Select-Object -First 1
    if (-not $app) {
        Write-Step "Create '$name' (multi-tenant, public client, no secret) with $($definition.Scopes -join ', ')"
        Write-Step "  redirects: $($definition.Redirects -join ', ') and $ConsentPage"
        if ($Apply) { $app = New-MgApplication -DisplayName $name @settings }
    } else {
        Write-Step "Set '$name' ($($app.AppId)) to exactly $($definition.Scopes -join ', ')"
        Write-Step "  redirects: $($definition.Redirects -join ', ') and $ConsentPage"
        if ($Apply) { Update-MgApplication -ApplicationId $app.Id @settings }
    }
    Set-Publisher $app $name
    if ($app) { [pscustomobject]@{ App = $name; ClientId = $app.AppId } }
})

# 2. TenantKeep Alerts: no Microsoft Graph permission, one scope of its own
$alertsSettings = @{
    SignInAudience         = 'AzureADMultipleOrgs'
    IsFallbackPublicClient = $true
    PublicClient           = @{ RedirectUris = @($iosRedirect) }
    Web                    = @{ RedirectUris = @($ConsentPage) }
    Notes                  = 'TenantKeep On-Call: registers a phone for Instant alerts. No Microsoft Graph permission, no secret.'
}
$alerts = Get-MgApplication -Filter "displayName eq '$alertsName'" | Select-Object -First 1
if (-not $alerts) {
    Write-Step "Create '$alertsName' (multi-tenant, public client, no secret, no Microsoft Graph permission)"
    Write-Step "  redirects: $iosRedirect and $ConsentPage"
    if ($Apply) { $alerts = New-MgApplication -DisplayName $alertsName @alertsSettings }
} else {
    Write-Step "Set '$alertsName' ($($alerts.AppId)) redirects to exactly $iosRedirect and $ConsentPage"
    if ($Apply) { Update-MgApplication -ApplicationId $alerts.Id @alertsSettings }
}

$defined = $null
if ($alerts -and $alerts.Api) {
    $defined = $alerts.Api.Oauth2PermissionScopes | Where-Object { $_ -and $_.Value -eq $alertsScope } | Select-Object -First 1
}
if ($defined) {
    Write-Information "     '$alertsName' already defines $alertsScope." -InformationAction Continue
} else {
    Write-Step "Define the scope $alertsScope on '$alertsName': v2 tokens, and the app pre-authorized for its own scope"
    if ($Apply) {
        $scopeId = [guid]::NewGuid().ToString()
        $scopeDefinition = @{
            Id                      = $scopeId
            Value                   = $alertsScope
            Type                    = 'User'
            IsEnabled               = $true
            AdminConsentDisplayName = 'Register phones for TenantKeep Instant alerts'
            AdminConsentDescription = 'Lets an administrator register their phone to receive TenantKeep Instant alerts for this organization.'
            UserConsentDisplayName  = 'Register your phone for TenantKeep Instant alerts'
            UserConsentDescription  = 'Lets TenantKeep register this phone to receive Instant alerts for your organization.'
        }
        # The scope has to exist before anything can be pre-authorized for it.
        Update-MgApplication -ApplicationId $alerts.Id -IdentifierUris @("api://$($alerts.AppId)") -Api @{
            RequestedAccessTokenVersion = 2
            Oauth2PermissionScopes      = @($scopeDefinition)
        }
        Update-MgApplication -ApplicationId $alerts.Id -Api @{
            RequestedAccessTokenVersion = 2
            Oauth2PermissionScopes      = @($scopeDefinition)
            PreAuthorizedApplications   = @(@{ AppId = "$($alerts.AppId)"; DelegatedPermissionIds = @($scopeId) })
        }
        # Listed under the app's own required permissions so an admin consent link has a
        # registered permission to name. Sign-in works without it, so a refusal is a
        # warning and not a stop.
        try {
            Update-MgApplication -ApplicationId $alerts.Id -RequiredResourceAccess @(@{
                    ResourceAppId  = "$($alerts.AppId)"
                    ResourceAccess = @(@{ Id = $scopeId; Type = 'Scope' })
                })
        } catch {
            Write-Warning "Could not list $alertsScope under '$alertsName' required permissions: $($_.Exception.Message)"
        }
    }
}
Set-Publisher $alerts $alertsName
if ($alerts) { $results += [pscustomobject]@{ App = $alertsName; ClientId = $alerts.AppId } }

# 3. TenantKeep App Protection: no Microsoft Graph permission, one on Microsoft's Mobile
#    Application Management service
$mam = @(Get-MgServicePrincipal -Filter "displayName eq '$protectionService'")
if ($mam.Count -ne 1) {
    throw "Expected one service named '$protectionService' in this tenant and found $($mam.Count). It exists only where Intune is licensed."
}
$mamScope = @($mam[0].Oauth2PermissionScopes) | Where-Object { $_.Value -eq $protectionScope } | Select-Object -First 1
if (-not $mamScope) { throw "'$protectionService' ($($mam[0].AppId)) has no delegated permission named $protectionScope." }
Write-Information "     '$protectionService' is $($mam[0].AppId); $protectionScope is $($mamScope.Id)." -InformationAction Continue

$protectionSettings = @{
    SignInAudience         = 'AzureADMultipleOrgs'
    IsFallbackPublicClient = $true
    PublicClient           = @{ RedirectUris = @($iosRedirect) }
    Web                    = @{ RedirectUris = @($ConsentPage) }
    RequiredResourceAccess = @(@{
            ResourceAppId  = "$($mam[0].AppId)"
            ResourceAccess = @(@{ Id = "$($mamScope.Id)"; Type = 'Scope' })
        })
    Notes                  = 'TenantKeep On-Call: Intune app protection enrolment. One delegated permission on Mobile Application Management, none on Microsoft Graph, no secret.'
}
$protection = Get-MgApplication -Filter "displayName eq '$protectionName'" | Select-Object -First 1
if (-not $protection) {
    Write-Step "Create '$protectionName' (multi-tenant, public client, no secret) with $protectionScope on $protectionService"
    Write-Step "  redirects: $iosRedirect and $ConsentPage"
    if ($Apply) { $protection = New-MgApplication -DisplayName $protectionName @protectionSettings }
} else {
    Write-Step "Set '$protectionName' ($($protection.AppId)) to exactly $protectionScope on $protectionService"
    Write-Step "  redirects: $iosRedirect and $ConsentPage"
    if ($Apply) { Update-MgApplication -ApplicationId $protection.Id @protectionSettings }
}
Set-Publisher $protection $protectionName
if ($protection) { $results += [pscustomobject]@{ App = $protectionName; ClientId = $protection.AppId } }

# An app an earlier version of the alerts plan created. Reported, never changed here.
$earlier = Get-MgApplication -Filter "displayName eq 'TenantKeep Alerts API'" | Select-Object -First 1
if ($earlier) {
    Write-Information "     Note: an earlier app 'TenantKeep Alerts API' ($($earlier.AppId)) exists and is not used. Delete it by hand if nothing needs it." -InformationAction Continue
}

Write-Information '' -InformationAction Continue
if ($results) { Write-Information ($results | Format-Table -AutoSize | Out-String) -InformationAction Continue }
if ($Apply) {
    Write-Information 'Done. The client IDs above go into the On-Call code and the consent page.' -InformationAction Continue
    Write-Information 'Each app also belongs in docs/.well-known/microsoft-identity-association.json, and wants a verified publisher: pass -PublisherId to set it, or to check that it is set.' -InformationAction Continue
} else {
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
