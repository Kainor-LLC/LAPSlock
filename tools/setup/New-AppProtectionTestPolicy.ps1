#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Creates a small Intune app protection policy for TenantKeep On-Call and assigns it to one
    person, for trying app protection in a test tenant.

.DESCRIPTION
    TenantKeep On-Call is not in Microsoft's list of protected apps, so a policy reaches it
    as a custom app, by its bundle ID. This script makes what that takes:

      A security group with the one person in it, because a policy is assigned to groups.
      An iOS app protection policy that asks for a PIN and stops what is copied in the app
      from being pasted into apps the organization does not manage. Nothing else is
      restricted and there are no device conditions, so a first try shows only whether the
      policy arrives.
      The policy targeted at the app's bundle ID and assigned to the group.

    And two things only when asked for:

      -Notifications sets what the policy lets a notification show.
      -Setting makes an app configuration policy for managed apps, which carries the keys
      in docs/MANAGED-CONFIG.md to a phone that is not enrolled.

    The person also needs an Intune licence. The script checks and warns; it assigns none.

    Without -Apply it only reads and prints what it would do. Safe to run again: it finds the
    group and the policies by name and sets them to exactly this definition. It deletes
    nothing: a configuration policy made earlier stays when -Setting is left out.

    For the policy to apply, the organization must also have approved TenantKeep App
    Protection, the app registration Microsoft's Intune App SDK enrols through. Turning on
    Intune App Protection in the app's Settings, General asks for that.

    The app fetches a policy when the person signs in and about every eight hours after, so
    a change made here is seen soonest by signing out of the app and in again.

.PARAMETER User
    The person to assign the policy to, by sign-in address.

.PARAMETER TenantId
    The tenant to sign in to. Optional.

.PARAMETER PolicyName
    The policy's name in Intune. The configuration policy is named after it.

.PARAMETER GroupName
    The security group the policies are assigned to. Created with the person in it when it
    does not exist; the person is added when they are missing from it.

.PARAMETER BundleId
    The app the policies target.

.PARAMETER Notifications
    What a notification may show: allow (everything), blockOrganizationalData (that there is
    an alert, and nothing about it), or block (no notifications; the app also unregisters
    the phone from Instant alerts).

.PARAMETER Setting
    Configuration keys for the app, each as key=value, for example
    confirmation.level=strict or watch.allowed=true. Several: separate them with commas.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.

.EXAMPLE
    pwsh ./tools/setup/New-AppProtectionTestPolicy.ps1 -User someone@contoso.com

    Prints the plan and changes nothing.

.EXAMPLE
    pwsh ./tools/setup/New-AppProtectionTestPolicy.ps1 -User someone@contoso.com -Apply

.EXAMPLE
    pwsh ./tools/setup/New-AppProtectionTestPolicy.ps1 -User someone@contoso.com -Notifications blockOrganizationalData -Setting confirmation.level=strict -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $User,
    [string] $TenantId,
    [string] $PolicyName = 'TenantKeep On-Call Test',
    [string] $GroupName = 'TenantKeep App Protection Test',
    [string] $BundleId = 'com.kainor.lapslock',
    [ValidateSet('allow', 'blockOrganizationalData', 'block')] [string] $Notifications = 'allow',
    [string[]] $Setting = @(),
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

function Get-Graph([string] $Path, [string] $Version = 'v1.0') {
    Invoke-MgGraphRequest -Method GET -Uri "/$Version$Path" -OutputType PSObject
}

function Send-Graph([string] $Method, [string] $Path, $Body, [string] $Version = 'v1.0') {
    Invoke-MgGraphRequest -Method $Method -Uri "/$Version$Path" -Body ($Body | ConvertTo-Json -Depth 8) -ContentType 'application/json' -OutputType PSObject
}

# Targeting and assigning are actions on a policy. For a protection policy Microsoft's
# reference lists them under managedAppPolicies and its own tools call them on the iOS
# policy; one of the two answers. For a configuration policy there is the one path.
function Invoke-PolicyAction([string] $Collection, [string] $PolicyId, [string] $Action, $Body) {
    try {
        Send-Graph 'POST' "/deviceAppManagement/$Collection/$PolicyId/$Action" $Body | Out-Null
    } catch {
        if ($Collection -ne 'iosManagedAppProtections') { throw }
        Write-Information "     $Action on the iOS policy was refused ($($_.Exception.Message)); trying managedAppPolicies." -InformationAction Continue
        Send-Graph 'POST' "/deviceAppManagement/managedAppPolicies/$PolicyId/$Action" $Body | Out-Null
    }
}

# Started with -File, PowerShell hands over "a=1,b=2" as one value. Split it.
$pairs = @($Setting | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
$custom = @(foreach ($pair in $pairs) {
        $at = $pair.IndexOf('=')
        if ($at -lt 1) { throw "-Setting takes key=value, and got '$pair'." }
        @{ '@odata.type' = 'microsoft.graph.keyValuePair'; name = $pair.Substring(0, $at).Trim(); value = $pair.Substring($at + 1).Trim() }
    })
$configurationName = "$PolicyName Configuration"

# The definition. A PIN, and nothing copied here can be pasted into an app the organization
# does not manage. Everything else is left open on purpose.
$settings = [ordered]@{
    '@odata.type'                           = '#microsoft.graph.iosManagedAppProtection'
    displayName                             = $PolicyName
    description                             = 'Test policy for TenantKeep On-Call: a PIN, and no pasting into apps that are not managed. Made by New-AppProtectionTestPolicy.ps1.'
    pinRequired                             = $true
    minimumPinLength                        = 4
    pinCharacterSet                         = 'numeric'
    simplePinBlocked                        = $false
    maximumPinRetries                       = 5
    fingerprintBlocked                      = $false
    faceIdBlocked                           = $false
    disableAppPinIfDevicePinIsSet           = $false
    periodBeforePinReset                    = 'PT0S'
    allowedOutboundClipboardSharingLevel    = 'managedAppsWithPasteIn'
    allowedInboundDataTransferSources       = 'allApps'
    allowedOutboundDataTransferDestinations = 'allApps'
    allowedDataStorageLocations             = @()
    organizationalCredentialsRequired       = $false
    dataBackupBlocked                       = $false
    deviceComplianceRequired                = $false
    managedBrowserToOpenLinksRequired       = $false
    managedBrowser                          = 'notConfigured'
    saveAsBlocked                           = $false
    contactSyncBlocked                      = $false
    printBlocked                            = $false
    appDataEncryptionType                   = 'whenDeviceLocked'
    periodOfflineBeforeAccessCheck          = 'PT12H'
    periodOnlineBeforeAccessCheck           = 'PT30M'
    periodOfflineBeforeWipeIsEnforced       = 'P90D'
}

$targetApps = @{
    appGroupType = 'selectedPublicApps'
    apps         = @(@{
            '@odata.type'       = '#microsoft.graph.managedMobileApp'
            mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = $BundleId.ToLowerInvariant() }
        })
}

# A dry run only reads.
$scopes = if ($Apply) {
    'DeviceManagementApps.ReadWrite.All', 'Group.ReadWrite.All', 'User.Read.All'
} else {
    'DeviceManagementApps.Read.All', 'Group.Read.All', 'User.Read.All'
}
$connect = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$context = Get-MgContext
Write-Information "Signed in as $($context.Account) in tenant $($context.TenantId)" -InformationAction Continue

# 1. The person, and whether Intune is licensed for them
$person = Get-Graph "/users/$([uri]::EscapeDataString($User))?`$select=id,userPrincipalName,displayName"
Write-Information "     $($person.displayName) is $($person.id)." -InformationAction Continue
$licences = @((Get-Graph "/users/$($person.id)/licenseDetails").value)
$intune = @($licences | ForEach-Object { $_.servicePlans } | Where-Object { $_.servicePlanName -like 'INTUNE_A*' -and $_.provisioningStatus -eq 'Success' })
if ($intune.Count -gt 0) {
    Write-Information '     They have an Intune licence.' -InformationAction Continue
} else {
    Write-Warning "$User has no Intune licence that this script can see. Without one Intune answers 'not licensed' and no policy applies."
}

# 2. The group
$escapedGroup = $GroupName.Replace("'", "''")
$group = @((Get-Graph "/groups?`$filter=displayName eq '$escapedGroup'&`$select=id,displayName,securityEnabled").value) | Select-Object -First 1
if (-not $group) {
    Write-Step "Create the security group '$GroupName' with $User in it"
    if ($Apply) {
        $group = Send-Graph 'POST' '/groups' @{
            displayName          = $GroupName
            description          = 'Who the TenantKeep On-Call test app protection policy is assigned to.'
            mailEnabled          = $false
            mailNickname         = ($GroupName -replace '[^A-Za-z0-9]', '').ToLowerInvariant()
            securityEnabled      = $true
            'members@odata.bind' = @("https://graph.microsoft.com/v1.0/users/$($person.id)")
        }
    }
} else {
    $members = @((Get-Graph "/groups/$($group.id)/members?`$select=id").value | ForEach-Object { $_.id })
    if ($members -contains $person.id) {
        Write-Information "     '$GroupName' exists and $User is in it." -InformationAction Continue
    } else {
        Write-Step "Add $User to '$GroupName'"
        if ($Apply) {
            Send-Graph 'POST' "/groups/$($group.id)/members/`$ref" @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($person.id)" } | Out-Null
        }
    }
}
$assign = if ($group) {
    @{ assignments = @(@{
                '@odata.type' = '#microsoft.graph.targetedManagedAppPolicyAssignment'
                target        = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = "$($group.id)" }
            })
    }
}

# 3. The protection policy
$policy = @((Get-Graph '/deviceAppManagement/iosManagedAppProtections?$select=id,displayName').value) | Where-Object { $_.displayName -eq $PolicyName } | Select-Object -First 1
if (-not $policy) {
    Write-Step "Create the app protection policy '$PolicyName': a PIN of 4 digits, paste only into managed apps"
    if ($Apply) { $policy = Send-Graph 'POST' '/deviceAppManagement/iosManagedAppProtections' $settings }
} else {
    Write-Step "Set '$PolicyName' ($($policy.id)) to exactly this definition"
    if ($Apply) { Send-Graph 'PATCH' "/deviceAppManagement/iosManagedAppProtections/$($policy.id)" $settings | Out-Null }
}
Write-Step "Set what a notification may show to: $Notifications"
Write-Step "Target '$PolicyName' at the custom app $BundleId"
Write-Step "Assign '$PolicyName' to '$GroupName'"
if ($Apply) {
    # What a notification may show is not in Graph v1.0 yet, so this one call goes to beta.
    Send-Graph 'PATCH' "/deviceAppManagement/iosManagedAppProtections/$($policy.id)" @{
        '@odata.type'           = '#microsoft.graph.iosManagedAppProtection'
        notificationRestriction = $Notifications
    } 'beta' | Out-Null
    Invoke-PolicyAction 'iosManagedAppProtections' $policy.id 'targetApps' $targetApps
    Invoke-PolicyAction 'iosManagedAppProtections' $policy.id 'assign' $assign

    # Read back what Intune holds. A call that was accepted and did nothing fails here.
    $made = Get-Graph "/deviceAppManagement/iosManagedAppProtections/$($policy.id)?`$expand=apps,assignments" 'beta'
    $targeted = @($made.apps | ForEach-Object { $_.mobileAppIdentifier.bundleId })
    if ($targeted -notcontains $BundleId.ToLowerInvariant()) { throw "The policy does not target $BundleId. It targets: $($targeted -join ', ')" }
    $assigned = @($made.assignments | ForEach-Object { $_.target.groupId })
    if ($assigned -notcontains $group.id) { throw "The policy is not assigned to '$GroupName'. It is assigned to: $($assigned -join ', ')" }
    if ($made.notificationRestriction -ne $Notifications) { throw "Notifications are '$($made.notificationRestriction)', not '$Notifications'." }
    Write-Information "     '$PolicyName' ($($policy.id)) targets $($targeted -join ', '), is assigned to '$GroupName', PIN required: $($made.pinRequired), clipboard: $($made.allowedOutboundClipboardSharingLevel), notifications: $($made.notificationRestriction)." -InformationAction Continue
}

# 4. The configuration policy, when keys were given
$configuration = @((Get-Graph '/deviceAppManagement/targetedManagedAppConfigurations?$select=id,displayName').value) | Where-Object { $_.displayName -eq $configurationName } | Select-Object -First 1
if ($custom.Count -eq 0) {
    if ($configuration) {
        Write-Information "     '$configurationName' ($($configuration.id)) exists and is left as it is. Pass -Setting to change it, or delete it in Intune." -InformationAction Continue
    }
} else {
    $definition = @{
        '@odata.type'  = '#microsoft.graph.targetedManagedAppConfiguration'
        displayName    = $configurationName
        description    = 'Test configuration for TenantKeep On-Call through the managed apps channel. Made by New-AppProtectionTestPolicy.ps1.'
        customSettings = $custom
    }
    $listed = ($custom | ForEach-Object { "$($_.name)=$($_.value)" }) -join ', '
    if (-not $configuration) {
        Write-Step "Create the app configuration policy '$configurationName' for managed apps: $listed"
        if ($Apply) { $configuration = Send-Graph 'POST' '/deviceAppManagement/targetedManagedAppConfigurations' $definition }
    } else {
        Write-Step "Set '$configurationName' ($($configuration.id)) to exactly: $listed"
        if ($Apply) { Send-Graph 'PATCH' "/deviceAppManagement/targetedManagedAppConfigurations/$($configuration.id)" $definition | Out-Null }
    }
    Write-Step "Target '$configurationName' at $BundleId and assign it to '$GroupName'"
    if ($Apply) {
        Invoke-PolicyAction 'targetedManagedAppConfigurations' $configuration.id 'targetApps' $targetApps
        Invoke-PolicyAction 'targetedManagedAppConfigurations' $configuration.id 'assign' $assign

        $made = Get-Graph "/deviceAppManagement/targetedManagedAppConfigurations/$($configuration.id)?`$expand=apps,assignments"
        $targeted = @($made.apps | ForEach-Object { $_.mobileAppIdentifier.bundleId })
        if ($targeted -notcontains $BundleId.ToLowerInvariant()) { throw "The configuration policy does not target $BundleId. It targets: $($targeted -join ', ')" }
        $assigned = @($made.assignments | ForEach-Object { $_.target.groupId })
        if ($assigned -notcontains $group.id) { throw "The configuration policy is not assigned to '$GroupName'. It is assigned to: $($assigned -join ', ')" }
        $held = (@($made.customSettings) | ForEach-Object { "$($_.name)=$($_.value)" }) -join ', '
        Write-Information "     '$configurationName' ($($configuration.id)) targets $($targeted -join ', '), is assigned to '$GroupName', and holds: $held." -InformationAction Continue
    }
}

Write-Information '' -InformationAction Continue
if ($Apply) {
    Write-Information 'Done. The app fetches a policy at sign-in and about every eight hours: sign out of the app and in again to see a change now.' -InformationAction Continue
} else {
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
