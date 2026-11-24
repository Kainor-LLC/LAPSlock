#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Creates a small Intune app protection policy for TenantKeep On-Call and assigns it to one
    person, for trying app protection in a test tenant.

.DESCRIPTION
    TenantKeep On-Call is not in Microsoft's list of protected apps, so a policy reaches it
    as a custom app, by its bundle ID. This script makes the three things that takes:

      A security group with the one person in it, because a policy is assigned to groups.
      An iOS app protection policy that asks for a PIN and stops what is copied in the app
      from being pasted into apps the organization does not manage. Nothing else is
      restricted and there are no device conditions, so a first try shows only whether the
      policy arrives.
      The policy targeted at the app's bundle ID and assigned to the group.

    The person also needs an Intune licence. The script checks and warns; it assigns none.

    Without -Apply it only reads and prints what it would do. Safe to run again: it finds the
    group and the policy by name and sets the policy to exactly this definition.

    For the policy to apply, the organization must also have approved TenantKeep App
    Protection, the app registration Microsoft's Intune App SDK enrols through. Turning on
    Intune App Protection in the app's Settings, General asks for that.

.PARAMETER User
    The person to assign the policy to, by sign-in address.

.PARAMETER TenantId
    The tenant to sign in to. Optional.

.PARAMETER PolicyName
    The policy's name in Intune.

.PARAMETER GroupName
    The security group the policy is assigned to. Created with the person in it when it does
    not exist; the person is added when they are missing from it.

.PARAMETER BundleId
    The app the policy targets.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.

.EXAMPLE
    pwsh ./tools/setup/New-AppProtectionTestPolicy.ps1 -User someone@contoso.com

    Prints the plan and changes nothing.

.EXAMPLE
    pwsh ./tools/setup/New-AppProtectionTestPolicy.ps1 -User someone@contoso.com -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $User,
    [string] $TenantId,
    [string] $PolicyName = 'TenantKeep On-Call Test',
    [string] $GroupName = 'TenantKeep App Protection Test',
    [string] $BundleId = 'com.kainor.lapslock',
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

function Get-Graph([string] $Path) {
    Invoke-MgGraphRequest -Method GET -Uri "/v1.0$Path" -OutputType PSObject
}

function Send-Graph([string] $Method, [string] $Path, $Body) {
    Invoke-MgGraphRequest -Method $Method -Uri "/v1.0$Path" -Body ($Body | ConvertTo-Json -Depth 8) -ContentType 'application/json' -OutputType PSObject
}

# Targeting and assigning are actions on the policy. Microsoft's reference lists them under
# managedAppPolicies; its own tools call them on the iOS policy. One of the two answers.
function Invoke-PolicyAction([string] $PolicyId, [string] $Action, $Body) {
    try {
        Send-Graph 'POST' "/deviceAppManagement/iosManagedAppProtections/$PolicyId/$Action" $Body | Out-Null
    } catch {
        Write-Information "     $Action on the iOS policy was refused ($($_.Exception.Message)); trying managedAppPolicies." -InformationAction Continue
        Send-Graph 'POST' "/deviceAppManagement/managedAppPolicies/$PolicyId/$Action" $Body | Out-Null
    }
}

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

# 3. The policy
$policy = @((Get-Graph '/deviceAppManagement/iosManagedAppProtections?$select=id,displayName').value) | Where-Object { $_.displayName -eq $PolicyName } | Select-Object -First 1
if (-not $policy) {
    Write-Step "Create the app protection policy '$PolicyName': a PIN of 4 digits, paste only into managed apps"
    if ($Apply) { $policy = Send-Graph 'POST' '/deviceAppManagement/iosManagedAppProtections' $settings }
} else {
    Write-Step "Set '$PolicyName' ($($policy.id)) to exactly this definition"
    if ($Apply) { Send-Graph 'PATCH' "/deviceAppManagement/iosManagedAppProtections/$($policy.id)" $settings | Out-Null }
}

Write-Step "Target '$PolicyName' at the custom app $BundleId"
Write-Step "Assign '$PolicyName' to '$GroupName'"
if ($Apply) {
    Invoke-PolicyAction $policy.id 'targetApps' @{
        appGroupType = 'selectedPublicApps'
        apps         = @(@{
                '@odata.type'       = '#microsoft.graph.managedMobileApp'
                mobileAppIdentifier = @{ '@odata.type' = '#microsoft.graph.iosMobileAppIdentifier'; bundleId = $BundleId.ToLowerInvariant() }
            })
    }
    Invoke-PolicyAction $policy.id 'assign' @{
        assignments = @(@{
                '@odata.type' = '#microsoft.graph.targetedManagedAppPolicyAssignment'
                target        = @{ '@odata.type' = '#microsoft.graph.groupAssignmentTarget'; groupId = "$($group.id)" }
            })
    }

    # Read back what Intune holds. A call that was accepted and did nothing fails here.
    $made = Get-Graph "/deviceAppManagement/iosManagedAppProtections/$($policy.id)?`$expand=apps,assignments"
    $targeted = @($made.apps | ForEach-Object { $_.mobileAppIdentifier.bundleId })
    if ($targeted -notcontains $BundleId.ToLowerInvariant()) { throw "The policy does not target $BundleId. It targets: $($targeted -join ', ')" }
    $assigned = @($made.assignments | ForEach-Object { $_.target.groupId })
    if ($assigned -notcontains $group.id) { throw "The policy is not assigned to '$GroupName'. It is assigned to: $($assigned -join ', ')" }

    Write-Information '' -InformationAction Continue
    Write-Information "Done. '$PolicyName' ($($policy.id)) targets $($targeted -join ', ') and is assigned to '$GroupName' ($($group.id))." -InformationAction Continue
    Write-Information "PIN required: $($made.pinRequired). Clipboard: $($made.allowedOutboundClipboardSharingLevel)." -InformationAction Continue
    Write-Information 'Intune can take a few minutes to hand a new policy to an app.' -InformationAction Continue
} else {
    Write-Information '' -InformationAction Continue
    Write-Information 'Nothing changed. Run again with -Apply.' -InformationAction Continue
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
