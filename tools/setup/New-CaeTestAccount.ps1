#Requires -Version 7.4
#Requires -Modules Microsoft.Graph.Authentication
<#
.SYNOPSIS
    Makes the test account for measuring continuous access evaluation in TenantKeep On-Call:
    a member account that is eligible, not active, for one directory role.

.DESCRIPTION
    The measurement revokes the account's sessions, blocks its sign-in and ends its role, so
    it must not be anyone's real account. This script makes what that takes:

      The account, created when it does not exist, with a password asked for at the prompt.
      The password is sent to Microsoft and never printed or kept. An existing account is
      used as it is, and enabled if it was left blocked by an earlier run.
      An eligible assignment to one role through Privileged Identity Management, for a day
      by default, so the role can be activated and deactivated during the run. Reports
      Reader by default: the sign-in log the measurement reads needs a role, and it is the
      least that does.

    It warns, and changes nothing, if the account already holds the role actively: a role
    that is always on cannot be timed ending.

    Without -Apply it only reads and prints what it would do. Safe to run again. It deletes
    nothing. When the measurement is over, block or delete the account in the Entra admin
    center if it is not wanted.

    Signing in needs Privileged Role Administrator or Global Administrator active, for the
    eligible assignment, and User Administrator or above for the account.

.PARAMETER User
    The test account's sign-in address. Created when it does not exist.

.PARAMETER DisplayName
    The name the account is created with.

.PARAMETER TenantId
    The tenant to sign in to. Optional.

.PARAMETER Role
    The directory role the account is made eligible for, by its name.

.PARAMETER EligibleFor
    How long the eligible assignment lasts, as an ISO 8601 duration.

.PARAMETER Apply
    Make the changes. Without it, nothing is changed.

.EXAMPLE
    pwsh ./tools/setup/New-CaeTestAccount.ps1 -User cae-test@contoso.com

    Prints the plan and changes nothing.

.EXAMPLE
    pwsh ./tools/setup/New-CaeTestAccount.ps1 -User cae-test@contoso.com -Apply
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $User,
    [string] $DisplayName = 'TenantKeep CAE Test',
    [string] $TenantId,
    [string] $Role = 'Reports Reader',
    [string] $EligibleFor = 'P1D',
    [switch] $Apply
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Step([string] $Text) {
    $prefix = if ($Apply) { 'DO  ' } else { 'PLAN' }
    Write-Information "$prefix $Text" -InformationAction Continue
}

function Write-Note([string] $Text) {
    Write-Information "     $Text" -InformationAction Continue
}

function Get-Graph([string] $Path) {
    Invoke-MgGraphRequest -Method GET -Uri "/v1.0$Path" -OutputType PSObject
}

function Send-Graph([string] $Method, [string] $Path, $Body) {
    Invoke-MgGraphRequest -Method $Method -Uri "/v1.0$Path" -Body ($Body | ConvertTo-Json -Depth 8) -ContentType 'application/json' -OutputType PSObject
}

# A dry run only reads.
$scopes = if ($Apply) {
    'User.ReadWrite.All', 'RoleEligibilitySchedule.ReadWrite.Directory', 'RoleManagement.Read.Directory'
} else {
    'User.Read.All', 'RoleManagement.Read.Directory'
}
$connect = @{ Scopes = $scopes; NoWelcome = $true }
if ($TenantId) { $connect.TenantId = $TenantId }
Connect-MgGraph @connect
$context = Get-MgContext
Write-Information "Signed in as $($context.Account) in tenant $($context.TenantId)" -InformationAction Continue

# 1. The account
$account = $null
try {
    $account = Get-Graph "/users/$([uri]::EscapeDataString($User))?`$select=id,userPrincipalName,displayName,accountEnabled"
} catch {
    if ($_.Exception.Message -notmatch 'NotFound|404|does not exist') { throw }
}

if (-not $account) {
    Write-Step "Create the member account $User, named '$DisplayName', with a password you type"
    if ($Apply) {
        $secret = Read-Host -AsSecureString -Prompt "Password for $User"
        $nickname = ($User -split '@')[0] -replace '[^A-Za-z0-9]', ''
        $account = Send-Graph 'POST' '/users' @{
            accountEnabled    = $true
            displayName       = $DisplayName
            mailNickname      = $nickname
            userPrincipalName = $User
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $false
                password                      = (ConvertFrom-SecureString -SecureString $secret -AsPlainText)
            }
        }
        $secret.Dispose()
        Write-Note "Created: $($account.id)."
    }
} else {
    Write-Note "$($account.displayName) exists: $($account.id), sign-in $(if ($account.accountEnabled) { 'allowed' } else { 'blocked' })."
    if (-not $account.accountEnabled) {
        Write-Step "Allow $User to sign in again (an earlier run blocked it)"
        if ($Apply) { Send-Graph 'PATCH' "/users/$($account.id)" @{ accountEnabled = $true } | Out-Null }
    }
}

# 2. The role
$escapedRole = $Role.Replace("'", "''")
$definition = @((Get-Graph "/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$escapedRole'&`$select=id,displayName,templateId").value) | Select-Object -First 1
if (-not $definition) { throw "No directory role is named '$Role'." }
Write-Note "$($definition.displayName) is $($definition.templateId)."

if (-not $account) {
    Write-Step "Make the new account eligible for $Role through PIM for $EligibleFor"
    Write-Information 'Dry run: nothing changed. Run again with -Apply.' -InformationAction Continue
    return
}

# 3. Not active already: a role that is always on cannot be timed ending
$active = @((Get-Graph "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($account.id)' and roleDefinitionId eq '$($definition.id)'").value)
if ($active.Count -gt 0) {
    Write-Warning "$User holds $Role actively. Remove that assignment in the Entra admin center first; the measurement needs the role eligible only."
}

# 4. Eligible
$eligible = @((Get-Graph "/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($account.id)' and roleDefinitionId eq '$($definition.id)'").value)
if ($eligible.Count -gt 0) {
    $until = $eligible[0].scheduleInfo.expiration.endDateTime
    Write-Note "Already eligible for $Role$(if ($until) { " until $until" } else { '' })."
} else {
    Write-Step "Make $User eligible for $Role through PIM for $EligibleFor"
    if ($Apply) {
        Send-Graph 'POST' '/roleManagement/directory/roleEligibilityScheduleRequests' @{
            action           = 'adminAssign'
            justification    = 'TenantKeep On-Call: measuring continuous access evaluation'
            roleDefinitionId = $definition.id
            directoryScopeId = '/'
            principalId      = $account.id
            scheduleInfo     = @{
                startDateTime = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
                expiration    = @{ type = 'afterDuration'; duration = $EligibleFor }
            }
        } | Out-Null
    }
}

if (-not $Apply) {
    Write-Information 'Dry run: nothing changed. Run again with -Apply.' -InformationAction Continue
    return
}

# 5. Read back
$account = Get-Graph "/users/$($account.id)?`$select=id,userPrincipalName,accountEnabled"
$eligible = @((Get-Graph "/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$($account.id)' and roleDefinitionId eq '$($definition.id)'").value)
Write-Information '' -InformationAction Continue
Write-Information "Account     $($account.userPrincipalName), sign-in $(if ($account.accountEnabled) { 'allowed' } else { 'blocked' })" -InformationAction Continue
Write-Information "Eligible     $(if ($eligible.Count -gt 0) { "$Role, until $($eligible[0].scheduleInfo.expiration.endDateTime)" } else { 'not yet: PIM can take a minute; run this again to see it' })" -InformationAction Continue
Write-Information '' -InformationAction Continue
Write-Information 'Next: sign in to TenantKeep On-Call with this account. If Conditional Access asks for multifactor authentication, register a method for it then.' -InformationAction Continue
