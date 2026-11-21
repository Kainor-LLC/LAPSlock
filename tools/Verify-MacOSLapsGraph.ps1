<#
.SYNOPSIS
    Checks what Microsoft Graph returns for a macOS LAPS local administrator account, and
    whether the function TenantKeep On-Call reveals Mac passwords with works on this tenant.

.DESCRIPTION
    Five read-only probes against a live tenant, in order:

      A. GET /v1.0/directory/deviceLocalCredentials/{entraDeviceId}?$select=credentials
         The Windows LAPS store. Shows whether macOS passwords are kept there (they are not).
      B. GET /beta/deviceManagement/managedDevices/{id}/retrieveDeviceLocalAdminAccountDetail
         The function tested in 2026-08. Documented to return passwordLastRotationDateTime
         only; it answered 500 then. The app still calls it for the rotation date.
      C. GET /v1.0 and /beta deviceManagement/managedDevices/{id}
         A property scan, to rule out an undocumented field carrying the password.
      D. GET /beta/deviceManagement/managedDevices/{id}/retrieveMacOSManagedDeviceLocalAdminAccountDetail
         The function Microsoft pointed to on 2026-11-08 and the one the app's Mac reveal
         calls. Reports the status, the property names, the password's LENGTH and the
         rotation date. Never the password.
      E. The device's ADE enrollment profile, for the admin account's user name, which the
         function in D does not return. (verify) the property names; any property whose
         name contains "password" is never printed.

    Performs no rotation and writes nothing. Probe D is a password view: Intune records it
    in this tenant's audit log, as the admin center's Passwords and keys page does.

    URIs are built with the -f format operator rather than string interpolation:
    PowerShell treats "$var?" as a variable named "var?", which silently drops both the
    value and the question mark.

.PREREQUISITES
    - Install-Module Microsoft.Graph -Scope CurrentUser
    - Signed-in admin should hold:
        * custom Intune RBAC role: Enrollment programs > "View macOS admin password" = Yes
        * (for the Windows-store comparison) Cloud Device Administrator or Intune Service Administrator
    - A Mac enrolled through Automated Device Enrollment with a local admin account in its
      enrollment profile.
    - The first run asks to consent DeviceManagementManagedDevices.PrivilegedOperations.All
      and DeviceManagementServiceConfig.Read.All for Microsoft Graph PowerShell.

    To learn whether Graph enforces the custom role as the admin center does, run it a
    second time as an Intune Administrator WITHOUT the custom role: a 403 on probe D means
    it does.

.NOTES
    PowerShell 7 on macOS.
#>

[CmdletBinding()]
param(
    [string] $ManagedDeviceId,
    # Optional: pre-fill the sign-in hint. Left empty on purpose, this file is public.
    [string] $UserPrincipalName = ""
)

$ErrorActionPreference = "Stop"

function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-Pass($t)    { Write-Host "  [PASS] $t" -ForegroundColor Green }
function Write-Fail($t)    { Write-Host "  [FAIL] $t" -ForegroundColor Red }
function Write-Info($t)    { Write-Host "  [info] $t" -ForegroundColor DarkGray }
function Write-Found($t)   { Write-Host "  [FOUND] $t" -ForegroundColor Yellow }

$graphBase = "https://graph.microsoft.com"

# Probe helper: returns a result object; never prints response bodies.
function Invoke-Probe {
    param([Parameter(Mandatory)][string] $Uri)
    Write-Info "GET $Uri"
    try {
        $resp = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType PSObject -ErrorAction Stop
        return [pscustomobject]@{ Ok = $true; Body = $resp; Status = 200; Message = $null }
    } catch {
        $status = $null
        try { $status = $_.Exception.Response.StatusCode.value__ } catch { }
        if (-not $status -and $_.ErrorDetails.Message -match '"code"\s*:\s*"([^"]+)"') { $status = $Matches[1] }
        return [pscustomobject]@{ Ok = $false; Body = $null; Status = $status; Message = $_.Exception.Message }
    }
}

# Normalizes PSObject / Hashtable responses into a name->value map so property
# scanning works regardless of what the SDK hands back.
function Get-PropertyMap {
    param($Body)
    $map = @{}
    if ($null -eq $Body) { return $map }
    if ($Body -is [System.Collections.IDictionary]) {
        foreach ($k in $Body.Keys) { $map[[string]$k] = $Body[$k] }
    } else {
        foreach ($p in $Body.PSObject.Properties) { $map[$p.Name] = $p.Value }
    }
    return $map
}

# ---------------------------------------------------------------------------
# 1. Connect
# ---------------------------------------------------------------------------
Write-Section "Connecting to Microsoft Graph (delegated)"
$scopes = @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementServiceConfig.Read.All",
    "Device.Read.All",
    "DeviceLocalCredential.Read.All",
    "DeviceManagementConfiguration.Read.All"
)
Connect-MgGraph -Scopes $scopes -NoWelcome
$ctx = Get-MgContext
Write-Info "Signed in as: $($ctx.Account)"
Write-Info "Tenant:       $($ctx.TenantId)"
Write-Info "NOTE: every retrieval attempt below is audited in THIS tenant's logs."

# ---------------------------------------------------------------------------
# 2. Locate a macOS managed device
# ---------------------------------------------------------------------------
Write-Section "Locating a macOS managed device"
if (-not $ManagedDeviceId) {
    $mac = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'macOS'" -Top 1
    if (-not $mac) { Write-Fail "No macOS managed devices found in this tenant."; return }
    $ManagedDeviceId = $mac.Id
} else {
    $mac = Get-MgDeviceManagementManagedDevice -ManagedDeviceId $ManagedDeviceId
}
$entraDeviceId = $mac.AzureAdDeviceId

Write-Info "managedDeviceId: $ManagedDeviceId"
Write-Info "deviceName:      $($mac.DeviceName)"
Write-Info "azureADDeviceId: $entraDeviceId"

# Sanity guard so a malformed URI can never masquerade as a real answer again.
if ([string]::IsNullOrWhiteSpace($ManagedDeviceId)) { Write-Fail "managedDeviceId empty, aborting."; return }

$foundPasswordSomewhere = $false
$foundVia = @()
$revealWorks = $false

# ---------------------------------------------------------------------------
# TEST A, Entra deviceLocalCredentials (the Windows LAPS store)
# ---------------------------------------------------------------------------
Write-Section "TEST A: /v1.0/directory/deviceLocalCredentials (Windows LAPS store)"
if ([string]::IsNullOrWhiteSpace($entraDeviceId)) {
    Write-Fail "Device has no azureADDeviceId; cannot query deviceLocalCredentials."
} else {
    # Explicit construction, no interpolation adjacent to '?'.
    $uriA = '{0}/v1.0/directory/deviceLocalCredentials/{1}?$select=credentials' -f $graphBase, $entraDeviceId
    $a = Invoke-Probe -Uri $uriA
    if ($a.Ok) {
        $mapA  = Get-PropertyMap $a.Body
        $creds = $mapA["credentials"]
        if ($creds -and @($creds).Count -gt 0) {
            $entries  = @($creds)
            $withPwd  = @($entries | Where-Object { (Get-PropertyMap $_)["passwordBase64"] })
            $accounts = ($entries | ForEach-Object { (Get-PropertyMap $_)["accountName"] }) -join ", "
            if ($withPwd.Count -gt 0) {
                Write-Found "$($entries.Count) credential entry/entries WITH passwordBase64. Accounts: $accounts"
                $foundPasswordSomewhere = $true
                $foundVia += "v1.0 deviceLocalCredentials"
            } else {
                Write-Fail "Credential entries returned but none contain passwordBase64. Accounts: $accounts"
            }
        } else {
            Write-Fail "200 OK but no credentials array: macOS device not in the Windows LAPS store."
        }
    } else {
        Write-Fail "HTTP $($a.Status). $($a.Message)"
        Write-Info "404/'not found' here supports MS's 'stored and encrypted by Intune' statement."
    }
}

# ---------------------------------------------------------------------------
# TEST B, the 2026-08 function: rotation metadata only
# ---------------------------------------------------------------------------
Write-Section "TEST B: retrieveDeviceLocalAdminAccountDetail (rotation metadata, used by the app for the date)"
$uriB = '{0}/beta/deviceManagement/managedDevices/{1}/retrieveDeviceLocalAdminAccountDetail' -f $graphBase, $ManagedDeviceId
$b = Invoke-Probe -Uri $uriB
if ($b.Ok) {
    $mapB = Get-PropertyMap $b.Body
    # Documented response shape is { "value": { ... } }
    $inner = if ($mapB.ContainsKey("value")) { Get-PropertyMap $mapB["value"] } else { $mapB }
    Write-Pass "200 OK. Returned properties: $(($inner.Keys | Sort-Object) -join ', ')"
    if ($inner.ContainsKey("passwordLastRotationDateTime")) {
        Write-Info "passwordLastRotationDateTime = $($inner['passwordLastRotationDateTime'])"
    }
    Write-Info "It answers now: the app keeps calling it for the rotation date."
} else {
    Write-Fail "HTTP $($b.Status). $($b.Message)"
    Write-Info "500 again: the app should stop calling it (supportsMetadata false) and take the date from the reveal."
}

# ---------------------------------------------------------------------------
# TEST C, managedDevice object scan (v1.0 + beta)
# ---------------------------------------------------------------------------
Write-Section "TEST C: managedDevices object property scan (v1.0 + beta)"
$betaDevice = @{}
foreach ($v in @("v1.0", "beta")) {
    $uriC = '{0}/{1}/deviceManagement/managedDevices/{2}' -f $graphBase, $v, $ManagedDeviceId
    $c = Invoke-Probe -Uri $uriC
    if ($c.Ok) {
        $mapC = Get-PropertyMap $c.Body
        if ($v -eq "beta") { $betaDevice = $mapC }
        Write-Info "$v returned $($mapC.Keys.Count) properties."
        $cand = @($mapC.Keys | Where-Object { $_ -match 'password|localAdmin|laps|credential' })
        if ($cand.Count -gt 0) {
            foreach ($p in $cand) {
                $populated = -not [string]::IsNullOrEmpty([string]$mapC[$p])
                Write-Info ("   {0}: {1}" -f $p, $(if ($populated) { "POPULATED (value hidden)" } else { "null/empty" }))
                if ($populated -and $p -match 'password' -and $p -notmatch 'RotationDateTime') {
                    $foundPasswordSomewhere = $true
                    $foundVia += "$v managedDevice.$p (undocumented for reveal)"
                }
            }
        } else {
            Write-Info "$v managedDevice exposes no password/localAdmin/laps property."
        }
    } else {
        Write-Fail "$v managedDevice request failed: HTTP $($c.Status)."
    }
}

# ---------------------------------------------------------------------------
# TEST D, the function the app's Mac reveal calls
# ---------------------------------------------------------------------------
Write-Section "TEST D: retrieveMacOSManagedDeviceLocalAdminAccountDetail (the app's Mac reveal)"
$uriD = '{0}/beta/deviceManagement/managedDevices/{1}/retrieveMacOSManagedDeviceLocalAdminAccountDetail' -f $graphBase, $ManagedDeviceId
$d = Invoke-Probe -Uri $uriD
if ($d.Ok) {
    $mapD = Get-PropertyMap $d.Body
    $wrapped = $mapD.ContainsKey("value")
    $inner = if ($wrapped) { Get-PropertyMap $mapD["value"] } else { $mapD }
    Write-Info "Shape: $(if ($wrapped) { 'wrapped in value, as documented' } else { 'a bare object (the app reads both)' })"
    Write-Info "Returned properties: $(($inner.Keys | Sort-Object) -join ', ')"
    $passwordText = [string]$inner["adminAccountPassword"]
    if (-not [string]::IsNullOrEmpty($passwordText)) {
        Write-Found "adminAccountPassword POPULATED, $($passwordText.Length) characters (value hidden)"
        $revealWorks = $true
        $foundPasswordSomewhere = $true
        $foundVia += "beta retrieveMacOSManagedDeviceLocalAdminAccountDetail (documented, beta)"
    } else {
        Write-Fail "200 OK but adminAccountPassword is missing or empty. The app would say Intune has no password for this Mac."
    }
    $passwordText = $null
    if ($inner.ContainsKey("passwordLastRotatedDateTime")) {
        Write-Info "passwordLastRotatedDateTime = $($inner['passwordLastRotatedDateTime'])"
    }
    $extra = @($inner.Keys | Where-Object { $_ -notin @("@odata.type", "adminAccountPassword", "passwordLastRotatedDateTime") })
    if ($extra.Count -gt 0) { Write-Info "Undocumented extra properties: $($extra -join ', ')" }
} else {
    Write-Fail "HTTP $($d.Status). $($d.Message)"
    Write-Info "403 = no Intune role that can view macOS admin passwords (the custom role in PREREQUISITES), or the permission was not consented."
    Write-Info "404 = Intune holds no admin account for this Mac: not enrolled through ADE, or no local admin account in the profile."
    Write-Info "500 = inconclusive. Run tools/Diagnose-MacOSLaps.ps1 for the error body."
}

# ---------------------------------------------------------------------------
# TEST E, the admin account's user name, from the ADE enrollment profile
# ---------------------------------------------------------------------------
Write-Section "TEST E: the enrollment profile's admin account name"
$profileName = [string]$betaDevice["enrollmentProfileName"]
if ([string]::IsNullOrEmpty($profileName)) {
    Write-Fail "The beta managedDevice carries no enrollmentProfileName; the app cannot match this Mac to a profile."
} else {
    Write-Info "enrollmentProfileName = $profileName"
    $settings = Invoke-Probe -Uri ('{0}/beta/deviceManagement/depOnboardingSettings' -f $graphBase)
    if (-not $settings.Ok) {
        Write-Fail "depOnboardingSettings: HTTP $($settings.Status). $($settings.Message)"
    } else {
        $matched = 0
        foreach ($token in @((Get-PropertyMap $settings.Body)["value"])) {
            $tokenId = (Get-PropertyMap $token)["id"]
            $profiles = Invoke-Probe -Uri ('{0}/beta/deviceManagement/depOnboardingSettings/{1}/enrollmentProfiles' -f $graphBase, $tokenId)
            if (-not $profiles.Ok) { Write-Fail "enrollmentProfiles: HTTP $($profiles.Status)."; continue }
            foreach ($p in @((Get-PropertyMap $profiles.Body)["value"])) {
                $pm = Get-PropertyMap $p
                if ([string]$pm["displayName"] -ne $profileName) { continue }
                $matched++
                Write-Info "Matched profile $($pm['displayName']) ($($pm['@odata.type']))"
                $adminProps = @($pm.Keys | Where-Object { $_ -match 'admin|account' } | Sort-Object)
                foreach ($k in $adminProps) {
                    if ($k -match 'password') { Write-Info "   ${k}: (not printed)"; continue }
                    Write-Info "   ${k}: $($pm[$k])"
                }
                if ($adminProps.Count -eq 0) { Write-Fail "The profile exposes no admin or account property." }
            }
        }
        if ($matched -eq 0) { Write-Fail "No enrollment profile is named $profileName." }
        if ($matched -gt 1) { Write-Fail "$matched profiles share that name; matching by name is not reliable in this tenant." }
    }
}

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
Write-Section "VERDICT"
if ($revealWorks) {
    Write-Pass "The Mac reveal's function returned a password for this Mac. Record the shape, the role result and test E in the run sheet."
} else {
    Write-Fail "The Mac reveal's function did not return a password. Mac reveal stays unreleased (MACOS-REVEAL-PLAN.md, decision 1)."
}
if ($foundPasswordSomewhere) {
    Write-Info "A password value was returned via:"
    $foundVia | Sort-Object -Unique | ForEach-Object { Write-Info "  * $_" }
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
Write-Info "Done."
