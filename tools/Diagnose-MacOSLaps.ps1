<#
.SYNOPSIS
    Diagnose the HTTP 500 from retrieveDeviceLocalAdminAccountDetail and determine
    whether the target Mac is actually macOS-LAPS-managed.

.DESCRIPTION
    The main harness got a 500 on the documented beta function. A 500 is NOT a clean
    negative — it usually means the request was accepted but the service had no record
    to return. This script distinguishes the possibilities:

      (a) Device is not ADE-enrolled / has no macOS LAPS account configured
          -> 500 is expected-ish; the endpoint was never going to return anything.
      (b) Caller lacks the custom Intune "View macOS admin password" role
          -> normally 403, but some Intune functions surface authz oddly.
      (c) Genuine Graph service defect
          -> worth a Microsoft support case; re-test after the next service release.

    It prints the FULL Graph error body (which the main harness swallowed), then reports
    the enrollment/eligibility signals that determine macOS LAPS applicability.

    Read-only. Never rotates. Never prints a password value.

.PREREQUISITES
    Install-Module Microsoft.Graph -Scope CurrentUser
#>

[CmdletBinding()]
param(
    # Intune managedDeviceId to probe. If omitted, the first macOS device found is used.
    [string] $ManagedDeviceId = "",
    # Optional sign-in hint. Left empty on purpose — this file is public.
    [string] $UserPrincipalName = ""
)

$ErrorActionPreference = "Stop"

function Write-Section($t) { Write-Host "`n=== $t ===" -ForegroundColor Cyan }
function Write-Info($t)    { Write-Host "  [info] $t" -ForegroundColor DarkGray }
function Write-Good($t)    { Write-Host "  [ OK ] $t" -ForegroundColor Green }
function Write-Bad($t)     { Write-Host "  [ !! ] $t" -ForegroundColor Red }
function Write-Note($t)    { Write-Host "  [note] $t" -ForegroundColor Yellow }

$graphBase = "https://graph.microsoft.com"

Write-Section "Connect"
Connect-MgGraph -Scopes @(
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementServiceConfig.Read.All",
    "Device.Read.All"
) -NoWelcome
$ctx = Get-MgContext
Write-Info "Account: $($ctx.Account)"
Write-Info "Tenant:  $($ctx.TenantId)"

# ---------------------------------------------------------------------------
# 0. Resolve a device to probe (no hardcoded IDs — this file is public).
# ---------------------------------------------------------------------------
if ([string]::IsNullOrWhiteSpace($ManagedDeviceId)) {
    Write-Section "0. Finding a macOS managed device"
    $first = Get-MgDeviceManagementManagedDevice -Filter "operatingSystem eq 'macOS'" -Top 1
    if (-not $first) {
        Write-Bad "No macOS managed devices in this tenant. Pass -ManagedDeviceId explicitly."
        return
    }
    $ManagedDeviceId = $first.Id
    Write-Info "Using: $($first.DeviceName) ($ManagedDeviceId)"
}

# ---------------------------------------------------------------------------
# 1. Device eligibility signals for macOS LAPS
#    Requirements: macOS 12+, ADE-enrolled (after wipe), synced from ABM/ASM.
# ---------------------------------------------------------------------------
Write-Section "1. Is this device even eligible for macOS LAPS?"
$uri = '{0}/beta/deviceManagement/managedDevices/{1}' -f $graphBase, $ManagedDeviceId
$dev = Invoke-MgGraphRequest -Method GET -Uri $uri -OutputType PSObject

$interesting = @(
    'deviceName','operatingSystem','osVersion','managedDeviceOwnerType',
    'deviceEnrollmentType','enrolledDateTime','isSupervised','managementAgent',
    'joinType','deviceRegistrationState','autopilotEnrolled','managementState',
    'complianceState','lastSyncDateTime','userPrincipalName','serialNumber'
)
foreach ($p in $interesting) {
    $v = $dev.PSObject.Properties[$p]
    if ($v) { Write-Info ("{0,-24} = {1}" -f $p, $v.Value) }
}

$enrollType = [string]$dev.deviceEnrollmentType
$isADE = $enrollType -match 'appleBulkWithUser|appleBulkWithoutUser|appleDeviceEnrollmentProgram|deviceEnrollmentProgram'
Write-Host ""
if ($isADE) {
    Write-Good "Enrollment type '$enrollType' looks like Automated Device Enrollment (ADE). Eligible."
} else {
    Write-Bad "Enrollment type '$enrollType' does NOT look like ADE."
    Write-Note "macOS LAPS requires ADE enrollment after a factory reset. If this Mac was"
    Write-Note "enrolled via Company Portal / manual / user-driven, it has NO macOS LAPS"
    Write-Note "account, and the 500 is simply 'no record exists' — not a Graph defect."
}

$osVer = [string]$dev.osVersion
if ($osVer) {
    $major = ($osVer -split '\.')[0]
    if ([int]::TryParse($major, [ref]$null) -and [int]$major -ge 12) {
        Write-Good "macOS $osVer meets the 12+ requirement."
    } else {
        Write-Bad "macOS $osVer may not meet the 12+ requirement."
    }
}

# ---------------------------------------------------------------------------
# 2. Re-call the documented function and DUMP THE FULL ERROR BODY
# ---------------------------------------------------------------------------
Write-Section "2. retrieveDeviceLocalAdminAccountDetail — full error detail"
$fnUri = '{0}/beta/deviceManagement/managedDevices/{1}/retrieveDeviceLocalAdminAccountDetail' -f $graphBase, $ManagedDeviceId
Write-Info "GET $fnUri"
try {
    $resp = Invoke-MgGraphRequest -Method GET -Uri $fnUri -OutputType PSObject -ErrorAction Stop
    Write-Good "200 OK."
    $inner = if ($resp.PSObject.Properties['value']) { $resp.value } else { $resp }
    $names = @($inner.PSObject.Properties.Name)
    Write-Info "Properties returned: $($names -join ', ')"
    foreach ($n in $names) {
        $isPwdValue = ($n -match 'password') -and ($n -notmatch 'RotationDateTime')
        $val = if ($isPwdValue) { "<<POPULATED - VALUE HIDDEN>>" } else { $inner.$n }
        Write-Info ("   {0} = {1}" -f $n, $val)
    }
    if ($names | Where-Object { $_ -match 'password' -and $_ -notmatch 'RotationDateTime' }) {
        Write-Note "A password VALUE property exists. Beta endpoint — record for follow-up."
    } else {
        Write-Note "Metadata only, exactly as documented. Confirms macOS reveal is not available."
    }
}
catch {
    $status = $null
    try { $status = $_.Exception.Response.StatusCode.value__ } catch { }
    Write-Bad "HTTP $status"
    # THE PART THE MAIN HARNESS SWALLOWED: Graph's actual error payload.
    if ($_.ErrorDetails -and $_.ErrorDetails.Message) {
        Write-Host "  --- Graph error body ---" -ForegroundColor Red
        Write-Host $_.ErrorDetails.Message
        Write-Host "  ------------------------" -ForegroundColor Red
    } else {
        Write-Info "No ErrorDetails payload. Raw: $($_.Exception.Message)"
    }
    Write-Host ""
    Write-Note "Interpretation guide:"
    Write-Note "  'not found' / 'no record' / null-ref    -> device has no macOS LAPS account (see section 1)"
    Write-Note "  'Forbidden' / 'authorization'           -> missing custom Intune role"
    Write-Note "  generic 'internal server error' + ADE   -> likely a real Graph defect; open a support case"
}

# ---------------------------------------------------------------------------
# 3. Are there ANY macOS devices in this tenant with LAPS configured?
#    Compare against the enrollment profiles that would enable it.
# ---------------------------------------------------------------------------
Write-Section "3. Tenant-wide: macOS devices and ADE profiles"
try {
    $macsUri = '{0}/beta/deviceManagement/managedDevices?$filter=operatingSystem eq ''macOS''&$select=id,deviceName,deviceEnrollmentType,osVersion&$top=50' -f $graphBase
    $macs = Invoke-MgGraphRequest -Method GET -Uri $macsUri -OutputType PSObject
    $list = @($macs.value)
    Write-Info "macOS managed devices found: $($list.Count)"
    $adeMacs = @($list | Where-Object { [string]$_.deviceEnrollmentType -match 'appleBulk|DeviceEnrollmentProgram' })
    Write-Info "…of which ADE-enrolled: $($adeMacs.Count)"
    if ($adeMacs.Count -gt 0) {
        Write-Note "Re-run section 2 against an ADE Mac to get a cleaner answer:"
        $adeMacs | Select-Object -First 5 | ForEach-Object {
            Write-Host ("     .\Diagnose-MacOSLaps.ps1 -ManagedDeviceId {0}   # {1} ({2})" -f $_.id, $_.deviceName, $_.deviceEnrollmentType)
        }
    } else {
        Write-Note "No ADE-enrolled Macs in this tenant -> macOS LAPS cannot be present on any of them."
        Write-Note "The 500 is therefore 'nothing to return', not evidence about the API's capability."
    }
} catch {
    Write-Bad "Device list query failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 4. Manual cross-check (the decisive test)
# ---------------------------------------------------------------------------
Write-Section "4. Manual cross-check in the Intune portal"
Write-Host @"
  This is the decisive comparison. In the Intune admin center:
     Devices > macOS > $($dev.deviceName) > "Local admin password" (or "Passwords and keys")

  Then interpret:
    * Portal SHOWS a password, but Graph returns metadata only / 500
        -> The portal uses an internal API. Public Graph cannot retrieve macOS LAPS.
           DECISION: macOS reveal is not buildable. Ship Windows-only reveal.
    * Portal shows NO password / "not available"
        -> This device has no macOS LAPS account. The API test was moot; retest on a
           device that does, or accept the documentation-based conclusion.
"@ -ForegroundColor Yellow

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
Write-Info "Done."
