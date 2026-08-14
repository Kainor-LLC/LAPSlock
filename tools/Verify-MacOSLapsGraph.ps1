<#
.SYNOPSIS
    PitLAPS macOS LAPS verification harness v2 — resolves Build Spec §2.4.

.DESCRIPTION
    v2 FIXES (v1 was wrong in two ways):
      1. BUG: "$entraDeviceId?`$select=..." — PowerShell accepts '?' as a valid
         character in a variable name, so it resolved a nonexistent variable
         'entraDeviceId?' and silently dropped BOTH the device id and the '?'.
         TEST A never actually ran; its HTTP 400 was a malformed URL, not a result.
         All URIs are now built with the -f format operator, never interpolated
         next to a '?'.
      2. MISSING ENDPOINT: v1 guessed two endpoint names that do not exist. The real
         documented function is:
             GET /beta/deviceManagement/managedDevices/{id}/retrieveDeviceLocalAdminAccountDetail
         It returns deviceLocalAdminAccountDetail (macOSDeviceLocalAdminAccountDetail).
         Per Microsoft Learn that resource documents exactly ONE property,
         passwordLastRotationDateTime — rotation metadata, NOT a password value.
         This harness confirms that empirically against a live tenant.

    Read-only. Performs no rotation, writes nothing, and NEVER prints a password value.

.PREREQUISITES
    - Install-Module Microsoft.Graph -Scope CurrentUser
    - Signed-in admin should hold:
        * custom Intune RBAC role: Enrollment programs > "View macOS admin password" = Yes
        * (for the Windows-store comparison) Cloud Device Administrator or Intune Service Administrator
    - At least one ADE-enrolled, LAPS-managed macOS device.

.NOTES
    PowerShell 7 on macOS.
#>

[CmdletBinding()]
param(
    [string] $ManagedDeviceId,
    # Optional: pre-fill the sign-in hint. Left empty on purpose — this file is public.
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
if ([string]::IsNullOrWhiteSpace($ManagedDeviceId)) { Write-Fail "managedDeviceId empty — aborting."; return }

$foundPasswordSomewhere = $false
$foundVia = @()

# ---------------------------------------------------------------------------
# TEST A — Entra deviceLocalCredentials (the Windows LAPS store)
# ---------------------------------------------------------------------------
Write-Section "TEST A: /v1.0/directory/deviceLocalCredentials (Windows LAPS store)"
if ([string]::IsNullOrWhiteSpace($entraDeviceId)) {
    Write-Fail "Device has no azureADDeviceId; cannot query deviceLocalCredentials."
} else {
    # Explicit construction — no interpolation adjacent to '?'.
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
                Write-Pass "macOS LAPS reveal IS buildable via v1.0 deviceLocalCredentials."
                $foundPasswordSomewhere = $true
                $foundVia += "v1.0 deviceLocalCredentials (DOCUMENTED, shippable)"
            } else {
                Write-Fail "Credential entries returned but none contain passwordBase64. Accounts: $accounts"
            }
        } else {
            Write-Fail "200 OK but no credentials array — macOS device not in the Windows LAPS store."
        }
    } else {
        Write-Fail "HTTP $($a.Status). $($a.Message)"
        Write-Info "404/'not found' here supports MS's 'stored and encrypted by Intune' statement."
    }
}

# ---------------------------------------------------------------------------
# TEST B — the DOCUMENTED beta function (this is the real one; v1 missed it)
# ---------------------------------------------------------------------------
Write-Section "TEST B: retrieveDeviceLocalAdminAccountDetail (DOCUMENTED beta function)"
$uriB = '{0}/beta/deviceManagement/managedDevices/{1}/retrieveDeviceLocalAdminAccountDetail' -f $graphBase, $ManagedDeviceId
$b = Invoke-Probe -Uri $uriB
if ($b.Ok) {
    $mapB = Get-PropertyMap $b.Body
    # Documented response shape is { "value": { ... } }
    $inner = if ($mapB.ContainsKey("value")) { Get-PropertyMap $mapB["value"] } else { $mapB }
    Write-Info "Returned properties: $(($inner.Keys | Sort-Object) -join ', ')"

    $pwdProps = @($inner.Keys | Where-Object { $_ -match 'password' -and $_ -notmatch 'RotationDateTime' })
    if ($pwdProps.Count -gt 0) {
        $populated = @($pwdProps | Where-Object { -not [string]::IsNullOrEmpty([string]$inner[$_]) })
        if ($populated.Count -gt 0) {
            Write-Found "Password-bearing property present and POPULATED: $($populated -join ', ') (value hidden)"
            Write-Info "Endpoint is BETA — per Spec §2.4, beta is not shippable for production reveal."
            $foundPasswordSomewhere = $true
            $foundVia += "beta retrieveDeviceLocalAdminAccountDetail (DOCUMENTED but BETA)"
        } else {
            Write-Fail "Password-named property exists but is null/empty: $($pwdProps -join ', ')"
        }
    } else {
        Write-Fail "No password VALUE property. Documented resource carries only rotation metadata."
        if ($inner.ContainsKey("passwordLastRotationDateTime")) {
            Write-Info "passwordLastRotationDateTime = $($inner['passwordLastRotationDateTime'])  <- metadata only (still useful in the UI)"
        }
    }
} else {
    Write-Fail "HTTP $($b.Status). $($b.Message)"
    Write-Info "403 = missing the custom Intune 'View macOS admin password' role."
    Write-Info "404 = no macOS LAPS record for this device."
    Write-Info "500 = INCONCLUSIVE, not a negative. Run tools/Diagnose-MacOSLaps.ps1 for the error body."
}

# ---------------------------------------------------------------------------
# TEST C — managedDevice object scan (v1.0 + beta)
# ---------------------------------------------------------------------------
Write-Section "TEST C: managedDevices object property scan (v1.0 + beta)"
foreach ($v in @("v1.0", "beta")) {
    $uriC = '{0}/{1}/deviceManagement/managedDevices/{2}' -f $graphBase, $v, $ManagedDeviceId
    $c = Invoke-Probe -Uri $uriC
    if ($c.Ok) {
        $mapC = Get-PropertyMap $c.Body
        Write-Info "$v returned $($mapC.Keys.Count) properties."
        $cand = @($mapC.Keys | Where-Object { $_ -match 'password|localAdmin|laps|credential' })
        if ($cand.Count -gt 0) {
            foreach ($p in $cand) {
                $populated = -not [string]::IsNullOrEmpty([string]$mapC[$p])
                Write-Info ("   {0}: {1}" -f $p, $(if ($populated) { "POPULATED (value hidden)" } else { "null/empty" }))
                if ($populated -and $p -match 'password' -and $p -notmatch 'RotationDateTime') {
                    $foundPasswordSomewhere = $true
                    $foundVia += "$v managedDevice.$p (UNDOCUMENTED for reveal)"
                }
            }
        } else {
            Write-Fail "$v managedDevice exposes no password/localAdmin/laps property."
        }
    } else {
        Write-Fail "$v managedDevice request failed: HTTP $($c.Status)."
    }
}

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------
Write-Section "VERDICT (Spec §2.4)"
if ($foundPasswordSomewhere) {
    Write-Host "  A password value WAS returned via:" -ForegroundColor Yellow
    $foundVia | Sort-Object -Unique | ForEach-Object { Write-Host "    * $_" -ForegroundColor Yellow }
    Write-Host "  Shippable ONLY if the source is v1.0 and documented (Spec §2.4)." -ForegroundColor Yellow
} else {
    Write-Host @"
  No documented Graph endpoint returned a macOS LAPS password value.

  CONCLUSION: macOS LAPS reveal is NOT buildable on public Graph today.
    * The documented beta function returns rotation METADATA only
      (passwordLastRotationDateTime), not the password.
    * macOS passwords are held/encrypted by Intune, not in the Entra
      deviceLocalCredentials store that Windows LAPS uses.

  RECOMMENDED PRODUCT DECISION:
    1. Ship Windows LAPS reveal (v1.0, fully documented, GA).
    2. For macOS: show rotation metadata + a 'view in Intune portal' handoff,
       and optionally the rotate action (beta, off by default).
    3. Re-run this harness each Intune service release to detect a new endpoint.
"@ -ForegroundColor Yellow
}

try { Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null } catch { }
Write-Info "Done."
