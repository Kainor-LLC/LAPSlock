<#
.SYNOPSIS
    Sends a TenantKeep Watch alert to a paired phone through the TenantKeep relay.
    docs/RELAY-API.md. Dot-source it, then call the functions below.

.DESCRIPTION
    Runs in the customer's own Azure Automation account (or anywhere PowerShell 7 runs).
    Each alert is encrypted for one phone with HPKE in authenticated mode (Hpke.cs), using
    a sender key that stays in the customer's Automation account as an encrypted variable.
    The relay sees the phone's push token, the urgency and the tenant's entitlement token,
    and passes the ciphertext to Apple. It cannot read the alert or forge one.

    New-TenantKeepRelaySenderKey   once, at setup: a sender key, and the code to pin on the phone
    Get-TenantKeepEntitlement      the tenant's entitlement token, from Kainor's entitlement endpoint
    Send-TenantKeepRelayAlert      one alert to one phone

.EXAMPLE
    . ./TenantKeepRelaySender.ps1
    $setup = New-TenantKeepRelaySenderKey -TenantId 'c0ffee00-1111-2222-3333-444455556666'
    $setup.SenderCode    # paste into TenantKeep on the phone; store $setup.PrivateKey as an encrypted variable
#>

# Compiled once per session, and loudly: a failure was silenced, and the first sign of it was
# a missing type when the first alert was sealed. Dot-sourcing the script twice is fine.
if (-not ('TenantKeep.Relay.Hpke' -as [type])) {
    Add-Type -Path (Join-Path $PSScriptRoot 'Hpke.cs') -ErrorAction Stop
}

$script:RelayUri = 'https://kainor-relay-prod-func.azurewebsites.net/relay'
# One connection for the run's alerts, and no call waits more than 15 seconds: with no
# timeout, a relay that never answered stalled the whole Watch run.
$script:RelaySession = [Microsoft.PowerShell.Commands.WebRequestSession]::new()
$script:TimeoutSec = 15
$script:EntitlementUri = 'https://kainor-lapslock-prod-func.azurewebsites.net/entitlement'
$script:Info = [Text.Encoding]::ASCII.GetBytes('TenantKeep relay v1')
$script:Suite = 'DHKEM-P256-HKDF-SHA256/HKDF-SHA256/AES-256-GCM'

function ConvertTo-Base64Url([byte[]] $Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

function ConvertFrom-Base64Url([string] $Text) {
    $s = $Text.Replace('-', '+').Replace('_', '/')
    while ($s.Length % 4) { $s += '=' }
    [Convert]::FromBase64String($s)
}

function New-TenantKeepRelaySenderKey {
    <# A sender key for one tenant. Keep PrivateKey secret (an encrypted Automation variable);
       paste SenderCode into TenantKeep on each phone that should trust this tenant's alerts. #>
    param([Parameter(Mandatory)] [Guid] $TenantId)
    $key = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
    $pin = [ordered]@{ v = 1; tenant = $TenantId.ToString().ToLowerInvariant(); senderKey = (ConvertTo-Base64Url ([TenantKeep.Relay.Hpke]::PublicBytes($key))) }
    [pscustomobject]@{
        TenantId   = $pin.tenant
        PrivateKey = [Convert]::ToBase64String($key.ExportPkcs8PrivateKey())
        SenderCode = 'tksender1:' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes(($pin | ConvertTo-Json -Compress))))
    }
}

function Get-TenantKeepEntitlement {
    <# The tenant's entitlement token. Cache it and call this at most once a day. #>
    param([Parameter(Mandatory)] [Guid] $TenantId, [string] $Uri = $script:EntitlementUri)
    $body = @{ version = 1; tenantId = $TenantId.ToString().ToLowerInvariant() } | ConvertTo-Json -Compress
    (Invoke-RestMethod -Method Post -Uri $Uri -Body $body -ContentType 'application/json; charset=utf-8' -TimeoutSec $script:TimeoutSec).token
}

function Get-TenantKeepRelayRetryDelay {
    <# Seconds to wait before sending the same alert again, or $null to stop. Only a 503
       (Apple or the relay busy, "try again later" in the contract) or a 429 (the relay's rate
       limit) is tried again, at most twice; so is no answer at all, a timeout, which is safe
       to repeat because the phone drops an alert id it has already shown. Every other answer
       means something a retry cannot change. Retry-After is honoured up to 30 seconds. #>
    param([int] $Status, [Nullable[double]] $RetryAfter, [int] $Attempt)
    if ($Attempt -ge 2 -or $Status -notin 0, 429, 503) { return $null }
    if ($null -ne $RetryAfter -and $RetryAfter -gt 0) { return [Math]::Min([double] $RetryAfter, 30) }
    @(2, 5)[$Attempt]
}

function ConvertFrom-TenantKeepPairingCode([string] $PairingCode) {
    if (-not $PairingCode.StartsWith('tkrelay1:')) { throw 'Not a pairing code from TenantKeep. It starts tkrelay1:.' }
    $code = [Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $PairingCode.Substring(9))) | ConvertFrom-Json
    if ($code.v -ne 1 -or $code.deviceToken -notmatch '^[0-9a-f]{64,200}$') { throw 'The pairing code is not version 1 or its token is malformed.' }
    $code
}

function New-TenantKeepRelayRequest {
    <# The request body for one alert, without sending it. Send-TenantKeepRelayAlert uses it. #>
    param(
        [Parameter(Mandatory)] [string] $PairingCode,
        [Parameter(Mandatory)] [string] $SenderPrivateKey,
        [Parameter(Mandatory)] [Guid] $TenantId,
        [Parameter(Mandatory)] [string] $Entitlement,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [ValidateLength(1, 80)] [string] $Title,
        [Parameter(Mandatory)] [ValidateLength(1, 400)] [string] $Body,
        [string] $Link,
        [ValidateSet('normal', 'time-sensitive')] [string] $Urgency = 'normal'
    )
    $phone = ConvertFrom-TenantKeepPairingCode $PairingCode
    $sender = [System.Security.Cryptography.ECDiffieHellman]::Create()
    [int] $read = 0
    $sender.ImportPkcs8PrivateKey([Convert]::FromBase64String($SenderPrivateKey), [ref] $read)
    $alert = [ordered]@{
        v = 1; id = [Guid]::NewGuid().ToString(); at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        tenant = $TenantId.ToString().ToLowerInvariant(); kind = $Kind; title = $Title; body = $Body
    }
    if ($Link) { $alert.link = $Link }
    $plaintext = [Text.Encoding]::UTF8.GetBytes(($alert | ConvertTo-Json -Compress))
    if ($plaintext.Length -gt 2700) { throw 'The alert is over 2,700 bytes.' }
    $context = [TenantKeep.Relay.Hpke]::SetupAuthSender((ConvertFrom-Base64Url $phone.publicKey), $sender, $script:Info, 2, $null)
    $ct = $context.Seal([Text.Encoding]::ASCII.GetBytes($phone.deviceToken), $plaintext)
    [ordered]@{
        v = 1; deviceToken = $phone.deviceToken; environment = $phone.environment; urgency = $Urgency; entitlement = $Entitlement
        envelope = [ordered]@{ suite = $script:Suite; mode = 'auth'; enc = (ConvertTo-Base64Url $context.Enc); ct = (ConvertTo-Base64Url $ct) }
    } | ConvertTo-Json -Compress
}

function Send-TenantKeepRelayAlert {
    <# One alert to one phone. Returns Apple's apns-id, or throws with the relay's error code.
       A 410 means the phone was reset or the app removed: pair it again. A busy relay or
       Apple is tried twice more first; see Get-TenantKeepRelayRetryDelay. #>
    param(
        [Parameter(Mandatory)] [string] $PairingCode,
        [Parameter(Mandatory)] [string] $SenderPrivateKey,
        [Parameter(Mandatory)] [Guid] $TenantId,
        [Parameter(Mandatory)] [string] $Entitlement,
        [Parameter(Mandatory)] [string] $Kind,
        [Parameter(Mandatory)] [string] $Title,
        [Parameter(Mandatory)] [string] $Body,
        [string] $Link,
        [ValidateSet('normal', 'time-sensitive')] [string] $Urgency = 'normal',
        [string] $Uri = $script:RelayUri
    )
    $request = New-TenantKeepRelayRequest -PairingCode $PairingCode -SenderPrivateKey $SenderPrivateKey -TenantId $TenantId `
        -Entitlement $Entitlement -Kind $Kind -Title $Title -Body $Body -Link $Link -Urgency $Urgency
    for ($attempt = 0; ; $attempt++) {
        try {
            return (Invoke-RestMethod -Method Post -Uri $Uri -Body $request -ContentType 'application/json; charset=utf-8' `
                -TimeoutSec $script:TimeoutSec -WebSession $script:RelaySession).apnsId
        } catch {
            $response = $_.Exception.Response
            $status = if ($response) { [int] $response.StatusCode } else { 0 }
            $retryAfter = if ($response -and $response.Headers.RetryAfter.Delta) { $response.Headers.RetryAfter.Delta.TotalSeconds } else { $null }
            $wait = Get-TenantKeepRelayRetryDelay -Status $status -RetryAfter $retryAfter -Attempt $attempt
            if ($null -eq $wait) {
                $detail = $_.ErrorDetails.Message
                throw ('The relay refused the alert: ' + ($detail ?? $_.Exception.Message))
            }
            # Up to a second of jitter, so many runs refused at once do not return at once.
            Start-Sleep -Milliseconds ([int] ($wait * 1000) + (Get-Random -Minimum 0 -Maximum 1000))
        }
    }
}
