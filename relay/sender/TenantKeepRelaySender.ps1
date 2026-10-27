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

Add-Type -Path (Join-Path $PSScriptRoot 'Hpke.cs') -ErrorAction SilentlyContinue

$script:RelayUri = 'https://kainor-relay-prod-func.azurewebsites.net/relay'
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
    (Invoke-RestMethod -Method Post -Uri $Uri -Body $body -ContentType 'application/json; charset=utf-8').token
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
       A 410 means the phone was reset or the app removed: pair it again. #>
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
    try {
        (Invoke-RestMethod -Method Post -Uri $Uri -Body $request -ContentType 'application/json; charset=utf-8').apnsId
    } catch {
        $detail = $_.ErrorDetails.Message
        throw ('The relay refused the alert: ' + ($detail ?? $_.Exception.Message))
    }
}
