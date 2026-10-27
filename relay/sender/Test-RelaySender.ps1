<#
.SYNOPSIS
    Round trip without a network: a sender key, a phone key, a request body, and the phone's
    side opening it. The Swift side is tested in RelayKitTests with an envelope sealed here.
#>
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'TenantKeepRelaySender.ps1')
$tenant = 'c0ffee00-1111-2222-3333-444455556666'
$setup = New-TenantKeepRelaySenderKey -TenantId $tenant
if (-not $setup.SenderCode.StartsWith('tksender1:')) { throw 'sender code prefix' }
$phone = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
$token = -join (0..31 | ForEach-Object { '{0:x2}' -f $_ })
$pair = [ordered]@{ v = 1; deviceToken = $token; environment = 'sandbox'; publicKey = (ConvertTo-Base64Url ([TenantKeep.Relay.Hpke]::PublicBytes($phone))) } | ConvertTo-Json -Compress
$pairingCode = 'tkrelay1:' + (ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($pair)))
$json = New-TenantKeepRelayRequest -PairingCode $pairingCode -SenderPrivateKey $setup.PrivateKey -TenantId $tenant -Entitlement 'a.b.c' `
    -Kind breakGlassSignIn -Title 'Contoso: break-glass sign-in' -Body 'bg-admin signed in' -Link 'tenantkeep://people' -Urgency 'time-sensitive'
$req = $json | ConvertFrom-Json
$keys = ($req.PSObject.Properties.Name | Sort-Object) -join ','
if ($keys -ne 'deviceToken,entitlement,envelope,environment,urgency,v') { throw "unexpected fields: $keys" }
$senderPublic = ConvertFrom-Base64Url (([Text.Encoding]::UTF8.GetString((ConvertFrom-Base64Url $setup.SenderCode.Substring(10))) | ConvertFrom-Json).senderKey)
$open = [TenantKeep.Relay.Hpke]::SetupAuthRecipient((ConvertFrom-Base64Url $req.envelope.enc), $phone, $senderPublic, [Text.Encoding]::ASCII.GetBytes('TenantKeep relay v1'), 2)
$alert = [Text.Encoding]::UTF8.GetString($open.Open([Text.Encoding]::ASCII.GetBytes($token), (ConvertFrom-Base64Url $req.envelope.ct))) | ConvertFrom-Json
if ($alert.title -ne 'Contoso: break-glass sign-in' -or $alert.tenant -ne $tenant) { throw 'round trip content' }
if ($req.envelope.enc.Length -ne 87) { throw 'enc length' }
'Sender round trip passed: fields ' + $keys + '; the phone opened "' + $alert.title + '".'
