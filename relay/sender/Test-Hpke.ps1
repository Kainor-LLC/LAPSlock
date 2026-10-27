<#
.SYNOPSIS
    Checks Hpke.cs against the CFRG test vectors for the relay's suite, authenticated mode:
    DHKEM(P-256), HKDF-SHA256, with AES-128-GCM and AES-256-GCM, every encryption listed.

.EXAMPLE
    pwsh ./relay/sender/Test-Hpke.ps1 -Vectors ./test-vectors.json

    The vectors are https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/master/test-vectors.json
#>
param([Parameter(Mandatory)] [string] $Vectors)
$ErrorActionPreference = 'Stop'
Add-Type -Path (Join-Path $PSScriptRoot 'Hpke.cs')

function FromHex([string] $hex) { [Convert]::FromHexString($hex) }
function ToHex([byte[]] $bytes) { [Convert]::ToHexString($bytes).ToLowerInvariant() }

$all = Get-Content -Raw $Vectors | ConvertFrom-Json
$cases = $all | Where-Object { $_.mode -eq 2 -and $_.kem_id -eq 16 -and $_.kdf_id -eq 1 -and $_.aead_id -in 1, 2 }
if ($cases.Count -lt 2) { throw 'the vectors for the suite were not found' }
$checked = 0
foreach ($case in $cases) {
    $skE = [TenantKeep.Relay.Hpke]::Key((FromHex $case.pkEm), (FromHex $case.skEm))
    $skS = [TenantKeep.Relay.Hpke]::Key((FromHex $case.pkSm), (FromHex $case.skSm))
    $skR = [TenantKeep.Relay.Hpke]::Key((FromHex $case.pkRm), (FromHex $case.skRm))
    $info = FromHex $case.info
    $send = [TenantKeep.Relay.Hpke]::SetupAuthSender((FromHex $case.pkRm), $skS, $info, [uint16]$case.aead_id, $skE)
    if ((ToHex $send.Enc) -ne $case.enc) { throw "enc differs, aead $($case.aead_id)" }
    if ((ToHex $send.Key) -ne $case.key) { throw "key differs, aead $($case.aead_id)" }
    if ((ToHex $send.BaseNonce) -ne $case.base_nonce) { throw "base nonce differs, aead $($case.aead_id)" }
    $receive = [TenantKeep.Relay.Hpke]::SetupAuthRecipient((FromHex $case.enc), $skR, (FromHex $case.pkSm), $info, [uint16]$case.aead_id)
    foreach ($e in $case.encryptions) {
        $ct = $send.Seal((FromHex $e.aad), (FromHex $e.pt))
        if ((ToHex $ct) -ne $e.ct) { throw "ciphertext differs at an encryption, aead $($case.aead_id)" }
        $pt = $receive.Open((FromHex $e.aad), $ct)
        if ((ToHex $pt) -ne $e.pt) { throw "open differs, aead $($case.aead_id)" }
        $checked++
    }
}
"HPKE matches the CFRG vectors: $($cases.Count) suites, $checked encryptions sealed and opened."
