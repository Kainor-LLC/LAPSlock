#Requires -Version 7.4
<#
.SYNOPSIS
    Makes the hosted watcher's alert sender key and stores it in Key Vault (HOSTED-WATCH-PLAN.md, H1).

.DESCRIPTION
    The relay contract's HPKE sender key: P-256, authenticated mode. Key Vault's standard tier
    cannot do the key agreement HPKE needs, so the private key is a secret that only the
    function app's identity can read (Key Vault Secrets User, granted by main.bicep). The key
    is made in memory and sent straight to Key Vault; it is never written to disk.
    Prints the public key, which phones receive from the Alerts API when they register.

    Needs, for this run only, Key Vault Secrets Officer on the vault for the signed-in
    account. Remove that role afterwards. Refuses to replace an existing key unless -Replace
    is given, because replacing it makes every registered phone reject alerts until it
    registers again.

.PARAMETER VaultName
    main.bicep's vaultName output.

.PARAMETER Replace
    Replace an existing key.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $VaultName,
    [switch] $Replace
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$secretName = 'watch-sender-key'

$existing = az keyvault secret list --vault-name $VaultName --query "[?name=='$secretName'].name" --output tsv
if ($LASTEXITCODE -ne 0) { throw "Cannot list secrets in $VaultName. Sign in with az login and check the Secrets Officer role." }
if ($existing -and -not $Replace) { throw "$secretName already exists. Use -Replace only if every phone may register again." }

$key = [System.Security.Cryptography.ECDiffieHellman]::Create([System.Security.Cryptography.ECCurve+NamedCurves]::nistP256)
try {
    $private = [Convert]::ToBase64String($key.ExportPkcs8PrivateKey())
    $point = $key.ExportParameters($false).Q
    $public = [byte[]](@(0x04) + $point.X + $point.Y)
    # Sent from this process to Key Vault's REST API, not passed to az as an argument, so the
    # key never appears in the process list.
    $token = az account get-access-token --resource 'https://vault.azure.net' --query accessToken --output tsv
    if ($LASTEXITCODE -ne 0) { throw 'Could not get a Key Vault token from az.' }
    $body = @{ value = $private; contentType = 'application/pkcs8;base64' } | ConvertTo-Json
    Invoke-RestMethod -Method Put -Uri "https://$VaultName.vault.azure.net/secrets/$($secretName)?api-version=7.4" `
        -Headers @{ Authorization = "Bearer $token" } -ContentType 'application/json' -Body $body | Out-Null
    $private = $null
    $body = $null
    $encoded = [Convert]::ToBase64String($public).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    Write-Information "Stored $secretName in $VaultName." -InformationAction Continue
    Write-Information "Sender public key (X9.63, base64url): $encoded" -InformationAction Continue
} finally {
    $key.Dispose()
}
