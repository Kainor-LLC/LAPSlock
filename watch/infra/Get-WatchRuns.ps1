#Requires -Version 7.4
<#
.SYNOPSIS
    Says whether the alert service is running, and lists its runs that sent an alert or had
    a failure.

.DESCRIPTION
    Run in Kainor's tenant, signed in with the Azure CLI (az login --tenant kainor.com). It
    changes nothing. It reads the service's own log through Azure Resource Manager, so it
    works from a network that blocks the log query hosts.

    The service writes one line a minute, and that line holds counts only: organizations
    watched, alerts the relay accepted, failures, and the relay's answers to the alerts that
    did not go ("403x1" is one alert answered 403; status 0 is no answer at all). It names
    no organization, account, policy or phone, so neither does this.

    This is the only readout there is. The service has no endpoint that reports its state.

.PARAMETER Hours
    How far back to look. A day by default.
#>
[CmdletBinding()]
param(
    [string] $ResourceGroup = 'kainor-watch-prod-rg',
    [ValidateRange(1, 720)] [int] $Hours = 24
)

$ErrorActionPreference = 'Stop'

$insights = az resource list --resource-group $ResourceGroup --resource-type microsoft.insights/components --query '[0].id' --output tsv
if ($LASTEXITCODE -ne 0 -or -not $insights) { throw "No Application Insights resource was found in $ResourceGroup." }
$url = "https://management.azure.com$insights/query?api-version=2018-04-20"

function Read-Log([string] $Query) {
    # The query goes in a file: a body with quotes in it does not survive every shell.
    $file = Join-Path ([IO.Path]::GetTempPath()) "watch-runs-$([Guid]::NewGuid().ToString('N')).json"
    try {
        @{ query = $Query } | ConvertTo-Json | Set-Content -Path $file -Encoding utf8
        $answer = az rest --method post --url $url --body "@$file" --output json
        if ($LASTEXITCODE -ne 0) { throw 'The log could not be read.' }
        # The comma keeps a single row from being unrolled into its cells.
        return , @(($answer | ConvertFrom-Json).tables[0].rows)
    }
    finally {
        Remove-Item $file -ErrorAction SilentlyContinue
    }
}

$runs = "traces | where timestamp > ago($($Hours)h) | where message startswith 'TenantWatch organizations'"

function Format-Time($Value) {
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') }
    return "$Value"
}

$summary = Read-Log "$runs | summarize runs = count(), latest = max(timestamp)"
if ($summary.Count -eq 0 -or $summary[0][0] -eq 0) {
    Write-Host "No run in the last $Hours hours. The service runs every minute, so it is stopped or its log is not arriving."
    return
}
Write-Host "Runs in the last $Hours hours: $($summary[0][0]). Last run: $(Format-Time $summary[0][1]) UTC."

$notable = Read-Log "$runs | where message !contains 'alerts=0 failures=0' | project timestamp, message | order by timestamp asc"
if ($notable.Count -eq 0) {
    Write-Host 'No run sent an alert or had a failure.'
    return
}
Write-Host 'Runs that sent an alert or had a failure (UTC):'
foreach ($row in $notable) { Write-Host "  $(Format-Time $row[0])  $($row[1])" }
