<#
.SYNOPSIS
Stops a service's log from keeping where a request came from.

.DESCRIPTION
Azure Application Insights works out a city, state and country from the address each
request arrives from, stores them on the log row, and then discards the address. Nothing
in a function app's settings turns that off. So the alert service's log held, for each
phone that registered, the city it registered from, while the privacy policy says the
service keeps no locations.

This puts a transformation on the log workspace that empties those three columns as rows
arrive, before they are stored. It changes nothing else: every row still arrives, with its
time, name, result and message. Rows already stored are not changed; they age out with the
workspace's retention.

A workspace has one such rule. Run it once for each service's workspace, and again after
anything that redeploys the workspace (`main.bicep` declares the watcher's, and a redeploy
may drop the link to the rule). Running it twice is harmless.

Takes effect about thirty minutes after it is first linked. Check with:

  pwsh ./watch/infra/Set-LogLocationBlanking.ps1 -ResourceGroup kainor-watch-prod-rg -Workspace kainor-watch-prod-law -Check

.EXAMPLE
pwsh ./watch/infra/Set-LogLocationBlanking.ps1 -ResourceGroup kainor-watch-prod-rg -Workspace kainor-watch-prod-law

.EXAMPLE
pwsh ./watch/infra/Set-LogLocationBlanking.ps1 -ResourceGroup DefaultResourceGroup-CUS -Workspace DefaultWorkspace-<subscription>-CUS -RuleResourceGroup kainor-lapslock-prod-rg -Tables AppRequests,AppExceptions,AppDependencies
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $ResourceGroup,
    [Parameter(Mandatory)] [string] $Workspace,
    # Where the rule is kept. The workspace's own group unless that group is not ours.
    [string] $RuleResourceGroup = $ResourceGroup,
    # The log tables to empty the columns in. A table has to have received rows before a
    # rule can name it, so name the ones the service writes.
    [string[]] $Tables = @('AppRequests', 'AppTraces', 'AppExceptions'),
    # Reports how many rows of the last hour still carry a place, and changes nothing.
    [switch] $Check
)

$ErrorActionPreference = 'Stop'

# Started with -File, PowerShell hands over "A,B" as one name. Split it, or the rule is made
# for a table that does not exist and empties nothing.
$Tables = @($Tables | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

$workspaceId = az monitor log-analytics workspace show --resource-group $ResourceGroup --workspace-name $Workspace --query id --output tsv
if (-not $workspaceId) { throw "Workspace $Workspace not found in $ResourceGroup." }

if ($Check) {
    $query = 'union withsource=tbl App* | where TimeGenerated > ago(1h) | summarize rows=count(), withPlace=countif(isnotempty(column_ifexists("ClientCity","")) or isnotempty(column_ifexists("ClientCountryOrRegion",""))), newestWithPlace=maxif(TimeGenerated, isnotempty(column_ifexists("ClientCity",""))) by tbl | order by tbl asc'
    $body = Join-Path ([IO.Path]::GetTempPath()) "log-location-check-$PID.json"
    @{ query = $query } | ConvertTo-Json | Set-Content -Path $body -Encoding utf8
    try {
        az rest --method post --url "https://management.azure.com$workspaceId/query?api-version=2017-10-01" --body "@$body" --query 'tables[0].rows' --output table
    } finally {
        Remove-Item $body -ErrorAction SilentlyContinue
    }
    Write-Host 'withPlace should stop growing about thirty minutes after the rule is linked. Rows from before stay until they age out.'
    return
}

$location = az monitor log-analytics workspace show --resource-group $ResourceGroup --workspace-name $Workspace --query location --output tsv
$ruleName = "$Workspace-no-location"
if ($ruleName.Length -gt 64) { $ruleName = $ruleName.Substring($ruleName.Length - 64).TrimStart('-') }

$rule = @{
    location   = $location
    kind       = 'WorkspaceTransforms'
    properties = @{
        description  = 'Empties the city, state and country that Application Insights derives from the caller address, before rows are stored.'
        destinations = @{ logAnalytics = @(@{ workspaceResourceId = $workspaceId; name = 'workspace' }) }
        dataFlows    = @($Tables | ForEach-Object {
                @{
                    streams      = @("Microsoft-Table-$_")
                    destinations = @('workspace')
                    transformKql = "source | extend ClientCity = '', ClientStateOrProvince = '', ClientCountryOrRegion = ''"
                }
            })
    }
}
$file = Join-Path ([IO.Path]::GetTempPath()) "log-location-rule-$PID.json"
$rule | ConvertTo-Json -Depth 8 | Set-Content -Path $file -Encoding utf8
try {
    # Sent to Resource Manager as it is. The command line's own rule file takes another shape.
    $subscription = ($workspaceId -split '/')[2]
    $ruleUrl = "https://management.azure.com/subscriptions/$subscription/resourceGroups/$RuleResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$($ruleName)?api-version=2023-03-11"
    $ruleId = az rest --method put --url $ruleUrl --body "@$file" --query id --output tsv
    if (-not $ruleId) { throw 'The rule was not created.' }
    $made = az rest --method get --url $ruleUrl --query 'properties.dataFlows[].streams[0]' --output tsv
    foreach ($table in $Tables) {
        if ($made -notcontains "Microsoft-Table-$table") { throw "The rule has no flow for $table. It has: $($made -join ', ')" }
    }
} finally {
    Remove-Item $file -ErrorAction SilentlyContinue
}

$linked = az monitor log-analytics workspace update --resource-group $ResourceGroup --workspace-name $Workspace --data-collection-rule $ruleId --query defaultDataCollectionRuleResourceId --output tsv
if ($linked -ne $ruleId) { throw "The workspace is not linked to the rule. It reports: $linked" }

Write-Host "Linked. Rows arriving in $($Tables -join ', ') lose their city, state and country from about thirty minutes from now."
Write-Host "Check with: pwsh ./watch/infra/Set-LogLocationBlanking.ps1 -ResourceGroup $ResourceGroup -Workspace $Workspace -Check"
