// TenantKeep Watch, hosted by Kainor (HOSTED-WATCH-PLAN.md, step H1): the Azure side.
//
// One resource group in Central US with everything the watcher needs and nothing else:
// a Flex Consumption function app with a system-assigned identity, a storage account
// reached by that identity only (no shared keys), a Key Vault for the alert sender's key,
// Log Analytics capped at 0.1 GB a day, and a $10 monthly budget. The identity gets exactly
// the data roles below. The Entra apps are made separately (New-WatchApps.ps1), because a
// template cannot create app registrations.
//
//   az group create --name kainor-watch-prod-rg --location centralus
//   az deployment group create --resource-group kainor-watch-prod-rg --template-file watch/infra/main.bicep --parameters budgetEmail=<address>

targetScope = 'resourceGroup'

@description('Prefix for every resource name.')
param prefix string = 'kainor-watch-prod'

@description('Region. Central US, with the relay.')
param location string = 'centralus'

@description('Who the budget alerts go to.')
param budgetEmail string

@description('Monthly budget in US dollars.')
param budgetAmount int = 10

@description('First day of the month the budget starts, yyyy-MM-01.')
param budgetStart string = '2026-11-01'

@description('The TenantKeep Watch app registration client ID, from New-WatchApps.ps1. Empty on the first run.')
param watchClientId string = ''

@description('The TenantKeep Alerts API app ID URI, from New-WatchApps.ps1. Empty on the first run.')
param alertsApiAudience string = ''

var storageName = replace('${prefix}st', '-', '')
var deploymentContainer = 'deploymentpackage'

// Data roles, by built-in role definition ID.
var roles = {
  blobOwner: 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
  queueContributor: '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
  tableContributor: '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
  secretsUser: '4633458b-17de-408a-b874-0445c86b69e6'
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: storageName
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    supportsHttpsTrafficOnly: true
    defaultToOAuthAuthentication: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storage
  name: 'default'
}

resource container 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: deploymentContainer
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-law'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    workspaceCapping: { dailyQuotaGb: json('0.1') }
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${prefix}-ai'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: workspace.id
    DisableIpMasking: false
  }
}

resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: { family: 'A', name: 'standard' }
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: '${prefix}-plan'
  location: location
  kind: 'functionapp'
  sku: { name: 'FC1', tier: 'FlexConsumption' }
  properties: { reserved: true }
}

resource site 'Microsoft.Web/sites@2024-04-01' = {
  name: '${prefix}-func'
  location: location
  kind: 'functionapp,linux'
  identity: { type: 'SystemAssigned' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      appSettings: [
        { name: 'AzureWebJobsStorage__accountName', value: storage.name }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
        { name: 'WATCH_STORAGE_ACCOUNT', value: storage.name }
        { name: 'WATCH_CLIENT_ID', value: watchClientId }
        { name: 'WATCH_HOME_TENANT_ID', value: subscription().tenantId }
        { name: 'ALERTS_API_AUDIENCE', value: alertsApiAudience }
        { name: 'SENDER_KEY_SECRET_URI', value: '${vault.properties.vaultUri}secrets/watch-sender-key' }
        { name: 'RELAY_URL', value: 'https://kainor-relay-prod-func.azurewebsites.net/api/v1/relay' }
        { name: 'ENTITLEMENT_URL', value: 'https://kainor-lapslock-prod-func.azurewebsites.net' }
      ]
    }
    functionAppConfig: {
      deployment: {
        storage: {
          type: 'blobContainer'
          value: '${storage.properties.primaryEndpoints.blob}${deploymentContainer}'
          authentication: { type: 'SystemAssignedIdentity' }
        }
      }
      scaleAndConcurrency: {
        maximumInstanceCount: 40
        instanceMemoryMB: 512
      }
      runtime: { name: 'dotnet-isolated', version: '10.0' }
    }
  }
}

resource storageRoles 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for role in [roles.blobOwner, roles.queueContributor, roles.tableContributor]: {
  name: guid(storage.id, site.id, role)
  scope: storage
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', role)
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
  }
}]

resource vaultRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, site.id, roles.secretsUser)
  scope: vault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roles.secretsUser)
    principalId: site.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

resource budget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: '${prefix}-budget'
  properties: {
    category: 'Cost'
    amount: budgetAmount
    timeGrain: 'Monthly'
    timePeriod: { startDate: budgetStart }
    notifications: {
      actual80: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 80
        contactEmails: [ budgetEmail ]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThan'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [ budgetEmail ]
      }
    }
  }
}

@description('The function identity, which New-WatchApps.ps1 trusts as the Watch app\'s credential.')
output functionPrincipalId string = site.identity.principalId
output functionName string = site.name
output vaultName string = vault.name
