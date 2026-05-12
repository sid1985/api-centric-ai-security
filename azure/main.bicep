// Azure deployment for API Security Demo
//
// Architecture:
//   ┌────────────┐   APIM policy  ┌──────────────────┐   internal   ┌─────────────┐
//   │  Internet  │ ─────────────► │  Azure APIM      │ ────────────► │ AI Service  │
//   └────────────┘                │  (Consumption)   │              │ (Container  │
//                                 │  5-layer security │              │   Apps)     │
//                                 └──────────────────┘              └─────────────┘
//
// Cost: ~$0 for this experiment (APIM Consumption: $3.50/million calls, CA scale-to-zero)

@description('Azure region')
param location string = resourceGroup().location

@description('Short unique suffix (auto-generated from RG ID if not supplied)')
param suffix string = uniqueString(resourceGroup().id)

@description('APIM publisher email (required by ARM)')
param publisherEmail string = 'demo@example.com'

// NOTE: The AI Service container image is pushed by deploy.ps1 after Bicep runs.
// Bicep provisions the infrastructure; the image reference is updated separately.
@description('AI Service container image (updated by deploy.ps1 post-provision)')
param aiServiceImage string = 'mcr.microsoft.com/azuredocs/containerapps-helloworld:latest'

@description('ACR server name (for image pull credentials)')
param acrServer string = ''

@description('ACR admin username')
param acrUsername string = ''

@description('ACR admin password')
@secure()
param acrPassword string = ''

// ── Log Analytics (5 GB/month free) ──────────────────────────────────────────
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'law-api-security-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// ── Container Apps Environment ────────────────────────────────────────────────
resource caEnv 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: 'cae-api-security-${suffix}'
  location: location
  properties: {
    appLogsConfiguration: {
      destination: 'log-analytics'
      logAnalyticsConfiguration: {
        customerId: logAnalytics.properties.customerId
        sharedKey: logAnalytics.listKeys().primarySharedKey
      }
    }
  }
}

// ── AI Service Container App (internal — APIM is the only entry point) ────────
resource aiService 'Microsoft.App/containerApps@2024-03-01' = {
  name: 'ca-ai-service'
  location: location
  properties: {
    managedEnvironmentId: caEnv.id
    configuration: {
      activeRevisionsMode: 'Single'
      ingress: {
        external: false       // internal FQDN only; routable by APIM within the environment
        targetPort: 8001
        transport: 'http'
      }
      registries: empty(acrServer) ? [] : [
        {
          server:   acrServer
          username: acrUsername
          passwordSecretRef: 'acr-password'
        }
      ]
      secrets: empty(acrPassword) ? [] : [
        { name: 'acr-password', value: acrPassword }
      ]
    }
    template: {
      containers: [
        {
          name:  'ai-service'
          image: aiServiceImage
          resources: {
            cpu:    json('0.25')
            memory: '0.5Gi'
          }
          env: [
            { name: 'DB_PATH', value: '/tmp/ai_service.db' }
          ]
          probes: [
            {
              type: 'Liveness'
              httpGet: { path: '/health', port: 8001 }
              initialDelaySeconds: 30
              periodSeconds: 10
            }
          ]
        }
      ]
      scale: {
        minReplicas: 0    // scale-to-zero (free when idle)
        maxReplicas: 2
        rules: [
          { name: 'http-scale', http: { metadata: { concurrentRequests: '30' } } }
        ]
      }
    }
  }
}

// ── Azure APIM (Consumption tier — security enforcement layer) ────────────────
var aiServiceUrl = 'https://${aiService.properties.configuration.ingress.fqdn}'

module apim 'apim.bicep' = {
  name: 'apim-deploy'
  params: {
    location:       location
    suffix:         suffix
    publisherEmail: publisherEmail
    aiServiceUrl:   aiServiceUrl
  }
}

// ── Outputs ───────────────────────────────────────────────────────────────────
output apimGatewayUrl    string = apim.outputs.apimGatewayUrl
output apimName          string = apim.outputs.apimName
output aiServiceFqdn     string = aiService.properties.configuration.ingress.fqdn
output aiServiceUrl      string = aiServiceUrl
output resourceGroupName string = resourceGroup().name
