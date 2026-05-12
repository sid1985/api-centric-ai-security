# BOM-safe UTF-8 recovery script — completes APIM deployment after crash
param(
    [string]$ResourceGroup  = "rg-api-security-demo",
    [string]$Location       = "eastus",
    [string]$PublisherEmail = "sid061985@gmail.com"
)

$ErrorActionPreference = "Stop"
$Root     = Split-Path $PSScriptRoot -Parent
$AzureDir = $PSScriptRoot
$Suffix   = "72672d61"
$ApimName = "apim-ai-security-$Suffix"

Write-Host "[Step 1] Updating Container App to external ingress..." -ForegroundColor Yellow
az containerapp ingress enable `
    --name ca-ai-service `
    --resource-group $ResourceGroup `
    --type external `
    --target-port 8001 `
    --transport http | Out-Null

$AiServiceFqdn = az containerapp show `
    --name "ca-ai-service" --resource-group $ResourceGroup `
    --query "properties.configuration.ingress.fqdn" -o tsv
$AiServiceUrl = "https://$AiServiceFqdn"
Write-Host "  OK: $AiServiceUrl"

Write-Host "[Step 2] Purging soft-deleted APIM if present..." -ForegroundColor Yellow
$_prevEAP = $ErrorActionPreference
$ErrorActionPreference = "Continue"
az apim deletedservice purge --service-name $ApimName --location $Location 2>&1 | Out-Null
$ErrorActionPreference = $_prevEAP
Write-Host "  OK (purge attempted)"

Write-Host "[Step 3] Deploying APIM Consumption via Bicep (~5 min)..." -ForegroundColor Yellow
az deployment group create `
    --resource-group $ResourceGroup `
    --template-file "$AzureDir\apim.bicep" `
    --parameters `
        location=$Location `
        suffix=$Suffix `
        publisherEmail=$PublisherEmail `
        aiServiceUrl=$AiServiceUrl | Out-Null

$ApimGatewayUrl = az apim show `
    --name $ApimName --resource-group $ResourceGroup `
    --query "gatewayUrl" -o tsv
Write-Host "  OK: $ApimGatewayUrl"

Write-Host "[Step 4] Retrieving subscription key..." -ForegroundColor Yellow
$SubId = az account show --query id -o tsv
$ApimSubKey = az rest `
    --method post `
    --uri "https://management.azure.com/subscriptions/$SubId/resourceGroups/$ResourceGroup/providers/Microsoft.ApiManagement/service/$ApimName/subscriptions/demo-subscription/listSecrets?api-version=2023-09-01-preview" `
    --query primaryKey -o tsv
Write-Host "  OK: (key retrieved)"

$GatewayWithPath = "$ApimGatewayUrl/ai"
$envData = @{
    GatewayUrl = $GatewayWithPath
    DirectUrl  = $AiServiceUrl
    ApimKey    = $ApimSubKey
}
$envData | ConvertTo-Json | Out-File "$Root\.azure-env.json" -Encoding utf8

Write-Host ""
Write-Host "Deployment complete! .azure-env.json saved." -ForegroundColor Green
Write-Host "  Gateway : $GatewayWithPath"
Write-Host "  Direct  : $AiServiceUrl"
