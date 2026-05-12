<#
.SYNOPSIS
    Deploy API Security Demo to Azure:
      - AI Service  → Azure Container Apps (internal, scale-to-zero)
      - Security    → Azure APIM Consumption tier (pay-per-call, ~$0 for demo)

.PARAMETER ResourceGroup  Target resource group (created if missing)
.PARAMETER Location       Azure region (default: eastus)
.PARAMETER PublisherEmail Required by APIM provisioning
#>
param(
    [string]$ResourceGroup  = "rg-api-security-demo",
    [string]$Location       = "eastus",
    [string]$PublisherEmail = "demo@example.com"
)

$ErrorActionPreference = "Stop"
$Root     = Split-Path $PSScriptRoot -Parent
$AzureDir = $PSScriptRoot

# Stable 8-char suffix derived from RG name (deterministic re-runs)
$Bytes   = [System.Text.Encoding]::UTF8.GetBytes($ResourceGroup)
$Suffix  = (-join ($Bytes | ForEach-Object { $_.ToString("x2") })).Substring(0, 8)
$AcrName = "acrapisec$Suffix"

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║    API Security Demo — Azure Deployment                      ║
║    AI Service : Container Apps (external, scale-to-zero)     ║
║    Gateway    : Azure APIM Consumption (~`$0 for this demo)   ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ── 1. Register providers ─────────────────────────────────────────────────────
Write-Host "`n[1/7] Registering providers..." -ForegroundColor Yellow
az provider register --namespace Microsoft.App               --wait 2>$null
az provider register --namespace Microsoft.ApiManagement     --wait 2>$null
az provider register --namespace Microsoft.OperationalInsights --wait 2>$null
Write-Host "  ✓ Providers ready"

# ── 2. Resource Group ─────────────────────────────────────────────────────────
Write-Host "`n[2/7] Creating resource group '$ResourceGroup'..." -ForegroundColor Yellow
az group create --name $ResourceGroup --location $Location | Out-Null
Write-Host "  ✓ Resource group ready"

# ── 3. Azure Container Registry ──────────────────────────────────────────────
Write-Host "`n[3/7] Creating ACR '$AcrName'..." -ForegroundColor Yellow
az acr create --resource-group $ResourceGroup --name $AcrName --sku Basic --admin-enabled true
if ($LASTEXITCODE -ne 0) { throw "ACR creation failed" }
$AcrServer = "$AcrName.azurecr.io"
Write-Host "  ✓ ACR ready: $AcrServer"

# ── 4. Build & push AI Service image (ACR Tasks — no local Docker needed) ────
Write-Host "`n[4/7] Building & pushing AI Service image via ACR Tasks..." -ForegroundColor Yellow
$AiImage = "$AcrServer/ai-service:latest"
az acr build `
    --registry $AcrName `
    --image "ai-service:latest" `
    --file "$Root\ai-service\Dockerfile" `
    "$Root\ai-service"
Write-Host "  ✓ Image pushed"

# ── 5. Deploy AI Service to Container Apps ────────────────────────────────────
Write-Host "`n[5/7] Deploying AI Service to Container Apps..." -ForegroundColor Yellow

$CaEnvName   = "cae-api-security-$Suffix"
$LawName     = "law-api-security-$Suffix"

az monitor log-analytics workspace create `
    --resource-group $ResourceGroup --workspace-name $LawName --location $Location | Out-Null

$LawId  = az monitor log-analytics workspace show -g $ResourceGroup -n $LawName --query customerId   -o tsv
$LawKey = az monitor log-analytics workspace get-shared-keys -g $ResourceGroup -n $LawName --query primarySharedKey -o tsv

az containerapp env create `
    --name $CaEnvName --resource-group $ResourceGroup --location $Location `
    --logs-workspace-id $LawId --logs-workspace-key $LawKey | Out-Null

$AcrPassword = az acr credential show --name $AcrName --query "passwords[0].value" -o tsv

az containerapp create `
    --name "ca-ai-service" `
    --resource-group $ResourceGroup `
    --environment $CaEnvName `
    --image $AiImage `
    --registry-server $AcrServer `
    --registry-username $AcrName `
    --registry-password $AcrPassword `
    --ingress external `
    --target-port 8001 `
    --min-replicas 0 --max-replicas 2 `
    --cpu 0.25 --memory 0.5Gi `
    --env-vars "DB_PATH=/tmp/ai_service.db" | Out-Null

$AiServiceFqdn = az containerapp show `
    --name "ca-ai-service" --resource-group $ResourceGroup `
    --query "properties.configuration.ingress.fqdn" -o tsv
$AiServiceUrl = "https://$AiServiceFqdn"
Write-Host "  ✓ AI Service deployed (internal): $AiServiceUrl"

# ── 6. Deploy Azure APIM (Consumption) ───────────────────────────────────────
Write-Host "`n[6/7] Deploying APIM Consumption tier (3-5 min)..." -ForegroundColor Yellow
# Purge soft-deleted APIM if it exists (Azure retains deleted instances 48h)
$ApimName = "apim-ai-security-$Suffix"
# Auto-purge if in soft-delete state (Azure retains deleted APIM 48h after RG deletion)
# Use Continue so NativeCommandError on "not found" does not abort the script
$_prevEAP = $ErrorActionPreference; $ErrorActionPreference = "Continue"
az apim deletedservice purge --service-name $ApimName --location $Location 2>&1 | Out-Null
$ErrorActionPreference = $_prevEAP

az deployment group create `
    --resource-group $ResourceGroup `
    --template-file "$AzureDir\apim.bicep" `
    --parameters `
        location=$Location `
        suffix=$Suffix `
        publisherEmail=$PublisherEmail `
        aiServiceUrl=$AiServiceUrl | Out-Null

$ApimGatewayUrl = az apim show --name $ApimName --resource-group $ResourceGroup --query "gatewayUrl" -o tsv
Write-Host "  ✓ APIM deployed: $ApimGatewayUrl"

# ── 7. Retrieve subscription key ──────────────────────────────────────────────
Write-Host "`n[7/7] Retrieving APIM subscription key..." -ForegroundColor Yellow
$ApimSubKey = az apim subscription keys list `
    --resource-group $ResourceGroup `
    --service-name $ApimName `
    --sid "demo-subscription" `
    --query "primaryKey" -o tsv
Write-Host "  ✓ Subscription key retrieved"

# Save env file so run_experiment.ps1 auto-picks it up
@{
    GatewayUrl = "$ApimGatewayUrl/ai"
    DirectUrl  = $AiServiceUrl
    ApimKey    = $ApimSubKey
} | ConvertTo-Json | Out-File "$Root\.azure-env.json" -Encoding utf8

# ── Done ──────────────────────────────────────────────────────────────────────
Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║  Deployment complete!                                        ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

Write-Host "  APIM URL:    $ApimGatewayUrl/ai" -ForegroundColor Cyan
Write-Host "  Sub Key:     $ApimSubKey"         -ForegroundColor Yellow
Write-Host ""
Write-Host "  Run experiment (copy-paste ready):"
Write-Host "    python attack-simulator\simulator.py ``"         -ForegroundColor White
Write-Host "        --gateway-url $ApimGatewayUrl/ai ``"         -ForegroundColor White
Write-Host "        --direct-url  $AiServiceUrl ``"              -ForegroundColor White
Write-Host "        --apim-key    $ApimSubKey"                   -ForegroundColor White
Write-Host ""
Write-Host "  Or just run: .\scripts\run_experiment.ps1  (reads .azure-env.json automatically)"
Write-Host ""
Write-Host "  Cleanup:"
Write-Host "    az group delete --name $ResourceGroup --yes --no-wait" -ForegroundColor DarkGray
