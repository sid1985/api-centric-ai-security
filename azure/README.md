# Azure Container Apps Deployment

Deploys the full API security experiment to Azure Container Apps using the **free tier**.

## Cost Estimate

| Resource | Tier | Estimated Cost |
|----------|------|---------------|
| Container Apps Environment | Consumption | ~$0 (180k vCPU-s/month free) |
| Log Analytics Workspace | Pay-per-GB (5 GB free) | ~$0 |
| Azure Container Registry | Basic | ~$0.17/day |
| **Total for demo** | | **~$0–$0.20/day** |

Scale to 0 replicas when idle = **zero idle cost**.

## Prerequisites

```powershell
# Install Azure CLI
winget install Microsoft.AzureCLI

# Install Azure Container Registry extension
az extension add --name containerapp

# Login
az login
```

## Deploy

```powershell
.\deploy.ps1 -ResourceGroup "rg-api-security-demo" -Location "eastus"
```

The script will:
1. Create a Resource Group
2. Create an Azure Container Registry (Basic, ~$0.17/day)
3. Build and push Docker images to ACR
4. Deploy to Azure Container Apps via Bicep
5. Print the public gateway URL

## Run Experiment Against Azure

After deployment, update the simulator URLs:

```powershell
$gatewayUrl = "https://<output-gateway-url>"
$directUrl  = "https://<ai-service-url>"   # internal, use gateway for demo

python attack-simulator\simulator.py `
  --gateway-url $gatewayUrl `
  --direct-url $directUrl
```

## Cleanup (avoid charges)

```powershell
az group delete --name rg-api-security-demo --yes --no-wait
```
