<#
.SYNOPSIS
    Full experiment runner.
    1. Starts the AI Service in Docker (direct/baseline endpoint).
    2. Reads APIM URL + subscription key from .azure-env.json (created by azure/deploy.ps1).
    3. Fires all 462 requests at both endpoints.
    4. Generates charts + HTML report.

.PARAMETER Concurrency   Async workers for the simulator (default: 10)
.PARAMETER GatewayUrl    Override APIM URL (skips .azure-env.json)
.PARAMETER DirectUrl     Override direct AI Service URL
.PARAMETER ApimKey       Override APIM subscription key
.PARAMETER SkipBuild     Skip docker compose build (use cached images)
.PARAMETER SkipSimulator Skip experiment, re-run analysis only
.PARAMETER SkipAnalysis  Skip chart generation
#>
param(
    [int]$Concurrency   = 10,
    [string]$GatewayUrl = "",
    [string]$DirectUrl  = "http://localhost:8001",
    [string]$ApimKey    = "",
    [switch]$SkipBuild,
    [switch]$SkipSimulator,
    [switch]$SkipAnalysis
)

$ErrorActionPreference = "Stop"
$Root = Split-Path $PSScriptRoot -Parent

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║    API-CENTRIC AI SECURITY — EXPERIMENT RUNNER               ║
║    Gateway: Azure APIM  |  Backend: Docker (local)           ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Cyan

# ── Load APIM connection info from deploy output ──────────────────────────────
$EnvFile = "$Root\.azure-env.json"
if (Test-Path $EnvFile) {
    $env = Get-Content $EnvFile | ConvertFrom-Json
    if (-not $GatewayUrl) { $GatewayUrl = $env.GatewayUrl }
    if (-not $ApimKey)    { $ApimKey    = $env.ApimKey    }
    if ($env.DirectUrl -and -not $PSBoundParameters.ContainsKey("DirectUrl")) {
        $DirectUrl = $env.DirectUrl
    }
    Write-Host "  Loaded connection info from .azure-env.json" -ForegroundColor DarkCyan
}

if (-not $GatewayUrl) {
    Write-Warning @"
No APIM URL found. Deploy Azure APIM first:
    .\azure\deploy.ps1

Or supply --GatewayUrl manually:
    .\scripts\run_experiment.ps1 -GatewayUrl https://apim-xxx.azure-api.net/ai -ApimKey <key>
"@
    exit 1
}

Write-Host "  APIM Gateway: $GatewayUrl"
Write-Host "  Direct AI:    $DirectUrl"

# ── Prerequisites ─────────────────────────────────────────────────────────────
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker not found. Install Docker Desktop."
    exit 1
}
if (-not (Get-Command python  -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found. Install Python 3.11+."
    exit 1
}

# ── Step 1: Python deps ───────────────────────────────────────────────────────
Write-Host "`n[1/5] Installing Python dependencies..." -ForegroundColor Yellow
pip install -q httpx matplotlib numpy pandas scikit-learn joblib
Write-Host "  ✓ Dependencies ready"

# ── Step 2: Start AI Service (direct baseline) ────────────────────────────────
Write-Host "`n[2/5] Starting AI Service in Docker..." -ForegroundColor Yellow
Push-Location $Root
if ($SkipBuild) {
    docker compose up -d ai-service
} else {
    Write-Host "  Building image (first run: 2-3 min)..."
    docker compose up -d --build ai-service
}
Write-Host "  ✓ AI Service starting..."

# ── Step 3: Wait for AI Service health ───────────────────────────────────────
Write-Host "`n[3/5] Waiting for AI Service to be healthy..." -ForegroundColor Yellow
python "$Root\scripts\wait_for_services.py" --services "http://localhost:8001/health"
if ($LASTEXITCODE -ne 0) {
    Write-Error "AI Service failed to start. Check: docker compose logs ai-service"
    exit 1
}
Write-Host "  ✓ AI Service healthy"

# ── Step 4: Run experiment ────────────────────────────────────────────────────
if (-not $SkipSimulator) {
    Write-Host "`n[4/5] Running 462-request experiment..." -ForegroundColor Yellow
    Write-Host "  → Protected path:  APIM ($GatewayUrl)"
    Write-Host "  → Baseline path:   Direct ($DirectUrl)"

    $simArgs = @(
        "$Root\attack-simulator\simulator.py",
        "--gateway-url", $GatewayUrl,
        "--direct-url",  $DirectUrl,
        "--concurrency", $Concurrency
    )
    if ($ApimKey) { $simArgs += @("--apim-key", $ApimKey) }

    python @simArgs
    if ($LASTEXITCODE -ne 0) { Write-Error "Simulator failed."; exit 1 }
    Write-Host "  ✓ Experiment complete"
} else {
    Write-Host "`n[4/5] Skipping simulator" -ForegroundColor DarkGray
}

# ── Step 5: Generate report ───────────────────────────────────────────────────
if (-not $SkipAnalysis) {
    Write-Host "`n[5/5] Generating charts and HTML report..." -ForegroundColor Yellow
    python "$Root\analysis\visualize.py"
    if ($LASTEXITCODE -ne 0) { Write-Error "Analysis failed."; exit 1 }
    Write-Host "  ✓ Report generated"
} else {
    Write-Host "`n[5/5] Skipping analysis" -ForegroundColor DarkGray
}

Pop-Location

# ── Done ──────────────────────────────────────────────────────────────────────
$reportPath = "$Root\analysis\results\report.html"

Write-Host @"

╔══════════════════════════════════════════════════════════════╗
║  DONE!                                                       ║
╚══════════════════════════════════════════════════════════════╝
"@ -ForegroundColor Green

if (Test-Path $reportPath) {
    Write-Host "  Report: $reportPath" -ForegroundColor Cyan
    $open = Read-Host "`n  Open in browser? [Y/n]"
    if ($open -ne "n" -and $open -ne "N") { Start-Process $reportPath }
}

Write-Host @"

  Endpoints:
    APIM (protected):  $GatewayUrl
    Direct (baseline): $DirectUrl
    AI Health:         http://localhost:8001/health

  Useful:
    docker compose logs -f ai-service   # stream AI service logs
    docker compose down                  # stop local container
    az group delete --name rg-api-security-demo --yes --no-wait   # remove Azure resources
"@ -ForegroundColor DarkCyan
