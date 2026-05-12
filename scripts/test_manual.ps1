<#
.SYNOPSIS
    Quick manual smoke-test against Azure APIM + direct AI service.
    Run AFTER 'azure/deploy.ps1' has completed.

.PARAMETER ApimUrl  Full APIM gateway URL, e.g. https://apim-ai-security-xxxx.azure-api.net/ai
.PARAMETER ApimKey  APIM subscription primary key (Ocp-Apim-Subscription-Key)
.PARAMETER DirectUrl Direct AI service URL for baseline comparison
#>
param(
    [string]$ApimUrl   = "",
    [string]$ApimKey   = "",
    [string]$DirectUrl = "http://localhost:8001"
)

$Root    = Split-Path $PSScriptRoot -Parent
$EnvFile = "$Root\.azure-env.json"

# Load from .azure-env.json if available
if (Test-Path $EnvFile) {
    $env = Get-Content $EnvFile | ConvertFrom-Json
    if (-not $ApimUrl) { $ApimUrl = $env.GatewayUrl }
    if (-not $ApimKey) { $ApimKey = $env.ApimKey    }
    Write-Host "  Loaded connection info from .azure-env.json" -ForegroundColor DarkCyan
}

if (-not $ApimUrl -or -not $ApimKey) {
    Write-Error @"
Missing APIM URL or subscription key.
Deploy first:  .\azure\deploy.ps1
Or supply:     .\scripts\test_manual.ps1 -ApimUrl https://... -ApimKey <key>
"@
    exit 1
}

$AI      = $DirectUrl
$headers = @{ "Ocp-Apim-Subscription-Key" = $ApimKey; "Content-Type" = "application/json" }

Write-Host "`n=== Manual API Test (APIM + Direct) ===" -ForegroundColor Cyan
Write-Host "  APIM:   $ApimUrl"
Write-Host "  Direct: $AI"

# ── Health checks ──────────────────────────────────────────────────────────────
Write-Host "`n[Health checks]" -ForegroundColor Yellow
try {
    $apimHealth = Invoke-RestMethod -Uri "$ApimUrl/health" -Headers $headers
    Write-Host "  APIM gateway: $($apimHealth | ConvertTo-Json -Compress)" -ForegroundColor Green
} catch {
    Write-Host "  APIM health: $($_.Exception.Response.StatusCode)" -ForegroundColor Red
}
$aiHealth = Invoke-RestMethod -Uri "$AI/health"
Write-Host "  AI Service:   $($aiHealth | ConvertTo-Json -Compress)" -ForegroundColor Green

# ── Legitimate predict via APIM ────────────────────────────────────────────────
Write-Host "`n[1] Legitimate request via APIM (should pass 200)" -ForegroundColor Green
$body = '{"request_size_kb":2.5,"response_time_ms":120,"anomaly_score":1.2,"cpu_load_pct":35}'
try {
    $resp = Invoke-RestMethod -Method Post -Uri "$ApimUrl/predict" -Headers $headers -Body $body
    Write-Host "  ✓ PASSED — prediction: $($resp.prediction), confidence: $($resp.confidence)" -ForegroundColor Green
} catch {
    Write-Host "  ✗ FAILED: $($_.Exception.Response.StatusCode) — $_" -ForegroundColor Red
}

# ── SQL injection via APIM ─────────────────────────────────────────────────────
Write-Host "`n[2] SQL injection via APIM (should be blocked)" -ForegroundColor Red
$sqlBody = '{"request_size_kb":2.5,"response_time_ms":120,"anomaly_score":1.2,"cpu_load_pct":35,"note":"1\u0027 OR 1=1--"}'
try {
    Invoke-RestMethod -Method Post -Uri "$ApimUrl/predict" -Headers $headers -Body $sqlBody | Out-Null
    Write-Host "  ✗ NOT blocked (unexpected)" -ForegroundColor Red
} catch {
    Write-Host "  ✓ BLOCKED: $($_.Exception.Response.StatusCode)" -ForegroundColor Green
}

# ── Request without subscription key ──────────────────────────────────────────
Write-Host "`n[3] Request without subscription key (should be 401)" -ForegroundColor Red
try {
    Invoke-RestMethod -Method Post -Uri "$ApimUrl/predict" `
        -Headers @{"Content-Type"="application/json"} -Body $body | Out-Null
    Write-Host "  ✗ NOT blocked" -ForegroundColor Red
} catch {
    Write-Host "  ✓ BLOCKED: $($_.Exception.Response.StatusCode)" -ForegroundColor Green
}

# ── High anomaly score via APIM ────────────────────────────────────────────────
Write-Host "`n[4] High anomaly score via APIM (anomaly_score=9.5, should block)" -ForegroundColor Red
$anomalyBody = '{"request_size_kb":2.5,"response_time_ms":120,"anomaly_score":9.5,"cpu_load_pct":35}'
try {
    Invoke-RestMethod -Method Post -Uri "$ApimUrl/predict" -Headers $headers -Body $anomalyBody | Out-Null
    Write-Host "  ✗ NOT blocked (APIM anomaly policy may need tuning)" -ForegroundColor DarkYellow
} catch {
    Write-Host "  ✓ BLOCKED: $($_.Exception.Response.StatusCode)" -ForegroundColor Green
}

# ── Direct access (unprotected baseline) ──────────────────────────────────────
Write-Host "`n[5] Direct AI service — high anomaly score (no security, should pass)" -ForegroundColor DarkYellow
$body2 = '{"request_size_kb":2.5,"response_time_ms":120,"anomaly_score":9.9,"cpu_load_pct":35}'
try {
    $resp = Invoke-RestMethod -Method Post -Uri "$AI/predict" `
        -Headers @{"Content-Type"="application/json"} -Body $body2
    Write-Host "  ⚠  PASSED (unprotected baseline) — prediction: $($resp.prediction)" -ForegroundColor DarkYellow
} catch {
    Write-Host "  Failed: $_" -ForegroundColor Red
}

Write-Host "`n✓ Manual smoke-test complete!" -ForegroundColor Green
Write-Host "  Run full experiment: .\scripts\run_experiment.ps1" -ForegroundColor Cyan
