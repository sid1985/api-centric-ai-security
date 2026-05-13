# API-Centric AI Security

> **Companion repository for the IEEE paper:**
> *"API-Centric Architectures as the Foundation for Secure AI Services"*
> Presented at **apidays New York 2026**

[![CI — Experiment Runner](https://github.com/sid1985/api-centric-ai-security/actions/workflows/experiment.yml/badge.svg)](https://github.com/sid1985/api-centric-ai-security/actions)

This repository contains the full experimental infrastructure, attack simulator, analysis pipeline, and results for a peer-reviewed empirical study measuring how well traditional API gateway security controls protect AI inference services against both structural and semantic attack types.

---

## Key Finding

> **Static API gateway controls block structural attacks at 100% but catch only 2.5% of semantic AI attacks (model inversion). This is not a tuning problem — it is a paradigm ceiling.**

| Attack Type | Requests | Blocked | Block Rate |
|---|---|---|---|
| DDoS | 200 | 200 | **100%** |
| SQL Injection | 50 | 50 | **100%** |
| Schema Violation | 60 | 60 | **100%** |
| Model Inversion | 40 | 1 | **2.5%** |
| Legitimate (FP rate) | 112 | 8 | 7.1% |
| **Total** | **462** | **319** | **69%** |

**Latency overhead:** 110.8ms (direct) → 2,001ms (via APIM gateway) — ~18× increase, +1,890ms overhead.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Attack Simulator                          │
│         (Python · 462 scenarios · GitHub Actions)           │
└────────────────────┬──────────────────┬─────────────────────┘
                     │                  │
          Direct URL │                  │ Gateway URL
          (control)  │                  │ (treatment)
                     ▼                  ▼
         ┌───────────────┐   ┌──────────────────────────────┐
         │  Azure        │   │  Azure API Management        │
         │  Container    │   │  (Consumption Tier)          │
         │  Apps         │   │                              │
         │  (no gateway) │   │  Layer 1: Auth / OAuth       │
         └───────┬───────┘   │  Layer 2: Zero Trust         │
                 │           │  Layer 3: Rate Limiting       │
                 │           │  Layer 4: Prompt Inspection   │
                 │           │  Layer 5: Threat Detection    │
                 │           └──────────────┬───────────────┘
                 │                          │
                 └──────────┬───────────────┘
                            ▼
              ┌─────────────────────────────┐
              │     Azure Container Apps    │
              │  FastAPI + RandomForest      │
              │  Classifier (inference)      │
              └─────────────────────────────┘
```

Both endpoints receive identical attack payloads simultaneously — enabling a direct controlled comparison of gateway vs. no-gateway protection.

---

## Repository Structure

```
├── ai-service/                 # FastAPI inference service (RandomForest classifier)
│   ├── main.py                 # API endpoints: /predict and /health
│   ├── model.py                # RandomForest model training + serialization
│   └── requirements.txt
│
├── attack-simulator/           # Python attack scenario runner
│   ├── simulator.py            # 462 scenarios across 5 attack types
│   ├── scenarios/              # Attack payload definitions
│   └── requirements.txt
│
├── gateway/                    # Azure APIM policy configuration
│   └── policies/               # 5-layer XML policy stack
│
├── analysis/
│   ├── results/
│   │   ├── experiment_results.json   # 924 raw request records (ground truth)
│   │   └── report.html               # Interactive results report
│   └── figures/                      # Generated analysis charts
│
├── scripts/
│   ├── generate_presentation_charts.py   # Reproduces slide charts
│   ├── generate_research_glance.py       # Research At a Glance slide PNG
│   ├── run_experiment.py                 # Full experiment orchestrator
│   └── wait_for_services.py
│
├── .github/workflows/
│   └── experiment.yml          # GitHub Actions CI — runs full experiment automatically
│
└── docs/
    └── (paper PDF and presentation — local only, not tracked)
```

---

## Experimental Design

### Infrastructure
- **Gateway:** Azure API Management — Consumption tier, 5-layer security policy
- **Inference service:** Azure Container Apps running FastAPI + scikit-learn RandomForest classifier
- **Training data:** Synthetic dataset of legitimate vs. adversarial feature vectors

### Attack Types Tested
| Type | Category | n | Description |
|---|---|---|---|
| DDoS | Structural | 200 | High-volume request bursts |
| SQL Injection | Structural | 50 | Malicious SQL in request fields |
| Schema Violation | Structural | 60 | Malformed JSON, wrong types, missing fields |
| Model Inversion | Semantic | 40 | Systematic feature probing to extract model decision boundary |
| Legitimate | Baseline | 112 | Valid inference requests (measures false positive rate) |

### Methodology
- **Dual endpoint simultaneous firing:** every scenario fires at both the direct Container App URL (no gateway) and the APIM gateway URL at the same time
- **Controlled comparison:** 462 scenarios × 2 endpoints = **924 total requests**
- **Automated and reproducible:** full workflow runs in ~2 minutes on a GitHub Actions runner
- **Three phases:** Baseline → Adversarial injection → Mixed workload under high concurrency

---

## Results

### Security Effectiveness
The gateway provides **perfect protection** against structural attacks — anything where the malicious signal lives in the *form* of the request (syntax, rate, schema). It provides **near-zero protection** against semantic AI attacks — where the malicious signal lives in the *meaning* of otherwise-valid requests.

The 2.5% model inversion block rate is not an implementation failure. It is a **ceiling of the current paradigm**: no amount of static rule tuning will catch an attack that looks indistinguishable from a legitimate inference request.

### Performance Trade-off
| Metric | Direct Endpoint | APIM Gateway |
|---|---|---|
| Avg Latency | 110.8ms | 2,001ms |
| Latency Overhead | — | +1,890ms (~18×) |
| Error Rate | 0.0% | 4.3% |
| Total Requests | 462 | 462 |

The overhead reflects the Consumption tier's policy evaluation chain (TLS termination, subscription key validation, rate limit checks, content inspection) plus network routing through Azure's infrastructure. A dedicated tier with response caching would reduce this significantly.

---

## Reproducing the Experiment

### Prerequisites
- Azure subscription with APIM Consumption tier deployed
- Azure Container Apps environment
- Python 3.11+

### Run locally
```bash
git clone https://github.com/sid1985/api-centric-ai-security
cd api-centric-ai-security
pip install -r attack-simulator/requirements.txt
python scripts/run_experiment.py
```

### Run via GitHub Actions
Push to `main` — the experiment workflow triggers automatically and commits results to `analysis/results/`.

### Regenerate charts
```bash
pip install matplotlib numpy
python scripts/generate_presentation_charts.py   # slides 6, 9, 10 charts
python scripts/generate_research_glance.py        # Research At a Glance PNG
```

---

## Implications

The structural vs. semantic gap identified in this experiment motivates a new architecture: the **AI-Aware Gateway** — a gateway that contains its own inference capability (lightweight ML anomaly scoring, behavioral profiling across sessions, semantic inspection of payloads) rather than relying solely on static rule evaluation.

Three conditions make this achievable now:
1. Lightweight anomaly detection models run at millisecond latency — no 70B LLM required
2. API gateways already hold the session context (subscriber ID, request history, token consumption patterns)
3. The threat signal exists — this experiment's 924 labeled requests are a starter training dataset

---

## Citation

If you use this code or data in your research, please cite:

```
Bhatt, S. (2026). API-Centric Architectures as the Foundation for Secure AI Services.
Presented at apidays New York 2026.
```

---

## License

MIT — see [LICENSE](LICENSE). Data and results in `analysis/results/` are released for research reproducibility.

## What This Proves

| Metric | Without Gateway | With Gateway | Delta |
|--------|----------------|--------------|-------|
| Latency (ms) | 45 | 62 | +17 |
| Throughput (RPS) | 120 | 105 | -15 |
| CPU Idle % | 15 | 40 | +25 |
| Error Rate % | 12 | 0.5 | -11.5 |
| Attack Block Rate | 0% | ~92% | +92% |

## Architecture

```
[Attack Simulator / Clients]
         │
         ▼
  ┌─────────────────────────────────────────┐
  │         API Gateway (:8000)             │
  │  ┌─────────────────────────────────┐    │
  │  │  1. JWT Auth                    │    │
  │  │  2. Rate Limiting (50 req/min)  │    │
  │  │  3. Schema Validation           │    │
  │  │  4. SQL Injection Detection     │    │
  │  │  5. Anomaly Scoring             │    │
  │  │  6. Request Logging → SQLite    │    │
  │  └─────────────────────────────────┘    │
  └─────────────────────────────────────────┘
         │ (only clean traffic passes)
         ▼
  ┌─────────────────────────────────────────┐
  │       AI Inference Service (:8001)      │
  │   sklearn RandomForest Classifier       │
  │   (trained on synthetic traffic data)   │
  └─────────────────────────────────────────┘
         │
         ▼
  ┌─────────────────────────────────────────┐
  │       SQLite Logging DB                 │
  │   (all requests logged for analysis)    │
  └─────────────────────────────────────────┘
```

## Quick Start (2 hours, local Docker)

### Prerequisites
- Docker Desktop (Windows)
- Python 3.11+ (for attack simulator and analysis)

### Run the Full Experiment

```powershell
# Clone or navigate to repo
cd c:\github\api-centric-ai-security

# Option 1: Full automated run (recommended)
.\scripts\run_experiment.ps1

# Option 2: Step by step
docker compose up -d --build          # Start services (2-3 min)
python scripts\wait_for_services.py   # Wait until healthy
python attack-simulator\simulator.py  # Run 462-request experiment (~3 min)
python analysis\visualize.py          # Generate charts + HTML report
start analysis\report.html            # View results in browser
```

### What Happens
1. Docker builds and starts the AI service and API Gateway
2. Attack simulator fires 462 synthetic requests: legitimate + 4 attack types
3. Both gateway and direct-access modes are tested
4. Analysis script generates charts matching the paper's Figures 2 & 3 and Tables 1 & 2
5. HTML report summarizes findings

## Project Structure

```
├── ai-service/          # AI Inference Engine (FastAPI + sklearn)
├── gateway/             # API Gateway with security plugins (FastAPI)
├── attack-simulator/    # Traffic generator: legit + SQL/schema/DDoS/model-inversion
├── analysis/            # Results collection and paper-matching charts
├── monitoring/          # Prometheus + Grafana (optional, for cloud demo)
├── azure/               # Azure Container Apps deployment (Bicep + deploy script)
├── scripts/             # Setup and run automation
└── docs/                # Original research paper
```

## Azure Deployment (Optional, ~$0–$2/day)

Uses Azure Container Apps free tier (180,000 vCPU-seconds/month free).

```powershell
cd azure
.\deploy.ps1 -ResourceGroup "rg-api-security-demo" -Location "eastus"
```

See [azure/README.md](azure/README.md) for details.

## Attack Types Simulated

| Attack | Attempts | Expected Block Rate | Description |
|--------|----------|-------------------|-------------|
| SQL Injection | 50 | ~100% | SQL strings injected into payload metadata |
| Schema Violation | 60 | ~96.6% | Wrong types, missing required fields |
| Model Inversion | 40 | ~75% | Crafted feature vectors to probe model boundaries |
| High-Vol DDoS | 200 | ~95% | Burst traffic exceeding rate limits |
| Legitimate Traffic | 112 | 0% (no false positives) | Normal inference requests |

## Key Findings Reproduced

- **Fail-fast at edge**: Large malicious payloads blocked at header scan → near-zero backend latency
- **CPU stabilization**: Backend CPU idle rises from 15% → 40% when gateway absorbs attacks
- **Effective throughput**: Valid users maintain performance even under active attack
- **17 ms overhead**: Acceptable cost for >92% attack mitigation
