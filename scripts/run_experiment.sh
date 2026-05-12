#!/usr/bin/env bash
# Full experiment runner (Linux/macOS)
# Usage: bash scripts/run_experiment.sh

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONCURRENCY="${1:-10}"

echo -e "\n\033[36m╔══════════════════════════════════════════════════════════╗"
echo "║    API-CENTRIC AI SECURITY — EXPERIMENT RUNNER           ║"
echo -e "╚══════════════════════════════════════════════════════════╝\033[0m"

# Prerequisites
command -v docker >/dev/null 2>&1 || { echo "Docker not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3 not found"; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker daemon not running"; exit 1; }

echo -e "\n\033[33m[1/5] Installing Python dependencies...\033[0m"
pip3 install -q httpx matplotlib numpy pandas scikit-learn joblib

echo -e "\n\033[33m[2/5] Starting Docker services...\033[0m"
cd "$ROOT"
docker compose up -d --build

echo -e "\n\033[33m[3/5] Waiting for services to be healthy...\033[0m"
python3 "$ROOT/scripts/wait_for_services.py"

echo -e "\n\033[33m[4/5] Running experiment...\033[0m"
python3 "$ROOT/attack-simulator/simulator.py" --concurrency "$CONCURRENCY"

echo -e "\n\033[33m[5/5] Generating report...\033[0m"
python3 "$ROOT/analysis/visualize.py"

REPORT="$ROOT/analysis/results/report.html"
echo -e "\n\033[32m✓ Done!\033[0m"
echo -e "  Report: file://$REPORT"
command -v xdg-open >/dev/null 2>&1 && xdg-open "$REPORT" 2>/dev/null || \
command -v open     >/dev/null 2>&1 && open     "$REPORT" 2>/dev/null || true
