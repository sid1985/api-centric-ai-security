"""
Main experiment orchestrator — runs all 462 traffic scenarios against both
direct-access and gateway-protected endpoints, collecting timing metrics.

Gateway is now Azure APIM (Consumption tier). Auth is via subscription key
(Ocp-Apim-Subscription-Key header) rather than JWT Bearer tokens.

Usage:
    python simulator.py [--gateway-url URL] [--direct-url URL] \
                        [--apim-key KEY] [--concurrency N]

Example (after Azure deploy):
    python simulator.py \
        --gateway-url https://apim-ai-security-xxxx.azure-api.net/ai \
        --direct-url  http://localhost:8001 \
        --apim-key    <your-subscription-primary-key>
"""
import asyncio
import argparse
import json
import time
import uuid
import os
import sys
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Optional

import httpx

# ── Config ─────────────────────────────────────────────────────────────────────
# For local runs the gateway URL is the APIM endpoint provisioned in Azure.
# APIM_KEY is the subscription primary key (Ocp-Apim-Subscription-Key header).
GATEWAY_URL    = os.environ.get("GATEWAY_URL",   "")
DIRECT_AI_URL  = os.environ.get("DIRECT_AI_URL", "http://localhost:8001")
APIM_KEY       = os.environ.get("APIM_KEY",      "")
RESULTS_DIR    = Path(__file__).parent.parent / "analysis" / "results"

# Attack counts matching the paper
ATTACK_COUNTS = {
    "legitimate":      112,
    "sql_injection":    50,
    "schema_violation": 60,
    "model_inversion":  40,
    "ddos":            200,
}
TOTAL = sum(ATTACK_COUNTS.values())   # 462


@dataclass
class RequestResult:
    request_id: str
    attack_type: str
    target: str              # "gateway" | "direct"
    status_code: int
    latency_ms: float
    blocked: bool
    error: Optional[str] = None
    request_size_kb: float = 0.0
    timestamp: str = ""


# ── Payload factories ──────────────────────────────────────────────────────────
def _legit_payload(size_kb: float = None) -> dict:
    import random
    size = size_kb or random.uniform(0.5, 10.0)
    return {
        "request_size_kb": round(size, 3),
        "response_time_ms": round(random.uniform(20, 60), 2),
        "anomaly_score": round(random.uniform(0.0, 1.5), 3),
        "cpu_load_pct": round(random.uniform(10, 35), 2),
        "metadata": {"client_id": f"user_{random.randint(1,100)}", "model_id": "classifier-v1"},
    }


def _sql_injection_payload() -> dict:
    import random
    sql_strings = [
        "SELECT * FROM users WHERE id=1 OR 1=1--",
        "'; DROP TABLE inference_log; --",
        "1 UNION SELECT username, password FROM users",
        "admin'--",
        "1; EXEC xp_cmdshell('whoami')",
        "CAST(0x41 AS VARCHAR(10))",
        "1 AND SLEEP(5)--",
        "' OR '1'='1",
    ]
    payload = _legit_payload(random.uniform(0.1, 2.0))
    payload["metadata"]["client_id"] = random.choice(sql_strings)
    payload["anomaly_score"] = round(random.uniform(8.0, 10.0), 3)
    return payload


def _schema_violation_payload() -> dict:
    import random
    violation_type = random.choice(["missing_required", "wrong_type", "out_of_range", "extra_garbage"])
    if violation_type == "missing_required":
        # Missing request_size_kb
        return {
            "anomaly_score": 2.0,
            "cpu_load_pct": 20.0,
            "metadata": {"client_id": "attacker"},
        }
    elif violation_type == "wrong_type":
        return {
            "request_size_kb": "not-a-number",   # wrong type
            "anomaly_score": "high",
            "cpu_load_pct": True,
        }
    elif violation_type == "out_of_range":
        return {
            "request_size_kb": -999.9,            # negative
            "anomaly_score": 9999.0,              # way out of range
            "cpu_load_pct": -50.0,
        }
    else:
        return {
            "request_size_kb": 1.0,
            "__proto__": {"admin": True},          # prototype pollution attempt
            "constructor": {"name": "evil"},
            "anomaly_score": 5.0,
            "cpu_load_pct": 20.0,
        }


def _model_inversion_payload(attempt: int) -> dict:
    """
    Model inversion: systematically probe the decision boundary
    by sweeping feature space in small increments.
    """
    import math
    # Sweep anomaly_score slowly — looks legitimate but probes model
    anomaly = round(0.0 + (attempt % 40) * 0.1, 3)
    return {
        "request_size_kb": round(1.0 + math.sin(attempt * 0.3) * 0.5, 3),
        "response_time_ms": round(40.0 + math.cos(attempt * 0.2) * 10, 2),
        "anomaly_score": anomaly,
        "cpu_load_pct": round(20.0 + (attempt % 10), 2),
        "metadata": {
            "client_id": "researcher",
            "probe_index": attempt,
            "model_id": "classifier-v1",
        },
    }


def _ddos_payload(burst_large: bool = False) -> dict:
    import random
    if burst_large:
        # Large bomb payload
        size = random.uniform(50, 200)
    else:
        # Tiny rapid-fire
        size = random.uniform(0.01, 0.1)
    return {
        "request_size_kb": round(size, 3),
        "response_time_ms": 0.0,
        "anomaly_score": round(random.uniform(6.0, 10.0), 3),
        "cpu_load_pct": round(random.uniform(40, 95), 2),
        "metadata": {},
    }


# ── Request sender ─────────────────────────────────────────────────────────────
async def send_request(
    client: httpx.AsyncClient,
    url: str,
    payload: dict,
    attack_type: str,
    target: str,
    token: str = None,
) -> RequestResult:
    req_id   = str(uuid.uuid4())
    ts       = time.strftime("%Y-%m-%dT%H:%M:%S")
    size_kb  = len(json.dumps(payload).encode()) / 1024

    headers = {"Content-Type": "application/json"}
    if token:
        # token is the APIM subscription key
        headers["Ocp-Apim-Subscription-Key"] = token

    t0 = time.perf_counter()
    error = None
    try:
        resp = await client.post(url, json=payload, headers=headers, timeout=10.0)
        status = resp.status_code
    except httpx.TimeoutException:
        status = 504
        error  = "timeout"
    except httpx.RequestError as e:
        status = 503
        error  = str(e)

    latency_ms = (time.perf_counter() - t0) * 1000
    blocked    = status in (400, 401, 403, 429)

    return RequestResult(
        request_id=req_id,
        attack_type=attack_type,
        target=target,
        status_code=status,
        latency_ms=round(latency_ms, 2),
        blocked=blocked,
        error=error,
        request_size_kb=round(size_kb, 3),
        timestamp=ts,
    )


# ── Experiment runner ──────────────────────────────────────────────────────────
async def run_experiment(
    gateway_url: str,
    direct_url: str,
    apim_key: str = "",
    concurrency: int = 10,
) -> list[RequestResult]:
    print(f"\n{'='*60}")
    print(f"  API SECURITY EXPERIMENT — {TOTAL} requests")
    print(f"  Gateway (APIM): {gateway_url}")
    print(f"  Direct AI:      {direct_url}")
    print(f"  Auth:           {'APIM subscription key (set)' if apim_key else 'NO KEY — legitimate requests will get 401'}")
    print(f"  Workers:        {concurrency}")
    print(f"{'='*60}\n")

    if not apim_key:
        print("[!] No APIM subscription key supplied (--apim-key). "
              "Legitimate requests will receive 401 from APIM — "
              "this is expected and demonstrates Layer 1 auth enforcement.\n")

    # 'token' here is the APIM subscription key (not a JWT)
    token = apim_key or None

    # Build request queue
    tasks = []
    import random

    def add(payload_fn, attack_type, count, use_token=False):
        for i in range(count):
            pld = payload_fn() if not callable(payload_fn.__class__) else payload_fn
            if attack_type == "model_inversion":
                pld = _model_inversion_payload(i)
            elif attack_type == "ddos":
                pld = _ddos_payload(burst_large=(i % 3 == 0))
            elif attack_type == "legitimate":
                pld = _legit_payload()
            elif attack_type == "sql_injection":
                pld = _sql_injection_payload()
            elif attack_type == "schema_violation":
                pld = _schema_violation_payload()
            tasks.append((pld, attack_type, use_token))

    add(None, "legitimate",      ATTACK_COUNTS["legitimate"],      use_token=True)
    add(None, "sql_injection",   ATTACK_COUNTS["sql_injection"],   use_token=False)
    add(None, "schema_violation",ATTACK_COUNTS["schema_violation"],use_token=False)
    add(None, "model_inversion", ATTACK_COUNTS["model_inversion"], use_token=True)
    add(None, "ddos",            ATTACK_COUNTS["ddos"],            use_token=False)

    # Shuffle for realistic mixed traffic
    random.shuffle(tasks)

    results: list[RequestResult] = []
    semaphore = asyncio.Semaphore(concurrency)
    total = len(tasks) * 2   # gateway + direct for each

    async def run_one(payload, attack_type, use_token, idx):
        async with semaphore:
            async with httpx.AsyncClient() as client:
                # Legitimate traffic uses the APIM subscription key.
                # Attackers fire without a key — APIM Layer 1 blocks them.
                t = token if use_token else None

                # Test via APIM (protected)
                gw_result = await send_request(
                    client,
                    f"{gateway_url}/predict",
                    payload, attack_type, "gateway", token=t,
                )

                # Test direct against AI service (no security — baseline)
                dr_result = await send_request(
                    client,
                    f"{direct_url}/predict",
                    payload, attack_type, "direct", token=None,
                )

                return [gw_result, dr_result]

    print(f"Running {len(tasks)} scenarios ({total} total requests)...")
    coroutines = [run_one(p, a, u, i) for i, (p, a, u) in enumerate(tasks)]

    done = 0
    for coro in asyncio.as_completed(coroutines):
        batch = await coro
        results.extend(batch)
        done += 1
        if done % 50 == 0:
            pct = done / len(tasks) * 100
            print(f"  Progress: {done}/{len(tasks)} scenarios ({pct:.0f}%)")

    print(f"\n[+] Experiment complete. {len(results)} results collected.")
    return results


# ── Results persistence ────────────────────────────────────────────────────────
def save_results(results: list[RequestResult]) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RESULTS_DIR / "experiment_results.json"
    data = [asdict(r) for r in results]
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[+] Results saved → {out_path}")
    return out_path


def print_summary(results: list[RequestResult]):
    from collections import defaultdict
    gateway = [r for r in results if r.target == "gateway"]
    direct  = [r for r in results if r.target == "direct"]

    print(f"\n{'='*60}")
    print("  RESULTS SUMMARY")
    print(f"{'='*60}")

    # Table 1: Security efficacy by attack type
    print("\nTable 1: Security Efficacy by Attack Vector (Gateway)")
    print(f"{'Attack Type':<20} {'Attempts':>8} {'Blocked':>8} {'Passed':>8} {'Block%':>8}")
    print("-" * 55)
    by_attack = defaultdict(list)
    for r in gateway:
        by_attack[r.attack_type].append(r)

    for atk, rows in sorted(by_attack.items()):
        blocked = sum(1 for r in rows if r.blocked)
        passed  = len(rows) - blocked
        pct     = blocked / len(rows) * 100 if rows else 0
        print(f"{atk:<20} {len(rows):>8} {blocked:>8} {passed:>8} {pct:>7.1f}%")

    # Table 2: Performance comparison
    gw_pass   = [r for r in gateway if not r.blocked]
    dr_all    = direct

    gw_latency = [r.latency_ms for r in gw_pass] if gw_pass else [0]
    dr_latency = [r.latency_ms for r in dr_all]  if dr_all  else [0]

    gw_errors = sum(1 for r in gateway if r.status_code >= 500) / len(gateway) * 100
    dr_errors = sum(1 for r in direct  if r.status_code >= 500) / len(direct)  * 100

    import statistics
    print(f"\nTable 2: Performance Comparison")
    print(f"{'Metric':<25} {'Direct (Mean)':>15} {'Gateway (Mean)':>16} {'Delta':>10}")
    print("-" * 70)
    print(f"{'Latency (ms)':<25} {statistics.mean(dr_latency):>15.1f} {statistics.mean(gw_latency):>16.1f} {statistics.mean(gw_latency)-statistics.mean(dr_latency):>+10.1f}")
    print(f"{'Error Rate %':<25} {dr_errors:>15.1f} {gw_errors:>16.1f} {gw_errors-dr_errors:>+10.1f}")
    print(f"\nGateway blocked {sum(1 for r in gateway if r.blocked)}/{len(gateway)} requests ({sum(1 for r in gateway if r.blocked)/len(gateway)*100:.1f}%)")


# ── CLI ────────────────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(
        description="API Security Experiment Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # After Azure APIM + Container Apps deploy:
  python simulator.py \\
      --gateway-url https://apim-ai-security-xxxx.azure-api.net/ai \\
      --direct-url  https://ca-ai-service-xxxx.azurecontainerapps.io \\
      --apim-key    <primary-key>

  # Local AI service + APIM cloud gateway:
  python simulator.py \\
      --gateway-url https://apim-ai-security-xxxx.azure-api.net/ai \\
      --direct-url  http://localhost:8001 \\
      --apim-key    <primary-key>
"""
    )
    parser.add_argument("--gateway-url", default=GATEWAY_URL,   help="APIM gateway URL (e.g. https://apim-xxx.azure-api.net/ai)")
    parser.add_argument("--direct-url",  default=DIRECT_AI_URL, help="Direct AI service URL (baseline, no security)")
    parser.add_argument("--apim-key",    default=APIM_KEY,      help="APIM subscription primary key (Ocp-Apim-Subscription-Key)")
    parser.add_argument("--concurrency", default=10, type=int,  help="Concurrent workers (default: 10)")
    args = parser.parse_args()

    if not args.gateway_url:
        parser.error(
            "--gateway-url is required. "
            "Deploy APIM first: .\\azure\\deploy.ps1  then re-run with the printed URL."
        )

    results = await run_experiment(
        args.gateway_url, args.direct_url, args.apim_key, args.concurrency
    )
    save_results(results)
    print_summary(results)
    print("\n[+] Run 'python analysis/visualize.py' to generate charts and HTML report.")


if __name__ == "__main__":
    asyncio.run(main())
