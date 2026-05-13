"""
API Gateway — FastAPI reverse proxy with multi-layer security.

Security pipeline (in order):
  1. JWT Authentication
  2. Rate Limiting (sliding window)
  3. Schema + SQL Injection Validation
  4. Anomaly Detection (scoring)
  5. Forward to AI Service backend
  6. Log everything to SQLite

Also exposes /token endpoint for clients to get a JWT.
Exposes /metrics endpoint for experiment analysis.
"""
import os
import sys
import time
import uuid
import json
import logging
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, str(Path(__file__).parent))
from plugins.auth        import validate_token, create_token
from plugins.rate_limiter import check_rate_limit
from plugins.validator   import validate_payload
from plugins.anomaly     import check_anomaly
from plugins.logger      import init_db, log_transaction

# ── Config ─────────────────────────────────────────────────────────────────────
AI_SERVICE_URL = os.environ.get("AI_SERVICE_URL", "http://ai-service:8001")
DB_PATH        = os.environ.get("DB_PATH", "/app/logs/gateway.db")
SECURITY_MODE  = os.environ.get("SECURITY_MODE", "advanced")  # none | basic | advanced

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("api-gateway")

# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    log.info(f"Gateway started. Security mode: {SECURITY_MODE} | Backend: {AI_SERVICE_URL}")
    yield


app = FastAPI(
    title="API Gateway",
    description="Multi-layer security gateway protecting the AI Inference Service.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Token endpoint (pre-auth for legitimate clients) ──────────────────────────
@app.post("/token")
def get_token(client_id: str = "demo-client"):
    """Issues a JWT for legitimate clients. Attackers won't have valid tokens."""
    token = create_token(client_id)
    return {"access_token": token, "token_type": "Bearer", "expires_in": 3600}


# ── Health ─────────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "security_mode": SECURITY_MODE, "backend": AI_SERVICE_URL}


# ── Main proxy endpoint ────────────────────────────────────────────────────────
@app.post("/predict")
async def predict_proxy(request: Request):
    req_id  = str(uuid.uuid4())
    t_start = time.perf_counter()
    client_ip = request.client.host if request.client else "unknown"

    gateway_decision = "passed"
    block_reason     = None
    status_code      = 200
    anomaly_score    = 0.0
    body             = {}
    backend_latency  = None

    # ── Read body ──────────────────────────────────────────────────────────────
    try:
        raw  = await request.body()
        body = json.loads(raw) if raw else {}
    except Exception:
        body = {}

    request_size_kb = len(raw) / 1024 if raw else 0.0

    try:
        # ── Layer 1: Authentication ────────────────────────────────────────────
        if SECURITY_MODE in ("basic", "advanced"):
            validate_token(request)

        # ── Layer 2: Rate Limiting ─────────────────────────────────────────────
        if SECURITY_MODE in ("basic", "advanced"):
            check_rate_limit(request)

        # ── Layer 3: Schema + SQL Injection Validation ─────────────────────────
        if SECURITY_MODE == "advanced":
            await validate_payload(request, body)

        # ── Layer 4: Anomaly Detection ─────────────────────────────────────────
        if SECURITY_MODE == "advanced":
            anomaly_score = check_anomaly(request, body)

        # ── Layer 5: Forward to AI Service ─────────────────────────────────────
        t_backend_start = time.perf_counter()
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.post(
                f"{AI_SERVICE_URL}/predict",
                json=body,
                headers={"x-forwarded-from": "gateway", "x-request-id": req_id},
            )
        backend_latency = (time.perf_counter() - t_backend_start) * 1000
        status_code     = resp.status_code
        response_data   = resp.json()

    except HTTPException as exc:
        gateway_decision = "blocked"
        block_reason     = exc.detail
        status_code      = exc.status_code
        response_data    = {"error": exc.detail, "request_id": req_id}

    except httpx.RequestError as exc:
        gateway_decision = "error"
        block_reason     = f"Backend unreachable: {exc}"
        status_code      = 503
        response_data    = {"error": "AI service unavailable", "request_id": req_id}

    finally:
        total_latency   = (time.perf_counter() - t_start) * 1000
        gateway_latency = total_latency - (backend_latency or 0)

        log_transaction({
            "id":                 req_id,
            "timestamp":          time.strftime("%Y-%m-%dT%H:%M:%S"),
            "client_ip":          client_ip,
            "method":             request.method,
            "path":               str(request.url.path),
            "request_size_kb":    round(request_size_kb, 3),
            "anomaly_score":      anomaly_score,
            "gateway_decision":   gateway_decision,
            "block_reason":       block_reason,
            "status_code":        status_code,
            "gateway_latency_ms": round(gateway_latency, 2),
            "total_latency_ms":   round(total_latency, 2),
            "backend_latency_ms": round(backend_latency, 2) if backend_latency else None,
        })

        if gateway_decision == "blocked":
            log.info(f"BLOCKED [{status_code}] {client_ip} | {block_reason}")
        else:
            log.debug(f"PASSED  [{status_code}] {client_ip} | {total_latency:.1f}ms")

    return JSONResponse(content=response_data, status_code=status_code)


# ── Metrics endpoint (for experiment analysis) ─────────────────────────────────
@app.get("/metrics")
def metrics():
    con = sqlite3.connect(DB_PATH)
    summary = con.execute("""
        SELECT
            gateway_decision,
            COUNT(*) as count,
            AVG(total_latency_ms) as avg_latency_ms,
            AVG(gateway_latency_ms) as avg_gateway_latency_ms,
            AVG(backend_latency_ms) as avg_backend_latency_ms,
            AVG(anomaly_score) as avg_anomaly_score
        FROM gateway_log
        GROUP BY gateway_decision
    """).fetchall()

    by_code = con.execute("""
        SELECT status_code, COUNT(*) as count
        FROM gateway_log
        GROUP BY status_code
        ORDER BY count DESC
    """).fetchall()

    block_reasons = con.execute("""
        SELECT block_reason, COUNT(*) as count
        FROM gateway_log
        WHERE gateway_decision = 'blocked'
        GROUP BY block_reason
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()

    con.close()

    return {
        "by_decision": [
            dict(zip(["decision", "count", "avg_latency_ms",
                      "avg_gateway_latency_ms", "avg_backend_latency_ms", "avg_anomaly_score"], r))
            for r in summary
        ],
        "by_status_code": [dict(zip(["status_code", "count"], r)) for r in by_code],
        "block_reasons": [dict(zip(["reason", "count"], r)) for r in block_reasons],
    }


# ── Raw log dump (for analysis scripts) ───────────────────────────────────────
@app.get("/logs")
def logs(limit: int = 500):
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("""
        SELECT * FROM gateway_log ORDER BY timestamp DESC LIMIT ?
    """, (limit,)).fetchall()
    cols = [d[0] for d in con.execute("PRAGMA table_info(gateway_log)").fetchall()]
    con.close()
    return {"logs": [dict(zip(cols, r)) for r in rows]}
