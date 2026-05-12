"""
AI Inference Service — FastAPI
Intentionally has NO built-in security (demonstrates the vulnerable baseline).
The API Gateway in front of it provides all security.
"""
import os
import sys
import time
import uuid
import logging
import sqlite3
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from fastapi import FastAPI, Request, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ai-service")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
MODEL_DIR  = BASE_DIR / "model"
MODEL_PATH = MODEL_DIR / "classifier.joblib"
ENC_PATH   = MODEL_DIR / "label_encoder.joblib"
DB_PATH    = os.environ.get("DB_PATH", str(BASE_DIR / "logs" / "ai_service.db"))

# ── Models (loaded at startup) ─────────────────────────────────────────────────
_clf = None
_le  = None


def _init_db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS inference_log (
            id              TEXT PRIMARY KEY,
            timestamp       TEXT NOT NULL,
            request_size_kb REAL,
            anomaly_score   REAL,
            prediction      TEXT,
            confidence      REAL,
            processing_ms   REAL,
            error           TEXT,
            source          TEXT DEFAULT 'direct'
        )
    """)
    con.commit()
    con.close()


def _log_request(row: dict):
    try:
        con = sqlite3.connect(DB_PATH)
        con.execute("""
            INSERT INTO inference_log
                (id, timestamp, request_size_kb, anomaly_score, prediction, confidence, processing_ms, error, source)
            VALUES (:id, :timestamp, :request_size_kb, :anomaly_score, :prediction, :confidence, :processing_ms, :error, :source)
        """, row)
        con.commit()
        con.close()
    except Exception as e:
        log.warning(f"DB log failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _clf, _le
    # Train model if not present
    if not MODEL_PATH.exists():
        log.info("Model not found — training now...")
        sys.path.insert(0, str(MODEL_DIR))
        from train import train
        _clf, _le = train()
    else:
        _clf = joblib.load(MODEL_PATH)
        _le  = joblib.load(ENC_PATH)
        log.info("Model loaded.")
    _init_db()
    yield


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="AI Inference Service",
    description="Intentionally unprotected baseline — wrap with API Gateway for security.",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Schemas ────────────────────────────────────────────────────────────────────
class InferenceRequest(BaseModel):
    request_size_kb: float = Field(..., description="Size of the request payload in KB")
    response_time_ms: float = Field(default=0.0, description="Upstream response time hint")
    anomaly_score: float   = Field(default=0.0, description="Pre-computed anomaly score (0-10)")
    cpu_load_pct: float    = Field(default=20.0, description="Current CPU load percent")
    metadata: dict[str, Any] = Field(default_factory=dict)


class InferenceResponse(BaseModel):
    request_id: str
    prediction: str
    confidence: float
    processing_ms: float
    model_version: str = "v1.0"


# ── Endpoints ──────────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": _clf is not None}


@app.post("/predict", response_model=InferenceResponse)
async def predict(req: InferenceRequest, request: Request):
    t0 = time.perf_counter()
    req_id = str(uuid.uuid4())

    # Simulate occasional expensive computation on malicious inputs (no filtering here)
    if req.anomaly_score > 7.0:
        # Bad input reaches here in direct-access mode → wasted compute
        time.sleep(0.05)

    features = np.array([[
        req.request_size_kb,
        req.response_time_ms,
        req.anomaly_score,
        req.cpu_load_pct,
    ]])

    proba   = _clf.predict_proba(features)[0]
    cls_idx = int(np.argmax(proba))
    label   = _le.inverse_transform([cls_idx])[0]
    conf    = float(proba[cls_idx])

    processing_ms = (time.perf_counter() - t0) * 1000

    source = request.headers.get("x-forwarded-from", "direct")
    _log_request({
        "id":              req_id,
        "timestamp":       time.strftime("%Y-%m-%dT%H:%M:%S"),
        "request_size_kb": req.request_size_kb,
        "anomaly_score":   req.anomaly_score,
        "prediction":      label,
        "confidence":      conf,
        "processing_ms":   processing_ms,
        "error":           None,
        "source":          source,
    })

    return InferenceResponse(
        request_id=req_id,
        prediction=label,
        confidence=conf,
        processing_ms=processing_ms,
    )


@app.get("/metrics")
def metrics():
    """Simple metrics endpoint (used by analysis scripts)."""
    con = sqlite3.connect(DB_PATH)
    rows = con.execute("""
        SELECT
            COUNT(*) as total_requests,
            AVG(processing_ms) as avg_latency_ms,
            SUM(CASE WHEN error IS NOT NULL THEN 1 ELSE 0 END) as error_count,
            source
        FROM inference_log
        GROUP BY source
    """).fetchall()
    con.close()
    return {"metrics": [dict(zip(["total", "avg_latency_ms", "errors", "source"], r)) for r in rows]}
