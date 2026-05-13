"""
Anomaly detector plugin — tracks request frequency + payload characteristics
to compute a real-time anomaly score. High scores trigger throttling.

Uses a simple sliding-window statistical approach (not ML-based, for speed).
Implements the multivariate detection concept described in Equation (2) of the paper.
"""
import time
import math
import statistics
from collections import defaultdict, deque
from fastapi import HTTPException, Request

# Window: last N requests per client for statistics
WINDOW_SIZE  = 20
ANOMALY_THRESH = float(8.0)   # Score above this → block

# Per-client request history: deque of (timestamp, request_size_kb)
_history: dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))


def _compute_anomaly_score(
    client_ip: str,
    request_size_kb: float,
    anomaly_score_hint: float,
) -> float:
    """
    Composite score (0–10):
      - 40% from anomaly_score_hint in the payload (set by attacker or simulator)
      - 30% from request frequency deviation
      - 30% from payload size deviation
    """
    history = _history[client_ip]

    freq_score = 0.0
    size_score = 0.0

    if len(history) >= 3:
        # Frequency anomaly: inter-arrival time deviation
        timestamps = [h[0] for h in history]
        intervals  = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if intervals:
            mean_interval = statistics.mean(intervals)
            latest_interval = time.time() - timestamps[-1] if timestamps else 10.0
            if mean_interval > 0:
                ratio = mean_interval / max(latest_interval, 0.001)
                freq_score = min(10.0, math.log1p(ratio) * 3)

        # Size anomaly: z-score-like deviation
        sizes = [h[1] for h in history]
        if len(sizes) >= 2:
            mean_size = statistics.mean(sizes)
            stdev_size = statistics.stdev(sizes) or 1.0
            z = abs(request_size_kb - mean_size) / stdev_size
            size_score = min(10.0, z * 2.0)

    score = (
        0.40 * anomaly_score_hint +
        0.30 * freq_score +
        0.30 * size_score
    )
    return round(min(10.0, score), 3)


def check_anomaly(request: Request, body: dict) -> float:
    """
    Returns anomaly score (0–10). Raises 403 if score exceeds threshold.
    Also records request in history.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    request_size = body.get("request_size_kb", 1.0)
    hint = float(body.get("anomaly_score", 0.0))

    score = _compute_anomaly_score(client_ip, request_size, hint)

    # Record AFTER scoring so current request influences future
    _history[client_ip].append((now, request_size))

    if score >= ANOMALY_THRESH:
        raise HTTPException(
            status_code=403,
            detail=f"Request blocked: anomaly score {score:.2f} exceeds threshold {ANOMALY_THRESH}",
        )
    return score
