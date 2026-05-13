"""
Rate limiter plugin — in-memory sliding window.
Default: 50 requests per minute per client IP.
DDoS attempts will quickly exhaust this limit.
"""
import time
from collections import defaultdict, deque
from fastapi import HTTPException, Request

# Configurable via env
import os
RATE_LIMIT        = int(os.environ.get("RATE_LIMIT_RPM", "50"))    # requests per window
RATE_WINDOW_SECS  = int(os.environ.get("RATE_WINDOW_SECS", "60"))  # window size in seconds

# {client_key: deque of timestamps}
_windows: dict[str, deque] = defaultdict(deque)


def check_rate_limit(request: Request) -> None:
    """
    Sliding-window rate limiter. Raises 429 if client exceeds RATE_LIMIT RPM.
    """
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    window = _windows[client_ip]

    # Remove timestamps outside the window
    while window and now - window[0] > RATE_WINDOW_SECS:
        window.popleft()

    if len(window) >= RATE_LIMIT:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded: max {RATE_LIMIT} requests per {RATE_WINDOW_SECS}s",
            headers={"Retry-After": str(RATE_WINDOW_SECS)},
        )

    window.append(now)


def get_client_count(client_ip: str) -> int:
    return len(_windows.get(client_ip, []))
