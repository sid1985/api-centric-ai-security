"""
Validator plugin — schema validation + SQL injection detection.
Catches:
  - Schema violations: missing fields, wrong types, out-of-range values
  - SQL injection: regex-based pattern matching on all string fields
  - Oversized payloads
"""
import re
from fastapi import HTTPException, Request

# Max payload size (bytes)
MAX_PAYLOAD_BYTES = int(1024 * 50)  # 50 KB hard cap

# SQL injection patterns (OWASP-aligned)
_SQL_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|CAST)\b)",
    r"(--|;|/\*|\*/|xp_|@@|0x[0-9a-fA-F]+)",
    r"(CHAR\s*\(|NCHAR\s*\(|VARCHAR\s*\()",
    r"(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)",
    r"('.*'--|\bOR\b\s+'.+'\s*=\s*'.+')",
    r"(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY)",
]
_SQL_RE = re.compile("|".join(_SQL_PATTERNS), re.IGNORECASE)

# Field bounds for InferenceRequest
FIELD_BOUNDS = {
    "request_size_kb": (0.001, 10_000.0),
    "anomaly_score":   (0.0, 10.0),
    "cpu_load_pct":    (0.0, 100.0),
}
REQUIRED_FIELDS = {"request_size_kb"}


def _scan_string(value: str) -> bool:
    """Returns True if SQL injection pattern found."""
    return bool(_SQL_RE.search(value))


def _scan_recursive(obj, path: str = "") -> str | None:
    """Recursively scan dicts/lists for SQL patterns. Returns offending path or None."""
    if isinstance(obj, str):
        if _scan_string(obj):
            return path or "payload"
    elif isinstance(obj, dict):
        for k, v in obj.items():
            result = _scan_recursive(v, f"{path}.{k}" if path else k)
            if result:
                return result
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            result = _scan_recursive(item, f"{path}[{i}]")
            if result:
                return result
    return None


async def validate_payload(request: Request, body: dict) -> None:
    """
    1. Payload size check
    2. Required field check
    3. Type / range check
    4. SQL injection scan
    """
    # 1. Size check
    content_length = int(request.headers.get("content-length", 0))
    if content_length > MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=400,
            detail=f"Payload too large: {content_length} bytes (max {MAX_PAYLOAD_BYTES})",
        )

    # 2. Required fields
    for field in REQUIRED_FIELDS:
        if field not in body:
            raise HTTPException(
                status_code=400,
                detail=f"Missing required field: '{field}'",
            )

    # 3. Type & range validation
    for field, (lo, hi) in FIELD_BOUNDS.items():
        if field in body:
            val = body[field]
            if not isinstance(val, (int, float)):
                raise HTTPException(
                    status_code=400,
                    detail=f"Field '{field}' must be a number, got {type(val).__name__}",
                )
            if not (lo <= float(val) <= hi):
                raise HTTPException(
                    status_code=400,
                    detail=f"Field '{field}' out of range [{lo}, {hi}]: {val}",
                )

    # 4. SQL injection scan
    offending_path = _scan_recursive(body)
    if offending_path:
        raise HTTPException(
            status_code=400,
            detail=f"Potential SQL injection detected in field: '{offending_path}'",
        )
