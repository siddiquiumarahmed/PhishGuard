"""Rate-limit keys and limit strings.

PhishGuard runs locally, so limits are keyed on the client IP address as seen
by Flask. ``X-Forwarded-For`` is intentionally ignored: trusting it without a
known reverse proxy would let any client choose its own rate-limit key.
"""

from __future__ import annotations

from flask import current_app, request


def client_key() -> str:
    return request.remote_addr or "unknown"


def scan_limit() -> str:
    """Limit applied to scan-creating endpoints (configurable via SCAN_RATE_LIMIT)."""
    return str(current_app.config.get("SCAN_RATE_LIMIT", "20 per minute;300 per day"))
