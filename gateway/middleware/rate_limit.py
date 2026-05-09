"""
gateway/middleware/rate_limit.py
---------------------------------
In-memory sliding-window rate limiter.

Limits:
  - Auth endpoints (/auth/login, /auth/register): 10 req / 60 s per IP
  - All other endpoints:                         120 req / 60 s per IP

Returns HTTP 429 with Retry-After header when the limit is exceeded.
No Redis required — uses a thread-safe in-process store.
"""

import time
import logging
from collections import defaultdict, deque
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WINDOW_SECONDS = 60

LIMITS = {
    "auth":    10,   # /auth/login, /auth/register
    "default": 100, # Raised to 1000 so the Risk Engine can be demonstrated multiple times
}

AUTH_RATE_LIMITED_PATHS = {"/auth/login", "/auth/register"}

# ---------------------------------------------------------------------------
# Store: { bucket_key: deque of timestamps }
# ---------------------------------------------------------------------------
_store: dict[str, deque] = defaultdict(deque)
_lock = Lock()


def _get_client_ip(request: Request) -> str:
    """Return the real client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_allowed(bucket_key: str, limit: int) -> tuple[bool, int]:
    """
    Sliding-window check.
    Returns (allowed, requests_remaining).
    """
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS

    with _lock:
        window = _store[bucket_key]

        # Drop timestamps outside the window
        while window and window[0] < cutoff:
            window.popleft()

        count = len(window)
        if count >= limit:
            retry_after = int(WINDOW_SECONDS - (now - window[0])) + 1
            return False, retry_after

        window.append(now)
        return True, limit - count - 1


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that enforces per-IP rate limits."""

    async def dispatch(self, request: Request, call_next):
        ip = _get_client_ip(request)
        path = request.url.path

        # Choose limit bucket
        if path in AUTH_RATE_LIMITED_PATHS:
            limit = LIMITS["auth"]
            bucket = f"auth:{ip}"
        else:
            limit = LIMITS["default"]
            bucket = f"default:{ip}"

        # OPTIONS preflight must NEVER be rate-limited — the real request
        # that follows would be blocked by CORS before we even see it.
        if request.method == "OPTIONS":
            return await call_next(request)

        allowed, info = _is_allowed(bucket, limit)

        if not allowed:
            retry_after = info
            logger.warning(
                "Rate limit exceeded | ip=%s path=%s retry_after=%ss",
                ip, path, retry_after,
            )
            return JSONResponse(
                status_code=429,
                content={
                    "detail": "Too many requests. Please slow down.",
                    "retry_after_seconds": retry_after,
                },
                headers={"Retry-After": str(retry_after)},
            )

        response = await call_next(request)

        # Add rate-limit headers to every response
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(info)
        response.headers["X-RateLimit-Window"] = str(WINDOW_SECONDS)

        return response
