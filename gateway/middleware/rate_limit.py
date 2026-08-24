"""
gateway/middleware/rate_limit.py
---------------------------------
Sliding-window rate limiter with Redis backend (fallback to in-memory).

Limits:
  - Auth endpoints (/auth/login, /auth/register): 10 req / 60 s per IP
  - /auth/forgot-password:                         5 req / 60 s per IP
  - /auth/mfa/verify:                              5 req / 60 s per IP
  - All other endpoints:                          120 req / 60 s per IP

Returns HTTP 429 with Retry-After header when the limit is exceeded.

Backend selection:
  - If Redis is reachable (REDIS_URL in config): uses sorted sets for
    horizontally-scalable distributed rate limiting.
  - If Redis is unavailable: falls back to in-memory deque store (single-process only).
    Note that this fallback is NOT limit-equivalent — see _is_allowed().
"""

import time
import logging
from collections import defaultdict, deque
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.core.client_ip import get_client_ip

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
WINDOW_SECONDS = 60

# Throttle for the "Redis went away" warning in _is_allowed(): timestamp of the
# last emission, so a sustained outage logs once a minute instead of once a
# request.
_redis_fail_logged_at = 0.0

# 120/60s matches what PROJECT_DESCRIPTION.md documents ("120 req/60 s
# elsewhere"). The code shipped 1000, which is not a rate limit for any realistic
# single client — it silently made the default bucket decorative, so the middleware
# looked active in the stack while never firing outside /auth.
LIMITS = {
    "auth":    10,
    "forgot":  5,
    "mfa":     5,
    "default": 120,
}

AUTH_RATE_LIMITED_PATHS = {"/auth/login", "/auth/register"}
FORGOT_RATE_LIMITED_PATHS = {"/auth/forgot-password"}
# /auth/mfa/verify-setup is now rate-limited to prevent TOTP enumeration attacks
MFA_RATE_LIMITED_PATHS = {"/auth/mfa/verify", "/auth/mfa/verify-setup"}

# ---------------------------------------------------------------------------
# Redis backend (preferred — horizontally scalable)
# ---------------------------------------------------------------------------
_redis_client = None


def _init_redis():
    """Try to connect to Redis; return client or None."""
    global _redis_client
    try:
        import redis
        from gateway.config import settings
        url = getattr(settings, "REDIS_URL", "")
        if not url:
            return None
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        _redis_client = client
        logger.info("Rate limiter: using Redis backend (%s)", url)
        return client
    except Exception as exc:
        logger.info("Rate limiter: Redis unavailable (%s), using in-memory fallback.", exc)
        return None


# NOT called at import time any more. Importing this module used to open a TCP
# socket and issue PING with a 2s connect timeout, which meant: (a) `import
# gateway.middleware.rate_limit` blocked for up to 2s wherever Redis was
# configured but unreachable, including during test collection, and (b) the
# connection was established before the app had a chance to configure anything.
# main.py's lifespan calls init_rate_limit_backend() instead.


def init_rate_limit_backend():
    """Connect the Redis backend, if configured. Call once from the app lifespan."""
    return _init_redis()


def _redis_is_allowed(bucket_key: str, limit: int) -> tuple[bool, int]:
    """Redis sorted-set sliding window. Members are timestamps, scored by time."""
    now = time.time()
    cutoff = now - WINDOW_SECONDS
    pipe = _redis_client.pipeline()
    pipe.zremrangebyscore(bucket_key, "-inf", cutoff)
    pipe.zcard(bucket_key)
    pipe.zadd(bucket_key, {str(now): now})
    pipe.expire(bucket_key, WINDOW_SECONDS + 5)
    results = pipe.execute()
    count = results[1]

    if count >= limit:
        oldest = _redis_client.zrange(bucket_key, 0, 0, withscores=True)
        if oldest:
            retry_after = int(WINDOW_SECONDS - (now - oldest[0][1])) + 1
        else:
            retry_after = WINDOW_SECONDS
        _redis_client.zrem(bucket_key, str(now))
        return False, max(1, retry_after)

    return True, limit - count - 1


# ---------------------------------------------------------------------------
# In-memory fallback (single process only)
# ---------------------------------------------------------------------------
_store: dict[str, deque] = defaultdict(deque)
_lock = Lock()
_MAX_KEYS = 10000


def _evict_idle_keys():
    """
    Drop buckets whose newest entry has aged out of the window.

    The guard compares total key count against the cap. The previous version
    computed `len(_store) - len(empty)`, which is the count of *active* keys, so
    eviction only fired when active keys alone exceeded the cap — i.e. precisely
    when there was nothing idle to reclaim. With 1,000,000 idle and 100 active
    keys the condition was 100 > 10000 → False, and the dict grew without bound.
    """
    if len(_store) <= _MAX_KEYS:
        # Fast path: nothing to do, and crucially we avoid scanning the whole
        # dict under the lock on every single request.
        return
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS
    with _lock:
        empty = [k for k, dq in _store.items() if not dq or dq[-1] < cutoff]
        for k in empty:
            del _store[k]
        # If every key is still active we cannot reclaim by idleness alone;
        # evict the least-recently-seen buckets so memory stays bounded.
        if len(_store) > _MAX_KEYS:
            by_age = sorted(_store.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
            for k, _ in by_age[: len(_store) - _MAX_KEYS]:
                del _store[k]


def _memory_is_allowed(bucket_key: str, limit: int) -> tuple[bool, int]:
    """In-memory sliding-window check."""
    _evict_idle_keys()
    now = time.monotonic()
    cutoff = now - WINDOW_SECONDS

    with _lock:
        window = _store[bucket_key]
        while window and window[0] < cutoff:
            window.popleft()

        count = len(window)
        if count >= limit:
            retry_after = int(WINDOW_SECONDS - (now - window[0])) + 1
            return False, retry_after

        window.append(now)
        return True, limit - count - 1


# ---------------------------------------------------------------------------
# Unified check
# ---------------------------------------------------------------------------

def _is_allowed(bucket_key: str, limit: int) -> tuple[bool, int]:
    if _redis_client:
        try:
            return _redis_is_allowed(f"rl:{bucket_key}", limit)
        except Exception as exc:
            # Falling back to the in-memory limiter is the right behaviour, but
            # it is NOT equivalent: memory buckets are per-process, so across N
            # uvicorn workers the effective limit silently becomes N × limit.
            # Configure 120/min, run 4 workers, lose Redis, and an attacker gets
            # 480/min while the config, the docs and the dashboard all still say
            # 120. Warn once per minute so a Redis outage is visible without
            # emitting a line per request.
            global _redis_fail_logged_at
            now = time.time()
            if now - _redis_fail_logged_at > 60:
                _redis_fail_logged_at = now
                logger.warning(
                    "Redis rate-limit backend unavailable (%s: %s) — falling back "
                    "to the PER-PROCESS in-memory limiter. With multiple workers "
                    "the effective limit is now (workers × %s), not %s.",
                    type(exc).__name__, exc, limit, limit,
                )
    return _memory_is_allowed(bucket_key, limit)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that enforces per-IP rate limits."""

    async def dispatch(self, request: Request, call_next):
        ip = get_client_ip(request)
        path = request.url.path

        if path in AUTH_RATE_LIMITED_PATHS:
            limit = LIMITS["auth"]
            bucket = f"auth:{ip}"
        elif path in FORGOT_RATE_LIMITED_PATHS:
            limit = LIMITS["forgot"]
            bucket = f"forgot:{ip}"
        elif path in MFA_RATE_LIMITED_PATHS:
            limit = LIMITS["mfa"]
            bucket = f"mfa:{ip}"
        else:
            limit = LIMITS["default"]
            bucket = f"default:{ip}"

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

        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(info)
        response.headers["X-RateLimit-Window"] = str(WINDOW_SECONDS)

        return response
