"""
gateway/middleware/ip_blocker.py
---------------------------------
Outermost IP blocklist middleware.

Checks every incoming request against the `blocked_ips` table.
If the source IP is actively blocked, returns 403 immediately —
before WAF, rate limiter, or any route handler runs.

An IP is auto-blocked when:
  - The WAF fires against it more than WAF_BLOCK_THRESHOLD times in
    WAF_BLOCK_WINDOW seconds  (tracked in-memory, fast).
  - An admin manually blocks it via the admin API.

Blocks are time-limited (default: 1 hour) or permanent (blocked_until=None).
"""

import logging
import time
from collections import defaultdict, deque
from datetime import UTC, datetime, timedelta
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.db.database import AsyncSessionLocal
from gateway.db.models import BlockedIP

logger = logging.getLogger(__name__)

# ── Auto-block configuration ─────────────────────────────────────────────────
WAF_BLOCK_THRESHOLD = 5       # WAF hits required in window to auto-block
WAF_BLOCK_WINDOW    = 120     # seconds
AUTO_BLOCK_DURATION = 3600    # 1 hour

# ── In-memory WAF hit counters (fast, no DB round-trip per hit) ──────────────
_waf_hits: dict[str, deque] = defaultdict(deque)
_waf_lock = Lock()


def record_waf_hit(ip: str) -> bool:
    """Record a WAF block for this IP. Returns True if threshold exceeded."""
    now = time.monotonic()
    cutoff = now - WAF_BLOCK_WINDOW
    with _waf_lock:
        dq = _waf_hits[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq) >= WAF_BLOCK_THRESHOLD


async def auto_block_ip(ip: str, reason: str) -> None:
    """Persist an automatic block for an IP after repeated WAF hits."""
    try:
        from sqlalchemy import select
        blocked_until = datetime.now(UTC) + timedelta(seconds=AUTO_BLOCK_DURATION)
        async with AsyncSessionLocal() as session:
            existing = (await session.execute(
                select(BlockedIP).where(BlockedIP.ip_address == ip)
            )).scalar_one_or_none()
            if existing:
                existing.blocked_until = blocked_until
                existing.reason = reason
            else:
                session.add(BlockedIP(
                    ip_address=ip,
                    reason=reason,
                    blocked_until=blocked_until,
                ))
            await session.commit()
        logger.warning("IP AUTO-BLOCKED | ip=%s reason=%s duration=%ds", ip, reason, AUTO_BLOCK_DURATION)
    except Exception as exc:
        logger.warning("Failed to persist IP block for %s: %s", ip, exc)


class IPBlockerMiddleware(BaseHTTPMiddleware):
    """
    Outermost middleware — runs before WAF, rate limiter, and all routes.
    Checks the blocked_ips table and returns 403 for blocked IPs.
    Cleans up expired blocks lazily on each hit.
    """

    async def dispatch(self, request: Request, call_next):
        from gateway.core.client_ip import get_client_ip
        ip = get_client_ip(request)

        # Skip blocking for health endpoints so monitoring always works
        if request.url.path in ("/health", "/ready"):
            return await call_next(request)

        # The unblock route must stay reachable from a blocked IP, otherwise a
        # self-block (manual, or automatic via the WAF's 5-hits-in-120s rule) is
        # unrecoverable without direct database surgery: DELETE /admin/block-ip
        # is the only way to lift a block, and blocking it blocks the cure.
        # The route itself is still admin-authenticated, so exempting it here
        # does not widen access — it only preserves the recovery path.
        if request.url.path.startswith("/admin/block-ip"):
            logger.info(
                "IPBlocker: allowing blocked-IP recovery route | ip=%s path=%s",
                ip, request.url.path,
            )
            return await call_next(request)

        try:
            from sqlalchemy import select
            now = datetime.now(UTC).replace(tzinfo=None)
            async with AsyncSessionLocal() as session:
                row = (await session.execute(
                    select(BlockedIP).where(BlockedIP.ip_address == ip)
                )).scalar_one_or_none()

                if row:
                    # Permanent block (blocked_until is None) or still within window
                    if row.blocked_until is None:
                        logger.warning("BLOCKED IP (permanent) | ip=%s path=%s", ip, request.url.path)
                        return JSONResponse(
                            status_code=403,
                            content={"detail": "Your IP address has been blocked."},
                        )
                    fu = row.blocked_until
                    if fu.tzinfo is not None:
                        fu = fu.replace(tzinfo=None)
                    if fu >= now:
                        logger.warning("BLOCKED IP | ip=%s until=%s path=%s", ip, fu, request.url.path)
                        return JSONResponse(
                            status_code=403,
                            content={
                                "detail": "Your IP address is temporarily blocked.",
                                "blocked_until": str(row.blocked_until),
                            },
                        )
                    # Block expired — clean up
                    await session.delete(row)
                    await session.commit()
        except Exception as exc:
            # Deliberately fail open: a DB blip should not take the gateway
            # offline. Logged at warning (not debug) because a silent failure
            # here disables IP blocking entirely — that must be visible in logs.
            logger.warning(
                "IPBlocker DB check failed, allowing request (fail-open) | ip=%s path=%s | %s",
                ip, request.url.path, exc,
            )

        return await call_next(request)
