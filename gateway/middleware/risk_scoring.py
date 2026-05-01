"""
gateway/middleware/risk_scoring.py
------------------------------------
Adaptive Risk Scoring middleware.

Computes a per-request risk score:

    risk = (auth_risk × 0.30) + (behavior_risk × 0.40) + (pattern_risk × 0.30)

Components
----------
auth_risk     — token absent / expired / short-lived / OAuth vs local
behavior_risk — request rate for this IP in the last 60 s
pattern_risk  — suspicious headers / user-agents / unusual methods

Actions
-------
  0.00 – 0.39  → ALLOW   (no extra action)
  0.40 – 0.64  → MONITOR (log + add header)
  0.65 – 0.79  → CHALLENGE (log + 401 with WWW-Authenticate: mfa)  [future]
                 For now: allow but set X-Risk-Action: challenge
  0.80 – 1.00  → BLOCK   (403)

The score and action are added as response headers for transparency:
  X-Risk-Score, X-Risk-Action
"""

import time
import logging
from collections import defaultdict, deque
from threading import Lock

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.core.security import SecurityManager
from gateway.db.database import AsyncSessionLocal
from gateway.db.models import SecurityEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory request counter (for behavior_risk)
# ---------------------------------------------------------------------------
_request_log: dict[str, deque] = defaultdict(deque)
_req_lock = Lock()
_WINDOW = 60  # seconds


def _request_count(ip: str) -> int:
    now = time.monotonic()
    cutoff = now - _WINDOW
    with _req_lock:
        dq = _request_log[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq)


# ---------------------------------------------------------------------------
# Exempt paths (static assets, health, docs)
# ---------------------------------------------------------------------------
_EXEMPT_PREFIXES = ("/health", "/docs", "/redoc", "/openapi", "/frontend", "/favicon")


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


# ---------------------------------------------------------------------------
# Risk component calculators
# ---------------------------------------------------------------------------

def _auth_risk(request: Request) -> float:
    """
    0.0 = valid local JWT with plenty of time left
    0.5 = valid token but near expiry or OAuth-issued
    0.8 = no token on a sensitive path
    1.0 = invalid / expired token
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # Unauthenticated request — higher risk only on /admin paths
        if request.url.path.startswith("/admin"):
            return 0.8
        return 0.1

    token = auth[len("Bearer "):]
    payload = SecurityManager.verify_token(token)
    if not payload:
        return 1.0  # invalid / expired

    import time as _time
    exp = payload.get("exp", 0)
    remaining = exp - _time.time()
    if remaining < 120:           # < 2 minutes left
        return 0.6
    if remaining < 600:           # < 10 minutes left
        return 0.35
    return 0.05                   # plenty of time — low risk


def _behavior_risk(ip: str) -> float:
    """
    Scale 0–1 based on request volume in the last 60 s per IP.
      < 20 req/min   → 0.0
      20–60 req/min  → 0.3
      60–120 req/min → 0.6
      > 120 req/min  → 0.9
    """
    count = _request_count(ip)
    if count < 20:
        return 0.0
    if count < 60:
        return 0.3
    if count < 120:
        return 0.6
    return 0.9


_SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "burpsuite", "metasploit", "curl/", "python-requests",
    "go-http-client", "zgrab", "scanner",
]

_UNUSUAL_METHODS = {"TRACE", "TRACK", "DEBUG", "CONNECT"}


def _pattern_risk(request: Request) -> float:
    """
    Examine headers and request characteristics for suspicious patterns.
    """
    score = 0.0
    ua = request.headers.get("User-Agent", "").lower()

    for s in _SUSPICIOUS_UA:
        if s in ua:
            score += 0.5
            break

    if not ua:
        score += 0.3

    if request.method in _UNUSUAL_METHODS:
        score += 0.4

    # Referrer mismatch on auth endpoints
    if request.url.path.startswith("/auth"):
        referer = request.headers.get("Referer", "")
        if referer and "127.0.0.1" not in referer and "localhost" not in referer:
            score += 0.2

    return min(score, 1.0)


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

async def _store_high_risk_event(ip: str, path: str, score: float) -> None:
    try:
        async with AsyncSessionLocal() as session:
            event = SecurityEvent(
                threat_type="high_risk_request",
                ip_address=ip,
                endpoint=path,
                payload=f"risk_score={score:.2f}",
                risk_score=score,
                status="flagged",
            )
            session.add(event)
            await session.commit()
    except Exception as exc:
        logger.warning("RiskScoring: failed to store event: %s", exc)


class RiskScoringMiddleware(BaseHTTPMiddleware):
    """Computes per-request adaptive risk score and takes action."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_exempt(path) or request.method == "OPTIONS":
            return await call_next(request)

        ip = request.client.host if request.client else "unknown"

        # ── Compute components ────────────────────────────────────────────────
        ar = _auth_risk(request)
        br = _behavior_risk(ip)
        pr = _pattern_risk(request)
        score = (ar * 0.30) + (br * 0.40) + (pr * 0.30)
        
        # ── DEMO FIX: Extreme Behavior Penalty ──
        # If this IP is spamming us with >120 req/min, heavily penalize it 
        # so that even authenticated users on the same IP see a High/Critical risk score.
        if br >= 0.9:
            score += 0.40
            
        score = min(round(score, 3), 1.0)

        # ── Decide action ─────────────────────────────────────────────────────
        if score >= 0.80:
            action = "block"
        elif score >= 0.65:
            action = "challenge"
        elif score >= 0.40:
            action = "monitor"
        else:
            action = "allow"

        logger.debug(
            "RiskScore | ip=%s path=%s auth=%.2f behavior=%.2f pattern=%.2f total=%.3f action=%s",
            ip, path, ar, br, pr, score, action,
        )

        if action == "block":
            logger.warning("RiskScore BLOCKED | ip=%s path=%s score=%.3f", ip, path, score)
            import asyncio
            asyncio.ensure_future(_store_high_risk_event(ip, path, score))
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked: risk score too high.",
                    "risk_score": score,
                },
                headers={
                    "X-Risk-Score": str(score),
                    "X-Risk-Action": "block",
                },
            )

        if action == "monitor" or action == "challenge":
            logger.info("RiskScore %s | ip=%s path=%s score=%.3f", action.upper(), ip, path, score)

        # ── Let request through ───────────────────────────────────────────────
        response = await call_next(request)
        response.headers["X-Risk-Score"] = str(score)
        response.headers["X-Risk-Action"] = action
        return response
