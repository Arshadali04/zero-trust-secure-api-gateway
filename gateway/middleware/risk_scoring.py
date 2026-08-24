"""
gateway/middleware/risk_scoring.py
------------------------------------
Adaptive Risk Scoring middleware.

Computes a per-request risk score:

    risk = (auth_risk × 0.30) + (behavior_risk × 0.40) + (pattern_risk × 0.30)

…plus one term those weights do not account for: when behavior_risk on its
own reaches 0.90 (an IP hammering the gateway), a flat **+0.25** is added
before the result is clamped to 1.0. See the "Extreme Behavior Penalty" block
in dispatch(). It exists so a burst crosses the 0.80 block threshold quickly
— a maxed-out behavior_risk otherwise contributes only 0.40 and auth/pattern
risk have to supply the rest. It is also the reason a client with a clean
token and clean headers can be blocked on request rate alone, which is
exactly why it belongs in the documented formula and not only in the code.

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

from gateway.core.security import verify_token_for_request
from gateway.core.client_ip import get_client_ip
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
    _evict_idle_ips()
    now = time.monotonic()
    cutoff = now - _WINDOW
    with _req_lock:
        dq = _request_log[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        return len(dq)


_MAX_IPS_IN_MEMORY = 5000


def _evict_idle_ips():
    """
    Drop IPs with no recent requests to cap memory growth.

    The guard compares total key count against the cap. The previous version
    computed `len(_request_log) - len(empty_keys)`, which is the count of
    *active* IPs, so eviction only fired when active IPs alone exceeded the cap
    — precisely when there was nothing idle to reclaim. With 1,000,000 idle and
    100 active IPs the condition was 100 > 5000 → False and nothing was freed.
    The early return also keeps this off the hot path: previously every request
    scanned the entire dict under the lock, so latency degraded as the leak grew.
    """
    if len(_request_log) <= _MAX_IPS_IN_MEMORY:
        return
    now = time.monotonic()
    cutoff = now - _WINDOW
    with _req_lock:
        empty_keys = [k for k, dq in _request_log.items() if not dq or dq[-1] < cutoff]
        for k in empty_keys:
            del _request_log[k]
        # If everything is still active, evict least-recently-seen so the
        # dictionary stays bounded under a distributed flood.
        if len(_request_log) > _MAX_IPS_IN_MEMORY:
            by_age = sorted(_request_log.items(), key=lambda kv: kv[1][-1] if kv[1] else 0)
            for k, _ in by_age[: len(_request_log) - _MAX_IPS_IN_MEMORY]:
                del _request_log[k]


# ---------------------------------------------------------------------------
# Exempt paths (static assets, health, docs)
# ---------------------------------------------------------------------------
_EXEMPT_PREFIXES = (
    "/health", "/docs", "/redoc", "/openapi", "/frontend", "/favicon",
    "/auth/oauth", "/auth/callback",  # OAuth login + callback must never be risk-blocked
)


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


# ---------------------------------------------------------------------------
# Risk component calculators
# ---------------------------------------------------------------------------

def _auth_risk(request: Request) -> float:
    """
    0.0 = valid local JWT with plenty of time left
    0.5 = valid token but near expiry
    0.8 = no token on a sensitive path
    1.0 = invalid / expired token

    OAuth-issued tokens are treated the same as local ones — OAuth via
    authlib is as strong as local auth, so there is no OAuth penalty.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        # Unauthenticated request — higher risk only on /admin paths
        if request.url.path.startswith("/admin"):
            return 0.8
        return 0.1

    token = auth[len("Bearer "):]
    payload = verify_token_for_request(request, token)
    if not payload:
        # An expired-but-previously-valid token is the single most common benign
        # case in a browser app: the tab was left open past the 30-minute access
        # token lifetime and the client has not refreshed yet. Scoring it 1.0
        # meant a lapsed session was rated MORE hostile than a request with no
        # credentials at all (0.1), so ordinary users got blocked for idling
        # while genuine anonymous scanners scored low. Distinguish the two:
        # a malformed/forged token stays high, a merely expired one does not.
        try:
            import jwt as _jwt
            claims = _jwt.decode(token, options={"verify_signature": False, "verify_exp": False})
            import time as _t
            if claims.get("exp") and float(claims["exp"]) < _t.time():
                return 0.45  # expired but structurally valid — needs refresh, not a block
        except Exception as exc:
            # Unparseable means forged, truncated or not a JWT at all, and the
            # 1.0 below is the correct verdict — so this is genuinely non-fatal.
            # Logged at DEBUG anyway: while tuning the scorer, "why did this
            # token score 1.0?" is otherwise unanswerable from the logs.
            logger.debug(
                "Risk scorer could not decode token for exp inspection "
                "(%s: %s) — scoring as forged/invalid",
                type(exc).__name__, exc,
            )
        return 1.0  # invalid / forged / unparseable

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
    # Use more tolerant thresholds so normal UI navigation doesn't rapidly
    # escalate the behaviour risk. Thresholds are still proportional to
    # requests-per-minute but scaled up for demo/front-end noise.
    count = _request_count(ip)
    if count < 60:
        return 0.0
    if count < 180:
        return 0.3
    if count < 360:
        return 0.6
    return 0.9


# Only true attack tooling belongs here. "curl/" and "go-http-client" were
# previously included, which permanently charged pattern_risk 0.5 to every CI
# job, health probe, monitoring agent and command-line test — legitimate traffic
# that then combined with other signals to trigger blocks and account-risk
# elevation. Generic HTTP clients are not evidence of an attack.
_SUSPICIOUS_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "dirbuster",
    "burpsuite", "metasploit", "zgrab", "scanner",
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


async def _elevate_authenticated_account_risk(
    request: Request,
    *,
    ip: str,
    path: str,
    action: str,
    score: float,
    behavior_risk: float,
    pattern_risk: float,
) -> None:
    """Raise persistent account risk for severe authenticated requests only.

    Normal dashboard usage should not move account risk. We only elevate on
    suspicious monitor/challenge/block outcomes with clear hostile signals.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return

    token = auth[len("Bearer "):]
    payload = verify_token_for_request(request, token)
    if not payload:
        return

    email = payload.get("sub")
    if not email:
        return

    amount = 0.0
    if action == "waf_block":
        amount = 0.30
    elif action == "block":
        amount = 0.35
    elif action == "challenge":
        if pattern_risk >= 0.5 or behavior_risk >= 0.6:
            amount = 0.20
    elif action == "monitor":
        # Only elevate on monitor when the request already looks strongly
        # suspicious (scanner signature) or extreme burst behaviour.
        if pattern_risk >= 0.5 or behavior_risk >= 0.9:
            amount = 0.12

    if amount <= 0.0:
        return

    try:
        from sqlalchemy import select
        from gateway.db.models import User
        from gateway.detection.account_risk import elevate_account_risk

        async with AsyncSessionLocal() as session:
            result = await session.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            if not user:
                return
            # A WAF block is a confirmed-malicious signal, not a heuristic, so
            # it must not be swallowed by the 2-second per-account cooldown.
            # The per-request elevation for this same request has usually just
            # stamped risk_updated_at microseconds earlier, which meant the
            # strongest available signal contributed nothing.
            new_risk = await elevate_account_risk(
                session, user.id, amount, ip=ip,
                bypass_cooldown=(action == "waf_block"),
            )
            logger.warning(
                "RiskScore policy elevate | user=%s ip=%s path=%s action=%s req_score=%.3f account_risk=%.2f",
                user.id, ip, path, action, score, new_risk,
            )
    except Exception as exc:
        logger.warning("RiskScoring: account-risk elevate failed: %s", exc)


class RiskScoringMiddleware(BaseHTTPMiddleware):
    """Computes per-request adaptive risk score and takes action."""

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_exempt(path) or request.method == "OPTIONS":
            return await call_next(request)

        ip = get_client_ip(request)

        # ── Compute components ────────────────────────────────────────────────
        ar = _auth_risk(request)
        br = _behavior_risk(ip)
        pr = _pattern_risk(request)
        score = (ar * 0.30) + (br * 0.40) + (pr * 0.30)

        # ── DEMO FIX: Extreme Behavior Penalty ──
        # If this IP is spamming us with a very high request rate, add a
        # modest penalty so attacks are surfaced quickly but normal UI
        # navigation doesn't immediately push scores to critical.
        if br >= 0.9:
            score += 0.25

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
            "RiskScore | ip=%s path=%s auth=%.2f behavior=%.2f pat=%.2f total=%.3f action=%s cnt=%d",
            ip, path, ar, br, pr, score, action,
            (len(_request_log.get(ip, [])) if _req_lock else 0),
        )

        if action in ("monitor", "challenge", "block"):
            await _elevate_authenticated_account_risk(
                request,
                ip=ip,
                path=path,
                action=action,
                score=score,
                behavior_risk=br,
                pattern_risk=pr,
            )

        if action == "block":
            logger.warning("RiskScore BLOCKED | ip=%s path=%s score=%.3f", ip, path, score)
            await _store_high_risk_event(ip, path, score)
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

        # If WAF blocked the request, treat it as a high-severity risk signal.
        # This makes the Attack Lab graph reflect real attacks and feeds the
        # persistent account-risk policy path (step-up/freeze).
        waf_threat = response.headers.get("X-WAF-Blocked", "")
        waf_score_raw = response.headers.get("X-WAF-Risk-Score", "")
        if waf_threat:
            try:
                waf_score = float(waf_score_raw)
            except (TypeError, ValueError):
                waf_score = 0.85

            # Blend WAF severity with live request context so the chart reflects
            # progression during an attack instead of a perfectly flat line.
            waf_score = min(max(waf_score, 0.8), 1.0)
            score = min(1.0, round((waf_score * 0.75) + (score * 0.25), 3))
            action = "block"

            await _elevate_authenticated_account_risk(
                request,
                ip=ip,
                path=path,
                action="waf_block",
                score=score,
                behavior_risk=br,
                pattern_risk=max(pr, 0.8),
            )

        response.headers["X-Risk-Score"] = str(score)
        response.headers["X-Risk-Action"] = action
        return response
