"""
gateway/middleware/logging.py
------------------------------
Request logging middleware.

Logs every HTTP request to:
  1. The Python logger (always)
  2. The AuditLog database table (async, non-blocking)

event_type tags stored in AuditLog.event_type:
  successful    → 2xx responses
  unsuccessful  → 4xx responses (auth failures, validation errors)
  blocked       → WAF / risk-score blocks (X-WAF-Blocked or X-Risk-Action: block)
  rate_limited  → 429 responses
  server_error  → 5xx responses
  proxied       → 2xx responses on /api/v1/* proxy routes

Skips logging for: /health, /docs, /redoc, /openapi.json, /favicon.ico
"""

import json
import logging
import time

from fastapi import Request
from sqlalchemy import select
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from gateway.core.client_ip import get_client_ip
from gateway.core.security import verify_token_for_request
from gateway.db.database import AsyncSessionLocal
from gateway.db.models import AuditLog

logger = logging.getLogger(__name__)

# Paths we don't bother logging
SKIP_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/", "/favicon.ico"}


def _extract_user_email(request: Request) -> str | None:
    """Extract user email from JWT if present in Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    try:
        # Per-request cached decode. This is the first of up to four verifications
        # of the same token in one request; see verify_token_for_request.
        payload = verify_token_for_request(request, token)
        return payload.get("sub") if payload else None
    except Exception:
        return None


def _classify_event(
    status_code: int,
    path: str,
    response_headers: dict,
) -> str:
    """
    Classify the request outcome into a human-readable event_type tag.

    Priority order (highest specificity first):
      1. WAF blocked  → 'blocked'
      2. Risk blocked → 'blocked'
      3. Rate limited → 'rate_limited'
      4. 5xx          → 'server_error'
      5. 4xx on auth  → 'unsuccessful'
      6. 4xx other    → 'unsuccessful'
      7. 2xx on proxy → 'proxied'
      8. 2xx          → 'successful'
      9. 3xx          → 'redirect'
    """
    # Normalise header keys to lowercase for reliable matching
    rh = {k.lower(): v for k, v in response_headers.items()}

    # WAF block (X-WAF-Blocked header set by WAFMiddleware)
    if rh.get("x-waf-blocked"):
        return "blocked"

    # Risk-score block (X-Risk-Action: block set by RiskScoringMiddleware)
    if rh.get("x-risk-action") == "block":
        return "blocked"

    if status_code == 429:
        return "rate_limited"

    if status_code >= 500:
        return "server_error"

    # Proxy routes should always show as proxied regardless of success/fail
    if path.startswith("/api/v1/"):
        return "proxied"

    if status_code >= 400:
        # 401/403 on auth paths are "unsuccessful" login/access attempts
        return "unsuccessful"

    if status_code >= 300:
        return "redirect"

    return "successful"


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request to Python logger and AuditLog DB table."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        # Also skip static frontend asset logging (css/js) to keep logs clean
        path = request.url.path
        if path.startswith("/frontend/css/") or path.startswith("/frontend/js/"):
            return await call_next(request)

        start = time.monotonic()
        ip = get_client_ip(request)
        method = request.method
        user_agent = request.headers.get("User-Agent", "")[:500]
        user_email = _extract_user_email(request)

        # Process the request
        response = None
        resp_headers: dict = {}
        try:
            response = await call_next(request)
            status_code = response.status_code
            resp_headers = dict(response.headers)
        except Exception as exc:
            status_code = 500
            logger.exception("Unhandled error on %s %s", method, path)
            raise exc
        finally:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            event_type = _classify_event(status_code, path, resp_headers)

            # If the route injected an audit user (like /login or /register), use it
            if not user_email and "x-audit-user" in resp_headers:
                user_email = resp_headers["x-audit-user"]

            logger.info(
                "%s %s %s [%s] | ip=%s user=%s elapsed=%dms",
                method, path, status_code, event_type.upper(),
                ip, user_email or "anonymous", elapsed_ms,
            )

            await _write_audit_log(
                method=method,
                path=path,
                status_code=status_code,
                event_type=event_type,
                ip=ip,
                user_agent=user_agent,
                user_email=user_email,
                elapsed_ms=elapsed_ms,
            )

            # ── Behavioural profiling (every authenticated request) ────────────
            if user_email and status_code < 500:
                content_len = 0
                try:
                    content_len = int(request.headers.get("Content-Length", 0) or 0)
                except (TypeError, ValueError):
                    content_len = 0
                await _track_behavior(user_email, ip, content_len)

        return response


async def _track_behavior(user_email: str, ip: str, body_bytes: int = 0) -> None:
    """Feed behavioural profiling and log anomalies as SecurityEvents."""
    try:
        from datetime import datetime

        from gateway.db.models import SecurityEvent, User
        from gateway.detection.behavior import update_behavior_profile

        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(User).where(User.email == user_email)
            )
            user = result.scalar_one_or_none()
            if not user:
                return
            anomaly = await update_behavior_profile(
                user.id, ip, session,
                body_bytes=body_bytes,
                hour=datetime.now().hour,
            )
            if anomaly:
                event = SecurityEvent(
                    threat_type=anomaly["threat_type"],
                    ip_address=ip,
                    endpoint="/api/v1/*",
                    payload=anomaly.get("reason", ""),
                    risk_score=anomaly["risk_score"],
                    status="flagged",
                )
                session.add(event)
                await session.commit()

                # ── Persistent account risk ────────────────────────────────
                # Only elevate for BEHAVIOR_ANOMALY (genuine sustained
                # traffic spike > 50 req/min).  auth_spike is logged above
                # for the admin dashboard but should NOT auto-elevate —
                # after a brute-force attack the _user_failures deque still
                # has entries, so every normal request within the 60 s
                # window would fire auth_spike and keep climbing the score.
                # ML anomalies (ml_anomaly) are also excluded because
                # IsolationForest with contamination=0.08 flags ~8% of
                # normal requests.
                if anomaly.get("threat_type") == "behavior_anomaly":
                    from gateway.detection.account_risk import elevate_account_risk
                    try:
                        await elevate_account_risk(session, user.id, 0.15, ip=ip)
                    except Exception:
                        await session.rollback()
    except Exception as exc:
        logger.warning("Behaviour profiling skipped: %s", exc)


async def _write_audit_log(
    method: str,
    path: str,
    status_code: int,
    event_type: str,
    ip: str,
    user_agent: str,
    user_email: str | None,
    elapsed_ms: int,
) -> None:
    """Write one row to the audit_logs table. Swallows all errors."""
    try:
        details = json.dumps({
            "user": user_email,
            "elapsed_ms": elapsed_ms,
        })
        async with AsyncSessionLocal() as session:
            # Resolve the acting principal. user_id was previously hardcoded to
            # None on every row, so all 10,478 audit_logs rows had no user, the
            # idx_audit_user index was dead, and the audit log could not answer
            # "who did this?" — the one question an audit log exists to answer.
            resolved_user_id = None
            if user_email:
                try:
                    from sqlalchemy import select

                    from gateway.db.models import User
                    resolved_user_id = (await session.execute(
                        select(User.id).where(User.email == user_email)
                    )).scalar_one_or_none()
                except Exception:
                    resolved_user_id = None

            log_entry = AuditLog(
                user_id=resolved_user_id,
                action=f"{method} {path}",
                resource=path,
                method=method,
                status_code=status_code,
                event_type=event_type,
                ip_address=ip,
                user_agent=user_agent,
                details=details,
            )
            session.add(log_entry)
            await session.commit()
    except Exception as e:
        logger.warning("Failed to write audit log: %s", e)
