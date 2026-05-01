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

import time
import logging
import json

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.database import AsyncSessionLocal
from gateway.db.models import AuditLog
from gateway.core.security import SecurityManager

logger = logging.getLogger(__name__)

# Paths we don't bother logging
SKIP_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/", "/favicon.ico"}


def _get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _extract_user_email(request: Request) -> str | None:
    """Extract user email from JWT if present in Authorization header."""
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):]
    try:
        payload = SecurityManager.verify_token(token)
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
        ip = _get_client_ip(request)
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

        return response


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
            log_entry = AuditLog(
                user_id=None,
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
