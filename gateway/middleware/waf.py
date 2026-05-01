"""
gateway/middleware/waf.py
--------------------------
Web Application Firewall (WAF) middleware.

Scans incoming request paths, query parameters, and JSON bodies for common
attack patterns: SQL Injection, XSS, Path Traversal, Command Injection.

On match:
  - Logs a SecurityEvent to the DB
  - Returns HTTP 400 with a sanitised error message
  - Adds X-WAF-Blocked header to the response

Exempt paths: /docs, /redoc, /openapi.json, /health, /frontend/*, /favicon.ico
"""

import re
import json
import logging
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.db.database import AsyncSessionLocal
from gateway.db.models import SecurityEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

# SQL Injection
_SQLI_PATTERNS = [
    r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|drop\s+table|"
    r"delete\s+from|update\s+.*\s+set|exec\s*\(|execute\s*\(|"
    r"--\s|;\s*drop|;\s*delete|;\s*insert|;\s*update|"
    r"or\s+1\s*=\s*1|and\s+1\s*=\s*1|'\s*or\s+'|'\s*and\s+'|"
    r"benchmark\s*\(|sleep\s*\(|waitfor\s+delay|"
    r"information_schema|pg_sleep|xp_cmdshell)",
]

# Cross-Site Scripting (XSS)
_XSS_PATTERNS = [
    r"(?i)(<script[\s>]|</script>|javascript\s*:|vbscript\s*:|"
    r"on\w+\s*=\s*[\"']?[^\"'>]*[\"']?\s*(?:>|/>)|"
    r"<\s*iframe|<\s*object|<\s*embed|<\s*svg\s+on|"
    r"document\.(cookie|write|location)|window\.(location|open)|"
    r"eval\s*\(|expression\s*\(|alert\s*\(|prompt\s*\(|confirm\s*\()",
]

# Path Traversal
_PATH_TRAVERSAL_PATTERNS = [
    r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%2e\.%2f|"
    r"/etc/passwd|/etc/shadow|/proc/self|\\windows\\system32)",
]

# Command Injection
_CMD_INJECTION_PATTERNS = [
    r"(?i)([`|;&$]\s*(ls|cat|whoami|id|uname|wget|curl|nc|bash|sh|cmd|"
    r"powershell|python|perl|ruby|php)\s*|"
    r"\|\s*\w+|\bping\s+-[nc]\b|\bnslookup\b|\bdig\b)",
]

_ALL_PATTERNS: list[tuple[str, list[str]]] = [
    ("sql_injection",       _SQLI_PATTERNS),
    ("xss",                 _XSS_PATTERNS),
    ("path_traversal",      _PATH_TRAVERSAL_PATTERNS),
    ("command_injection",   _CMD_INJECTION_PATTERNS),
]

# Pre-compile for performance
_COMPILED: list[tuple[str, re.Pattern]] = [
    (name, re.compile("|".join(patterns)))
    for name, patterns in _ALL_PATTERNS
]

# ---------------------------------------------------------------------------
# Paths exempt from WAF scanning
# ---------------------------------------------------------------------------
_EXEMPT_PREFIXES = ("/docs", "/redoc", "/openapi", "/health", "/frontend", "/favicon")


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


def _detect_threat(text: str) -> Optional[str]:
    """Return the threat type name if any pattern matches, else None."""
    for name, pattern in _COMPILED:
        if pattern.search(text):
            return name
    return None


def _get_client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


async def _log_security_event(
    threat_type: str, ip: str, endpoint: str, payload: str, risk_score: float
) -> None:
    """Persist a SecurityEvent row (fire-and-forget)."""
    try:
        async with AsyncSessionLocal() as session:
            event = SecurityEvent(
                threat_type=threat_type,
                ip_address=ip,
                endpoint=endpoint,
                payload=payload[:2000],
                risk_score=risk_score,
                status="blocked",
            )
            session.add(event)
            await session.commit()
    except Exception as exc:
        logger.warning("WAF: failed to write security event: %s", exc)


class WAFMiddleware(BaseHTTPMiddleware):
    """
    Lightweight WAF that checks query params and JSON body for attack patterns.
    Runs before the route handler; blocks and logs malicious requests.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_exempt(path) or request.method == "OPTIONS":
            return await call_next(request)

        ip = _get_client_ip(request)

        # ── 1. Check URL path + query string ─────────────────────────────────
        full_url = str(request.url)
        threat = _detect_threat(full_url)

        # ── 2. Check JSON body (read & cache so route handler can still read it)
        body_text = ""
        if not threat and request.headers.get("content-type", "").startswith("application/json"):
            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="replace")
                threat = _detect_threat(body_text)
                # Re-inject body so downstream can still read it
                # (Starlette caches it internally after first read)
            except Exception:
                pass  # malformed body — let the route handle it

        if threat:
            payload_sample = (full_url + " " + body_text)[:500]
            risk_scores = {
                "sql_injection": 0.9,
                "xss": 0.8,
                "path_traversal": 0.85,
                "command_injection": 0.95,
            }
            score = risk_scores.get(threat, 0.75)

            logger.warning(
                "WAF BLOCKED | threat=%s ip=%s path=%s score=%.2f",
                threat, ip, path, score,
            )

            # Fire-and-forget — don't await so we don't slow the 400 response
            import asyncio
            asyncio.ensure_future(
                _log_security_event(threat, ip, path, payload_sample, score)
            )

            return JSONResponse(
                status_code=400,
                content={
                    "detail": "Request blocked by security policy.",
                    "threat_type": threat,
                },
                headers={"X-WAF-Blocked": threat},
            )

        return await call_next(request)
