"""
gateway/middleware/waf.py
--------------------------
Web Application Firewall (WAF) middleware.

Scans incoming request paths, query parameters, JSON bodies, AND HTTP
headers for common attack patterns: SQL Injection, XSS, Path Traversal,
Command Injection.

On match:
  - Logs a SecurityEvent to the DB (awaited — guaranteed write)
  - Returns HTTP 400 with a sanitised error message
  - Adds X-WAF-Blocked header to the response

Exempt paths: /docs, /redoc, /openapi.json, /health, /frontend/*, /favicon.ico
"""

import logging
import re
from urllib.parse import unquote_plus

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from gateway.core.client_ip import get_client_ip
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
    r"(?i)([`|;&$]\s*(ls|cat|rm|mv|cp|chmod|chown|whoami|id|uname|wget|curl|nc|bash|sh|cmd|"
    r"powershell|python|perl|ruby|php)\s*|"
    r"\|\s*\w+|\bping\s+-[nc]\b|\bnslookup\b|\bdig\b|;\s*rm\s+-[rf])",
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

# Risk scores per threat type (used by RiskScoring and displayed in admin)
RISK_SCORES = {
    "sql_injection": 0.9,
    "xss": 0.8,
    "path_traversal": 0.85,
    "command_injection": 0.95,
}

# ---------------------------------------------------------------------------
# Paths exempt from WAF scanning
# ---------------------------------------------------------------------------
_EXEMPT_PREFIXES = (
    "/docs", "/redoc", "/openapi", "/health", "/frontend", "/favicon",
    "/auth/oauth", "/auth/callback",  # OAuth login + callback must never be WAF-blocked
)


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


def _detect_threat(text: str) -> str | None:
    """Return the threat type name if any pattern matches, else None."""
    for name, pattern in _COMPILED:
        if pattern.search(text):
            return name
    return None


# ---------------------------------------------------------------------------
# Security event logging (awaited, not fire-and-forget)
# ---------------------------------------------------------------------------


async def _log_security_event(
    threat_type: str, ip: str, endpoint: str, payload: str, risk_score: float
) -> None:
    """Persist a SecurityEvent row. Called with await so we know it succeeded."""
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


# ---------------------------------------------------------------------------
# Headers we always scan for threats (even when content-type isn't JSON)
# ---------------------------------------------------------------------------
_HEADERS_ALWAYS_SCANNED = (
    "user-agent",
    "referer",
    "x-forwarded-for",
    "cookie",
)


class WAFMiddleware(BaseHTTPMiddleware):
    """
    Lightweight WAF that inspects:
      1. URL path + query string
      2. JSON body
      3. HTTP headers (User-Agent, Referer, X-Forwarded-For, Cookie)

    Runs before the route handler; blocks and logs malicious requests.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        if _is_exempt(path) or request.method == "OPTIONS":
            return await call_next(request)

        ip = get_client_ip(request)
        threat = None

        # ── 1. Check URL path + query string ─────────────────────────────────
        # URL-decode so patterns like `union\s+select` match even when the
        # attacker sends `union%20select` (percent-encoded).
        full_url = unquote_plus(str(request.url))
        threat = _detect_threat(full_url)

        # ── 2. Check HTTP headers for attack patterns ────────────────────────
        if not threat:
            for header_name in _HEADERS_ALWAYS_SCANNED:
                header_value = request.headers.get(header_name, "")
                if header_value:
                    threat = _detect_threat(header_value)
                    if threat:
                        break

        # ── 3. Check JSON body ───────────────────────────────────────────────
        body_text = ""
        if not threat and request.headers.get("content-type", "").startswith("application/json"):
            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="replace")
                threat = _detect_threat(body_text)
            except Exception as exc:
                # A body we cannot read is a body we cannot inspect, so the
                # request continues to the route with NO WAF coverage of its
                # payload. That used to happen in total silence: a client that
                # aborted mid-body, or any transport hiccup, produced an
                # uninspected request indistinguishable from a clean one. The
                # request is still allowed through (failing closed here would
                # reject legitimate large or slow uploads and hand an attacker a
                # trivial denial-of-service), but it is now recorded so a run of
                # these is visible instead of invisible.
                logger.warning(
                    "WAF could not read request body — payload NOT inspected. "
                    "ip=%s path=%s content-length=%s (%s: %s)",
                    ip, path, request.headers.get("content-length", "?"),
                    type(exc).__name__, exc,
                )

        # ── Threat found → block, log, return 400 ────────────────────────────
        if threat:
            score = RISK_SCORES.get(threat, 0.75)
            payload_sample = (full_url + " " + body_text)[:500]

            logger.warning(
                "WAF BLOCKED | threat=%s ip=%s path=%s score=%.2f",
                threat, ip, path, score,
            )

            # Await the DB write so we're sure the event is persisted
            await _log_security_event(threat, ip, path, payload_sample, score)

            # Auto-block IPs that repeatedly trigger the WAF
            try:
                from gateway.middleware.ip_blocker import auto_block_ip, record_waf_hit
                if record_waf_hit(ip):
                    await auto_block_ip(
                        ip,
                        reason=f"WAF auto-block: {threat} triggered {5}+ times in {120}s",
                    )
            except Exception as exc:
                # Swallowing this silently meant the escalation step — the one
                # that turns "we blocked this request" into "we blocked this
                # source" — could fail on every hit and never be noticed. The
                # per-request 403s keep appearing, so the WAF looks like it is
                # working, while a repeat attacker is never actually banned.
                logger.error(
                    "WAF auto-block FAILED for ip=%s threat=%s (%s: %s) — this "
                    "IP will keep being allowed to retry",
                    ip, threat, type(exc).__name__, exc, exc_info=True,
                )

            return JSONResponse(
                status_code=403,
                content={
                    "detail": "Request blocked by security policy.",
                    "threat_type": threat,
                    "risk_score": score,
                },
                headers={
                    "X-WAF-Blocked": threat,
                    "X-WAF-Risk-Score": str(score),
                },
            )

        return await call_next(request)
