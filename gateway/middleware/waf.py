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

# SSRF — Server-Side Request Forgery: private/loopback addresses and dangerous protocols
# Detects attempts to access internal infrastructure via proxy / URL parameters.
_SSRF_PATTERNS = [
    r"(?i)(file://|dict://|gopher://|tftp://|ldap://|ftp://|phar://|data://|php://|"
    r"localhost|127\.0\.0\.1|0\.0\.0\.0|::1|\[::1\]|"
    r"169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"metadata\.google\.internal|169\.254\.169\.254)",
]

# XXE — XML External Entity injection
# Detects DOCTYPE/ENTITY declarations used to exfiltrate files or SSRF.
_XXE_PATTERNS = [
    r"(?i)(<!ENTITY\s|SYSTEM\s+[\"']|PUBLIC\s+[\"']|<!DOCTYPE[^>]*\[|\]\s*>|%[a-z]+;)",
]

# LDAP Injection — filter manipulation in LDAP queries
_LDAP_PATTERNS = [
    r"(?i)(\*\)\(|\(\||\(&|\)\(|\\28|\\29|"
    r"\(objectClass=\*\)|cn=[^,]+,|uid=[^,]+,|ou=[^,]+,|dc=[^,]+,)",
]

# Prototype Pollution — JavaScript object prototype overwrite
_PROTO_POLLUTION_PATTERNS = [
    r"(__proto__|constructor\s*\[\s*[\"']?prototype[\"']?\s*\]|prototype\s*\.\s*\w+\s*=)",
]

_ALL_PATTERNS: list[tuple[str, list[str]]] = [
    ("sql_injection",       _SQLI_PATTERNS),
    ("xss",                 _XSS_PATTERNS),
    ("path_traversal",      _PATH_TRAVERSAL_PATTERNS),
    ("command_injection",   _CMD_INJECTION_PATTERNS),
    ("ssrf",                _SSRF_PATTERNS),
    ("xxe",                 _XXE_PATTERNS),
    ("ldap_injection",      _LDAP_PATTERNS),
    ("prototype_pollution", _PROTO_POLLUTION_PATTERNS),
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
    "ssrf": 0.88,
    "xxe": 0.90,
    "ldap_injection": 0.82,
    "prototype_pollution": 0.75,
}

# Human-readable labels for each threat type (used in frontend displays)
THREAT_LABELS = {
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting",
    "path_traversal": "Path Traversal",
    "command_injection": "Command Injection",
    "ssrf": "Server-Side Request Forgery",
    "xxe": "XML External Entity",
    "ldap_injection": "LDAP Injection",
    "prototype_pollution": "Prototype Pollution",
    "failed_login": "Brute-Force Login",
    "ml_anomaly": "ML Anomaly",
    "high_risk_request": "High Risk Request",
    "impossible_travel": "Impossible Travel",
    "rapid_ip_change": "Rapid IP Change",
}

# ---------------------------------------------------------------------------
# Paths exempt from WAF scanning
# ---------------------------------------------------------------------------
_EXEMPT_PREFIXES = (
    "/docs", "/redoc", "/openapi", "/health", "/frontend", "/favicon",
    "/metrics",
    "/auth/oauth", "/auth/callback",  # OAuth login + callback must never be WAF-blocked
)


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in _EXEMPT_PREFIXES)


# Patterns that are ONLY scanned in request bodies and query parameters,
# NOT in the URL path or browser navigation headers. SSRF patterns match
# private IPs/protocols that would produce false positives when the WAF scans
# the request URL scheme/host or browser CORS headers (Origin / Referer),
# which legitimately contain the server's own address (e.g. http://127.0.0.1:8000).
_BODY_ONLY_THREATS = {"ssrf", "xxe", "prototype_pollution"}


def _detect_threat(text: str) -> str | None:
    """Return the threat type name if any pattern matches, else None.

    Scans ALL compiled patterns including body-only ones. Use this for
    request bodies and query parameter values.
    """
    for name, pattern in _COMPILED:
        if pattern.search(text):
            return name
    return None


def _detect_url_threat(path_and_query: str) -> str | None:
    """Scan only the URL path + query string (excluding scheme and host).

    SSRF/XXE/prototype-pollution patterns are excluded here because:
    - SSRF patterns match private IPs/protocols that appear in the server's
      own hostname (http://127.0.0.1:8000/...) causing false positives.
    - XXE patterns may appear in URL-encoded params legitimately.
    - These attack classes are better detected in the request body.
    """
    for name, pattern in _COMPILED:
        if name in _BODY_ONLY_THREATS:
            continue
        if pattern.search(path_and_query):
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
        # Scan only the path + query string (NOT the full URL including scheme
        # and host). The full URL always contains the server's own address
        # (e.g. http://127.0.0.1:8000/...) which would false-positive on SSRF
        # patterns. Path-only threats are detected via _detect_url_threat, while
        # explicit query parameters (e.g. ?url=http://127.0.0.1...) are also
        # scanned for SSRF/XXE attacks.
        path_and_query = unquote_plus(path)
        qs = str(request.url.query)
        if qs:
            path_and_query = path_and_query + "?" + unquote_plus(qs)
        threat = _detect_url_threat(path_and_query)

        # Scan query string for full threats (including SSRF, XXE parameters)
        if not threat and qs:
            threat = _detect_threat(unquote_plus(qs))

        # ── 2. Check HTTP headers for attack patterns ────────────────────────
        # Headers like User-Agent, Referer, Cookie, X-Forwarded-For are scanned
        # for injection patterns (SQLi, XSS, Path Traversal, Command Injection).
        # We do NOT scan Origin or Referer for SSRF, as local navigation
        # legitimately references localhost/127.0.0.1.
        if not threat:
            for header_name in _HEADERS_ALWAYS_SCANNED:
                header_value = request.headers.get(header_name, "")
                if header_value:
                    threat = _detect_url_threat(header_value)
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

        # ── Threat found → block, log, return 403 ────────────────────────────
        if threat:
            score = RISK_SCORES.get(threat, 0.75)
            # Build payload sample from decoded path/query + body excerpt
            payload_sample = (path_and_query + " " + body_text)[:500]

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
