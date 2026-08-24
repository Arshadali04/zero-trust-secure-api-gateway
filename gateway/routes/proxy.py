"""
gateway/routes/proxy.py
------------------------
Reverse Proxy Engine.

Routes incoming authenticated requests to registered upstream services.
Configuration is done via environment variables or the PROXY_ROUTES dict below.

URL mapping (configurable via .env PROXY_ROUTES_JSON):
  /api/v1/service-a/* → http://localhost:8001
  /api/v1/service-b/* → http://localhost:8002
  … etc.

Features
--------
- JWT authentication required (Bearer token) for all proxy routes
- Strips the /api/v1/{service} prefix and forwards the remaining path
- Forwards: original method, headers (with Authorization), query params, body
- Injects: X-Forwarded-For, X-Gateway-User (email from JWT), X-Request-ID
- Streams the upstream response back to the caller
- Logs every proxy call to the audit log
- Returns 502 on upstream failure, 504 on timeout
"""

import ipaddress
import json
import logging
import os
import socket
import uuid
import time
from urllib.parse import urlparse as _urlparse

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from gateway.core.client_ip import get_client_ip
from gateway.dependencies import require_authenticated_user, require_api_key_or_user
from gateway.core.apikeys import scopes_allow
from gateway.db.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Proxy"])

# ---------------------------------------------------------------------------
# Upstream route registry
# ---------------------------------------------------------------------------
# Default built-in routes.  Override / extend with PROXY_ROUTES_JSON env var:
#   PROXY_ROUTES_JSON='{"service-a":"http://localhost:8001","service-b":"http://localhost:8002"}'

# Empty on purpose: the services table is the only authority on what this
# gateway will proxy to.
#
# This used to hold {"data": "http://127.0.0.1:8001"}, which made deleting a
# service fail to revoke it. delete_service (routes/services.py:221) is a hard
# `db.delete`, so after a delete there is no row, _db_entry_found stays False,
# and the lookup below fell through to this dict — /api/v1/data/* kept proxying
# with 200 forever. tests/e2e/test_full_flow.py:152 asserts 404 after a delete
# and was catching exactly that. The _db_entry_found guard already blocked the
# inactive/orphaned cases; a hard delete was the hole it could not see.
#
# For local demos, add the route back through the env var rather than here, so
# it is a deployment choice and not baked into the image:
#   PROXY_ROUTES_JSON='{"data":"http://127.0.0.1:8001"}'
# Or just register it once at runtime: POST /services.
_DEFAULT_ROUTES: dict[str, str] = {}

def _load_routes() -> dict[str, str]:
    raw = os.getenv("PROXY_ROUTES_JSON", "")
    if raw:
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {**_DEFAULT_ROUTES, **parsed}
        except json.JSONDecodeError:
            logger.warning("PROXY_ROUTES_JSON is invalid JSON — using default routes only.")
    return _DEFAULT_ROUTES.copy()


UPSTREAM_ROUTES: dict[str, str] = _load_routes()

# Timeout for upstream calls
PROXY_TIMEOUT = float(os.getenv("PROXY_TIMEOUT_SECONDS", "30"))

# Headers we strip before forwarding (hop-by-hop)
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade", "host",
}


def _build_upstream_headers(request: Request, user_email: str, request_id: str, path: str = "") -> dict:
    """Build the header dict to forward to the upstream service."""
    headers = {}
    for k, v in request.headers.items():
        if k.lower() not in _HOP_BY_HOP:
            headers[k] = v

    headers["X-Forwarded-For"] = get_client_ip(request)
    headers["X-Gateway-User"] = user_email
    headers["X-Request-ID"] = request_id
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    headers["X-Forwarded-Proto"] = "http"

    # HMAC request signing (zero-trust upstream verification)
    from gateway.core.request_signing import sign_request
    sig_headers = sign_request(request.method, path or request.url.path, user_email, request_id)
    headers.update(sig_headers)

    return headers


async def _proxy_request(
    method: str,
    upstream_url: str,
    headers: dict,
    params: dict,
    body: bytes,
) -> Response:
    """Forward the request to the upstream and return the response."""
    async with httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=False) as client:
        try:
            upstream_resp = await client.request(
                method=method,
                url=upstream_url,
                headers=headers,
                params=params,
                content=body,
            )
        except httpx.TimeoutException:
            # from None: the timeout carries nothing the detail does not already
            # say, and chaining it only adds noise to the server traceback.
            raise HTTPException(
                status_code=504,
                detail=f"Upstream service timed out after {PROXY_TIMEOUT}s.",
            ) from None
        except httpx.ConnectError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not connect to upstream service: {exc}",
            ) from exc

    # Build a FastAPI Response from the upstream response
    # Strip hop-by-hop headers from upstream reply
    response_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in _HOP_BY_HOP
    }
    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type", "application/octet-stream"),
    )


# ---------------------------------------------------------------------------
# Management endpoints (admin only)
# IMPORTANT: must be registered BEFORE the catch-all /{service}/{path:path}
# route below, otherwise FastAPI will match e.g. _gateway/routes as a
# service named "_gateway" and the admin handler is never reached.
# ---------------------------------------------------------------------------

@router.get(
    "/_gateway/routes",
    tags=["Admin"],
    summary="List registered proxy routes",
)
async def list_routes(current_user: User = Depends(require_authenticated_user)):
    """Return the currently registered upstream service map. Admin only."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required.")
    return {
        "routes": UPSTREAM_ROUTES,
        "proxy_timeout_seconds": PROXY_TIMEOUT,
        "total": len(UPSTREAM_ROUTES),
    }


# ---------------------------------------------------------------------------
# Dynamic catch-all proxy route
# ---------------------------------------------------------------------------

@router.api_route(
    "/{service}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
    summary="Authenticated reverse proxy",
    description=(
        "Forwards any authenticated request to the registered upstream service. "
        "Requires a valid Bearer JWT token."
    ),
)
async def proxy(
    service: str,
    path: str,
    request: Request,
    principal: dict = Depends(require_api_key_or_user),
):
    """
    Reverse proxy endpoint.  Resolves the upstream from UPSTREAM_ROUTES[service],
    strips the /api/v1/{service} prefix, and forwards the call.

    Accepts either:
      - X-API-Key header (machine clients, scope-enforced), or
      - Bearer JWT (interactive users, full access).
    """
    # ── Resolve user + scope enforcement ──────────────────────────────────────
    current_user: User = principal["user"]

    if principal["mode"] == "apikey":
        scopes = principal.get("scopes", [])
        if not scopes_allow(scopes, service):
            raise HTTPException(
                status_code=403,
                detail=(
                    f"API key not authorized for service '{service}'. "
                    f"Required scope: proxy:{service}"
                ),
            )

    # ── Resolve upstream ──────────────────────────────────────────────────────
    # Check the DB first: user-registered services take precedence over the
    # built-in static demo routes.  This ensures that deleting a DB service
    # actually blocks proxy access even when a static fallback exists.
    upstream_base = None
    _db_entry_found = False

    from gateway.db.database import AsyncSessionLocal
    from gateway.db.models import Service
    from sqlalchemy import select as sa_select

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                sa_select(Service).where(Service.name == service)
            )
            svc = result.scalar_one_or_none()
            if svc is not None:
                _db_entry_found = True
                # Ownership check. The schema has no ForeignKeys, so deleting a
                # user historically left their `services` row behind and any
                # authenticated caller could keep routing traffic through the
                # deleted account's registered upstream. delete_user now purges
                # those rows, but older databases already contain orphans, so
                # refuse to route for an owner that no longer exists.
                owner_ok = True
                if getattr(svc, "owner_user_id", None) is not None:
                    from gateway.db.models import User as _User
                    owner = await session.execute(
                        sa_select(_User.id).where(_User.id == svc.owner_user_id)
                    )
                    owner_ok = owner.scalar_one_or_none() is not None
                    if not owner_ok:
                        logger.warning(
                            "Proxy refused service '%s': owner_user_id=%s no longer exists "
                            "(orphaned upstream %s)",
                            service, svc.owner_user_id, svc.upstream_url,
                        )
                if owner_ok and bool(svc.is_active):
                    upstream_base = svc.upstream_url
                # else: inactive, deleted, or orphaned → block even if a static route exists
    except Exception as exc:
        logger.warning("Proxy DB lookup failed for service '%s': %s", service, exc)

    # Fall back to static demo routes only if the service has never been
    # registered in the DB (i.e., no DB entry at all).
    if upstream_base is None and not _db_entry_found:
        upstream_base = UPSTREAM_ROUTES.get(service)

    if not upstream_base:
        # Deliberately does not enumerate the services table: that would let any
        # authenticated caller inventory every registered upstream from a single
        # 404. UPSTREAM_ROUTES only ever holds statically configured routes, and
        # is normally empty now.
        raise HTTPException(
            status_code=404,
            detail=f"Unknown or unavailable service: '{service}'. "
                   f"Register it via POST /services.",
        )

    # ── Build upstream URL ────────────────────────────────────────────────────
    upstream_url = upstream_base.rstrip("/") + "/" + path.lstrip("/")

    # ── SSRF guard: resolve and validate upstream target ──────────────────────
    from gateway.config import settings as _cfg

    _parsed = _urlparse(upstream_url)
    _host = _parsed.hostname or ""

    try:
        _resolved = socket.getaddrinfo(_host, _parsed.port or 80)
    except socket.gaierror:
        raise HTTPException(
            status_code=502,
            detail=f"SSRF blocked: cannot resolve upstream host '{_host}'",
        ) from None

    _ip = ipaddress.ip_address(_resolved[0][4][0])

    if not getattr(_cfg, "ALLOW_UPSTREAM_PRIVATE", False):
        if _ip.is_private or _ip.is_loopback or _ip.is_link_local or _ip.is_reserved:
            raise HTTPException(
                status_code=403,
                detail=f"SSRF blocked: upstream resolves to private/reserved address {_ip}",
            )
    else:
        if _ip.is_link_local or _ip.is_reserved:
            raise HTTPException(
                status_code=403,
                detail=f"SSRF blocked: upstream resolves to link-local/reserved address {_ip}",
            )

    # ── Request metadata ──────────────────────────────────────────────────────
    request_id = str(uuid.uuid4())
    start = time.monotonic()

    headers = _build_upstream_headers(request, current_user.email, request_id)

    # Query params (forward as-is)
    params = dict(request.query_params)

    # Body (read once)
    body = await request.body()

    logger.info(
        "PROXY → %s %s [user=%s rid=%s]",
        request.method, upstream_url, current_user.email, request_id,
    )

    # ── Forward ───────────────────────────────────────────────────────────────
    try:
        response = await _proxy_request(
            method=request.method,
            upstream_url=upstream_url,
            headers=headers,
            params=params,
            body=body,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Proxy unexpected error for %s", upstream_url)
        raise HTTPException(status_code=502, detail=f"Upstream error: {exc}") from exc

    elapsed_ms = int((time.monotonic() - start) * 1000)

    logger.info(
        "PROXY ← %s %s [status=%s elapsed=%dms rid=%s]",
        request.method, upstream_url, response.status_code, elapsed_ms, request_id,
    )

    # Add gateway metadata headers to the response
    response.headers["X-Gateway-Request-ID"] = request_id
    response.headers["X-Gateway-Elapsed-Ms"] = str(elapsed_ms)
    response.headers["X-Gateway-Service"] = service

    return response
