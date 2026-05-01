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

import json
import logging
import os
import uuid
import time

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response

from gateway.core.security import SecurityManager
from gateway.db.schemas import require_authenticated_user
from gateway.db.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["Proxy"])

# ---------------------------------------------------------------------------
# Upstream route registry
# ---------------------------------------------------------------------------
# Default built-in routes.  Override / extend with PROXY_ROUTES_JSON env var:
#   PROXY_ROUTES_JSON='{"service-a":"http://localhost:8001","service-b":"http://localhost:8002"}'

_DEFAULT_ROUTES: dict[str, str] = {
    "data": "http://127.0.0.1:8001",
}

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


def _get_client_ip(request: Request) -> str:
    fwd = request.headers.get("X-Forwarded-For")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _build_upstream_headers(request: Request, user_email: str, request_id: str) -> dict:
    """Build the header dict to forward to the upstream service."""
    headers = {}
    for k, v in request.headers.items():
        if k.lower() not in _HOP_BY_HOP:
            headers[k] = v

    # Gateway-injected headers
    headers["X-Forwarded-For"] = _get_client_ip(request)
    headers["X-Gateway-User"] = user_email
    headers["X-Request-ID"] = request_id
    headers["X-Forwarded-Host"] = request.headers.get("host", "")
    headers["X-Forwarded-Proto"] = "http"

    return headers


async def _proxy_request(
    method: str,
    upstream_url: str,
    headers: dict,
    params: dict,
    body: bytes,
) -> Response:
    """Forward the request to the upstream and return the response."""
    async with httpx.AsyncClient(timeout=PROXY_TIMEOUT, follow_redirects=True) as client:
        try:
            upstream_resp = await client.request(
                method=method,
                url=upstream_url,
                headers=headers,
                params=params,
                content=body,
            )
        except httpx.TimeoutException:
            raise HTTPException(
                status_code=504,
                detail=f"Upstream service timed out after {PROXY_TIMEOUT}s.",
            )
        except httpx.ConnectError as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not connect to upstream service: {exc}",
            )

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
    current_user: User = Depends(require_authenticated_user),
):
    """
    Reverse proxy endpoint.  Resolves the upstream from UPSTREAM_ROUTES[service],
    strips the /api/v1/{service} prefix, and forwards the call.
    """
    # ── Resolve upstream ──────────────────────────────────────────────────────
    upstream_base = UPSTREAM_ROUTES.get(service)
    if not upstream_base:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown service: '{service}'. "
                   f"Registered services: {list(UPSTREAM_ROUTES.keys()) or ['(none configured)']}",
        )

    # ── Build upstream URL ────────────────────────────────────────────────────
    upstream_url = upstream_base.rstrip("/") + "/" + path.lstrip("/")

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
        raise HTTPException(status_code=502, detail=f"Upstream error: {exc}")

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


# ---------------------------------------------------------------------------
# Management endpoints (admin only)
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
