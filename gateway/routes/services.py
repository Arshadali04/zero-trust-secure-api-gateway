"""
gateway/routes/services.py
--------------------------
Service registration endpoints.

Developers register their backend services here so the proxy can forward
traffic dynamically. This is what turns the gateway from a single-app tool
into a multi-tenant API gateway (similar to Cloudflare or AWS API Gateway).
"""

import ipaddress
import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.database import get_db
from gateway.db.models import Service, User
from gateway.db.schemas import ServiceCreate, ServiceResponse, ServiceUpdate
from gateway.dependencies import require_authenticated_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/services", tags=["Services"])


# ── Helpers ──────────────────────────────────────────────────────────────────

def _validate_upstream_url(url: str) -> None:
    """Reject upstream URLs that point to loopback, private, or reserved IPs.

    This prevents Server-Side Request Forgery (SSRF) — an attacker could
    otherwise register an upstream_url pointing at cloud metadata endpoints
    (169.254.169.254), internal admin panels, or other services.
    """
    from gateway.config import settings as _settings
    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid upstream URL format.") from None

    if parsed.scheme not in ("http", "https"):
        raise HTTPException(
            status_code=400,
            detail=f"Upstream URL scheme must be http or https, got '{parsed.scheme}'.",
        )

    hostname = parsed.hostname or ""
    if not hostname:
        raise HTTPException(status_code=400, detail="Upstream URL must include a hostname.")

    # Block obviously dangerous targets regardless of settings.
    _BLOCKED_HOSTS = {"169.254.169.254", "metadata.google.internal", "0.0.0.0"}
    if hostname in _BLOCKED_HOSTS:
        raise HTTPException(
            status_code=400,
            detail=f"Upstream hostname '{hostname}' is blocked for security reasons.",
        )

    # Try to resolve to an IP and check against private ranges.
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is a domain name — try to resolve it.
        import socket
        try:
            resolved = socket.getaddrinfo(hostname, None)
            ip = ipaddress.ip_address(resolved[0][4][0])
        except (socket.gaierror, IndexError, ValueError):
            raise HTTPException(
                status_code=400,
                detail=f"Could not resolve upstream hostname '{hostname}'.",
            ) from None

    if ip.is_loopback and not getattr(_settings, "ALLOW_UPSTREAM_PRIVATE", True):
        raise HTTPException(status_code=400, detail="Upstream URL must not target loopback (127.x.x.x / ::1).")
    if ip.is_link_local:
        raise HTTPException(status_code=400, detail="Upstream URL must not target link-local addresses (169.254.x.x / fe80::).")
    if ip.is_reserved:
        raise HTTPException(status_code=400, detail=f"Upstream IP {ip} is a reserved address.")
    if not getattr(_settings, "ALLOW_UPSTREAM_PRIVATE", True) and ip.is_private:
        raise HTTPException(
            status_code=400,
            detail=f"Upstream IP {ip} is in a private range. Set ALLOW_UPSTREAM_PRIVATE=true for local dev.",
        )


async def _get_owned_service(service_id: int, user: User, db: AsyncSession) -> Service:
    result = await db.execute(
        select(Service).where(Service.id == service_id, Service.owner_user_id == user.id)
    )
    svc = result.scalar_one_or_none()
    if not svc:
        raise HTTPException(status_code=404, detail="Service not found")
    return svc


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("", response_model=ServiceResponse, status_code=status.HTTP_201_CREATED)
async def register_service(
    payload: ServiceCreate,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Register a new backend service that can be accessed via /api/v1/{name}/*."""
    slug = payload.name.lower().strip()
    _validate_upstream_url(payload.upstream_url)
    if not slug.isalnum() and "-" not in slug and "_" not in slug:
        raise HTTPException(status_code=400, detail="Service name may only contain letters, digits, hyphens, and underscores.")

    # Block only ACTIVE duplicate names — a deactivated/deleted service name can be reused
    existing = await db.execute(
        select(Service).where(Service.name == slug, Service.is_active.is_(True))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"A service named '{slug}' is already active. Choose a different name or delete the existing service.")

    svc = Service(
        owner_user_id=current_user.id,
        name=slug,
        upstream_url=payload.upstream_url,
        description=payload.description,
    )
    db.add(svc)
    await db.commit()
    await db.refresh(svc)
    logger.info("Service registered: name=%s owner=%s url=%s", slug, current_user.email, payload.upstream_url)
    return svc


@router.get("", response_model=list[ServiceResponse])
async def list_my_services(
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """List services owned by the current user."""
    result = await db.execute(
        select(Service)
        .where(Service.owner_user_id == current_user.id)
        .order_by(Service.created_at.desc())
    )
    return result.scalars().all()


@router.patch("/{service_id}", response_model=ServiceResponse)
async def update_service(
    service_id: int,
    payload: ServiceUpdate,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Update a service's configuration (name, URL, description, active status)."""
    svc = await _get_owned_service(service_id, current_user, db)

    if payload.name is not None:
        new_slug = payload.name.lower().strip()
        dup = await db.execute(select(Service).where(Service.name == new_slug, Service.id != service_id))
        if dup.scalar_one_or_none():
            raise HTTPException(status_code=400, detail=f"Service name '{new_slug}' is already taken.")
        svc.name = new_slug

    if payload.upstream_url is not None:
        _validate_upstream_url(payload.upstream_url)
        svc.upstream_url = payload.upstream_url
    if payload.description is not None:
        svc.description = payload.description
    if payload.is_active is not None:
        svc.is_active = payload.is_active

    await db.commit()
    await db.refresh(svc)
    return svc


@router.post("/{service_id}/revoke", response_model=ServiceResponse)
async def revoke_service(
    service_id: int,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Deactivate a registered service (no new traffic will be forwarded)."""
    svc = await _get_owned_service(service_id, current_user, db)
    svc.is_active = False
    await db.commit()
    await db.refresh(svc)
    logger.info("Service deactivated: name=%s owner=%s", svc.name, current_user.email)
    return svc


@router.post("/{service_id}/reactivate", response_model=ServiceResponse)
async def reactivate_service(
    service_id: int,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Re-activate a previously revoked service."""
    svc = await _get_owned_service(service_id, current_user, db)
    svc.is_active = True
    await db.commit()
    await db.refresh(svc)
    return svc


@router.delete("/{service_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_service(
    service_id: int,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Permanently delete a registered service (and its registration)."""
    svc = await _get_owned_service(service_id, current_user, db)
    await db.delete(svc)
    await db.commit()
    logger.info("Service deleted: name=%s owner=%s", svc.name, current_user.email)
    return None
