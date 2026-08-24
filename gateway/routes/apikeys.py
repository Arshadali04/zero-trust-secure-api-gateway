"""
gateway/routes/apikeys.py
--------------------------
API Key management endpoints.

All endpoints require JWT user authentication (the keys are owned by a user).

Security model
--------------
  - Keys are stored as SHA-256 hashes. The full plaintext key is returned
    exactly once (at creation / rotation).
  - Keys have scopes ("all" or "proxy:<service>") enforced at the proxy.
  - Keys support optional expiry and manual revoke / rotate.
"""

from datetime import datetime, timedelta, UTC
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.security import generate_api_key
from gateway.core.apikeys import serialize_scopes, deserialize_scopes
from gateway.db.database import get_db
from gateway.db.models import ApiKey, User
from gateway.db.schemas import (
    ApiKeyCreate,
    ApiKeyUpdate,
    ApiKeyResponse,
    ApiKeyCreated,
)
from gateway.dependencies import require_authenticated_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api-keys", tags=["API Keys"])


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_owned_key(key_id: int, user: User, db: AsyncSession) -> ApiKey:
    result = await db.execute(
        select(ApiKey).where(ApiKey.id == key_id, ApiKey.user_id == user.id)
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="API key not found")
    return key


def _to_response(key: ApiKey) -> ApiKeyResponse:
    return ApiKeyResponse(
        id=key.id,
        name=key.name,
        key_prefix=key.key_prefix,
        scopes=deserialize_scopes(key.scopes),
        last_used_at=key.last_used_at,
        expires_at=key.expires_at,
        revoked_at=key.revoked_at,
        created_at=key.created_at,
    )


def _to_created(key: ApiKey, plaintext: str) -> ApiKeyCreated:
    base = _to_response(key)
    return ApiKeyCreated(**base.model_dump(), key=plaintext)


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: ApiKeyCreate,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new API key. The full plaintext key is shown exactly once."""
    # Prevent duplicate active key names per user
    existing = await db.execute(
        select(ApiKey).where(
            ApiKey.user_id == current_user.id,
            ApiKey.name == payload.name,
            ApiKey.revoked_at.is_(None),
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=400,
            detail=f"An active key named '{payload.name}' already exists. Choose a different name or revoke the existing key first.",
        )

    prefix, plaintext, key_hash = generate_api_key()

    expires_at = None
    if payload.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=payload.expires_in_days)

    key = ApiKey(
        user_id=current_user.id,
        name=payload.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=serialize_scopes(payload.scopes),
        expires_at=expires_at,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    logger.info("API key created: user=%s name=%s id=%s", current_user.email, key.name, key.id)
    return _to_created(key, plaintext)


@router.get("", response_model=list[ApiKeyResponse])
async def list_api_keys(
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """List the current user's API keys (never returns the keys themselves)."""
    result = await db.execute(
        select(ApiKey)
        .where(ApiKey.user_id == current_user.id)
        .order_by(ApiKey.created_at.desc())
    )
    return [_to_response(k) for k in result.scalars().all()]


@router.get("/{key_id}", response_model=ApiKeyResponse)
async def get_api_key(
    key_id: int,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch one API key's metadata (never returns the key itself).

    This route was missing: the collection had POST and GET, and the item had
    PATCH, revoke and rotate, but no plain GET. A request for a single key
    therefore matched the PATCH path and returned 405 Method Not Allowed, not
    404 — which is what tests/integration/test_api_keys.py's
    test_nonexistent_key_returns_404 was catching. _get_owned_key raises 404 for
    both a missing id and one owned by another user, so an id cannot be probed
    for existence across accounts.
    """
    key = await _get_owned_key(key_id, current_user, db)
    return _to_response(key)


@router.patch("/{key_id}", response_model=ApiKeyResponse)
async def update_api_key(
    key_id: int,
    payload: ApiKeyUpdate,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Rename an API key and/or update its scopes."""
    key = await _get_owned_key(key_id, current_user, db)
    if payload.name is not None:
        key.name = payload.name
    if payload.scopes is not None:
        key.scopes = serialize_scopes(payload.scopes)
    await db.commit()
    await db.refresh(key)
    return _to_response(key)


@router.post("/{key_id}/revoke", response_model=ApiKeyResponse)
async def revoke_api_key(
    key_id: int,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Revoke an API key immediately. Revoked keys are rejected at the proxy."""
    key = await _get_owned_key(key_id, current_user, db)
    key.revoked_at = datetime.now(UTC)
    await db.commit()
    await db.refresh(key)
    logger.info("API key revoked: user=%s key_id=%s", current_user.email, key.id)
    return _to_response(key)


@router.post("/{key_id}/rotate", response_model=ApiKeyCreated)
async def rotate_api_key(
    key_id: int,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Rotate an API key: revoke the old key and issue a fresh one with the
    same name, scopes, and expiry. The new plaintext is shown exactly once.
    """
    old_key = await _get_owned_key(key_id, current_user, db)

    # Revocation has to be terminal. Without this check, an admin revoking a
    # leaked key achieved nothing: whoever held the plaintext could POST
    # /rotate and receive a brand-new *active* key with identical scopes and
    # expiry, undoing the revocation from the attacker's side.
    if old_key.revoked_at is not None:
        raise HTTPException(
            status_code=400,
            detail="This key has been revoked and cannot be rotated. Create a new key instead.",
        )
    if old_key.expires_at is not None:
        exp = old_key.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        if exp < datetime.now(UTC):
            raise HTTPException(
                status_code=400,
                detail="This key has expired and cannot be rotated. Create a new key instead.",
            )

    prefix, plaintext, key_hash = generate_api_key()
    new_key = ApiKey(
        user_id=current_user.id,
        name=old_key.name,
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=old_key.scopes,
        expires_at=old_key.expires_at,
    )

    old_key.revoked_at = datetime.now(UTC)
    db.add(new_key)
    await db.commit()
    await db.refresh(new_key)

    logger.info(
        "API key rotated: user=%s old_id=%s new_id=%s",
        current_user.email, old_key.id, new_key.id,
    )
    return _to_created(new_key, plaintext)
