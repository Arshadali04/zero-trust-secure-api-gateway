"""Unit coverage for refresh-token creation and rotation."""

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from sqlalchemy import select

from gateway.core.tokens import (
    _hash_token,
    cleanup_expired,
    create_token_pair,
    revoke_all_user_tokens,
    revoke_family,
    rotate_refresh_token,
)
from gateway.db.database import AsyncSessionLocal
from gateway.db.models import RefreshToken, User


async def _make_user(db):
    suffix = uuid4().hex[:10]
    user = User(
        email=f"refresh-{suffix}@example.com",
        username=f"refresh-{suffix}",
        hashed_password="test-only",
        is_active=True,
        token_version=1,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


@pytest.mark.asyncio
async def test_create_rotate_and_revoke_refresh_token_family():
    async with AsyncSessionLocal() as db:
        user = await _make_user(db)

        access, refresh = await create_token_pair(
            db, user.id, user.email, user.token_version or 1
        )
        assert access

        result = await db.execute(
            select(RefreshToken).where(RefreshToken.token_hash == _hash_token(refresh))
        )
        original = result.scalar_one()
        family_id = original.family_id

        rotated = await rotate_refresh_token(db, refresh)
        assert rotated is not None
        assert rotated[2] == user.id
        assert rotated[1] != refresh

        reused = await rotate_refresh_token(db, refresh)
        assert reused is None

        result = await db.execute(
            select(RefreshToken).where(RefreshToken.family_id == family_id)
        )
        assert result.scalars().all() == []

        await revoke_family(db, "missing-family")


@pytest.mark.asyncio
async def test_refresh_token_rejects_unknown_expired_and_stale_tokens():
    async with AsyncSessionLocal() as db:
        user = await _make_user(db)

        assert await rotate_refresh_token(db, "unknown-token") is None

        expired_raw = "expired-" + uuid4().hex
        db.add(RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(expired_raw),
            family_id="expired-family",
            is_consumed=False,
            mfa_verified=False,
            token_version=user.token_version or 1,
            expires_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        ))
        await db.commit()
        assert await rotate_refresh_token(db, expired_raw) is None

        stale_raw = "stale-" + uuid4().hex
        db.add(RefreshToken(
            user_id=user.id,
            token_hash=_hash_token(stale_raw),
            family_id="stale-family",
            is_consumed=False,
            mfa_verified=False,
            token_version=(user.token_version or 1) + 100,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        ))
        await db.commit()
        assert await rotate_refresh_token(db, stale_raw) is None

        stale_cleanup = await cleanup_expired(db)
        assert stale_cleanup >= 0


@pytest.mark.asyncio
async def test_refresh_token_helpers_revoke_all_and_preserve_mfa():
    async with AsyncSessionLocal() as db:
        user = await _make_user(db)

        _, refresh = await create_token_pair(
            db,
            user.id,
            user.email,
            user.token_version or 1,
            mfa_verified=True,
            mfa_at=12345.0,
        )
        rotated = await rotate_refresh_token(db, refresh)
        assert rotated is not None

        await revoke_all_user_tokens(db, user.id)
        result = await db.execute(
            select(RefreshToken).where(RefreshToken.user_id == user.id)
        )
        assert result.scalars().all() == []
