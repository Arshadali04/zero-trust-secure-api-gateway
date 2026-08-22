"""
gateway/core/tokens.py
-----------------------
JWT refresh token rotation with reuse detection.

Security properties:
  - Access tokens are short-lived (30 min default)
  - Refresh tokens are long-lived (7 days) but single-use
  - Each refresh produces a new (access, refresh) pair
  - Reuse of a consumed refresh token invalidates the entire family
    (detects token theft)
  - Refresh tokens are stored hashed (SHA-256) in the DB
"""

import hashlib
import secrets
import logging
from datetime import datetime, timedelta, UTC

from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

# RefreshToken and User both live in gateway.db.models — that module is the one
# place the schema is declared. Imported at module level rather than inside each
# function: gateway/db/ imports nothing from gateway/core/, so there is no cycle
# to dodge. Re-exporting RefreshToken from this module is deliberate and
# load-bearing — migrations/versions/a3536f8a2d84_initial_schema.py registers
# the table via `import gateway.core.tokens`, and that must keep working.
from gateway.db.models import RefreshToken, User
from gateway.core.security import SecurityManager
from gateway.config import settings

logger = logging.getLogger(__name__)

REFRESH_TOKEN_BYTES = 48
REFRESH_TOKEN_EXPIRE_DAYS = 7


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


async def create_token_pair(
    db: AsyncSession,
    user_id: int,
    email: str,
    token_version: int,
    *,
    mfa_verified: bool = False,
    mfa_at: float | None = None,
    family_id: str | None = None,
) -> tuple[str, str]:
    """
    Create a new (access_token, refresh_token) pair.
    If family_id is None, starts a new token family.
    """
    access_token = SecurityManager.create_user_token(
        email,
        token_version,
        mfa_verified=mfa_verified,
        mfa_at=mfa_at,
        expires_delta=timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    refresh_raw = generate_refresh_token()
    refresh_hash = _hash_token(refresh_raw)

    if not family_id:
        family_id = secrets.token_urlsafe(32)

    expires_at = datetime.now(UTC) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    rt = RefreshToken(
        user_id=user_id,
        token_hash=refresh_hash,
        family_id=family_id,
        is_consumed=False,
        mfa_verified=mfa_verified,
        mfa_at=mfa_at,
        token_version=token_version,
        expires_at=expires_at,
    )
    db.add(rt)
    await db.commit()

    return access_token, refresh_raw


async def rotate_refresh_token(
    db: AsyncSession,
    refresh_token: str,
) -> tuple[str, str, int] | None:
    """
    Consume the given refresh token and issue a new pair.

    Returns (access_token, new_refresh_token, user_id) or None if invalid.

    Reuse detection: if the token was already consumed, the entire family
    is revoked (token theft scenario).
    """
    token_hash = _hash_token(refresh_token)

    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    rt = result.scalar_one_or_none()

    if not rt:
        return None

    # Reuse detection — token already consumed means theft
    if rt.is_consumed:
        logger.warning(
            "REFRESH TOKEN REUSE DETECTED: family=%s user=%s — revoking entire family",
            rt.family_id, rt.user_id,
        )
        await db.execute(
            delete(RefreshToken).where(RefreshToken.family_id == rt.family_id)
        )
        # Deleting the family stops further refreshes, but the thief may still
        # hold an unexpired access token (up to ACCESS_TOKEN_EXPIRE_MINUTES).
        # Bump token_version so those die immediately too — confirmed theft is
        # exactly the case where a hard cut-off is warranted.
        user_result = await db.execute(select(User).where(User.id == rt.user_id))
        victim = user_result.scalar_one_or_none()
        if victim:
            victim.token_version = (victim.token_version or 1) + 1
            logger.warning(
                "Bumped token_version for user=%s to invalidate outstanding "
                "access tokens after refresh-token reuse", rt.user_id,
            )
        await db.commit()
        return None

    # Check expiry
    exp = rt.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    if exp < datetime.now(UTC):
        await db.delete(rt)
        await db.commit()
        return None

    # Look up the user BEFORE consuming, so a version mismatch does not burn
    # the token (the caller gets a clean 401 and can re-authenticate).
    user_result = await db.execute(select(User).where(User.id == rt.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        return None

    # Version binding: any operation that bumped users.token_version after this
    # refresh token was issued (password change, reset, risk auto-logout) must
    # invalidate it. Without this check the bump revokes access tokens only,
    # and a stolen refresh token still mints valid new ones.
    issued_version = int(rt.token_version or 1)
    current_version = int(user.token_version or 1)
    if issued_version != current_version:
        logger.warning(
            "Refresh token rejected: stale token_version (issued=%s current=%s) "
            "user=%s family=%s", issued_version, current_version,
            rt.user_id, rt.family_id,
        )
        await db.execute(
            delete(RefreshToken).where(RefreshToken.family_id == rt.family_id)
        )
        await db.commit()
        return None

    # Mark as consumed
    rt.is_consumed = True
    await db.commit()

    # Issue new pair in the same family, preserving the MFA state from the
    # original token. Never silently promote mfa_verified=False → True here;
    # that would allow MFA bypass by refreshing instead of completing TOTP.
    access_token, new_refresh = await create_token_pair(
        db,
        user.id,
        user.email,
        current_version,
        mfa_verified=bool(rt.mfa_verified),
        mfa_at=rt.mfa_at,
        family_id=rt.family_id,
    )

    return access_token, new_refresh, user.id


async def revoke_family(db: AsyncSession, family_id: str) -> None:
    """Revoke all tokens in a family (used on logout / password change)."""
    await db.execute(
        delete(RefreshToken).where(RefreshToken.family_id == family_id)
    )
    await db.commit()


async def revoke_all_user_tokens(db: AsyncSession, user_id: int) -> None:
    """Revoke all refresh tokens for a user (password change, account freeze)."""
    await db.execute(
        delete(RefreshToken).where(RefreshToken.user_id == user_id)
    )
    await db.commit()


async def cleanup_expired(db: AsyncSession) -> int:
    """Remove expired refresh tokens. Call periodically."""
    now = datetime.now(UTC)
    result = await db.execute(
        delete(RefreshToken).where(RefreshToken.expires_at < now)
    )
    await db.commit()
    return result.rowcount or 0
