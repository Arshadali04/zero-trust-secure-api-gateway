"""
gateway/routes/mfa.py
----------------------
TOTP-based Multi-Factor Authentication endpoints.

Flow
----
1. POST /auth/mfa/setup        → generates a secret + provisioning URI (QR data)
2. POST /auth/mfa/verify-setup → confirms the TOTP code and enables MFA on the account
3. POST /auth/mfa/verify       → validates a TOTP code during login (returns new JWT)
4. POST /auth/mfa/disable      → turns off MFA (requires valid TOTP code to prevent lockout)
5. GET  /auth/mfa/status       → returns whether MFA is currently enabled for the user
"""

import logging
import base64
import io

import pyotp
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import timedelta

from gateway.db.database import get_db
from gateway.db.models import User
from gateway.db.schemas import require_authenticated_user, TokenResponse
from gateway.core.security import SecurityManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/mfa", tags=["MFA"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class MFASetupResponse(BaseModel):
    secret: str
    provisioning_uri: str
    qr_code_base64: str   # PNG as base64 — use in <img src="data:image/png;base64,...">


class MFAVerifyRequest(BaseModel):
    code: str             # 6-digit TOTP code


class MFAStatusResponse(BaseModel):
    mfa_enabled: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _generate_qr_base64(provisioning_uri: str) -> str:
    """Return base64-encoded PNG of the QR code, or '' if qrcode not installed."""
    try:
        import qrcode  # type: ignore
        img = qrcode.make(provisioning_uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        logger.warning("qrcode package not installed – QR image unavailable.")
        return ""


def _verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code. Allows ±1 window (30 s clock drift)."""
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception:
        return False


async def _get_user_from_db(email: str, db: AsyncSession) -> User:
    """
    Re-fetch the user from the SAME db session we will commit to.
    This avoids the 'detached instance' / session-mismatch bug where
    require_authenticated_user opens its own session and the mutations
    made via `db` would be invisible.
    """
    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")
    return user


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/status", response_model=MFAStatusResponse)
async def mfa_status(current_user: User = Depends(require_authenticated_user)):
    """Return whether MFA is enabled for the authenticated user."""
    return MFAStatusResponse(mfa_enabled=bool(current_user.mfa_enabled))


@router.post("/setup", response_model=MFASetupResponse)
async def mfa_setup(
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a new TOTP secret and QR code.
    The secret is saved but MFA is NOT activated until /auth/mfa/verify-setup is called.
    """
    # Re-fetch user in THIS session so mutations are tracked correctly
    user = await _get_user_from_db(current_user.email, db)

    if user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled. Disable it first before re-setting up.",
        )

    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=user.email,
        issuer_name="Zero Trust Gateway",
    )

    user.mfa_secret = secret
    await db.commit()

    qr_b64 = _generate_qr_base64(provisioning_uri)
    logger.info("MFA setup initiated for: %s", user.email)

    return MFASetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_code_base64=qr_b64,
    )


@router.post("/verify-setup", status_code=status.HTTP_200_OK)
async def mfa_verify_setup(
    body: MFAVerifyRequest,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Confirm the TOTP code to activate MFA on the account.
    Must be called after /auth/mfa/setup.
    """
    user = await _get_user_from_db(current_user.email, db)

    if not user.mfa_secret:
        raise HTTPException(
            status_code=400,
            detail="MFA setup not initiated. Call /auth/mfa/setup first.",
        )

    if not _verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code. Please try again.")

    user.mfa_enabled = True
    await db.commit()

    logger.info("MFA enabled for: %s", user.email)
    return {"message": "MFA has been successfully enabled on your account."}


@router.post("/verify", response_model=TokenResponse)
async def mfa_verify(
    body: MFAVerifyRequest,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Validate a TOTP code. On success, returns a new JWT with mfa_verified=True.
    Call this after a normal login when MFA is enabled.
    """
    user = await _get_user_from_db(current_user.email, db)

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this account.")

    if not _verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code.")

    token = SecurityManager.create_access_token(
        data={"sub": user.email, "mfa_verified": True},
        expires_delta=timedelta(minutes=30),
    )

    from gateway.db.schemas import UserResponse
    logger.info("MFA verified for: %s", user.email)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=1800,
        user=UserResponse.model_validate(user),
    )


@router.post("/disable", status_code=status.HTTP_200_OK)
async def mfa_disable(
    body: MFAVerifyRequest,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Disable MFA. Requires a valid current TOTP code to prevent accidental lockout.
    """
    user = await _get_user_from_db(current_user.email, db)

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this account.")

    if not _verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code. MFA not disabled.")

    user.mfa_enabled = False
    user.mfa_secret = None
    await db.commit()

    logger.info("MFA disabled for: %s", user.email)
    return {"message": "MFA has been disabled on your account."}
