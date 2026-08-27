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

Status codes
------------
A rejected TOTP code returns **400**, not 401. See `_INVALID_CODE_STATUS` below —
this is a deliberate, load-bearing choice, not an oversight.
"""

import base64
import io
import logging
from datetime import UTC, datetime

import pyotp
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.config import settings
from gateway.db.database import get_db
from gateway.db.models import User
from gateway.db.schemas import TokenResponse, UserResponse
from gateway.dependencies import require_authenticated_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/mfa", tags=["MFA"])


# ---------------------------------------------------------------------------
# Why a bad TOTP code is 400 and not 401
# ---------------------------------------------------------------------------
# `/verify` and `/disable` used to return 401 for a wrong code while
# `/verify-setup` returned 400. The obvious tidy-up is to standardise on 401 —
# "authentication failed" reads correct in isolation. It is the wrong call here,
# and the reason is in the client.
#
# frontend/js/api.js:85 intercepts *every* 401 globally, before the calling
# page's own catch block ever runs. On 401 it calls _tryRefresh(); the refresh
# token is perfectly valid (the session is fine — only the second factor was
# wrong), so the refresh succeeds and api.js re-issues the identical request via
# `return this.request(...)`. Same wrong code, another 401, another refresh.
# Neither api.js nor _tryRefresh has a once-only guard, despite the comment
# there claiming one, so a single mistyped digit becomes an unbounded recursion
# that rotates the refresh-token family on every iteration.
#
# It does not even fail closed: the `if (token)` logout branch is unreachable
# while refresh keeps succeeding. All four callers — login.js:140, stepup.js:97,
# profile.js:329, profile.js:359 — are written to catch the error and show an
# inline "Invalid code" message, and with 401 none of those catch blocks ever
# run. The user sees a button stuck on "Verifying…" forever. login.js has also
# swapped localStorage.token for a temp token by that point and restores it in
# the catch, so the loop leaves token state corrupted too.
#
# The session is valid; the submitted code is bad input. 400 is both the honest
# status and the one that makes every existing client handler work as written.
# Whoever revisits this: fix the missing retry guard in api.js *first*, or these
# will regress together.
_INVALID_CODE_STATUS = status.HTTP_400_BAD_REQUEST


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
    """Verify a TOTP code. Allows ±1 window (30 s clock drift).

    A wrong code does not raise — pyotp compares strings and returns False. So
    anything that *does* raise here is structural, not user error, and the two
    realistic causes both need a human:

    * a stored `mfa_secret` that is not valid base32 (pyotp raises
      binascii.Error, a ValueError subclass);
    * pyotp itself missing or broken.

    Either way every code fails forever, which locks the account owner out of
    `/disable` as much as `/verify` — they cannot turn off the factor they can
    no longer satisfy. The previous `except Exception: return False` reported
    that as an ordinary bad code, so the only symptom was a user insisting their
    authenticator was correct. Log it at ERROR; still return False, because
    failing closed on a broken second factor is right.
    """
    try:
        return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)
    except Exception as exc:
        logger.error(
            "TOTP verification raised %s: %s — a wrong code returns False "
            "without raising, so this means the stored mfa_secret is corrupt or "
            "pyotp is broken. The owner can neither verify NOR disable MFA "
            "until an operator intervenes.",
            type(exc).__name__, exc, exc_info=True,
        )
        return False


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
#
# On the removal of `_get_user_from_db`:
#
# Every endpoint below used to re-SELECT the user by email into `db` before
# mutating it, justified by a docstring claiming require_authenticated_user
# "opens its own session" so mutations through `db` would be invisible. That
# claim is false. `require_authenticated_user` takes `db: AsyncSession =
# Depends(get_db)` — the same dependency the routes declare — and FastAPI
# caches sub-dependency results per request (`use_cache=True` by default), so
# the dependency and the route are handed the *same* AsyncSession. `current_user`
# is therefore already in that session's identity map, and assigning to it is
# tracked by the `db.commit()` these handlers already call.
#
# So the re-fetch bought nothing and cost one extra SELECT on each of four
# endpoints. Its "User not found" (401) and "Account is disabled" (403) branches
# were unreachable too: require_authenticated_user raises both, with the same
# codes, before the handler body runs.
#
# The invariant to preserve if this is ever refactored: the authn dependency and
# the route must share one session. If require_authenticated_user is ever
# changed to open its own (e.g. AsyncSessionLocal() directly), these handlers
# must go back to re-fetching — the mutations really would be lost.


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
    user = current_user

    if user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
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
    user = current_user

    if not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA setup not initiated. Call /auth/mfa/setup first.",
        )

    if not _verify_totp(user.mfa_secret, body.code):
        raise HTTPException(
            status_code=_INVALID_CODE_STATUS,
            detail="Invalid TOTP code. Please try again.",
        )

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
    Validate a TOTP code. On success, returns a new (access, refresh) pair
    with mfa_verified=True so subsequent token rotations preserve that state.
    """
    user = current_user

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled for this account.",
        )

    if not _verify_totp(user.mfa_secret, body.code):
        raise HTTPException(status_code=_INVALID_CODE_STATUS, detail="Invalid TOTP code.")

    # Successful re-verification clears any outstanding step-up demand.
    if user.stepup_required or user.stepup_since:
        user.stepup_required = False
        user.stepup_since = None
        await db.commit()
        logger.info("Step-up demand cleared for: %s", user.email)

    mfa_ts = datetime.now(UTC).timestamp()

    # Issue a new token pair so the refresh token also carries mfa_verified=True.
    # This prevents MFA bypass via refresh: the new refresh token will propagate
    # mfa_verified=True on all future rotations.
    from gateway.core.tokens import create_token_pair
    access_token, refresh_token_val = await create_token_pair(
        db,
        user.id,
        user.email,
        user.token_version or 1,
        mfa_verified=True,
        mfa_at=mfa_ts,
    )

    logger.info("MFA verified for: %s", user.email)
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token_val,
        token_type="bearer",
        # Was hardcoded to 1800. ACCESS_TOKEN_EXPIRE_MINUTES is what actually
        # governs the token's exp claim, so the literal agreed with reality only
        # while the setting stayed at its default of 30. Deploy with a different
        # value and every client that schedules its refresh off expires_in
        # refreshes at the wrong time — too late means a window of 401s.
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
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
    user = current_user

    if not user.mfa_enabled or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled for this account.",
        )

    if not _verify_totp(user.mfa_secret, body.code):
        raise HTTPException(
            status_code=_INVALID_CODE_STATUS,
            detail="Invalid TOTP code. MFA not disabled.",
        )

    user.mfa_enabled = False
    user.mfa_secret = None
    await db.commit()

    logger.info("MFA disabled for: %s", user.email)
    return {"message": "MFA has been disabled on your account."}
