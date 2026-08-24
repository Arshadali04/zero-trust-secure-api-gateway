from datetime import datetime, timedelta, UTC
import logging

from fastapi import APIRouter, HTTPException, status, Depends, Response, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.security import SecurityManager
# Module level, not inside a function: reset_password (line ~330) calls this
# and had no import in scope, so the handler raised NameError before reaching
# db.commit(). The password change and token_version bump were pending in the
# session at that point, so the request 500'd and the reset silently did
# nothing. Introduced by the C1 fix in ac54438; no test covers that branch.
from gateway.core.tokens import revoke_all_user_tokens
from gateway.config import settings
from gateway.db.database import get_db
from gateway.db.models import User, PasswordReset, SecurityEvent
from gateway.db.schemas import (
    UserCreate,
    UserResponse,
    TokenResponse,
    LoginRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest
)
import secrets

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, response: Response, db: AsyncSession = Depends(get_db)):
    # email exists?
    result = await db.execute(select(User).where(User.email == user_data.email))
    existing_user = result.scalar_one_or_none()
    if existing_user:
        if existing_user.hashed_password is not None:
            raise HTTPException(status_code=400, detail="Email already registered")

        result = await db.execute(
            select(User).where(
                User.username == user_data.username,
                User.email != user_data.email,
            )
        )
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Username already taken")

        # Allow completing an OAuth-created account with a local password so the
        # same user can sign in with either method.
        existing_user.username = user_data.username
        existing_user.full_name = user_data.full_name
        existing_user.hashed_password = SecurityManager.hash_password(user_data.password)
        existing_user.is_active = True
        existing_user.last_login = datetime.now(UTC)

        await db.commit()
        await db.refresh(existing_user)
        response.headers["X-Audit-User"] = existing_user.email
        return existing_user

    # username exists?
    result = await db.execute(select(User).where(User.username == user_data.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Username already taken")

    hashed_password = SecurityManager.hash_password(user_data.password)
    new_user = User(
        email=user_data.email,
        username=user_data.username,
        full_name=user_data.full_name,
        hashed_password=hashed_password,
        is_active=True,
        role="user",
        last_login=datetime.now(UTC),
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    response.headers["X-Audit-User"] = new_user.email
    return new_user


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, response: Response, request: Request, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not bool(user.is_active):
        raise HTTPException(status_code=403, detail="User account is disabled")

    # ── Critical-risk freeze (account-wide) ──────────────────────────────────────
    # When account risk reaches CRITICAL threshold (0.85), freeze for 1 hour.
    from gateway.detection.account_risk import is_user_frozen
    from gateway.core.client_ip import get_client_ip
    current_ip = get_client_ip(request)
    if await is_user_frozen(db, user.id, current_ip):
        # Calculate time remaining until thaw
        freeze_until = user.account_frozen_until
        if freeze_until and freeze_until.tzinfo is None:
            freeze_until = freeze_until.replace(tzinfo=UTC)
        now_utc = datetime.now(UTC)
        remaining_seconds = int((freeze_until - now_utc).total_seconds()) if freeze_until else 0
        minutes = max(1, remaining_seconds // 60)

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Account frozen due to critical security risk. Please try again in {minutes} minute{'s' if minutes != 1 else ''}.",
            headers={"X-Account-Frozen": "1", "X-Freeze-Until": str(freeze_until)},
        )

    if user.hashed_password is None:
        raise HTTPException(
            status_code=400,
            detail="This account uses Google/GitHub sign-in. Please sign in with OAuth or reset your password.",
        )

    if not SecurityManager.verify_password(payload.password, str(user.hashed_password)):
        # ── Brute-force detection ─────────────────────────────────────────────
        # Feed the behavior engine so >5 failed attempts/min trips an
        # auth_spike behavior anomaly, and persist a security event so the
        # Attack Lab's brute-force attack shows up in the admin view.
        try:
            from gateway.detection.behavior import record_failed_auth
            record_failed_auth(user.id)
            db.add(SecurityEvent(
                threat_type="failed_login",
                ip_address=request.client.host if request.client else "unknown",
                endpoint="/auth/login",
                payload=f"email={payload.email}",
                risk_score=0.35,
                status="flagged",
            ))
            await db.commit()
        except Exception:
            await db.rollback()
        raise HTTPException(status_code=401, detail="Invalid email or password")

    # ── Context validation: impossible travel detection ────────────────────────
    from gateway.detection.context_validation import check_impossible_travel

    ip = get_client_ip(request)

    # Capture the PREVIOUS login timestamp before overwriting it. Assigning
    # user.last_login first meant SQLAlchemy's autoflush/identity map handed the
    # new value straight back to check_impossible_travel, so its "elapsed since
    # last login" was always ~0 and the 24-hour suppression window could never
    # apply — a login from a new region was flagged as impossible travel even if
    # the previous login was years earlier.
    previous_login = user.last_login

    try:
        travel_check = await check_impossible_travel(
            user.id, ip, db, previous_login=previous_login
        )
        if travel_check:
            event = SecurityEvent(
                threat_type=travel_check["threat_type"],
                ip_address=ip,
                endpoint="/auth/login",
                # `detail` states the measurement and `method` states whether it
                # came from GeoIP or the degraded fallback. The old payload
                # recorded `distance=0.58`, a unitless octet-arithmetic figure
                # that could not be acted on and implied a precision the check
                # did not have.
                payload=(
                    f"method={travel_check['method']} "
                    f"last_ip={travel_check['last_ip']} "
                    f"current_ip={travel_check['current_ip']} "
                    f"{travel_check['detail']}"
                ),
                risk_score=travel_check["risk_score"],
                status="flagged",
            )
            db.add(event)

            # Persistent account risk. Degraded-mode flags carry a smaller
            # elevation: `rapid_ip_change` is a weaker signal than a measured
            # impossible journey, and 0.25 on a weak signal is what walks an
            # ordinary user into step-up MFA and eventually a one-hour freeze.
            from gateway.detection.account_risk import elevate_account_risk
            elevation = 0.25 if travel_check["method"] == "geoip" else 0.12
            try:
                await elevate_account_risk(db, user.id, elevation, ip=ip)
            except Exception as exc:
                # The rollback here is load-bearing but was also destructive: it
                # discards the SecurityEvent added above, so a failure to raise
                # the risk score silently threw away the record of the detection
                # as well. Re-add the event after the rollback so the flag
                # survives even when the elevation does not.
                logger.error(
                    "Could not elevate account risk after an impossible-travel "
                    "flag for user_id=%s (%s: %s) — re-recording the event so "
                    "the detection is not lost",
                    user.id, type(exc).__name__, exc, exc_info=True,
                )
                await db.rollback()
                db.add(SecurityEvent(
                    threat_type=travel_check["threat_type"],
                    ip_address=ip,
                    endpoint="/auth/login",
                    payload=(
                        f"method={travel_check['method']} "
                        f"last_ip={travel_check['last_ip']} "
                        f"current_ip={travel_check['current_ip']} "
                        f"{travel_check['detail']} (risk elevation failed)"
                    ),
                    risk_score=travel_check["risk_score"],
                    status="flagged",
                ))
    except Exception as exc:
        logger.warning("Impossible travel check failed: %s", exc)

    # Both timestamps are written only after the check has consumed the previous
    # values, so last_login/last_login_ip always describe the *current* login.
    user.last_login = datetime.now(UTC)
    user.last_login_ip = ip

    # Decay the stored risk score before returning it so the login response
    # shows the same value as /auth/me (which decays on every read).
    try:
        from gateway.detection.account_risk import decay_and_persist
        await decay_and_persist(db, user)
    except Exception as exc:
        # Same control as dependencies.py, on the login path. Silent failure
        # here meant the risk_score returned in the login response could be a
        # stale un-decayed value while /auth/me showed a decayed one, and the
        # inconsistency looked like a frontend caching bug rather than a
        # backend error. Still swallowed — a decay failure must not block login.
        logger.error(
            "Risk decay failed during login for user_id=%s (%s: %s) — the "
            "risk_score in this response is un-decayed",
            getattr(user, "id", "?"), type(exc).__name__, exc, exc_info=True,
        )

    await db.commit()

    response.headers["X-Audit-User"] = user.email

    # Issue token pair (access + refresh) with rotation support
    from gateway.core.tokens import create_token_pair

    access_token, refresh_token_val = await create_token_pair(
        db,
        user.id,
        user.email,
        user.token_version or 1,
        mfa_verified=False,
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token_val,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": UserResponse.model_validate(user).model_dump(),
        "mfa_required": bool(user.mfa_enabled),
    }


@router.post("/forgot-password")
async def forgot_password(payload: ForgotPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    # We always return success to prevent email enumeration
    if not user:
        return {"message": "If that email is in our database, a reset link has been generated."}

    if user.hashed_password is None:
        return {"message": "If that email is in our database, a reset link has been generated."}

    # Generate token and save it
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(UTC) + timedelta(hours=1)

    # In a real app, delete old tokens for this user first
    await db.execute(PasswordReset.__table__.delete().where(PasswordReset.email == payload.email))

    reset_entry = PasswordReset(
        email=payload.email,
        token=token,
        expires_at=expires_at
    )
    db.add(reset_entry)
    await db.commit()

    # In a real app we would send an email here.
    # For now, we will just log it so the user can click. In production, use your domain name. For local demo, we point to the FastAPI served frontend.
    reset_link = f"http://127.0.0.1:8000/frontend/reset-password.html#token={token}"
    logger.info("=======================================================")
    logger.info(f"PASSWORD RESET LINK FOR {payload.email}:")
    logger.info(reset_link)
    logger.info("=======================================================")

    return {"message": "If that email is in our database, a reset link has been generated."}


@router.post("/reset-password")
async def reset_password(payload: ResetPasswordRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(PasswordReset).where(PasswordReset.token == payload.token)
    )
    reset_entry = result.scalar_one_or_none()

    if not reset_entry:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    # SQLite stores naive datetimes — normalise to aware (UTC) before comparing
    reset_exp = reset_entry.expires_at
    if reset_exp.tzinfo is None:
        reset_exp = reset_exp.replace(tzinfo=UTC)
    if reset_exp < datetime.now(UTC):
        await db.delete(reset_entry)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")

    # Find user and update password
    user_result = await db.execute(select(User).where(User.email == reset_entry.email))
    user = user_result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=400, detail="User not found.")

    user.hashed_password = SecurityManager.hash_password(payload.new_password)
    # Revoke every outstanding session for this account. token_version kills
    # outstanding access tokens; refresh tokens are not version-bound, so they
    # must be deleted explicitly or a stolen refresh token survives the reset.
    user.token_version = (user.token_version or 1) + 1
    await revoke_all_user_tokens(db, user.id)

    # Clean up token
    await db.delete(reset_entry)
    await db.commit()

    return {"message": "Password successfully reset. You can now log in."}


@router.post("/refresh")
async def refresh_token(request: Request, db: AsyncSession = Depends(get_db)):
    """
    Exchange a valid refresh token for a new (access_token, refresh_token) pair.
    Implements token rotation with reuse detection.
    """
    from gateway.core.tokens import rotate_refresh_token

    body = await request.json()
    refresh = body.get("refresh_token")
    if not refresh:
        raise HTTPException(status_code=400, detail="refresh_token is required")

    result = await rotate_refresh_token(db, refresh)
    if not result:
        raise HTTPException(
            status_code=401,
            detail="Invalid, expired, or reused refresh token. Please sign in again.",
        )

    access_token, new_refresh, user_id = result
    return {
        "access_token": access_token,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    }


@router.post("/logout")
async def logout(request: Request, db: AsyncSession = Depends(get_db)):
    """Revoke the refresh token family (if provided) and clear the session."""
    from gateway.core.tokens import revoke_all_user_tokens
    from gateway.core.security import verify_token_for_request

    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token = auth[len("Bearer "):]
        payload = verify_token_for_request(request, token)
        if payload:
            from gateway.db.models import User
            email = payload.get("sub")
            if email:
                result = await db.execute(select(User).where(User.email == email))
                user = result.scalar_one_or_none()
                if user:
                    await revoke_all_user_tokens(db, user.id)
                    # Bump token_version so outstanding access tokens are
                    # immediately rejected — not just refresh tokens.
                    user.token_version = (user.token_version or 1) + 1
                    await db.commit()

    return {"message": "Logged out successfully."}
