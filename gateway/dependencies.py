"""
gateway/dependencies.py
------------------------
FastAPI auth dependencies extracted from schemas.py for clean separation
of concerns. Schemas define data shapes; dependencies enforce access control.
"""

from datetime import datetime, UTC
import logging

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.database import get_db

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)


async def require_authenticated_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: AsyncSession = Depends(get_db)
):
    """
    FastAPI dependency.
    Validates the Bearer token and returns the User ORM object.
    Raises 401 if token is invalid, 403 if account is inactive,
    or 403 if MFA is enabled but the token is not MFA-verified.
    """
    from gateway.core.security import verify_token_for_request
    from gateway.db.models import User

    token = credentials.credentials if credentials else None

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Cached: the logging and risk-scoring middleware have already verified this
    # exact token earlier in the same request. Reusing their result also means
    # this dependency cannot disagree with the audit log about whether the
    # request was authenticated — see verify_token_for_request.
    payload = verify_token_for_request(request, token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    email = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
        )

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account is disabled")

    if int(payload.get("ver", 1) or 1) != int(user.token_version or 1):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been revoked. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        from gateway.detection.account_risk import decay_and_persist
        await decay_and_persist(db, user)
    except Exception as exc:
        # This runs on EVERY authenticated request, and it is the only thing
        # that advances risk decay and re-anchors the step-up cooldown. It used
        # to `pass`, which meant the entire risk engine could be dead — decay
        # frozen, scores stuck at whatever they were, step-up either permanently
        # demanded or permanently not — while every request still returned 200
        # and the dashboard still rendered a risk number. There was no signal
        # anywhere. Log at ERROR: if this fires it fires constantly, and a flood
        # of identical errors is the correct alarm for "a security control
        # stopped running." Deliberately still swallowed rather than raised —
        # a decay failure must not lock every user out of the gateway.
        logger.error(
            "Risk decay failed for user_id=%s (%s: %s) — risk scores are NOT "
            "decaying and step-up state may be stale",
            getattr(user, "id", "?"), type(exc).__name__, exc,
            exc_info=True,
        )

    path = request.url.path

    from gateway.detection.account_risk import is_user_frozen
    from gateway.core.client_ip import get_client_ip
    _freeze_ip = get_client_ip(request)
    if await is_user_frozen(db, user.id, _freeze_ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account frozen from this IP due to critical risk. Try again later.",
            headers={"X-Account-Frozen": "1"},
        )

    if user.mfa_enabled:
        # /auth/me is exempt: the moment a user enables MFA their *existing*
        # access token still carries mfa_verified=False, so the dashboard's
        # /auth/me poll would 403 with mfa_required and log them straight out
        # before they could reach the TOTP prompt. Reading your own profile is
        # not a sensitive action, and every genuinely sensitive path stays gated.
        if path not in (
            "/auth/mfa/verify",
            "/auth/mfa/status",
            "/auth/mfa/disable",
            "/auth/me",
        ):
            if not payload.get("mfa_verified"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="mfa_required"
                )

    if user.stepup_required:
        # The gate used to read `user.stepup_required and user.mfa_enabled`, so
        # for every account without MFA the control was silently inert: risk
        # crossed the threshold, apply_risk_policy set the flag and wrote a
        # "risk_stepup" SecurityEvent, the admin UI showed step-up enforced —
        # and the request sailed through to /api/v1/*. Most accounts in this
        # project have mfa_enabled=False, so "most accounts" was the failure set.
        #
        # A user with no second factor has nothing to step up *to*, so the only
        # honest options are deny or force re-auth. Denying sensitive paths is
        # the conservative choice and it makes the audit event truthful.
        if not user.mfa_enabled:
            from gateway.config import settings as _settings
            sensitive = any(
                path.startswith(p)
                for p in getattr(_settings, "SENSITIVE_PATH_PREFIXES", ["/api/v1", "/admin"])
            )
            if sensitive and not path.startswith(("/auth/mfa", "/auth/me")):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="stepup_required_no_mfa",
                    headers={"X-Risk-Stepup": "1", "X-Stepup-Enroll": "1"},
                )
    if user.stepup_required and user.mfa_enabled:
        from gateway.config import settings as _settings
        sensitive = any(path.startswith(p) for p in getattr(_settings, "SENSITIVE_PATH_PREFIXES", ["/api/v1", "/admin"]))
        stepup_path_ok = path.startswith(("/auth/mfa", "/auth/me"))
        if sensitive and not stepup_path_ok:
            mfa_at = payload.get("mfa_at", 0) or 0
            since_ts = 0.0
            if user.stepup_since:
                try:
                    since = user.stepup_since
                    if isinstance(since, datetime) and since.tzinfo is not None:
                        since = since.replace(tzinfo=None)
                    since_ts = since.replace(tzinfo=UTC).timestamp()
                except Exception:
                    since_ts = 0.0
            if float(mfa_at) < float(since_ts):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="stepup_required",
                    headers={"X-Risk-Stepup": "1"},
                )

    return user


async def require_admin_user(
    user=Depends(require_authenticated_user),
):
    """Enforces role == 'admin'. Raises 403 if the user is not an admin."""
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user


async def require_api_key(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Authenticate a machine client with an X-API-Key header.
    Returns a principal dict: {"mode": "apikey", "user": User, "key": ApiKey, "scopes": list[str]}
    """
    from gateway.db.models import ApiKey, User, SecurityEvent
    from gateway.core.security import hash_api_key
    from gateway.core.apikeys import is_ip_blocked, record_failure, deserialize_scopes

    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required (X-API-Key header)",
        )

    ip = request.client.host if request.client else "unknown"

    if is_ip_blocked(ip):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Too many invalid API key attempts. Please try again later.",
        )

    result = await db.execute(select(ApiKey).where(ApiKey.key_hash == hash_api_key(api_key)))
    key = result.scalar_one_or_none()

    if not key:
        is_now_blocked = record_failure(ip)
        if is_now_blocked:
            try:
                event = SecurityEvent(
                    threat_type="api_key_bruteforce",
                    ip_address=ip,
                    endpoint=request.url.path,
                    payload="Repeated invalid X-API-Key attempts",
                    risk_score=0.85,
                    status="blocked",
                )
                db.add(event)
                await db.commit()
            except Exception:
                await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key",
        )

    if key.revoked_at is not None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key has been revoked",
        )

    if key.expires_at is not None:
        exp = key.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=UTC)
        if exp < datetime.now(UTC):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="API key has expired",
            )

    user_result = await db.execute(select(User).where(User.id == key.user_id))
    user = user_result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="API key owner account is disabled",
        )

    try:
        key.last_used_at = datetime.now(UTC)
        await db.commit()
    except Exception:
        await db.rollback()

    return {
        "mode": "apikey",
        "user": user,
        "key": key,
        "scopes": deserialize_scopes(key.scopes),
    }


async def require_api_key_or_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    db: AsyncSession = Depends(get_db),
):
    """
    Accept either X-API-Key header (machine clients) or Bearer JWT (interactive users).
    Returns a principal dict with mode indicator.
    """
    if request.headers.get("X-API-Key"):
        return await require_api_key(request, db)

    user = await require_authenticated_user(request, credentials, db)
    return {"mode": "jwt", "user": user}
