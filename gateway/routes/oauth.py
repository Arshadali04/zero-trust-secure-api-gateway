import logging
from datetime import datetime, timezone
from urllib.parse import quote

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.config import settings
from gateway.core.client_ip import get_client_ip
from gateway.db.database import get_db
from gateway.db.models import SecurityEvent, User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["OAuth"])

oauth = OAuth()

# ---- Register Google OAuth ----
google_id = settings.GOOGLE_CLIENT_ID
google_secret = settings.GOOGLE_CLIENT_SECRET

if google_id and google_secret:
    oauth.register(
        name="google",
        client_id=google_id,
        client_secret=google_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    logger.info("Google OAuth registered")
else:
    logger.warning("Google OAuth not configured (missing GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET)")

# ---- Register GitHub OAuth ----
github_id = settings.GITHUB_CLIENT_ID
github_secret = settings.GITHUB_CLIENT_SECRET

if github_id and github_secret:
    oauth.register(
        name="github",
        client_id=github_id,
        client_secret=github_secret,
        access_token_url="https://github.com/login/oauth/access_token",
        authorize_url="https://github.com/login/oauth/authorize",
        api_base_url="https://api.github.com/",
        client_kwargs={"scope": "user:email"},
    )
    logger.info("GitHub OAuth registered")
else:
    logger.warning("GitHub OAuth not configured (missing GITHUB_CLIENT_ID/GITHUB_CLIENT_SECRET)")


@router.get("/oauth/login/google")
async def login_google(request: Request):
    """Redirect to Google OAuth"""
    redirect_uri = settings.GOOGLE_REDIRECT_URI
    if not google_id or not google_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")

    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/oauth/login/github")
async def login_github(request: Request):
    """Redirect to GitHub OAuth"""
    redirect_uri = settings.GITHUB_REDIRECT_URI
    if not github_id or not github_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")

    return await oauth.github.authorize_redirect(request, redirect_uri)


async def _check_freeze(request: Request, user: User, db: AsyncSession) -> None:
    """
    Block an OAuth login if the (account, IP) pair is frozen.
    Raises 403 if frozen; otherwise returns None.
    """
    from gateway.core.client_ip import get_client_ip
    from gateway.detection.account_risk import is_user_frozen
    current_ip = get_client_ip(request)
    if await is_user_frozen(db, user.id, current_ip):
        raise HTTPException(
            status_code=403,
            detail="Account frozen from this IP due to critical risk. Try again later.",
            headers={"X-Account-Frozen": "1"},
        )


async def upsert_oauth_user(
    db: AsyncSession,
    *,
    email: str,
    full_name: str | None = None,
    request_ip: str | None = None,
) -> User:
    """
    Create the user if it doesn't exist; otherwise update last_login.
    OAuth users have hashed_password = None.
    """
    result = await db.execute(select(User).where(User.email == email))
    existing = result.scalar_one_or_none()

    now = datetime.now(timezone.utc)

    if existing:
        # ── Account-linking gate (H1) ────────────────────────────────────────
        # Matching on email alone and attaching the OAuth identity with no
        # confirmation is a takeover primitive, because registration has no
        # email-verification step: an attacker can register victim@corp.com
        # locally (proving nothing), set a password, and wait. When the victim
        # clicks "Sign in with Google" they land in the attacker's row, and the
        # attacker's password keeps working alongside the victim's sessions.
        #
        # The complete fix is verified-email-on-registration, which needs mail
        # delivery this project does not have (tracked as Phase 9 List B work).
        # What is enforced here instead:
        #   - operators can refuse auto-linking outright via OAUTH_ALLOW_AUTOLINK
        #   - when it is allowed, the first link to a password-bearing account is
        #     recorded as a high-severity SecurityEvent and raises account risk,
        #     so a silent takeover becomes a loud, auditable, visible one.
        first_link = existing.hashed_password is not None and not bool(
            getattr(existing, "oauth_linked", False)
        )
        if first_link and not getattr(settings, "OAUTH_ALLOW_AUTOLINK", True):
            raise HTTPException(
                status_code=409,
                detail=(
                    "An account with this email already has a password. Sign in with "
                    "your password first, then link this provider from your profile."
                ),
            )
        if first_link:
            logger.warning(
                "OAuth identity linked to an existing PASSWORD account: %s "
                "(auto-link is enabled; this is a takeover vector without email verification)",
                email,
            )
            try:
                db.add(SecurityEvent(
                    threat_type="oauth_account_link",
                    ip_address=(request_ip or "unknown"),
                    endpoint="/auth/oauth/callback",
                    payload=f"email={email} linked_to_local_password_account=1",
                    risk_score=0.5,
                    status="flagged",
                ))
            except Exception as exc:
                logger.warning("Could not record oauth_account_link event: %s", exc)

        # oauth_linked is a declared column on User, so this assignment cannot
        # raise. It was previously wrapped in `try/except Exception: pass`,
        # which caught nothing and hid the only case that matters: if the
        # database column is missing, the failure surfaces as an OperationalError
        # at flush, not here. `_apply_column_migrations` adds it on startup.
        existing.oauth_linked = True
        existing.last_login = now
        if full_name and not existing.full_name:
            existing.full_name = full_name
        await db.commit()
        await db.refresh(existing)
        return existing

    username = email.split("@")[0]

    new_user = User(
        email=email,
        username=username,
        full_name=full_name,
        hashed_password=None,  # OAuth-only
        is_active=True,
        role="user",
        last_login=now,
        # Set in the constructor rather than assigned afterwards inside a
        # `try/except Exception: pass`. That guard could not fire — oauth_linked
        # is a declared column — and a missing database column would surface as
        # an OperationalError at flush regardless.
        oauth_linked=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.get("/callback/google")
async def callback_google(request: Request, db: AsyncSession = Depends(get_db)):
    """Google OAuth callback"""
    frontend_base = settings.FRONTEND_BASE_URL.rstrip("/") + "/frontend/login.html?r=1"

    try:
        token = await oauth.google.authorize_access_token(request)

        # Authlib often places userinfo here when using OIDC metadata
        user = token.get("userinfo")

        # Fallback: fetch userinfo endpoint if missing
        if not user:
            resp = await oauth.google.get("userinfo", token=token)
            user = resp.json()

        email = (user or {}).get("email")
        full_name = (user or {}).get("name")

        if not email:
            return RedirectResponse(url=f"{frontend_base}#error=no_email", status_code=302)

        # Upsert user in DB + update last_login
        user_db = await upsert_oauth_user(
            db, email=email, full_name=full_name,
            request_ip=get_client_ip(request),
        )

        # ── Critical-risk freeze (same enforcement as password login) ────────
        await _check_freeze(request, user_db, db)

        # Check MFA
        mfa_req = "false"
        mfa_ver = True
        if user_db.mfa_enabled:
            mfa_req = "true"
            mfa_ver = False

        # A refresh token is issued here too (M13). Previously the OAuth paths
        # minted an access token only, so a Google/GitHub user was hard-logged-out
        # 30 minutes in with no silent-refresh path — the frontend's refresh flow
        # had no token to present. mfa_verified is threaded through so a step-up
        # is not silently granted by the rotation.
        from gateway.core.tokens import create_token_pair

        jwt_token, oauth_refresh = await create_token_pair(
            db,
            user_db.id,
            email,
            user_db.token_version or 1,
            mfa_verified=mfa_ver,
        )
        logger.info("Google OAuth successful for: %s", email)

        response = RedirectResponse(
            url=(
                f"{frontend_base}#token={jwt_token}&refresh_token={quote(oauth_refresh)}"
                f"&user={quote(email)}&mfa_required={mfa_req}"
            ),
            status_code=302,
        )
        response.headers["X-Audit-User"] = email
        return response

    except HTTPException as e:
        logger.warning("Google OAuth blocked: %s", e.detail)
        code = "oauth_blocked"
        detail = str(e.detail or "OAuth login blocked.")
        if (e.status_code == 403 and "frozen" in detail.lower()) or (e.headers or {}).get("X-Account-Frozen") == "1":
            code = "account_frozen"
            detail = "Account frozen due to suspicious behavior. Please try again after 1 hour."
        return RedirectResponse(
            url=f"{frontend_base}#error={code}&msg={quote(detail)}",
            status_code=302,
        )
    except Exception as e:
        logger.error("Google callback error: %s", str(e))
        return RedirectResponse(
            url=f"{frontend_base}#error=oauth_failed&msg={quote(str(e))}",
            status_code=302,
        )


@router.get("/callback/github")
async def callback_github(request: Request, db: AsyncSession = Depends(get_db)):
    """GitHub OAuth callback"""
    frontend_base = settings.FRONTEND_BASE_URL.rstrip("/") + "/frontend/login.html?r=1"

    try:
        token = await oauth.github.authorize_access_token(request)

        # Get basic user info
        resp = await oauth.github.get("user", token=token)
        user_info = resp.json()

        # GitHub's "login" (username) is deliberately not read: upsert_oauth_user
        # takes email and full_name only, so the value was assigned and dropped.
        full_name = user_info.get("name")

        # Email may be null depending on GitHub privacy settings
        email = user_info.get("email")

        if not email:
            resp = await oauth.github.get("user/emails", token=token)
            emails = resp.json()
            primary = next(
                (e for e in emails if e.get("primary") and e.get("verified")),
                None,
            )
            if primary:
                email = primary.get("email")

        if not email:
            return RedirectResponse(
                url=f"{frontend_base}#error=no_email&msg=GitHub account has no verified email. Please add/verify an email in GitHub or make it public, then try again.",
                status_code=302,
            )
        # Upsert user in DB + update last_login
        user_db = await upsert_oauth_user(
            db, email=email, full_name=full_name,
            request_ip=get_client_ip(request),
        )

        # ── Critical-risk freeze (same enforcement as password login) ────────
        await _check_freeze(request, user_db, db)

        # Check MFA
        mfa_req = "false"
        mfa_ver = True
        if user_db.mfa_enabled:
            mfa_req = "true"
            mfa_ver = False

        # A refresh token is issued here too (M13). Previously the OAuth paths
        # minted an access token only, so a Google/GitHub user was hard-logged-out
        # 30 minutes in with no silent-refresh path — the frontend's refresh flow
        # had no token to present. mfa_verified is threaded through so a step-up
        # is not silently granted by the rotation.
        from gateway.core.tokens import create_token_pair

        jwt_token, oauth_refresh = await create_token_pair(
            db,
            user_db.id,
            email,
            user_db.token_version or 1,
            mfa_verified=mfa_ver,
        )
        logger.info("GitHub OAuth successful for: %s", email)

        return RedirectResponse(
            url=(
                f"{frontend_base}#token={jwt_token}&refresh_token={quote(oauth_refresh)}"
                f"&user={quote(email)}&mfa_required={mfa_req}"
            ),
            status_code=302,
        )

    except HTTPException as e:
        logger.warning("GitHub OAuth blocked: %s", e.detail)
        code = "oauth_blocked"
        detail = str(e.detail or "OAuth login blocked.")
        if (e.status_code == 403 and "frozen" in detail.lower()) or (e.headers or {}).get("X-Account-Frozen") == "1":
            code = "account_frozen"
            detail = "Account frozen due to suspicious behavior. Please try again after 1 hour."
        return RedirectResponse(
            url=f"{frontend_base}#error={code}&msg={quote(detail)}",
            status_code=302,
        )
    except Exception as e:
        logger.error("GitHub callback error: %s", str(e))
        return RedirectResponse(
            url=f"{frontend_base}#error=oauth_failed&msg={quote(str(e))}",
            status_code=302,
        )
