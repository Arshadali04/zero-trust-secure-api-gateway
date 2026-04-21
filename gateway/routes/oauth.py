from datetime import datetime, timedelta
import logging
import os

from authlib.integrations.starlette_client import OAuth
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request
from starlette.responses import RedirectResponse

from gateway.core.security import SecurityManager
from gateway.db.database import get_db
from gateway.db.models import User

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["OAuth"])

oauth = OAuth()

# ---- Register Google OAuth ----
google_id = os.getenv("GOOGLE_CLIENT_ID")
google_secret = os.getenv("GOOGLE_CLIENT_SECRET")

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
github_id = os.getenv("GITHUB_CLIENT_ID")
github_secret = os.getenv("GITHUB_CLIENT_SECRET")

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
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI")
    if not google_id or not google_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="Google OAuth not configured")

    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/oauth/login/github")
async def login_github(request: Request):
    """Redirect to GitHub OAuth"""
    redirect_uri = os.getenv("GITHUB_REDIRECT_URI")
    if not github_id or not github_secret or not redirect_uri:
        raise HTTPException(status_code=500, detail="GitHub OAuth not configured")

    return await oauth.github.authorize_redirect(request, redirect_uri)


async def upsert_oauth_user(
    db: AsyncSession,
    *,
    email: str,
    full_name: str | None = None,
) -> User:
    """
    Create the user if it doesn't exist; otherwise update last_login.
    OAuth users have hashed_password = None.
    """
    result = await db.execute(select(User).where(User.email == email))
    existing = result.scalar_one_or_none()

    now = datetime.utcnow()

    if existing:
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
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.get("/callback/google")
async def callback_google(request: Request, db: AsyncSession = Depends(get_db)):
    """Google OAuth callback"""
    frontend_base = "http://127.0.0.1:5500/login.html"

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
            return RedirectResponse(url=f"{frontend_base}?error=no_email", status_code=302)

        # Upsert user in DB + update last_login
        await upsert_oauth_user(db, email=email, full_name=full_name)

        jwt_token = SecurityManager.create_access_token(
            data={"sub": email},
            expires_delta=timedelta(minutes=30),
        )
        logger.info("Google OAuth successful for: %s", email)

        return RedirectResponse(
            url=f"{frontend_base}?token={jwt_token}&user={email}",
            status_code=302,
        )

    except Exception as e:
        logger.error("Google callback error: %s", str(e))
        return RedirectResponse(
            url=f"{frontend_base}?error=oauth_failed&msg={str(e)}",
            status_code=302,
        )


@router.get("/callback/github")
async def callback_github(request: Request, db: AsyncSession = Depends(get_db)):
    """GitHub OAuth callback"""
    frontend_base = "http://127.0.0.1:5500/login.html"

    try:
        token = await oauth.github.authorize_access_token(request)

        # Get basic user info
        resp = await oauth.github.get("user", token=token)
        user_info = resp.json()

        login = user_info.get("login")  # GitHub username
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
                url=f"{frontend_base}?error=no_email&msg=GitHub account has no verified email. Please add/verify an email in GitHub or make it public, then try again.",
                status_code=302,
            )
        # Upsert user in DB + update last_login
        await upsert_oauth_user(db, email=email, full_name=full_name)

        jwt_token = SecurityManager.create_access_token(
            data={"sub": email},
            expires_delta=timedelta(minutes=30),
        )
        logger.info("GitHub OAuth successful for: %s", email)

        return RedirectResponse(
            url=f"{frontend_base}?token={jwt_token}&user={email}",
            status_code=302,
        )

    except Exception as e:
        logger.error("GitHub callback error: %s", str(e))
        return RedirectResponse(
            url=f"{frontend_base}?error=oauth_failed&msg={str(e)}",
            status_code=302,
        )