from datetime import datetime, timedelta, timezone
import logging

from fastapi import APIRouter, HTTPException, status, Depends, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.security import SecurityManager
from gateway.db.database import get_db
from gateway.db.models import User, PasswordReset
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
        existing_user.last_login = datetime.now(timezone.utc)

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
        last_login=datetime.now(timezone.utc),
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    response.headers["X-Audit-User"] = new_user.email
    return new_user


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, response: Response, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not bool(user.is_active):
        raise HTTPException(status_code=403, detail="User account is disabled")

    if user.hashed_password is None:
        raise HTTPException(
            status_code=400,
            detail="This account uses Google/GitHub sign-in. Please sign in with OAuth or reset your password.",
        )

    if not SecurityManager.verify_password(payload.password, str(user.hashed_password)):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user.last_login = datetime.now(timezone.utc)
    await db.commit()

    response.headers["X-Audit-User"] = user.email

    # Note: If MFA is enabled, we do NOT put mfa_verified=True in the payload.
    # The user must use this token to call /auth/mfa/verify to get a fully verified token.
    access_token = SecurityManager.create_access_token(
        data={"sub": user.email, "mfa_verified": False},
        expires_delta=timedelta(minutes=30),
    )

    return TokenResponse(
        access_token=access_token,
        token_type="bearer",
        expires_in=1800,
        user=user,
        mfa_required=bool(user.mfa_enabled),
    )


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
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    
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
    reset_link = f"http://127.0.0.1:8000/frontend/reset-password.html?token={token}"
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
        
    if reset_entry.expires_at < datetime.now(timezone.utc):
        await db.delete(reset_entry)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
        
    # Find user and update password
    user_result = await db.execute(select(User).where(User.email == reset_entry.email))
    user = user_result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=400, detail="User not found.")
        
    user.hashed_password = SecurityManager.hash_password(payload.new_password)
    
    # Clean up token
    await db.delete(reset_entry)
    await db.commit()
    
    return {"message": "Password successfully reset. You can now log in."}
