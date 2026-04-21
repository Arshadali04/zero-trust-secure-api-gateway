from datetime import datetime, timedelta
import logging

from fastapi import APIRouter, HTTPException, status, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.core.security import SecurityManager
from gateway.db.database import get_db
from gateway.db.models import User
from gateway.db.schemas import UserCreate, UserResponse, TokenResponse, LoginRequest

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
    # email exists?
    result = await db.execute(select(User).where(User.email == user_data.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

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
        last_login=datetime.utcnow(),
    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user


@router.post("/login", response_model=TokenResponse)
async def login(payload: LoginRequest, db: AsyncSession = Depends(get_db)):
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

    user.last_login = datetime.utcnow()
    await db.commit()

    access_token = SecurityManager.create_access_token(
        data={"sub": user.email},
        expires_delta=timedelta(minutes=30),
    )

    return TokenResponse(access_token=access_token, token_type="bearer", expires_in=1800)