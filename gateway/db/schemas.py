"""
gateway/db/schemas.py
----------------------
Pydantic schemas (request/response models) + shared auth dependencies.
"""

import re
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import datetime
from typing import Optional

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from gateway.db.database import get_db

# ─────────────────────────────────────────────────────────────────────────────
# Password strength helper
# ─────────────────────────────────────────────────────────────────────────────

_SPECIAL = re.compile(r'[!@#$%^&*(),.?":{}|<>_\-]')


def _validate_password_strength(v: str) -> str:
    errors = []
    if len(v) < 8:
        errors.append("at least 8 characters")
    if not any(c.isupper() for c in v):
        errors.append("at least one uppercase letter")
    if not any(c.islower() for c in v):
        errors.append("at least one lowercase letter")
    if not any(c.isdigit() for c in v):
        errors.append("at least one digit")
    if not _SPECIAL.search(v):
        errors.append("at least one special character (!@#$% etc.)")
    if errors:
        raise ValueError("Password must contain: " + ", ".join(errors))
    return v


# ─────────────────────────────────────────────────────────────────────────────
# Auth request / response schemas
# ─────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)


class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username may only contain letters, digits, and underscores.")
        return v.lower()


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    full_name: Optional[str] = None

    @field_validator("username")
    @classmethod
    def username_alphanumeric(cls, v: str) -> str:
        if v is not None and not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("Username may only contain letters, digits, and underscores.")
        return v.lower() if v else None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        return _validate_password_strength(v)


class UserResponse(UserBase):
    id: int
    is_active: bool
    role: str
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: Optional[UserResponse] = None
    mfa_required: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# Audit / security event schemas
# ─────────────────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    method: str
    resource: Optional[str]
    ip_address: str
    user_agent: Optional[str]
    status_code: Optional[int]
    event_type: Optional[str] = None
    timestamp: datetime
    details: Optional[str]

    class Config:
        from_attributes = True


class SecurityEventResponse(BaseModel):
    id: int
    threat_type: str
    ip_address: str
    endpoint: Optional[str]
    risk_score: float
    status: str
    timestamp: datetime

    class Config:
        from_attributes = True


# ─────────────────────────────────────────────────────────────────────────────
# Auth dependencies  (import here to avoid circular imports)
# ─────────────────────────────────────────────────────────────────────────────

_bearer = HTTPBearer(auto_error=False)


def _get_current_user_email(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    from gateway.core.security import SecurityManager

    token = credentials.credentials if credentials else request.query_params.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    payload = SecurityManager.verify_token(token)
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
    return email


async def get_current_user(
    email: str = Depends(_get_current_user_email),
    db: AsyncSession = Depends(None),  # overridden below
):
    """Dependency: returns the authenticated User ORM object."""
    from gateway.db.models import User

    # Can't use Depends(get_db) here directly because of circular import timing;
    # callers should use require_authenticated_user below instead.
    raise NotImplementedError  # not used directly


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
    from gateway.core.security import SecurityManager
    from gateway.db.models import User

    # 1. Try to get token from header
    token = credentials.credentials if credentials else None
    
    # 2. Fallback to query parameter (convenient for browser demos)
    if not token:
        token = request.query_params.get("token")
        
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = SecurityManager.verify_token(token)
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

    # MFA Enforcement: If MFA is enabled, the token must be MFA-verified,
    # EXCEPT when hitting the MFA verification or disable endpoints.
    if user.mfa_enabled:
        path = request.url.path
        if path not in ("/auth/mfa/verify", "/auth/mfa/status", "/auth/mfa/disable"):
            if not payload.get("mfa_verified"):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, 
                    detail="mfa_required"
                )

    return user


async def require_admin_user(
    user=Depends(require_authenticated_user),
):
    """
    FastAPI dependency.
    Same as require_authenticated_user but also enforces role == 'admin'.
    Raises 403 if the user is not an admin.
    """
    if user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
