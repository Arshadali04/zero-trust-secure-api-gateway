"""
gateway/db/schemas.py
----------------------
Pydantic schemas — request/response models only.

Auth dependencies live in `gateway/dependencies.py` and are imported from there
directly. This module used to re-export them for backwards compatibility, which
made `gateway/db/` import upward into the application layer: schemas → gateway
.dependencies → gateway.db.database. Nothing in `gateway/db/` should reach
outside it, and now nothing does.
"""

import re
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from datetime import datetime

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
    full_name: str | None = None


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
    username: str | None = Field(None, min_length=3, max_length=50)
    full_name: str | None = None

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
    last_login: datetime | None = None
    last_login_ip: str | None = None
    risk_score: float | None = None
    mfa_enabled: bool | None = None
    # Adaptive security policy state (for the dashboard)
    stepup_required: bool | None = None
    account_frozen_until: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str | None = None
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse | None = None
    mfa_required: bool = False


# ─────────────────────────────────────────────────────────────────────────────
# API key schemas
# ─────────────────────────────────────────────────────────────────────────────

class ApiKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="Human-friendly label")
    scopes: list[str] = Field(
        default_factory=lambda: ["all"],
        description='Scopes: "all" or "proxy:<service>", e.g. ["proxy:data"]',
    )
    expires_in_days: int | None = Field(None, ge=1, le=365, description="Optional expiry")


class ApiKeyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=100)
    scopes: list[str] | None = None


class ApiKeyResponse(BaseModel):
    id: int
    name: str
    key_prefix: str
    scopes: list[str]
    last_used_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    created_at: datetime


class ApiKeyCreated(ApiKeyResponse):
    key: str   # full plaintext — returned exactly once


# ─────────────────────────────────────────────────────────────────────────────
# Service registration schemas
# ─────────────────────────────────────────────────────────────────────────────

class ServiceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=80, description="Unique service slug, e.g. 'data'")
    upstream_url: str = Field(..., min_length=1, max_length=500, description="Backend URL, e.g. 'http://127.0.0.1:8001'")
    description: str | None = None


class ServiceUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=80)
    upstream_url: str | None = Field(None, min_length=1, max_length=500)
    description: str | None = None
    is_active: bool | None = None


class ServiceResponse(BaseModel):
    id: int
    name: str
    upstream_url: str
    description: str | None = None
    is_active: bool
    owner_user_id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


# ─────────────────────────────────────────────────────────────────────────────
# Audit / security event schemas
# ─────────────────────────────────────────────────────────────────────────────

class AuditLogResponse(BaseModel):
    id: int
    user_id: int | None
    action: str
    method: str
    resource: str | None
    ip_address: str
    user_agent: str | None
    status_code: int | None
    event_type: str | None = None
    timestamp: datetime
    details: str | None

    model_config = ConfigDict(from_attributes=True)


class SecurityEventResponse(BaseModel):
    id: int
    threat_type: str
    ip_address: str
    endpoint: str | None
    payload: str | None = None
    risk_score: float
    status: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
