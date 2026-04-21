"""
Data models for Zero Trust API Gateway.
Uses in-memory storage for Phase 1 (25%).
Designed to be swapped with database models in future phases.
"""
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class Role(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MODERATOR = "moderator"


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)


class UserCreate(UserBase):
    password: str = Field(..., min_length=6, max_length=100)
    role: Role = Role.USER


class UserInDB(UserBase):
    hashed_password: str
    role: Role
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UserResponse(UserBase):
    role: Role
    is_active: bool


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    expires_in: int


class RequestLog(BaseModel):
    timestamp: datetime
    method: str
    path: str
    client_ip: str
    user: Optional[str] = None
    status_code: int
    response_time_ms: float
    blocked: bool = False
    block_reason: Optional[str] = None


class GatewayStatus(BaseModel):
    total_requests: int
    blocked_requests: int
    active_users: int
    uptime_seconds: float
