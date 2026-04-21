from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional

class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8)
    
class UserBase(BaseModel):
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str = Field(..., min_length=8)

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

class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    action: str
    method: str
    ip_address: str
    status_code: Optional[int]
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
