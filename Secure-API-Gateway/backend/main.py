"""
Zero Trust Secure API Gateway - Main Application
Phase 1 (25%): Core authentication, RBAC, rate limiting, and request logging.

Flowchart Implementation:
  1. User opens frontend (Login Page)
  2. Enter username & password → POST /api/login
  3. Validate credentials → Generate JWT Token ✅ or Show Error ❌
  4. Return token to frontend → Store in browser
  5. User requests protected API (GET /api/data)
  6. API Gateway receives request → Verify JWT Token
  7. Check Role (RBAC) → Authorized or Denied
  8. Apply Rate Limiting → Within limit or Blocked
  9. Log Request (Monitoring) → Send Response to User
"""
from datetime import timedelta
from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from starlette.responses import JSONResponse

from config import ALLOWED_ORIGINS, ACCESS_TOKEN_EXPIRE_MINUTES, RATE_LIMIT_REQUESTS
from models import UserCreate, UserResponse, LoginRequest, TokenResponse, Role
from auth import (
    hash_password, verify_password, create_access_token,
    get_current_user, check_permission, require_role,
)
from middleware import RequestLoggingMiddleware, get_logs, get_stats

# ── App Setup ────────────────────────────────────────────────────────
app = FastAPI(
    title="Zero Trust Secure API Gateway",
    description="A secure API gateway with JWT authentication, RBAC, rate limiting, and attack detection.",
    version="0.1.0 (Phase 1 - 25%)",
)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Rate limit exceeded",
            "detail": "Too many requests. Please try again later.",
            "blocked": True,
        },
    )


# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Logging Middleware
app.add_middleware(RequestLoggingMiddleware)

# ── In-Memory User Store (Phase 1) ──────────────────────────────────
# Will be replaced with database in Phase 2
users_db: dict = {}

# Seed default admin user
users_db["admin"] = {
    "username": "admin",
    "hashed_password": hash_password("admin123"),
    "role": "admin",
    "is_active": True,
}
users_db["user1"] = {
    "username": "user1",
    "hashed_password": hash_password("user123"),
    "role": "user",
    "is_active": True,
}


# ── Public Endpoints ────────────────────────────────────────────────

@app.get("/")
async def root():
    return {
        "service": "Zero Trust Secure API Gateway",
        "version": "0.1.0",
        "phase": "Phase 1 (25%)",
        "status": "running",
    }


@app.post("/api/register", response_model=UserResponse)
async def register(user: UserCreate):
    """Register a new user."""
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")

    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hash_password(user.password),
        "role": user.role.value,
        "is_active": True,
    }
    return UserResponse(username=user.username, role=user.role, is_active=True)


@app.post("/api/login", response_model=TokenResponse)
async def login(credentials: LoginRequest):
    """
    Authenticate user and return JWT token.
    Flowchart: Validate Credentials → Generate JWT Token ✅ or Show Error ❌
    """
    user = users_db.get(credentials.username)
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    token = create_access_token(
        data={"sub": user["username"], "role": user["role"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return TokenResponse(
        access_token=token,
        role=user["role"],
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


# ── Protected Endpoints (JWT + RBAC + Rate Limiting) ────────────────

@app.get("/api/data")
@limiter.limit(RATE_LIMIT_REQUESTS)
async def get_protected_data(request: Request, current_user: dict = Depends(get_current_user)):
    """
    Protected endpoint: requires valid JWT + rate limiting.
    Flowchart: Verify JWT → Check Role → Apply Rate Limiting → Send Response
    """
    check_permission(current_user["role"], "read")
    return {
        "message": "Access granted to protected data",
        "user": current_user["sub"],
        "role": current_user["role"],
        "data": {
            "id": 1,
            "title": "Confidential Resource",
            "content": "This data is protected by Zero Trust principles.",
            "classification": "internal",
        },
    }


@app.get("/api/admin/users")
@limiter.limit(RATE_LIMIT_REQUESTS)
async def list_users(request: Request, current_user: dict = Depends(require_role("admin"))):
    """Admin-only: list all users."""
    return {
        "users": [
            {"username": u["username"], "role": u["role"], "is_active": u["is_active"]}
            for u in users_db.values()
        ]
    }


@app.delete("/api/admin/users/{username}")
@limiter.limit(RATE_LIMIT_REQUESTS)
async def delete_user(username: str, request: Request, current_user: dict = Depends(require_role("admin"))):
    """Admin-only: deactivate a user."""
    if username not in users_db:
        raise HTTPException(status_code=404, detail="User not found")
    if username == current_user["sub"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    users_db[username]["is_active"] = False
    return {"message": f"User '{username}' deactivated"}


# ── Monitoring Endpoints ────────────────────────────────────────────

@app.get("/api/gateway/logs")
@limiter.limit(RATE_LIMIT_REQUESTS)
async def get_gateway_logs(request: Request, current_user: dict = Depends(require_role("admin"))):
    """Admin-only: view request logs."""
    return {"logs": get_logs()[:50]}


@app.get("/api/gateway/stats")
@limiter.limit(RATE_LIMIT_REQUESTS)
async def get_gateway_stats(request: Request, current_user: dict = Depends(require_role("admin"))):
    """Admin-only: gateway statistics."""
    return get_stats()


@app.get("/api/verify")
async def verify_token_endpoint(current_user: dict = Depends(get_current_user)):
    """Verify if the current token is valid."""
    return {
        "valid": True,
        "user": current_user["sub"],
        "role": current_user["role"],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
