"""
gateway/routes/user.py
-----------------------
User-facing and admin-only endpoints.

Public (authenticated):
  GET /auth/me           — return current user's profile

Admin only:
  GET /admin/users       — list all users
  GET /admin/audit-logs  — list recent audit log entries
  PATCH /admin/users/{user_id}/role  — change a user's role
"""

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.database import get_db
from gateway.db.models import AuditLog, User
from gateway.core.security import SecurityManager
from gateway.db.schemas import (
    AuditLogResponse,
    UserResponse,
    UserUpdate,
    ChangePasswordRequest,
    require_admin_user,
    require_authenticated_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["User"])


# ─────────────────────────────────────────────────────────────────────────────
# Public (authenticated) endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/auth/me", response_model=UserResponse)
async def me(current_user: User = Depends(require_authenticated_user)):
    """Return the profile of the currently authenticated user."""
    return current_user


@router.patch("/auth/me", response_model=UserResponse)
async def update_me(
    update_data: UserUpdate,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    """Update the currently authenticated user's profile."""
    # Check if username is being changed and is already taken
    if update_data.username and update_data.username != current_user.username:
        result = await db.execute(select(User).where(User.username == update_data.username))
        if result.scalar_one_or_none():
            raise HTTPException(status_code=400, detail="Username already taken")
        current_user.username = update_data.username

    if update_data.full_name is not None:
        current_user.full_name = update_data.full_name

    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.patch("/auth/me/password", status_code=status.HTTP_200_OK)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: User = Depends(require_authenticated_user),
    db: AsyncSession = Depends(get_db)
):
    """Change the currently authenticated user's password."""
    if current_user.hashed_password is None:
        raise HTTPException(status_code=400, detail="OAuth users cannot change passwords.")
        
    if not SecurityManager.verify_password(payload.current_password, str(current_user.hashed_password)):
        raise HTTPException(status_code=400, detail="Incorrect current password.")
        
    current_user.hashed_password = SecurityManager.hash_password(payload.new_password)
    await db.commit()
    
    return {"message": "Password changed successfully."}


# ─────────────────────────────────────────────────────────────────────────────
# Admin-only endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/admin/users", response_model=List[UserResponse])
async def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] List all registered users."""
    result = await db.execute(
        select(User).order_by(User.created_at.desc()).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/admin/audit-logs", response_model=List[AuditLogResponse])
async def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] Return recent audit log entries (newest first)."""
    result = await db.execute(
        select(AuditLog).order_by(desc(AuditLog.timestamp)).offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.patch("/admin/users/{user_id}/role", response_model=UserResponse)
async def change_user_role(
    user_id: int,
    role: str = Query(..., pattern="^(admin|user)$"),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] Change a user's role to 'admin' or 'user'."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    user.role = role
    await db.commit()
    await db.refresh(user)
    logger.info("Role changed: user_id=%s new_role=%s", user_id, role)
    return user


@router.delete("/admin/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] Delete a user."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        
    await db.delete(user)
    await db.commit()
    logger.info("User deleted: user_id=%s", user_id)
    return None
