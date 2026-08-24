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

import ipaddress
import logging
from datetime import datetime, timedelta, UTC

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from gateway.db.database import get_db
from gateway.db.models import AuditLog, User, AccountFreeze
from gateway.core.security import SecurityManager
from gateway.core.tokens import revoke_all_user_tokens
from gateway.db.schemas import (
    AuditLogResponse,
    SecurityEventResponse,
    UserResponse,
    UserUpdate,
    ChangePasswordRequest,
)
from gateway.dependencies import (
    require_admin_user,
    require_authenticated_user,
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["User"])


# ─────────────────────────────────────────────────────────────────────────────
# Public (authenticated) endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/auth/me", response_model=UserResponse)
async def me(
    current_user: User = Depends(require_authenticated_user),
):
    """Return the profile of the currently authenticated user.

    Decay is applied inside require_authenticated_user on every request —
    calling it again here would double-apply the decay and shrink the score
    twice as fast per request.
    """
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
    # Revoke every outstanding session for this account. Bumping token_version
    # invalidates outstanding *access* tokens (checked in
    # require_authenticated_user), but refresh tokens are not version-bound, so
    # they must be deleted explicitly — otherwise a stolen refresh token can be
    # exchanged for a fresh, valid access token after the password change.
    current_user.token_version = (current_user.token_version or 1) + 1
    await revoke_all_user_tokens(db, current_user.id)
    await db.commit()

    return {"message": "Password changed successfully."}


# ─────────────────────────────────────────────────────────────────────────────
# Admin-only endpoints
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/admin/users", response_model=list[UserResponse])
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


@router.post("/admin/users/{user_id}/unfreeze")
async def unfreeze_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """
    [Admin] Manually lift a critical-risk freeze before the 1h window expires.
    Also clears the step-up demand so the user can log straight back in.
    """
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Clear the freeze row(s) for this user. These are account-wide, not
    # per-IP (ip_address is always "*"), so this is a full unfreeze.
    result_q = await db.execute(
        select(AccountFreeze).where(AccountFreeze.user_id == user_id)
    )
    freezes = result_q.scalars().all()
    was_frozen = bool(freezes)
    for fr in freezes:
        await db.delete(fr)

    # Also clear legacy account-level freeze (back-compat)
    user.account_frozen_until = None
    user.stepup_required = False
    user.stepup_since = None
    await db.commit()

    return {
        "message": "Account unfrozen.",
        "was_frozen": was_frozen,
        "user_id": user.id,
        "email": user.email,
    }


@router.get("/admin/audit-logs", response_model=list[AuditLogResponse])
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

    # Demoting the only admin locks everyone out of every /admin route, and the
    # only recovery is scripts/make_admin.py against the database directly.
    if user.role == "admin" and role != "admin" and await _count_admins(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refusing to demote the last remaining admin — no one could administer the gateway.",
        )

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
    """[Admin] Delete a user and every row that belongs to them."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    if user.id == _admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot delete your own account while signed in as admin.",
        )

    if user.role == "admin" and await _count_admins(db) <= 1:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Refusing to delete the last remaining admin — the gateway would be unadministrable.",
        )

    # The schema declares NO ForeignKey constraints, so nothing cascades: a plain
    # delete left every child row behind. The dangerous one is `services`, because
    # proxy.py resolves an upstream by name with no owner scoping — a deleted
    # user's registered upstream stayed routable by any authenticated caller.
    # api_keys, refresh_tokens, account_freezes and behavior_profiles orphaned the
    # same way, and because ids are reused by SQLite's AUTOINCREMENT-less rowid
    # allocation, a future user could inherit them.
    await _purge_user_rows(db, user_id)

    await db.delete(user)
    await db.commit()
    logger.info("User deleted: user_id=%s (owned rows purged)", user_id)
    return None


async def _count_admins(db: AsyncSession) -> int:
    """Number of active admin accounts."""
    from sqlalchemy import func
    result = await db.execute(
        select(func.count()).select_from(User).where(User.role == "admin")
    )
    return int(result.scalar() or 0)


async def _purge_user_rows(db: AsyncSession, user_id: int) -> None:
    """Delete every row owned by *user_id* across the schema.

    Explicit rather than declarative because the models carry no ForeignKeys.
    Each table is deleted in its own try/except so an absent table on an older
    database cannot abort the whole operation and leave a half-deleted user.
    """
    from sqlalchemy import delete as sa_delete
    from gateway.db.models import (
        ApiKey, Service, AccountFreeze, BehaviorProfile, RefreshToken,
    )

    # The owner column is NOT uniformly named: Service uses `owner_user_id` while
    # everything else uses `user_id`. A generic `model.user_id` loop raises
    # AttributeError on Service and — because each iteration is wrapped in
    # try/except — would silently skip the single most important table, leaving
    # exactly the orphaned-upstream hole this function exists to close.
    owned = (
        (ApiKey, "user_id"),
        (Service, "owner_user_id"),
        (AccountFreeze, "user_id"),
        (BehaviorProfile, "user_id"),
        (RefreshToken, "user_id"),
    )
    for model, col in owned:
        column = getattr(model, col, None)
        if column is None:
            logger.error(
                "Purge MISSED %s: expected owner column %r not found — orphan rows "
                "will remain for user_id=%s",
                getattr(model, "__tablename__", model), col, user_id,
            )
            continue
        try:
            result = await db.execute(sa_delete(model).where(column == user_id))
            logger.info(
                "Purged %s rows from %s for user_id=%s",
                result.rowcount, getattr(model, "__tablename__", model), user_id,
            )
        except Exception as exc:
            logger.warning(
                "Purge skipped %s for user_id=%s: %s",
                getattr(model, "__tablename__", model), user_id, exc,
            )


# ─────────────────────────────────────────────────────────────────────────────
# Security Events (admin only)
# ─────────────────────────────────────────────────────────────────────────────

@router.get("/admin/security-events", response_model=list[SecurityEventResponse])
async def list_security_events(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
    threat_type: str | None = Query(None, description="Filter by threat type"),
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] Return recent security events (WAF blocks, risk blocks, brute-force, etc.)."""
    from gateway.db.models import SecurityEvent

    query = select(SecurityEvent).order_by(desc(SecurityEvent.timestamp))
    if threat_type:
        query = query.where(SecurityEvent.threat_type == threat_type)
    query = query.offset(skip).limit(limit)

    result = await db.execute(query)
    return result.scalars().all()


# ── IP Blocklist admin endpoints ─────────────────────────────────────────────

@router.get("/admin/blocked-ips", tags=["Admin"])
async def list_blocked_ips(
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] List all blocked IP addresses."""
    from gateway.db.models import BlockedIP
    result = await db.execute(select(BlockedIP).order_by(desc(BlockedIP.created_at)))
    rows = result.scalars().all()
    return [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "reason": r.reason,
            "blocked_until": r.blocked_until.isoformat() if r.blocked_until else None,
            "permanent": r.blocked_until is None,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in rows
    ]


@router.post("/admin/block-ip", tags=["Admin"], status_code=201)
async def block_ip(
    request: Request,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] Manually block an IP address."""
    from gateway.db.models import BlockedIP
    from gateway.core.client_ip import get_client_ip

    # Malformed or absent JSON body previously raised out of the handler as an
    # unhandled JSONDecodeError → HTTP 500. Return 400 instead.
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Request body must be valid JSON.") from None
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail="Request body must be a JSON object.")

    ip = str(body.get("ip_address") or "").strip()
    reason = body.get("reason", "Manual admin block")
    duration_hours = body.get("duration_hours")  # None = permanent

    if not ip:
        raise HTTPException(status_code=400, detail="ip_address is required")

    # Validate the address: an unvalidated string lands a permanent row in
    # blocked_ips that matches nothing and can never be hit, so the admin
    # believes an IP is blocked when it is not.
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"'{ip}' is not a valid IPv4 or IPv6 address.",
        ) from None

    # Refuse to block the caller's own address. The unblock route is exempted in
    # IPBlockerMiddleware so this is recoverable either way, but a self-block is
    # almost never intended and silently breaks the admin's own session.
    caller_ip = get_client_ip(request)
    if ip == caller_ip:
        raise HTTPException(
            status_code=400,
            detail=(
                "Refusing to block your own IP address "
                f"({caller_ip}). Blocking it would break your admin session."
            ),
        )

    blocked_until = None
    if duration_hours is not None:
        # Unvalidated float() previously raised ValueError → HTTP 500 for any
        # non-numeric input, e.g. {"duration_hours": "forever"}.
        try:
            hours = float(duration_hours)
        except (TypeError, ValueError):
            raise HTTPException(
                status_code=400,
                detail="duration_hours must be a number (omit it for a permanent block).",
            ) from None
        if hours <= 0:
            raise HTTPException(status_code=400, detail="duration_hours must be greater than 0.")
        blocked_until = datetime.now(UTC) + timedelta(hours=hours)

    existing = (await db.execute(select(BlockedIP).where(BlockedIP.ip_address == ip))).scalar_one_or_none()
    if existing:
        existing.reason = reason
        existing.blocked_until = blocked_until
    else:
        db.add(BlockedIP(ip_address=ip, reason=reason, blocked_until=blocked_until))
    await db.commit()
    logger.info("Admin blocked IP: %s reason=%s", ip, reason)
    return {"message": f"IP {ip} blocked.", "permanent": blocked_until is None}


@router.delete("/admin/block-ip/{ip_address:path}", tags=["Admin"])
async def unblock_ip(
    ip_address: str,
    db: AsyncSession = Depends(get_db),
    _admin: User = Depends(require_admin_user),
):
    """[Admin] Remove an IP from the blocklist."""
    from gateway.db.models import BlockedIP
    row = (await db.execute(select(BlockedIP).where(BlockedIP.ip_address == ip_address))).scalar_one_or_none()
    if not row:
        raise HTTPException(status_code=404, detail="IP not found in blocklist")
    await db.delete(row)
    await db.commit()
    logger.info("Admin unblocked IP: %s", ip_address)
    return {"message": f"IP {ip_address} unblocked."}
