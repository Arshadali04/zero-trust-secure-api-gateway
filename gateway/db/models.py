"""ORM models for the gateway.

Typing note
-----------
Columns are declared in SQLAlchemy 2.0 style — ``Mapped[T] = mapped_column(...)``
rather than ``x = Column(...)``. The old style types every attribute as
``Column[T]`` instead of ``T``, so mypy rejected every ordinary use of a model
field: reading ``user.email`` as a ``str``, assigning ``key.last_used_at = now``,
passing ``user.id`` to a function taking ``int``. That accounted for 94 of the 97
errors in ``mypy gateway/``.

``Optional[T]`` here mirrors the *database* schema, not what the application
usually expects to find. A column with a Python-side ``default=`` is still
``NULL``-able in DDL — the default is applied by the ORM on insert, not by a
``NOT NULL`` constraint — so e.g. ``is_active`` is ``Mapped[Optional[bool]]``.
Annotating it ``Mapped[bool]`` would make SQLAlchemy emit ``NOT NULL`` and
silently change the schema. CI runs mypy with ``--no-strict-optional``, so these
Optionals do not force ``is None`` guards at every call site.

The explicit SQL type is always passed to ``mapped_column`` (``String(255)``,
``DateTime(timezone=True)``, ...) rather than inferred from the annotation, so
column types and lengths are unchanged.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from gateway.db.database import Base


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        Index('idx_user_email', 'email', unique=True),
        Index('idx_user_active', 'is_active'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    full_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[Optional[bool]] = mapped_column(Boolean, default=True, index=True)
    is_superuser: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    role: Mapped[Optional[str]] = mapped_column(String(50), default="user")
    mfa_enabled: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=func.now())
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, default=0.0)
    risk_updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)  # decay anchor
    # Cooldown anchor, written only by elevate_account_risk. Kept separate from
    # risk_updated_at because decay_and_persist re-stamps that column on every
    # /auth/me read, which was resetting the elevation cooldown continuously.
    risk_elevated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    token_version: Mapped[Optional[int]] = mapped_column(Integer, default=1)
    # True once an OAuth identity has been attached to this account. Used to
    # distinguish a FIRST link to a password-bearing account (a takeover vector
    # while registration has no email verification) from routine OAuth logins.
    oauth_linked: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    # Adaptive security policy flags: stepup_required is set once risk crosses the
    # step-up threshold, stepup_since records when step-up was demanded, and
    # account_frozen_until is the end of a critical-risk 1h freeze.
    stepup_required: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    stepup_since: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    account_frozen_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<User {self.email}>"


class AuditLog(Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index('idx_audit_user', 'user_id'),
        Index('idx_audit_timestamp', 'timestamp'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    status_code: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # successful|unsuccessful|blocked|rate_limited|proxied
    event_type: Mapped[Optional[str]] = mapped_column(String(30), nullable=True, index=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (
        Index('idx_security_type', 'threat_type'),
        Index('idx_security_timestamp', 'timestamp'),
        Index('idx_security_ip', 'ip_address'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    threat_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    endpoint: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    payload: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, default=0.0)
    status: Mapped[Optional[str]] = mapped_column(String(20), default="detected")
    timestamp: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class AccountFreeze(Base):
    """Account-wide freeze window — one active row per frozen user.

    The ip_address column does NOT make this an (user, IP) scope, despite the
    old docstring saying so. The only writer, account_risk.apply_risk_policy,
    hardcodes ip_address="*", and is_user_frozen() decides from
    User.account_frozen_until without looking at the IP at all. Column and
    idx_freeze_user_ip index are kept for a per-IP scope that was never
    implemented; treat any row here as blocking every address.
    """
    __tablename__ = "account_freezes"
    __table_args__ = (
        Index('idx_freeze_user_ip', 'user_id', 'ip_address'),
    )
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    frozen_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<AccountFreeze user={self.user_id} ip={self.ip_address} until={self.frozen_until}>"


class PasswordReset(Base):
    __tablename__ = "password_resets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    token: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ApiKey(Base):
    """
    Machine-to-machine API keys.

    Security notes:
      - Only `key_hash` (SHA-256 of the full key) is stored. The plaintext
        is shown to the owner exactly once, at creation / rotation time.
      - `key_prefix` is a short public identifier so the UI can label a key
        without ever exposing it.
      - `scopes` is a JSON array, e.g. ["all"] or ["proxy:data", "proxy:payments"].
    """
    __tablename__ = "api_keys"
    __table_args__ = (
        Index('idx_apikey_user', 'user_id'),
        Index('idx_apikey_hash', 'key_hash', unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    scopes: Mapped[str] = mapped_column(Text, nullable=False, default="[]")       # JSON array string
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)

    def __repr__(self):
        return f"<ApiKey {self.key_prefix}*** user_id={self.user_id}>"


class Service(Base):
    """
    Backend service registered by a developer/user.

    Example:
      name='data', upstream_url='http://127.0.0.1:8001'
      Gateway path: /api/v1/data/* → upstream_url/*
    """
    __tablename__ = "services"
    __table_args__ = (
        Index('idx_service_owner', 'owner_user_id'),
        Index('idx_service_name', 'name'),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    owner_user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    upstream_url: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[Optional[bool]] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Service {self.name} → {self.upstream_url}>"


class BlockedIP(Base):
    """
    Persistent IP blocklist.

    An IP is added when it repeatedly triggers the WAF or rate limiter.
    The outermost middleware checks this table on every request and returns
    403 immediately — before any other processing — for blocked IPs.
    """
    __tablename__ = "blocked_ips"
    __table_args__ = (
        Index('idx_blocked_ip', 'ip_address', unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)
    reason: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)
    # None = permanent
    blocked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<BlockedIP {self.ip_address} until={self.blocked_until}>"


class BehaviorProfile(Base):
    """
    Lightweight per-user behavioural baseline used for anomaly detection.

    This is intentionally explainable (not black-box ML): we track moving
    averages and raise a SecurityEvent if current behaviour deviates sharply.
    """
    __tablename__ = "behavior_profiles"
    __table_args__ = (
        Index('idx_behavior_user', 'user_id', unique=True),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    avg_requests_per_minute: Mapped[Optional[float]] = mapped_column(Float, default=5.0)
    failed_auth_count: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    last_seen_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    last_seen_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    anomaly_count: Mapped[Optional[int]] = mapped_column(Integer, default=0)
    updated_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class RefreshToken(Base):
    """Single-use refresh token with family-based reuse detection.

    Moved here from gateway/core/tokens.py. It was the only ORM model declared
    outside this module, which had two costs: `Base.metadata` was only complete
    if something happened to have imported `core.tokens` first — hence the
    `import gateway.core.tokens  # noqa: F401` in the initial Alembic revision
    and the matching line in the test fixtures — and a reader looking for the
    schema had no reason to look in a module named "tokens". The rotation logic
    stays in core/tokens.py; only the table declaration moved.

    `gateway/db/` imports nothing from `gateway/core/`, so this direction is
    cycle-free.
    """
    __tablename__ = "refresh_tokens"
    __table_args__ = (
        Index("idx_refresh_hash", "token_hash", unique=True),
        Index("idx_refresh_family", "family_id"),
        Index("idx_refresh_user", "user_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    family_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_consumed: Mapped[Optional[bool]] = mapped_column(Boolean, default=False)
    # Stores whether MFA was verified when this token was issued.
    # rotate_refresh_token propagates this flag so token refresh cannot
    # silently promote a non-MFA session to mfa_verified=True.
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_at: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    # The user's token_version at the moment this refresh token was issued.
    # rotate_refresh_token rejects the token if the stored value no longer
    # matches users.token_version, so any operation that bumps token_version
    # (password change, password reset, critical-risk auto-logout) invalidates
    # refresh tokens as well as access tokens. Without this binding, a stolen
    # refresh token could be exchanged for a valid access token *after* a
    # password change, and the change would revoke nothing.
    token_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), server_default=func.now())
