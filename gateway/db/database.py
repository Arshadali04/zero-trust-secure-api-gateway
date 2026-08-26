import logging

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from gateway.config import settings

logger = logging.getLogger(__name__)

DATABASE_URL = settings.DATABASE_URL

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    future=True,
    pool_pre_ping=True,
)

# Enable foreign key enforcement for SQLite (disabled by default)
if DATABASE_URL.startswith("sqlite"):
    from sqlalchemy import event as _sa_event

    @_sa_event.listens_for(engine.sync_engine, "connect")
    def _set_sqlite_pragma(dbapi_conn, _):
        cursor = dbapi_conn.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

# Create async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

Base = declarative_base()


async def _apply_column_migrations(conn) -> None:
    """
    Idempotent column migrations — adds new columns that don't exist yet.
    SQLite's ALTER TABLE ADD COLUMN is safe to call on existing DBs.
    Each statement is wrapped in its own try/except so one failure doesn't
    block the others.
    """
    migrations = [
        # users: MFA support
        "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE users ADD COLUMN mfa_secret TEXT",
        # audit_logs: event_type classification
        "ALTER TABLE audit_logs ADD COLUMN event_type TEXT",
        # users: context validation
        "ALTER TABLE users ADD COLUMN last_login_ip TEXT",
        # users: persistent account risk score
        "ALTER TABLE users ADD COLUMN risk_score FLOAT DEFAULT 0.0",
        "ALTER TABLE users ADD COLUMN risk_updated_at DATETIME",
        # users: cooldown anchor, separate from the decay anchor above
        "ALTER TABLE users ADD COLUMN risk_elevated_at DATETIME",
        # users: JWT revocation version (bumped on password change/reset)
        "ALTER TABLE users ADD COLUMN token_version INTEGER DEFAULT 1",
        # users: has an OAuth identity ever been linked to this account?
        "ALTER TABLE users ADD COLUMN oauth_linked BOOLEAN DEFAULT 0",
        # users: adaptive security policy (step-up MFA + critical freeze)
        "ALTER TABLE users ADD COLUMN stepup_required BOOLEAN DEFAULT 0",
        "ALTER TABLE users ADD COLUMN stepup_since DATETIME",
        "ALTER TABLE users ADD COLUMN account_frozen_until DATETIME",
        # account_freezes: account-wide freeze window. ip_address is always "*"
        # in practice — see the AccountFreeze docstring in models.py.
        "CREATE TABLE IF NOT EXISTS account_freezes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER NOT NULL, "
        "ip_address TEXT NOT NULL, "
        "frozen_until DATETIME NOT NULL, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        "CREATE INDEX IF NOT EXISTS idx_freeze_user_ip ON account_freezes (user_id, ip_address)",
        # refresh_tokens: JWT refresh token rotation
        "CREATE TABLE IF NOT EXISTS refresh_tokens ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "user_id INTEGER NOT NULL, "
        "token_hash TEXT NOT NULL UNIQUE, "
        "family_id TEXT NOT NULL, "
        "is_consumed INTEGER DEFAULT 0, "
        "token_version INTEGER NOT NULL DEFAULT 1, "
        "expires_at DATETIME NOT NULL, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        "CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens (token_hash)",
        "CREATE INDEX IF NOT EXISTS idx_refresh_family ON refresh_tokens (family_id)",
        "CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens (user_id)",
        # refresh_tokens: preserve MFA state through token rotation (prevents MFA bypass)
        "ALTER TABLE refresh_tokens ADD COLUMN mfa_verified INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE refresh_tokens ADD COLUMN mfa_at FLOAT",
        # refresh_tokens: bind each token to the users.token_version in force
        # when it was issued, so bumping token_version revokes refresh tokens
        # as well as access tokens. Existing rows default to 1; any account
        # whose version has already advanced past 1 will see its pre-migration
        # refresh tokens rejected, which is the safe direction to fail.
        "ALTER TABLE refresh_tokens ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1",
        # blocked_ips: persistent IP blocklist checked at outermost middleware
        "CREATE TABLE IF NOT EXISTS blocked_ips ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "ip_address TEXT NOT NULL UNIQUE, "
        "reason TEXT, "
        "blocked_until DATETIME, "
        "created_at DATETIME DEFAULT CURRENT_TIMESTAMP)",
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips (ip_address)",
    ]
    for sql in migrations:
        try:
            await conn.execute(text(sql))
            logger.info("DB migration applied: %s", sql)
        except Exception as e:
            # "duplicate column name" is expected if column already exists
            msg = str(e).lower()
            if "duplicate column" in msg or "already exists" in msg:
                pass  # already applied — skip silently
            else:
                logger.warning("DB migration warning: %s — %s", sql, e)


async def init_db():
    """Initialize database — create all tables then apply column migrations.

    NOTE: The project uses two migration mechanisms:
      1. Alembic (alembic/versions/) — for tracked schema changes.
      2. Idempotent ALTER TABLE statements below — for columns added during
         iterative development that were never Alembic-managed.

    For a fresh DB, ``Base.metadata.create_all`` builds the full schema
    from the ORM models, and the ALTER statements below are safe no-ops
    (they silently skip if the column already exists).  Going forward,
    new schema changes should use ``alembic revision --autogenerate``.
    """
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await _apply_column_migrations(conn)
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")
        raise


async def get_db():
    """Dependency to get database session"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            await session.close()
