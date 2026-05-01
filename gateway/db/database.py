from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base
from gateway.config import settings
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = settings.DATABASE_URL

# Create async engine
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    future=True,
    pool_pre_ping=True,
)

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
    """Initialize database — create all tables then apply column migrations."""
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
