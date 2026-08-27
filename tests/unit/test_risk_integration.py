"""Integration tests: risk score -> step-up -> freeze -> decay -> recovery."""

from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from gateway.db.database import Base
from gateway.detection.account_risk import (
    ELEVATE_COOLDOWN_SECONDS,
    RISK_LOW_AFTER_DAYS,
    _naive_utc_now,
    decay_and_persist,
    elevate_account_risk,
    is_user_frozen,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ── In-memory test DB (separate from the shared one to keep tests isolated) ──

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def session(db_engine):
    factory = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as s:
        yield s


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _create_user(session, email):
    from gateway.db.models import User
    user = User(
        email=email, username=email.split("@")[0],
        hashed_password="x", is_active=True, token_version=1,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    return user


# ═════════════════════════════════════════════════════════════════════════════
# Risk lifecycle
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
class TestRiskLifecycle:
    """End-to-end risk lifecycle: elevation -> step-up -> freeze -> decay -> recovery."""

    async def test_full_lifecycle(self, session):
        """Elevate to step-up, then to critical/freeze, then verify decay restores access."""
        user = await _create_user(session, "lifecycle@test.com")

        # Phase 1: Elevate to step-up (risk 0.60 >= 0.55 threshold)
        risk = await elevate_account_risk(session, user.id, 0.60, ip="127.0.0.1")
        assert risk >= 0.55
        await session.refresh(user)
        assert user.stepup_required is True

        # Phase 2: Bypass the elevation cooldown, then elevate to critical -> freeze
        #
        # The cooldown anchor is risk_elevated_at, NOT risk_updated_at. Only
        # elevate_account_risk writes risk_elevated_at; risk_updated_at is the
        # decay anchor and gets re-stamped by decay_and_persist on every
        # /auth/me hit, which is why it can no longer gate the cooldown.
        # Rewinding only risk_updated_at (as this test used to) left the
        # cooldown in force, so this second elevation was silently discarded
        # and risk stayed at the decayed 0.60 instead of climbing to 0.90.
        past = _naive_utc_now() - timedelta(seconds=ELEVATE_COOLDOWN_SECONDS + 1)
        user.risk_updated_at = past
        user.risk_elevated_at = past
        await session.commit()
        risk = await elevate_account_risk(session, user.id, 0.30, ip="127.0.0.1")
        assert risk >= 0.85
        frozen = await is_user_frozen(session, user.id, "127.0.0.1")
        assert frozen is True

        # Phase 3: Simulate time passing (set risk_updated_at far in the past)
        user.risk_updated_at = _naive_utc_now() - timedelta(hours=2)
        await session.commit()
        await session.refresh(user)

        # Phase 4: Decay should bring score below critical
        decayed = await decay_and_persist(session, user)
        assert decayed < 0.85, f"Score should be below critical after 2h, got {decayed}"

        # Phase 5: Verify step-up is cleared when risk drops
        user.stepup_required = True
        user.stepup_since = _naive_utc_now()
        await session.commit()
        from gateway.detection.account_risk import apply_risk_policy
        await apply_risk_policy(session, user, decayed, ip="127.0.0.1")
        if decayed < 0.35:
            assert user.stepup_required is False

    async def test_full_recovery_after_low_days(self, session):
        """After RISK_LOW_AFTER_DAYS, risk should be exactly 0.0."""
        user = await _create_user(session, "recovery@test.com")
        await elevate_account_risk(session, user.id, 0.90, ip="127.0.0.1")

        # Simulate many days passing
        user.risk_updated_at = _naive_utc_now() - timedelta(days=RISK_LOW_AFTER_DAYS + 1)
        await session.commit()
        await session.refresh(user)

        decayed = await decay_and_persist(session, user)
        assert decayed == 0.0
