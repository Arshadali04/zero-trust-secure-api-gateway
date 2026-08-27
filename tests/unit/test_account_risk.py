"""Tests for gateway/detection/account_risk.py — risk decay, freeze lifecycle, policy enforcement."""

from datetime import timedelta

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from gateway.db.database import Base
from gateway.db.models import AccountFreeze, User
from gateway.detection.account_risk import (
    RISK_LOW_AFTER_DAYS,
    _decayed,
    _naive_utc_now,
    apply_risk_policy,
    decay_and_persist,
    is_user_frozen,
)


@pytest.fixture
def anyio_backend():
    return "asyncio"


# ── In-memory test DB ───────────────────────────────────────────────────────

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


@pytest_asyncio.fixture
async def frozen_user(session):
    """A user with risk_score=0.9 and an active 1-hour freeze on 127.0.0.1."""
    user = User(
        email="frozen@test.com", username="frozen", hashed_password="x",
        is_active=True, risk_score=0.9, risk_updated_at=_naive_utc_now(),
        token_version=1,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)

    freeze_until = _naive_utc_now() + timedelta(hours=1)
    session.add(AccountFreeze(
        user_id=user.id, ip_address="127.0.0.1", frozen_until=freeze_until,
    ))
    user.account_frozen_until = freeze_until
    await session.commit()
    await session.refresh(user)
    return user


# ═════════════════════════════════════════════════════════════════════════════
# _decayed
# ═════════════════════════════════════════════════════════════════════════════

class TestDecay:
    def test_no_update_time_returns_base(self):
        assert _decayed(0.8, None) == 0.8

    def test_immediate_returns_base(self):
        assert _decayed(0.8, _naive_utc_now()) == 0.8

    def test_one_hour_half_life(self):
        """After 4 hours (1 half-life), score should be half."""
        past = _naive_utc_now() - timedelta(hours=4)
        result = _decayed(0.8, past)
        assert abs(result - 0.4) < 0.01

    def test_two_half_lives(self):
        past = _naive_utc_now() - timedelta(hours=8)
        result = _decayed(0.8, past)
        assert abs(result - 0.2) < 0.01

    def test_one_hour_partial(self):
        """After 1 hour (0.25 half-lives), score = 0.85 * 0.5^0.25 ~ 0.714."""
        past = _naive_utc_now() - timedelta(hours=1)
        result = _decayed(0.85, past)
        expected = 0.85 * (0.5 ** 0.25)
        assert abs(result - expected) < 0.02

    def test_reaches_zero_after_low_days(self):
        past = _naive_utc_now() - timedelta(days=RISK_LOW_AFTER_DAYS + 1)
        result = _decayed(0.99, past)
        assert result == 0.0

    def test_clamped_to_one(self):
        assert _decayed(1.5, None) == 1.0

    def test_clamped_to_zero(self):
        assert _decayed(-0.1, None) == 0.0


# ═════════════════════════════════════════════════════════════════════════════
# is_user_frozen
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
class TestIsUserFrozen:
    async def test_active_freeze_returns_true(self, session, frozen_user):
        assert await is_user_frozen(session, frozen_user.id, "127.0.0.1") is True

    async def test_wrong_ip_not_frozen(self, session, frozen_user):
        # Freezes are now account-wide (not IP-scoped) — a frozen user is
        # blocked from ALL IPs until the freeze expires.
        assert await is_user_frozen(session, frozen_user.id, "10.0.0.1") is True

    async def test_expired_freeze_returns_false_and_cleans(self, session, frozen_user):
        # Make BOTH the AccountFreeze row AND the canonical User timestamp expired.
        # is_user_frozen checks user.account_frozen_until; the AccountFreeze row
        # is kept for admin visibility and cleaned up on expiry too.
        fr = (await session.execute(
            select(AccountFreeze).where(AccountFreeze.user_id == frozen_user.id)
        )).scalars().first()
        past = _naive_utc_now() - timedelta(hours=2)
        fr.frozen_until = past
        frozen_user.account_frozen_until = past
        await session.commit()

        assert await is_user_frozen(session, frozen_user.id, "127.0.0.1") is False

        # Verify the row was deleted
        remaining = (await session.execute(
            select(AccountFreeze).where(AccountFreeze.user_id == frozen_user.id)
        )).scalars().all()
        assert len(remaining) == 0

        # Verify legacy column was cleared
        await session.refresh(frozen_user)
        assert frozen_user.account_frozen_until is None

    async def test_no_freeze_returns_false(self, session):
        user = User(email="clean@test.com", username="clean", hashed_password="x", is_active=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)
        assert await is_user_frozen(session, user.id, "127.0.0.1") is False


# ═════════════════════════════════════════════════════════════════════════════
# apply_risk_policy
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
class TestApplyRiskPolicy:
    async def test_stepup_at_threshold(self, session):
        user = User(email="a@test.com", username="a", hashed_password="x", is_active=True,
                    token_version=1, mfa_enabled=True)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        result = await apply_risk_policy(session, user, 0.60, ip="127.0.0.1")
        assert result["stepup"] is True
        assert result["frozen"] is False
        assert user.stepup_required is True

    async def test_freeze_at_critical(self, session):
        user = User(email="b@test.com", username="b", hashed_password="x", is_active=True,
                    token_version=1)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        result = await apply_risk_policy(session, user, 0.90, ip="127.0.0.1")
        assert result["frozen"] is True
        assert user.token_version == 2  # bumped
        assert user.stepup_required is False
        # Verify freeze row exists
        frs = (await session.execute(
            select(AccountFreeze).where(AccountFreeze.user_id == user.id)
        )).scalars().all()
        assert len(frs) == 1
        # Freezes are account-wide, recorded with wildcard IP for admin visibility
        assert frs[0].ip_address == "*"

    async def test_recovery_clears_stepup(self, session):
        user = User(email="c@test.com", username="c", hashed_password="x", is_active=True,
                    token_version=1, stepup_required=True, stepup_since=_naive_utc_now())
        session.add(user)
        await session.commit()
        await session.refresh(user)

        await apply_risk_policy(session, user, 0.20, ip="127.0.0.1")
        assert user.stepup_required is False
        assert user.stepup_since is None

    async def test_already_frozen_skips_duplicate(self, session):
        user = User(email="d@test.com", username="d", hashed_password="x", is_active=True,
                    token_version=1)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        # First freeze
        await apply_risk_policy(session, user, 0.90, ip="127.0.0.1")
        v1 = user.token_version

        # Second attempt — should be skipped
        await apply_risk_policy(session, user, 0.95, ip="127.0.0.1")
        assert user.token_version == v1  # not bumped again


# ═════════════════════════════════════════════════════════════════════════════
# decay_and_persist
# ═════════════════════════════════════════════════════════════════════════════

@pytest.mark.anyio
class TestDecayAndPersist:
    async def test_persists_decayed_score(self, session):
        user = User(email="e@test.com", username="e", hashed_password="x", is_active=True,
                    risk_score=0.8, risk_updated_at=_naive_utc_now() - timedelta(hours=4))
        session.add(user)
        await session.commit()
        await session.refresh(user)

        result = await decay_and_persist(session, user)
        assert abs(result - 0.4) < 0.05  # ~1 half-life
        assert abs(user.risk_score - 0.4) < 0.05

    async def test_zero_score_not_committed(self, session):
        user = User(email="f@test.com", username="f", hashed_password="x", is_active=True,
                    risk_score=0.0, risk_updated_at=None)
        session.add(user)
        await session.commit()
        await session.refresh(user)

        result = await decay_and_persist(session, user)
        assert result == 0.0
