"""
tests/conftest.py
------------------
Shared pytest fixtures for all test modules.

Uses an in-memory SQLite database so tests never touch the real DB.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

from gateway.main import app
from gateway.db.database import Base, get_db
from gateway.core.tokens import RefreshToken  # noqa: F401 — registers table in Base.metadata


# ── In-memory test database ──────────────────────────────────────────────────
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(TEST_DATABASE_URL, echo=False)
TestSessionLocal = async_sessionmaker(
    test_engine, class_=AsyncSession, expire_on_commit=False
)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


# Override the real DB with the in-memory one for every test
app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_test_db():
    """Create all tables once before any test runs."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest_asyncio.fixture(scope="session")
async def client():
    """Async HTTP client wired directly to the FastAPI app (session-scoped)."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture(autouse=True)
def _reset_auth_rate_limits():
    """Clear the auth/mfa/forgot rate-limit buckets before each test.

    Tests share a single in-memory rate-limit store. Without this reset,
    auth-heavy tests exhaust the 10-req/min auth bucket and unrelated tests
    start receiving 429 instead of the expected status codes.
    The rate-limit tests themselves are unaffected: they flood within one
    test function and hit the limit before the next autouse reset runs.
    """
    from gateway.middleware.rate_limit import _store, _lock
    with _lock:
        for key in list(_store.keys()):
            if key.startswith(("auth:", "forgot:", "mfa:")):
                del _store[key]
    yield


# ── Convenience helpers ───────────────────────────────────────────────────────

VALID_USER = {
    "email": "testuser@example.com",
    "username": "testuser",
    "password": "Secure@Pass1",
    "full_name": "Test User",
}


@pytest_asyncio.fixture(scope="session")
async def registered_user(client):
    """Register the shared test user once per session and return the response JSON.
    Session-scoped to avoid hitting auth rate limits during long test runs.
    """
    resp = await client.post("/auth/register", json=VALID_USER)
    # 201 = new registration; 400 = already exists (previous session left the user)
    assert resp.status_code in (201, 400), resp.text
    if resp.status_code == 400:
        # User already exists — fetch current user data via login
        login_resp = await client.post(
            "/auth/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
        )
        assert login_resp.status_code == 200, login_resp.text
        return login_resp.json()["user"]
    return resp.json()


@pytest_asyncio.fixture(scope="session")
async def auth_token(client, registered_user):
    """Return a valid JWT for the shared test user. Session-scoped."""
    resp = await client.post(
        "/auth/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
