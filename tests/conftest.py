"""
tests/conftest.py
------------------
Shared pytest fixtures for all test modules.

Three things here are load-bearing and easy to break by accident, so they are
spelled out rather than left to be rediscovered.

1. THE ENVIRONMENT IS SET BEFORE `gateway.main` IS IMPORTED.
   `gateway/db/database.py` builds its engine at *module import* time from
   `settings.DATABASE_URL`, and `gateway/config.py` instantiates `Settings()` at
   import time too. So the block below has to run before the first `gateway`
   import, and the imports have to stay underneath it.

   This is not cosmetic. `tests/test_auth.py` drove the app through
   `TestClient(app)` used as a context manager, which runs the real lifespan,
   which calls `init_db()` — and `init_db()` uses the module-level engine, not
   anything overridden here. With no override that engine points at
   `data/gateway.db`, so every test run issued `CREATE TABLE` plus a dozen
   `ALTER TABLE`s against the developer's real database. Pointing DATABASE_URL
   at a temp file makes that impossible rather than merely unlikely.

   This works because `main.py` loads `.env` with `override=False`, so a
   DATABASE_URL already in os.environ wins. (`.env.oauth` *is* loaded with
   `override=True`, but it defines no DATABASE_URL. It does define SECRET_KEY,
   so the secret under test comes from that file when it exists — fine, since it
   only needs to be consistent within a run, but that is why SECRET_KEY below is
   a `setdefault` fallback and not an assertion about which key is in use.)

2. THE LIFESPAN ACTUALLY RUNS.
   `httpx.AsyncClient(transport=ASGITransport(app=app))` does **not** run startup
   or shutdown events. The async suite therefore ran against an app where
   `init_db()`, `init_rate_limit_backend()`, `load_persisted_models()` and
   `_start_demo_backend()` had never executed — while `tests/test_auth.py`, using
   `TestClient` as a context manager, ran against one where they had. Two
   different application states inside one test session, which is how you get a
   test that passes alone and fails in the suite. `_lifespan` enters the app's
   own lifespan context once per session so both halves see the same app.

   Starlette's own `app.router.lifespan_context` is used deliberately instead of
   adding an `asgi-lifespan` dependency, so this needs nothing that is not
   already in requirements.txt.

3. REQUEST SESSIONS USE A SEPARATE, POOL-LESS ENGINE.
   The suite drives the app from two different event loops: pytest-asyncio's
   session loop for the async tests, and the private loop `TestClient` runs in a
   worker thread for the sync ones. A pooled async connection belongs to the
   loop that opened it, so a single shared engine hands a connection created in
   one loop to code running in the other — the classic "attached to a different
   loop" failure, which surfaces as an order-dependent flake rather than an
   honest error. `_request_engine` therefore uses NullPool: every session opens
   and closes its own connection, so nothing is retained across loops.

   Both engines address the same temp *file*, so `init_db()` on the app engine
   and queries on the request engine see one database. That is the reason for a
   file rather than `:memory:` — an in-memory SQLite database is scoped to its
   pool, so two engines would silently get two empty, separate databases.
"""

import os
import tempfile

# ── Environment — MUST precede every gateway import (see note 1 above) ────────
_TEST_TMPDIR = tempfile.mkdtemp(prefix="ztg-tests-")
_TEST_DB_PATH = os.path.join(_TEST_TMPDIR, "test_gateway.db").replace("\\", "/")
TEST_DATABASE_URL = f"sqlite+aiosqlite:///{_TEST_DB_PATH}"

os.environ["DATABASE_URL"] = TEST_DATABASE_URL
# Do not bind port 8001 during tests. The demo backend is a real HTTP server, so
# starting it under pytest fails on any machine already running the gateway,
# with an EADDRINUSE that looks nothing like a test failure.
os.environ["GATEWAY_DEMO"] = "0"
# Keep ML model persistence away from data/models/ — a test run must not read,
# overwrite or sign the developer's real per-user models.
os.environ["GATEWAY_MODEL_DIR"] = os.path.join(_TEST_TMPDIR, "models")
# Fallbacks only, so the suite runs on a machine with no .env at all. config.py
# refuses to start on the shipped default secret outside development.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key-32-characters-minimum")
os.environ.setdefault("ENVIRONMENT", "development")

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine  # noqa: E402
from sqlalchemy.pool import NullPool  # noqa: E402

from gateway.db.database import engine, get_db  # noqa: E402
from gateway.main import app  # noqa: E402

# ── Request-path engine (see note 3 above) ────────────────────────────────────
_request_engine = create_async_engine(TEST_DATABASE_URL, poolclass=NullPool)

TestSessionLocal = async_sessionmaker(
    _request_engine, class_=AsyncSession, expire_on_commit=False
)


async def override_get_db():
    async with TestSessionLocal() as session:
        yield session


# Registered at import time, not in a fixture: tests/test_auth.py imports `app`
# directly and would otherwise reach the real get_db.
app.dependency_overrides[get_db] = override_get_db


@pytest_asyncio.fixture(scope="session", autouse=True)
async def _lifespan():
    """Run the app's real startup/shutdown exactly once for the whole session.

    This is also what creates the schema. `init_db()` inside the lifespan runs
    `Base.metadata.create_all` *and* the idempotent ALTER TABLE migrations in
    `_apply_column_migrations`, so tests exercise the schema the way production
    builds it. The manual `create_all` this replaces skipped those ALTERs, which
    meant columns added outside Alembic were absent under test and present in
    production — the suite was validating a schema that never shipped.
    """
    async with app.router.lifespan_context(app):
        yield
    await _request_engine.dispose()
    await engine.dispose()
    # _TEST_TMPDIR is intentionally left on disk: a few KB in the OS temp area,
    # and keeping it means a failed run's database can still be inspected.


@pytest_asyncio.fixture(scope="session")
async def client(_lifespan):
    """Async HTTP client wired directly to the FastAPI app (session-scoped).

    Depends on `_lifespan` explicitly. autouse does not guarantee ordering
    between two session-scoped fixtures, and a client that issues a request
    before `init_db()` has run fails with "no such table".
    """
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture(autouse=True)
def _reset_auth_rate_limits():
    """Clear the auth/mfa/forgot rate-limit buckets before each test.

    Tests share one in-memory rate-limit store. Without this reset, auth-heavy
    tests exhaust the 10-req/min auth bucket and later, unrelated tests start
    receiving 429 instead of the status they assert on. The rate-limit tests
    themselves are unaffected: they flood within a single test function, so they
    reach the limit before the next reset runs.
    """
    from gateway.middleware.rate_limit import _lock, _store
    with _lock:
        for key in list(_store.keys()):
            if key.startswith(("auth:", "forgot:", "mfa:")):
                del _store[key]
    yield


@pytest_asyncio.fixture(autouse=True)
async def _reset_ip_blocker():
    """Clear WAF hit counters and any auto-block rows before each test.

    The WAF auto-blocks an IP after 5 blocks in 120s (ip_blocker.py:34-36) and
    persists a BlockedIP row for an hour. IPBlockerMiddleware is the outermost
    middleware, so once 127.0.0.1 is in that table every later test gets a bare
    403 before its own logic runs. tests/unit/test_waf.py trips the threshold on
    its own (six blocking cases in one file), which is why
    test_command_injection_in_header and test_clean_request_passes failed with
    403 — test_clean_request_passes asserted 200 on `GET /` and never reached
    the route at all.

    Both halves matter: _waf_hits stops a fresh block being written, and the
    DELETE removes one already written, since the test database is
    session-scoped and outlives the test that caused it.
    """
    from gateway.middleware import ip_blocker
    with ip_blocker._waf_lock:
        ip_blocker._waf_hits.clear()
    from sqlalchemy import delete

    from gateway.db.database import AsyncSessionLocal
    from gateway.db.models import BlockedIP
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(delete(BlockedIP))
            await session.commit()
    except Exception:
        # Table may not exist yet on the very first test; the create_all in the
        # session-scoped setup fixture covers it from then on.
        pass
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
    """Register the shared test user once per session and return its JSON.

    Session-scoped to avoid burning the auth rate limit on long runs.
    """
    resp = await client.post("/auth/register", json=VALID_USER)
    # 201 = new registration; 400 = already exists
    assert resp.status_code in (201, 400), resp.text
    if resp.status_code == 400:
        login_resp = await client.post(
            "/auth/login",
            json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
        )
        assert login_resp.status_code == 200, login_resp.text
        return login_resp.json()["user"]
    return resp.json()


@pytest_asyncio.fixture(scope="session")
async def auth_token(client, registered_user):
    """Return a valid access token for the shared test user."""
    resp = await client.post(
        "/auth/login",
        json={"email": VALID_USER["email"], "password": VALID_USER["password"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def auth_headers(auth_token):
    return {"Authorization": f"Bearer {auth_token}"}
