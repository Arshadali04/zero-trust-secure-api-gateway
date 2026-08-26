"""
tests/test_auth.py
-------------------
Legacy synchronous API tests (kept for backward compatibility).
These use the synchronous httpx client; the fuller async tests live in
tests/integration/test_auth_flow.py.
"""

import pytest
from starlette.testclient import TestClient
from gateway.main import app


@pytest.fixture
def sync_client(_lifespan):
    # NOT used as a context manager, and that is deliberate: entering TestClient
    # as a context manager runs the application lifespan, so this fixture used to
    # run init_db(), init_rate_limit_backend(), load_persisted_models() and the
    # demo backend once per test function — while the async suite next door ran
    # the lifespan zero times. conftest's session-scoped `_lifespan` fixture now
    # owns startup/shutdown exactly once for the whole session; depending on it
    # here is what guarantees the schema exists before the first request.
    yield TestClient(app, base_url="http://test")


def test_register_user(sync_client):
    resp = sync_client.post("/auth/register", json={
        "email": "legacy1@example.com",
        "username": "legacy1",
        "password": "Secure@Pass1",
        "full_name": "Legacy User",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "legacy1"


def test_register_duplicate_email(sync_client):
    payload = {
        "email": "legacydup@example.com",
        "username": "legacydup1",
        "password": "Secure@Pass1",
        "full_name": "Dup",
    }
    sync_client.post("/auth/register", json=payload)
    resp = sync_client.post("/auth/register", json={**payload, "username": "legacydup2"})
    assert resp.status_code == 400


def test_login_user(sync_client):
    # Register first
    sync_client.post("/auth/register", json={
        "email": "legacylogin@example.com",
        "username": "legacylogin",
        "password": "Secure@Pass1",
        "full_name": "Legacy Login",
    })
    # Login with JSON body (NOT query params — that was the original bug)
    resp = sync_client.post("/auth/login", json={
        "email": "legacylogin@example.com",
        "password": "Secure@Pass1",
    })
    assert resp.status_code == 200
    assert "access_token" in resp.json()
