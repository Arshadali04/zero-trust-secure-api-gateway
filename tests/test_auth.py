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
def sync_client():
    with TestClient(app, base_url="http://test") as c:
        yield c


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
