"""Tests for authentication edge cases."""

import pytest
from gateway.core.security import SecurityManager
from datetime import timedelta


@pytest.mark.asyncio
class TestAuthEdgeCases:
    async def test_expired_token_rejected(self, client):
        token = SecurityManager.create_access_token(
            {"sub": "test@example.com", "ver": 1},
            expires_delta=timedelta(seconds=-10)
        )
        resp = await client.get("/auth/me", headers={
            "Authorization": f"Bearer {token}"
        })
        assert resp.status_code == 401

    async def test_malformed_token_rejected(self, client):
        resp = await client.get("/auth/me", headers={
            "Authorization": "Bearer not.a.valid.jwt"
        })
        assert resp.status_code == 401

    async def test_missing_auth_header(self, client):
        resp = await client.get("/auth/me")
        assert resp.status_code == 401

    async def test_valid_token_works(self, client, auth_headers):
        resp = await client.get("/auth/me", headers=auth_headers)
        assert resp.status_code == 200

    async def test_password_too_short_rejected(self, client):
        resp = await client.post("/auth/register", json={
            "email": "weak@example.com",
            "username": "weakuser",
            "password": "short",
            "full_name": "Weak User"
        })
        assert resp.status_code == 422

    async def test_password_no_uppercase_rejected(self, client):
        resp = await client.post("/auth/register", json={
            "email": "weak2@example.com",
            "username": "weakuser2",
            "password": "nouppercase1!",
            "full_name": "Weak User"
        })
        assert resp.status_code == 422

    async def test_duplicate_email_rejected(self, client, registered_user):
        resp = await client.post("/auth/register", json={
            "email": "testuser@example.com",
            "username": "differentuser",
            "password": "Secure@Pass2!",
            "full_name": "Other User"
        })
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"]

    async def test_wrong_password_rejected(self, client, registered_user):
        resp = await client.post("/auth/login", json={
            "email": "testuser@example.com",
            "password": "WrongPassword1!"
        })
        assert resp.status_code == 401
        assert "Invalid email or password" in resp.json()["detail"]
