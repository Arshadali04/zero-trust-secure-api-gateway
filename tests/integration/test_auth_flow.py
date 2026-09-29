"""
tests/integration/test_auth_flow.py
-------------------------------------
Integration tests for the full auth flow:
  register → login → /auth/me → protected routes → logout

These tests run against the real FastAPI app with an in-memory SQLite DB
(injected via the conftest.py override).
"""

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# Registration
# ─────────────────────────────────────────────────────────────────────────────


class TestRegistration:
    @pytest.mark.asyncio
    async def test_register_success(self, client):
        resp = await client.post("/auth/register", json={
            "email": "newuser@example.com",
            "username": "newuser",
            "password": "Secure@Pass1",
            "full_name": "New User",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "newuser@example.com"
        assert data["username"] == "newuser"
        assert data["role"] == "user"
        assert "id" in data
        assert "hashed_password" not in data   # never exposed

    @pytest.mark.asyncio
    async def test_register_duplicate_email(self, client):
        payload = {
            "email": "dup@example.com",
            "username": "dupuser1",
            "password": "Secure@Pass1",
            "full_name": "Dup",
        }
        await client.post("/auth/register", json=payload)
        resp = await client.post("/auth/register", json={**payload, "username": "dupuser2"})
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_register_duplicate_username(self, client):
        await client.post("/auth/register", json={
            "email": "first@example.com",
            "username": "sharedname",
            "password": "Secure@Pass1",
            "full_name": "First",
        })
        resp = await client.post("/auth/register", json={
            "email": "second@example.com",
            "username": "sharedname",
            "password": "Secure@Pass1",
            "full_name": "Second",
        })
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_register_weak_password_rejected(self, client):
        resp = await client.post("/auth/register", json={
            "email": "weak@example.com",
            "username": "weakuser",
            "password": "password",   # no uppercase, no digit, no special
            "full_name": "Weak",
        })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_register_invalid_email_rejected(self, client):
        resp = await client.post("/auth/register", json={
            "email": "not-an-email",
            "username": "someuser",
            "password": "Secure@Pass1",
        })
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# Login
# ─────────────────────────────────────────────────────────────────────────────

class TestLogin:
    @pytest.mark.asyncio
    async def test_login_returns_token(self, client, registered_user):
        from tests.conftest import VALID_USER
        resp = await client.post("/auth/login", json={
            "email": VALID_USER["email"],
            "password": VALID_USER["password"],
        })
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "user" in data
        assert data["user"]["email"] == VALID_USER["email"]

    @pytest.mark.asyncio
    async def test_login_wrong_password(self, client, registered_user):
        from tests.conftest import VALID_USER
        resp = await client.post("/auth/login", json={
            "email": VALID_USER["email"],
            "password": "WrongPass@1",
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_nonexistent_user(self, client):
        resp = await client.post("/auth/login", json={
            "email": "ghost@example.com",
            "password": "Secure@Pass1",
        })
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_login_bad_email_format(self, client):
        resp = await client.post("/auth/login", json={
            "email": "not-an-email",
            "password": "Secure@Pass1",
        })
        assert resp.status_code == 422


# ─────────────────────────────────────────────────────────────────────────────
# /auth/me
# ─────────────────────────────────────────────────────────────────────────────

class TestMe:
    @pytest.mark.asyncio
    async def test_me_returns_profile(self, client, auth_headers):
        resp = await client.get("/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        from tests.conftest import VALID_USER
        assert data["email"] == VALID_USER["email"]
        assert "id" in data

    @pytest.mark.asyncio
    async def test_me_no_token_returns_403(self, client):
        resp = await client.get("/auth/me")
        assert resp.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_me_invalid_token_rejected(self, client):
        resp = await client.get("/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
# Health
# ─────────────────────────────────────────────────────────────────────────────

class TestHealth:
    @pytest.mark.asyncio
    async def test_health_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "healthy"

    @pytest.mark.asyncio
    async def test_root_ok(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "Zero Trust" in resp.json()["message"]


# ─────────────────────────────────────────────────────────────────────────────
# Admin routes
# ─────────────────────────────────────────────────────────────────────────────

class TestAdminRoutes:
    @pytest.mark.asyncio
    async def test_list_users_requires_admin(self, client, auth_headers):
        """Regular user should get 403."""
        resp = await client.get("/admin/users", headers=auth_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_audit_logs_requires_admin(self, client, auth_headers):
        resp = await client.get("/admin/audit-logs", headers=auth_headers)
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_endpoints_and_user_freeze_flow(self, client, registered_user):
        admin_data = {
            "email": "flowadmin@example.com",
            "username": "flowadmin",
            "password": "AdminSecure@Pass1",
            "full_name": "Flow Admin",
        }
        await client.post("/auth/register", json=admin_data)

        target_data = {
            "email": "targetuser@example.com",
            "username": "targetuser",
            "password": "TargetSecure@Pass1",
            "full_name": "Target User",
        }
        target_res = await client.post("/auth/register", json=target_data)
        target_id = target_res.json()["id"]

        from sqlalchemy import select

        from gateway.db.database import AsyncSessionLocal
        from gateway.db.models import User

        async with AsyncSessionLocal() as session:
            result = await session.execute(select(User).where(User.email == admin_data["email"]))
            admin = result.scalar_one_or_none()
            admin.role = "admin"
            await session.commit()
            admin_id = admin.id

        login_resp = await client.post(
            "/auth/login",
            json={"email": admin_data["email"], "password": admin_data["password"]},
        )
        admin_token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {admin_token}"}

        # 1. List users
        users_resp = await client.get("/admin/users", headers=headers)
        assert users_resp.status_code == 200
        users = users_resp.json()
        assert any(u["email"] == registered_user["email"] for u in users)

        # 2. List audit logs
        logs_resp = await client.get("/admin/audit-logs", headers=headers)
        assert logs_resp.status_code == 200

        # 3. Freeze self should fail (400)
        self_freeze = await client.post(f"/admin/users/{admin_id}/freeze", headers=headers)
        assert self_freeze.status_code == 400

        # 4. Freeze nonexistent should fail (404)
        nonexistent = await client.post("/admin/users/999999/freeze", headers=headers)
        assert nonexistent.status_code == 404

        # 5. Freeze target user should succeed (200)
        freeze_resp = await client.post(f"/admin/users/{target_id}/freeze", headers=headers)
        assert freeze_resp.status_code == 200
        assert freeze_resp.json()["message"] == "Account frozen."

        # 6. Unfreeze target user should succeed (200)
        unfreeze_resp = await client.post(f"/admin/users/{target_id}/unfreeze", headers=headers)
        assert unfreeze_resp.status_code == 200
        assert unfreeze_resp.json()["message"] == "Account unfrozen."

        # 7. Change role with query param
        role_resp = await client.patch(
            f"/admin/users/{target_id}/role?role=admin",
            headers=headers,
        )
        assert role_resp.status_code == 200
        assert role_resp.json()["role"] == "admin"
