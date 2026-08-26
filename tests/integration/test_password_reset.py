"""
tests/integration/test_password_reset.py
----------------------------------------
Regression coverage for POST /auth/reset-password.

This file exists because that endpoint was broken and 135 passing tests did not
notice. The C1 fix (commit ac54438) added
`await revoke_all_user_tokens(db, user.id)` to reset_password without importing
the name — it was imported *locally* inside refresh_token further down the same
module, so it resolved there and nowhere else. The handler therefore raised
NameError after mutating user.hashed_password and user.token_version but before
db.commit(), so the request 500'd, the session was discarded, and the reset
silently did nothing while looking like a server fault.

Nothing in the suite touched the endpoint, so nothing caught it. These tests
assert the observable contract: the reset succeeds, the new password works, and
the old one stops working.

Uses a dedicated user rather than the shared conftest one on purpose. A reset
bumps token_version, which would invalidate the session-scoped `auth_token` and
401 every later test that depends on `auth_headers`.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

OLD_PASSWORD = "Secure@Pass1"
NEW_PASSWORD = "Brand@NewPass9"


async def _make_user(client):
    """Register a throwaway user and return its email."""
    suffix = uuid.uuid4().hex[:8]
    email = f"reset-{suffix}@example.com"
    resp = await client.post("/auth/register", json={
        "email": email,
        "username": f"reset{suffix}",
        "password": OLD_PASSWORD,
        "full_name": "Reset Target",
    })
    assert resp.status_code == 201, resp.text
    return email


async def _issue_reset_token(email, *, expires_in=timedelta(hours=1)):
    """Insert a PasswordReset row directly.

    forgot-password only writes the link to the log, so there is no API surface
    that hands the token back. Inserting it is the only way to drive the reset.
    """
    from gateway.db.database import AsyncSessionLocal
    from gateway.db.models import PasswordReset

    token = uuid.uuid4().hex
    async with AsyncSessionLocal() as session:
        session.add(PasswordReset(
            email=email,
            token=token,
            expires_at=datetime.now(timezone.utc) + expires_in,
        ))
        await session.commit()
    return token


async def _login(client, email, password):
    return await client.post("/auth/login", json={"email": email, "password": password})


@pytest.mark.asyncio
async def test_reset_password_succeeds_and_swaps_credentials(client):
    """The regression test proper: this 500'd on a NameError before the fix."""
    email = await _make_user(client)
    token = await _issue_reset_token(email)

    resp = await client.post("/auth/reset-password", json={
        "token": token,
        "new_password": NEW_PASSWORD,
    })
    assert resp.status_code == 200, resp.text

    # The password actually changed — the bug left it untouched because the
    # handler died before db.commit().
    assert (await _login(client, email, NEW_PASSWORD)).status_code == 200
    assert (await _login(client, email, OLD_PASSWORD)).status_code == 401


@pytest.mark.asyncio
async def test_reset_token_is_single_use(client):
    """The row is deleted on success, so replaying the token must fail."""
    email = await _make_user(client)
    token = await _issue_reset_token(email)

    first = await client.post("/auth/reset-password", json={
        "token": token, "new_password": NEW_PASSWORD,
    })
    assert first.status_code == 200, first.text

    replay = await client.post("/auth/reset-password", json={
        "token": token, "new_password": "Another@Pass7",
    })
    assert replay.status_code == 400, replay.text


@pytest.mark.asyncio
async def test_expired_reset_token_rejected(client):
    email = await _make_user(client)
    token = await _issue_reset_token(email, expires_in=timedelta(hours=-1))

    resp = await client.post("/auth/reset-password", json={
        "token": token, "new_password": NEW_PASSWORD,
    })
    assert resp.status_code == 400, resp.text
    # Old password must still work — a rejected reset must not half-apply.
    assert (await _login(client, email, OLD_PASSWORD)).status_code == 200


@pytest.mark.asyncio
async def test_unknown_reset_token_rejected(client):
    resp = await client.post("/auth/reset-password", json={
        "token": uuid.uuid4().hex, "new_password": NEW_PASSWORD,
    })
    assert resp.status_code == 400, resp.text
