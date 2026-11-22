"""
tests/unit/test_email_service.py
--------------------------------
Unit tests for the Zero Trust Gateway email notification service:
  - Password reset link email dispatch
  - Account frozen security alert dispatch
  - Password changed confirmation dispatch
  - Fault tolerance (SMTP errors never disrupt business logic)
  - Integration with POST /auth/forgot-password
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from gateway.core.email import (
    clear_outbox,
    get_outbox,
    send_account_frozen_email,
    send_email,
    send_password_changed_email,
    send_password_reset_email,
)


@pytest.fixture(autouse=True)
def _clean_outbox(monkeypatch):
    from gateway.config import settings
    monkeypatch.setattr(settings, "EMAIL_ENABLED", False)
    monkeypatch.setattr(settings, "SMTP_USER", "")
    clear_outbox()
    yield
    clear_outbox()


@pytest.mark.asyncio
async def test_password_reset_email_dev_mock():
    """Verify password reset email generation, outbox recording, and link contents."""
    to_email = "target_user@example.com"
    reset_link = "http://127.0.0.1:8000/frontend/reset-password.html#token=abc123xyz"

    result = await send_password_reset_email(to_email, reset_link)

    assert result["sent"] is True
    assert result["mode"] == "dev_mock"
    assert result["to"] == to_email
    assert "Reset your Zero Trust Gateway password" in result["subject"]
    assert reset_link in result["html"]
    assert reset_link in result["text"]

    outbox = get_outbox()
    assert len(outbox) == 1
    assert outbox[0]["to"] == to_email


@pytest.mark.asyncio
async def test_account_frozen_email_dev_mock():
    """Verify security alert dispatch when an account is frozen."""
    to_email = "compromised_user@example.com"
    reason = "Risk score 0.95 exceeded critical threshold 0.85"
    freeze_until = datetime.now(timezone.utc) + timedelta(hours=1)

    result = await send_account_frozen_email(to_email, reason, freeze_until)

    assert result["sent"] is True
    assert result["to"] == to_email
    assert "Security Alert: Your Zero Trust Gateway account has been temporarily frozen" in result["subject"]
    assert "High-Severity Security Event" in result["html"]
    assert reason in result["html"]
    assert reason in result["text"]

    outbox = get_outbox()
    assert len(outbox) == 1
    assert outbox[0]["to"] == to_email


@pytest.mark.asyncio
async def test_password_changed_email_dev_mock():
    """Verify security confirmation dispatch when password is updated."""
    to_email = "changed_user@example.com"

    result = await send_password_changed_email(to_email)

    assert result["sent"] is True
    assert result["to"] == to_email
    assert "Security Notice: Your Zero Trust Gateway password was changed" in result["subject"]
    assert "All previous sessions and refresh tokens have been revoked" in result["html"]

    outbox = get_outbox()
    assert len(outbox) == 1


@pytest.mark.asyncio
async def test_smtp_delivery_and_error_handling():
    """Verify that SMTP failure falls back gracefully to logging without raising exceptions."""
    with patch("gateway.config.settings.EMAIL_ENABLED", True), \
         patch("gateway.config.settings.SMTP_HOST", "invalid.smtp.host.local"), \
         patch("gateway.config.settings.SMTP_USER", "user@example.com"), \
         patch("gateway.config.settings.SMTP_PASSWORD", "secret"):

        # Mock _send_smtp_sync to raise an SMTPException
        with patch("gateway.core.email._send_smtp_sync", side_effect=Exception("SMTP Connection refused")):
            res = await send_email(
                "fail_target@example.com",
                "Test Subject",
                "<p>Test HTML</p>",
                "Test Text",
            )
            # Should NOT raise, must record mode and error gracefully
            assert res["sent"] is False
            assert res["mode"] == "smtp_error"
            assert "Connection refused" in res["error"]
            assert len(get_outbox()) == 1


@pytest.mark.asyncio
async def test_forgot_password_route_dispatches_email(client):
    """Verify that POST /auth/forgot-password triggers email generation for registered users."""
    import uuid
    suffix = uuid.uuid4().hex[:6]
    email = f"forgot_{suffix}@example.com"

    # Register user
    reg = await client.post("/auth/register", json={
        "email": email,
        "username": f"forgot{suffix}",
        "password": "Password123!",
        "full_name": "Forgot Test",
    })
    assert reg.status_code == 201

    clear_outbox()

    # Request password reset
    resp = await client.post("/auth/forgot-password", json={"email": email})
    assert resp.status_code == 200

    # Wait brief moment for background task
    await asyncio.sleep(0.1)

    outbox = get_outbox()
    assert len(outbox) == 1
    assert outbox[0]["to"] == email
    assert "Reset your Zero Trust Gateway password" in outbox[0]["subject"]
    assert "reset-password.html#token=" in outbox[0]["html"]


@pytest.mark.asyncio
async def test_account_freeze_dispatches_email():
    """Verify that enforcing critical risk policy triggers an account-frozen alert email."""
    from gateway.db.database import AsyncSessionLocal
    from gateway.db.models import User
    from gateway.detection.account_risk import apply_risk_policy

    async with AsyncSessionLocal() as session:
        user = User(
            email="frozen_target@example.com",
            username="frozentarget",
            hashed_password="hash",
            role="user",
            is_active=True,
            risk_score=0.1,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)

        clear_outbox()

        # Enforce adaptive policy with critical risk 0.95
        res = await apply_risk_policy(session, user, new_risk=0.95)
        assert res["frozen"] is True
        assert user.account_frozen_until is not None

    # Wait for background task
    await asyncio.sleep(0.1)

    outbox = get_outbox()
    assert len(outbox) == 1
    assert outbox[0]["to"] == "frozen_target@example.com"
    assert "Security Alert: Your Zero Trust Gateway account has been temporarily frozen" in outbox[0]["subject"]
    assert "0.95" in outbox[0]["html"]


@pytest.mark.asyncio
async def test_reset_password_dispatches_confirmation_email(client):
    """Verify that successfully resetting a password sends a confirmation notice."""
    import uuid
    suffix = uuid.uuid4().hex[:6]
    email = f"confirm_{suffix}@example.com"

    # Register user
    reg = await client.post("/auth/register", json={
        "email": email,
        "username": f"confirm{suffix}",
        "password": "OldPassword123!",
        "full_name": "Confirm Test",
    })
    assert reg.status_code == 201

    clear_outbox()

    # Request reset token
    await client.post("/auth/forgot-password", json={"email": email})
    await asyncio.sleep(0.1)

    outbox = get_outbox()
    assert len(outbox) == 1
    # Extract token from HTML link
    import re
    match = re.search(r"#token=([a-zA-Z0-9_\-]+)", outbox[0]["html"])
    assert match is not None
    token = match.group(1)

    clear_outbox()

    # Reset password with the token
    resp = await client.post("/auth/reset-password", json={
        "token": token,
        "new_password": "NewBrandPassword456!",
    })
    assert resp.status_code == 200

    await asyncio.sleep(0.1)

    # Confirmation email should be dispatched
    outbox2 = get_outbox()
    assert len(outbox2) == 1
    assert outbox2[0]["to"] == email
    assert "Security Notice: Your Zero Trust Gateway password was changed" in outbox2[0]["subject"]
