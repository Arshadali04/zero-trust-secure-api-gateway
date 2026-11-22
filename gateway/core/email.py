"""
gateway/core/email.py
---------------------
Email notification service for Zero Trust Gateway security events:
  - Password reset links (forgot password)
  - Account frozen security alerts (critical risk violation)
  - Password changed confirmation notices

Fault-tolerant design:
  - Supports standard SMTP (STARTTLS or SSL), e.g. Gmail, SendGrid, Amazon SES, Mailtrap, or local Postfix.
  - Non-blocking: executes network operations in a worker thread via asyncio.to_thread.
  - Safe fallback: if SMTP is disabled, credentials are missing, or the network is unreachable,
    the event is logged cleanly to the audit logger and stored in the dev outbox.
  - Never raises unhandled exceptions to callers so business logic (reset/freeze) is never disrupted.
"""

import asyncio
from collections import deque
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import smtplib
from typing import Any

from gateway.config import settings

logger = logging.getLogger(__name__)

# In-memory dev outbox: stores recent dispatched emails for testing and local development inspection
_outbox: deque[dict[str, Any]] = deque(maxlen=100)


def get_outbox() -> list[dict[str, Any]]:
    """Return all dispatched emails in the in-memory outbox."""
    return list(_outbox)


def clear_outbox() -> None:
    """Clear all records from the in-memory outbox."""
    _outbox.clear()


# ── HTML Template Generators ────────────────────────────────────────────────

def _render_base_email(title: str, subtitle: str, content_html: str, badge_text: str = "Security Notice", badge_color: str = "#5b8cff") -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0a0e14; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #f0f4ff;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background-color: #0a0e14; padding: 40px 15px;">
    <tr>
      <td align="center">
        <table role="presentation" width="100%" style="max-width: 580px; background-color: #0f1620; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; overflow: hidden; box-shadow: 0 12px 36px rgba(0,0,0,0.5);">
          <!-- Header -->
          <tr>
            <td style="padding: 32px 36px 20px 36px; border-bottom: 1px solid rgba(255,255,255,0.06);">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                <tr>
                  <td>
                    <span style="font-size: 20px; font-weight: 700; color: #f0f4ff; letter-spacing: -0.5px;">Zero<span style="color: #5b8cff;">Trust</span> <span style="font-size: 13px; font-weight: 500; color: rgba(240,244,255,0.55); margin-left: 6px;">Gateway</span></span>
                  </td>
                  <td align="right">
                    <span style="display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(91,140,255,0.12); color: {badge_color}; border: 1px solid {badge_color}33;">{badge_text}</span>
                  </td>
                </tr>
              </table>
              <h1 style="margin: 24px 0 6px 0; font-size: 22px; font-weight: 700; color: #ffffff; letter-spacing: -0.4px;">{title}</h1>
              <p style="margin: 0; font-size: 14px; color: rgba(240,244,255,0.65);">{subtitle}</p>
            </td>
          </tr>
          <!-- Body Content -->
          <tr>
            <td style="padding: 28px 36px 36px 36px; font-size: 14px; line-height: 1.65; color: #e2e8f0;">
              {content_html}
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="padding: 20px 36px; background-color: #0b1017; border-top: 1px solid rgba(255,255,255,0.05); font-size: 12px; color: rgba(240,244,255,0.4); text-align: center;">
              This is an automated security transmission from Zero Trust API Gateway.<br>
              If you did not initiate this action, please review your active security sessions immediately.
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""


# ── Core Dispatcher ──────────────────────────────────────────────────────────

def _send_smtp_sync(to_email: str, subject: str, html_content: str, text_content: str) -> None:
    """Synchronous worker that performs the actual SMTP protocol communication."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM
    msg["To"] = to_email
    msg["Date"] = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S +0000")

    msg.attach(MIMEText(text_content, "plain", "utf-8"))
    msg.attach(MIMEText(html_content, "html", "utf-8"))

    host = settings.SMTP_HOST
    port = settings.SMTP_PORT
    user = settings.SMTP_USER
    pwd = settings.SMTP_PASSWORD
    timeout = getattr(settings, "SMTP_TIMEOUT", 10)

    if settings.SMTP_SSL:
        with smtplib.SMTP_SSL(host, port, timeout=timeout) as server:
            if user and pwd:
                server.login(user, pwd)
            server.send_message(msg)
    else:
        with smtplib.SMTP(host, port, timeout=timeout) as server:
            if settings.SMTP_TLS:
                server.starttls()
            if user and pwd:
                server.login(user, pwd)
            server.send_message(msg)


async def send_email(to_email: str, subject: str, html_content: str, text_content: str) -> dict[str, Any]:
    """
    Send an email asynchronously without blocking the event loop.
    Falls back gracefully to logging and mock delivery if SMTP is unconfigured or fails.
    """
    record: dict[str, Any] = {
        "to": to_email,
        "subject": subject,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "html": html_content,
        "text": text_content,
        "sent": False,
        "mode": "dev_mock",
        "error": None,
    }

    # Check if real SMTP sending is requested & configured
    can_send_smtp = (
        bool(settings.EMAIL_ENABLED) and
        bool(settings.SMTP_HOST) and
        bool(settings.SMTP_USER)
    )

    if can_send_smtp:
        try:
            await asyncio.to_thread(_send_smtp_sync, to_email, subject, html_content, text_content)
            record["sent"] = True
            record["mode"] = "smtp"
            logger.info("EMAIL SENT [SMTP] | to=%s subject='%s'", to_email, subject)
        except Exception as exc:
            record["sent"] = False
            record["mode"] = "smtp_error"
            record["error"] = str(exc)
            logger.warning("EMAIL DELIVERY FAILED [SMTP] | to=%s err=%s — falling back to mock outbox", to_email, exc)
    else:
        # Dev / Test mode — log preview to console and record in outbox
        record["sent"] = True
        record["mode"] = "dev_mock"
        logger.info(
            "EMAIL DISPATCHED [DEV MOCK] | to=%s subject='%s'\nPreview:\n%s",
            to_email, subject, text_content[:260],
        )

    _outbox.append(record)
    return record


# ── High-Level Security Event Notifications ──────────────────────────────────

async def send_password_reset_email(to_email: str, reset_link: str) -> dict[str, Any]:
    """
    Dispatch a password reset link to the user.
    """
    subject = "Reset your Zero Trust Gateway password"
    title = "Password Reset Request"
    subtitle = "Secure link to reset your account credentials"

    content_html = f"""
      <p style="margin-top: 0;">We received a request to reset the password for your Zero Trust Gateway account (<strong>{to_email}</strong>).</p>
      <p>Click the button below to choose a new, secure password:</p>
      
      <div style="text-align: center; margin: 32px 0;">
        <a href="{reset_link}" style="display: inline-block; background: linear-gradient(135deg, #5b8cff, #3867d6); color: #ffffff; text-decoration: none; padding: 12px 28px; border-radius: 6px; font-weight: 600; font-size: 15px; box-shadow: 0 4px 16px rgba(91,140,255,0.35);">Reset Password</a>
      </div>

      <div style="background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; padding: 14px 16px; margin: 24px 0;">
        <span style="font-size: 12px; color: rgba(240,244,255,0.55); display: block; margin-bottom: 6px;">Or paste this secure URL directly into your browser:</span>
        <code style="font-size: 12px; font-family: monospace; color: #5b8cff; word-break: break-all;">{reset_link}</code>
      </div>

      <p style="font-size: 13px; color: rgba(240,244,255,0.65); margin-bottom: 0;">
        <strong>Notice:</strong> This single-use link expires in <strong>15 minutes</strong>. If you did not request a password reset, you can safely ignore this email — your existing password remains unchanged.
      </p>
    """

    content_text = f"""Zero Trust Gateway — Password Reset Request
==================================================

We received a request to reset the password for: {to_email}

Use the link below to set a new password:
{reset_link}

This link is valid for 15 minutes.
If you did not request this reset, no action is required — your credentials remain secure.
"""

    html = _render_base_email(title, subtitle, content_html, badge_text="Auth Gate", badge_color="#5b8cff")
    return await send_email(to_email, subject, html, content_text)


async def send_account_frozen_email(to_email: str, reason: str, until: datetime | str) -> dict[str, Any]:
    """
    Dispatch a critical security notification when an account is frozen.
    """
    subject = "Security Alert: Your Zero Trust Gateway account has been temporarily frozen"
    title = "Account Temporarily Frozen"
    subtitle = "Zero Trust security policy violation detected"

    until_str = until.strftime("%Y-%m-%d %H:%M:%S UTC") if isinstance(until, datetime) else str(until)

    content_html = f"""
      <div style="background: rgba(255,93,93,0.1); border-left: 4px solid #ff5d5d; padding: 14px 18px; border-radius: 4px; margin-bottom: 20px;">
        <strong style="color: #ff5d5d; font-size: 14px;">High-Severity Security Event Triggered</strong>
        <p style="margin: 6px 0 0 0; font-size: 13px; color: rgba(240,244,255,0.85);">
          Your account was temporarily suspended to protect gateway resources and sensitive APIs against unauthorized or abnormal activity.
        </p>
      </div>

      <table role="presentation" width="100%" style="background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); border-radius: 8px; margin: 20px 0; font-size: 13px;" cellpadding="10">
        <tr>
          <td style="color: rgba(240,244,255,0.55); width: 140px;">Account Email:</td>
          <td style="color: #f0f4ff; font-weight: 600;">{to_email}</td>
        </tr>
        <tr>
          <td style="color: rgba(240,244,255,0.55);">Trigger Reason:</td>
          <td style="color: #ffb636;">{reason}</td>
        </tr>
        <tr>
          <td style="color: rgba(240,244,255,0.55);">Frozen Until:</td>
          <td style="color: #f0f4ff; font-family: monospace;">{until_str}</td>
        </tr>
        <tr>
          <td style="color: rgba(240,244,255,0.55);">Active Sessions:</td>
          <td style="color: #2dd4a0;">All existing JWT & refresh tokens revoked</td>
        </tr>
      </table>

      <p style="font-size: 13px; color: rgba(240,244,255,0.7); line-height: 1.6;">
        <strong>What happens now?</strong><br>
        Your account will remain locked until the freeze window expires at <code>{until_str}</code>. Once the freeze elapses, your risk score will normalize through adaptive decay, and you will be able to log in normally.
      </p>

      <p style="font-size: 12px; color: rgba(240,244,255,0.5); margin-bottom: 0;">
        If you suspect your credentials have been compromised, please contact your security administrator immediately.
      </p>
    """

    content_text = f"""Zero Trust Gateway — Security Alert: Account Temporarily Frozen
==================================================================

Account: {to_email}
Trigger Reason: {reason}
Frozen Until: {until_str}
Action Taken: Account locked, all active tokens revoked.

Your account was temporarily suspended by the Zero Trust adaptive risk engine.
Access will be restored once the freeze window expires.
If you did not cause this activity, contact your gateway administrator.
"""

    html = _render_base_email(title, subtitle, content_html, badge_text="Incident Alert", badge_color="#ff5d5d")
    return await send_email(to_email, subject, html, content_text)


async def send_password_changed_email(to_email: str) -> dict[str, Any]:
    """
    Dispatch a security confirmation notice when a user's password is changed or reset.
    """
    subject = "Security Notice: Your Zero Trust Gateway password was changed"
    title = "Password Successfully Updated"
    subtitle = "Confirmation of credentials modification"

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    content_html = f"""
      <p style="margin-top: 0;">This email confirms that the password for your Zero Trust Gateway account (<strong>{to_email}</strong>) was successfully changed on <strong>{now_str}</strong>.</p>
      
      <div style="background: rgba(45,212,160,0.08); border-left: 4px solid #2dd4a0; padding: 12px 16px; border-radius: 4px; margin: 20px 0; font-size: 13px; color: #e2e8f0;">
        <strong>Security Enforced:</strong> All previous sessions and refresh tokens have been revoked. Any client or application using your old credentials must sign in again.
      </div>

      <p style="font-size: 13px; color: rgba(240,244,255,0.65); margin-bottom: 0;">
        If you performed this change, no further action is necessary.<br>
        <strong style="color: #ff5d5d;">If you did NOT change your password</strong>, your account may be compromised. Please notify your security team immediately.
      </p>
    """

    content_text = f"""Zero Trust Gateway — Security Notice: Password Changed
============================================================

Your account password for {to_email} was changed on {now_str}.
All prior sessions and tokens have been revoked.

If you made this change, you can safely disregard this message.
If you did NOT make this change, please contact security immediately.
"""

    html = _render_base_email(title, subtitle, content_html, badge_text="Security Update", badge_color="#2dd4a0")
    return await send_email(to_email, subject, html, content_text)

