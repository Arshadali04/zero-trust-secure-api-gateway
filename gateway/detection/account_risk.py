"""
gateway/detection/account_risk.py
---------------------------------
Persistent per-account risk score.

Unlike the per-request risk score (computed fresh by the Risk Scoring
middleware), this is a *stored* value that accumulates when the gateway
detects threats against a user's account and decays slowly over time.

  - Every security event that name a user raises their account risk.
  - Risk decays back toward zero over a few hours (half-life ~4h).
  - After RISK_LOW_AFTER_DAYS (default 7) of quiet, risk is exactly 0.0
    (Low), so the dashboard recovers fully from any past incident.
  - Survives restart (stored on the User row).

Read it via GET /auth/me  ->  user.risk_score  (decayed on every read)

Decay profile (4-hour half-life, starting from a 0.85 critical-level score):
  1 hour   → ~0.715  (still High, just under the 0.85 Critical threshold)
  4 hours  → ~0.425  (under the 0.55 step-up threshold)
  24 hours → ~0.013  (six half-lives: 0.85 × 0.5**6)
  7 days   → 0.0     (exact zero, forced by the RISK_LOW_AFTER_DAYS cutoff
                     rather than reached by decay)

The 24-hour row read "~0.05" until 2026-08-22. Nothing ever computed it; the
real figure is roughly 4x lower. Anyone sizing a "how long does a flagged
account stay flagged" window off that number was overestimating badly.
"""

import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select

from gateway.config import settings
from gateway.db.models import AccountFreeze, SecurityEvent, User

logger = logging.getLogger(__name__)

DECAY_HALF_LIFE_SECONDS = 4 * 3600   # ~4 hours

# Minimum time between two elevations of the SAME account. An attack storm
# (e.g. a flood) can produce hundreds of anomaly events per second — without
# this throttle the score would slam to 1.0 in a blink and the dashboard
# would never show the Low → Medium → High climb.
ELEVATE_COOLDOWN_SECONDS = 2.0

# After this many days of quiet (no new security events), the risk score is
# considered fully recovered and reset to 0.0 (Low).  The exponential decay
# with a 4-hour half-life already brings any score to ~0 after 7 days, but
# the explicit cutoff makes the recovery deterministic and demo-friendly.


def _risk_low_after_days() -> int:
    """Resolved per call, like the other four thresholds.

    This was a module-level constant evaluated at import, so an env change moved
    RISK_STEPUP_THRESHOLD / RISK_CRITICAL_THRESHOLD / RISK_FREEZE_SECONDS /
    RISK_STEPUP_CLEAR but silently left this one at its import-time value —
    settings applied partially, which is worse than not applying at all because
    it is invisible.
    """
    return int(getattr(settings, "RISK_LOW_AFTER_DAYS", 7))


# Back-compat module constant. Two test modules import this name directly
# (tests/unit/test_account_risk.py:12, tests/unit/test_risk_integration.py:9)
# and collection failed with ImportError when the constant became a function.
# Kept as an import-time snapshot for those callers; production code must call
# _risk_low_after_days() instead so an env override is actually honoured.
RISK_LOW_AFTER_DAYS: int = _risk_low_after_days()

# Time-based graceful degradation: if the clock is not available we fall back
# to these defaults.
_FREEZE_DEFAULT = 60 * 60  # seconds


def _naive_utc_now() -> datetime:
    """Return the current UTC time as a naive datetime.

    This used to return IST (UTC+5:30) — its own docstring said so. All five
    internal uses were self-consistent, so decay and freezes still worked, but
    every timestamp this module writes (users.risk_updated_at, stepup_since,
    account_frozen_until, account_freezes.frozen_until) landed 5h30m ahead of
    every timestamp written anywhere else (users.last_login, audit_logs.timestamp,
    security_events.timestamp, refresh_tokens.expires_at, blocked_ips.blocked_until).

    Consequence: the admin security timeline interleaved two clocks, so a freeze
    appeared to precede the event that caused it by five and a half hours — which
    makes incident reconstruction actively misleading rather than merely wrong.
    dependencies.py compares stepup_since against a JWT mfa_at (real epoch UTC),
    which was the one place the skew produced a wrong *decision*.
    """
    return datetime.now(UTC).replace(tzinfo=None)


# Rows written before the UTC correction above carry IST values, i.e. up to
# 5h30m in the future relative to a UTC "now". Left alone, an existing
# account_frozen_until would hold an account frozen for up to 5.5 extra hours,
# and a future risk_updated_at makes _decayed see a negative age and skip decay.
# Clamping anything further ahead than the longest legitimate freeze is safe in
# both directions: a genuine future timestamp can never exceed the freeze window.
_MAX_PLAUSIBLE_FUTURE_SECONDS = 6 * 3600


def _sanitize_stored(ts):
    """Treat implausibly-future stored timestamps (legacy IST rows) as 'now'."""
    if ts is None:
        return None
    try:
        if ts.tzinfo is not None:
            ts = ts.replace(tzinfo=None)
        drift = (ts - datetime.now(UTC).replace(tzinfo=None)).total_seconds()
        if drift > _MAX_PLAUSIBLE_FUTURE_SECONDS:
            logger.warning(
                "Clamping implausibly-future stored timestamp %s (drift=%.0fs) — "
                "almost certainly a pre-UTC-fix IST row.", ts, drift,
            )
            return datetime.now(UTC).replace(tzinfo=None)
    except Exception:
        return ts
    return ts


async def get_account_risk(db, user_id: int) -> float:
    """Return the current (decayed) risk for a user, 0.0 if none stored."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user or not user.risk_score:
        return 0.0
    return _decayed(user.risk_score, user.risk_updated_at)


def _decayed(base: float, updated_at) -> float:
    """Apply exponential decay (4h half-life). Returns 0.0 after RISK_LOW_AFTER_DAYS of quiet."""
    updated_at = _sanitize_stored(updated_at)
    if not updated_at:
        return max(0.0, min(base, 1.0))
    try:
        age = (_naive_utc_now() - updated_at).total_seconds()
    except Exception:
        age = 0.0
    if age <= 0:
        return max(0.0, min(base, 1.0))
    # After RISK_LOW_AFTER_DAYS the account is considered fully recovered.
    if age > _risk_low_after_days() * 86400:
        return 0.0
    half_lives = age / DECAY_HALF_LIFE_SECONDS
    return max(0.0, min(1.0, base * (0.5 ** half_lives)))


async def decay_and_persist(db, user: User) -> float:
    """Compute the time-decayed risk for *user* and persist it back to the DB.

    This is the lazy-decay entry point: whenever we READ the risk score
    (e.g. on /auth/me), we also persist the decayed value so that the
    frontend always shows the *current* risk, not the stale peak.

    Returns the decayed risk value.
    """
    if not user.risk_score or user.risk_score <= 0:
        return 0.0
    if not user.risk_updated_at:
        return min(user.risk_score, 1.0)
    decayed = _decayed(user.risk_score, user.risk_updated_at)
    # Only persist if the value actually changed (avoids a commit on every read).
    # IMPORTANT: also stamp risk_updated_at to NOW so subsequent calls compute
    # the decay from this point forward — without this, every call re-applies the
    # full decay from the original elevation timestamp, causing the score to shrink
    # by the same factor on each request (exponential double-decay bug).
    if abs((user.risk_score or 0.0) - decayed) > 1e-6:
        user.risk_score = decayed
        # risk_updated_at is the DECAY anchor and must be re-stamped here, or the
        # full decay is re-applied from the original elevation on every read.
        # It is deliberately NOT the cooldown anchor any more: because /auth/me
        # calls this function on every dashboard poll, a frontend polling faster
        # than ELEVATE_COOLDOWN_SECONDS (2.0) was permanently resetting the
        # cooldown clock, so elevate_account_risk returned early every single
        # time and the risk engine silently stopped accumulating. The cooldown
        # now reads risk_elevated_at, which only elevate_account_risk writes.
        user.risk_updated_at = _naive_utc_now()
        await db.commit()
    return decayed


def _write_policy_event(db, user: User, threat_type: str, payload: str, risk: float) -> None:
    """Persist a SecurityEvent for a policy action (step-up / freeze)."""
    try:
        db.add(SecurityEvent(
            threat_type=threat_type,
            ip_address=user.last_login_ip or "unknown",
            endpoint="/auth/me",
            payload=payload,
            risk_score=risk,
            status="flagged",
        ))
    except Exception as exc:
        logger.warning("Failed to write policy event %s: %s", threat_type, exc)


async def apply_risk_policy(db, user: User, new_risk: float, ip: str = "") -> dict:
    """
    Enforce adaptive policy based on the account's current risk score.

    `ip` is accepted and deliberately unused. It was threaded through for a
    per-IP freeze scope that was never built: the AccountFreeze row written
    below hardcodes ip_address="*" and is_user_frozen() ignores the IP too.
    The parameter is kept because three call sites and a dozen tests pass it,
    and because a real per-IP scope would want it — but nothing reads it today,
    so do not infer from the signature that freezes are address-specific.

      new_risk >= RISK_CRITICAL_THRESHOLD → auto-logout (token_version bump)
                                           + account-wide freeze for
                                             RISK_FREEZE_SECONDS
      new_risk >= RISK_STEPUP_THRESHOLD   → demand MFA step-up on sensitive routes
      new_risk <  RISK_STEPUP_CLEAR       → clear any previous step-up demand

    The freeze is account-wide for the full duration. Once critical is reached,
    every session is revoked and fresh logins are blocked until thaw.

    Returns a dict describing what changed: {"stepup": bool, "frozen": bool}.
    """
    result = {"stepup": False, "frozen": False}
    now = _naive_utc_now()

    stepup_thr = getattr(settings, "RISK_STEPUP_THRESHOLD", 0.55)
    crit_thr = getattr(settings, "RISK_CRITICAL_THRESHOLD", 0.85)
    freeze_secs = getattr(settings, "RISK_FREEZE_SECONDS", _FREEZE_DEFAULT)
    clear_thr = getattr(settings, "RISK_STEPUP_CLEAR", 0.35)

    # ── Freeze at critical (account-wide) ─────────────────────────────────────
    if new_risk >= crit_thr:
        already_frozen = False
        if user.account_frozen_until:
            try:
                fu = _sanitize_stored(user.account_frozen_until)
                already_frozen = fu >= now
            except Exception:
                already_frozen = False

        if not already_frozen:
            freeze_until = now + timedelta(seconds=freeze_secs)

            # Keep only one active freeze row for admin visibility.
            await db.execute(delete(AccountFreeze).where(AccountFreeze.user_id == user.id))
            db.add(AccountFreeze(
                user_id=user.id,
                ip_address="*",
                frozen_until=freeze_until,
            ))
            # Canonical account-wide freeze timestamp used by auth checks and UI.
            user.account_frozen_until = freeze_until
            # Auto-logout: bump the JWT version so every outstanding access
            # token dies, AND delete refresh tokens. The bump alone is not
            # enough — refresh tokens are checked against the version stored at
            # issue time, so deleting them here makes the revocation immediate
            # and unambiguous rather than relying on the next rotation.
            user.token_version = (user.token_version or 1) + 1
            # RefreshToken now lives in gateway.db.models alongside every other
            # table. Still a local import: this module is reached from
            # gateway.dependencies, and gateway.db.models is cheap to import
            # here without widening this module's import surface.
            from gateway.db.models import RefreshToken

            await db.execute(
                delete(RefreshToken).where(RefreshToken.user_id == user.id)
            )
            user.stepup_required = False
            user.stepup_since = None
            result["frozen"] = True
            logger.warning(
                "ACCOUNT FROZEN user=%s risk=%.2f until=%s (all sessions revoked)",
                user.id, new_risk, freeze_until,
            )
            _write_policy_event(
                db, user, "account_frozen",
                f"risk={new_risk:.2f} account-wide freeze {freeze_secs}s, sessions revoked",
                new_risk,
            )

    # ── Step-up at elevated risk (not already frozen) ─────────────────────────
    elif new_risk >= stepup_thr:
        if not user.stepup_required:
            user.stepup_required = True
            user.stepup_since = now
            result["stepup"] = True
            logger.warning(
                "STEP-UP REQUIRED user=%s risk=%.2f — sensitive routes demand fresh MFA",
                user.id, new_risk,
            )
            _write_policy_event(
                db, user, "risk_stepup",
                f"risk={new_risk:.2f} crossed step-up threshold",
                new_risk,
            )

    # ── Risk recovered → clear step-up demand ─────────────────────────────────
    else:
        if new_risk < clear_thr and (user.stepup_required or user.stepup_since):
            user.stepup_required = False
            user.stepup_since = None
            logger.info("Step-up demand cleared user=%s risk=%.2f", user.id, new_risk)

    return result


async def is_user_frozen(db, user_id: int, ip: str) -> bool:
    """Check whether a user is currently frozen.

    Canonical source is User.account_frozen_until; AccountFreeze rows are kept
    in sync for admin visibility and are cleaned up on expiry.

    `ip` is accepted and never read. A freeze applies to the account from every
    address, so passing the caller's IP changes nothing — tests/unit/
    test_account_risk.py:116-121 already asserts True for two different IPs.
    Kept for signature stability with the three call sites; if a per-IP scope
    is ever implemented, this is where it would be honoured.
    """
    now = _naive_utc_now()
    try:
        user_result = await db.execute(select(User).where(User.id == user_id))
        user_row = user_result.scalar_one_or_none()
        if not user_row:
            return False

        if user_row.account_frozen_until:
            fu = _sanitize_stored(user_row.account_frozen_until)
            if fu >= now:
                return True
        else:
            # Fast path for the overwhelming majority of requests: no freeze is
            # recorded, so there is nothing to clean up. Previously this function
            # fell through to an unconditional DELETE + COMMIT on *every*
            # authenticated request, which took a SQLite write lock per request
            # and — because `db` is the request-scoped session shared with the
            # route handler — also committed any unrelated pending changes the
            # handler had not finished with.
            return False

        # Freeze expired or stale rows present — clear and clean up.
        if user_row.account_frozen_until:
            user_row.account_frozen_until = None
        await db.execute(delete(AccountFreeze).where(AccountFreeze.user_id == user_id))
        await db.commit()
        return False
    except Exception as exc:
        logger.debug("is_user_frozen error (treating as not frozen): %s", exc)
        return False


async def elevate_account_risk(
    db, user_id: int, amount: float, ip: str = "", *, bypass_cooldown: bool = False
) -> float:
    """
    Raise a user's stored account risk by `amount` (capped at 1.0), stamp the
    update time, and enforce the adaptive policy (step-up / freeze).

    `ip` is forwarded to apply_risk_policy, which currently ignores it — the
    freeze it creates is account-wide, not per-address. See that function's
    docstring. Callers passing an IP here are not narrowing the blast radius.
    """
    if amount <= 0:
        return await get_account_risk(db, user_id)

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        return 0.0

    now = _naive_utc_now()

    # Throttle: if we just elevated this account, skip — the storm of events
    # will re-enter on the next tick and keep climbing the score gradually.
    #
    # bypass_cooldown exists for confirmed-malicious signals (a WAF block).
    # Those arrive *after* the per-request risk elevation has already stamped
    # risk_updated_at microseconds earlier, so the cooldown silently discarded
    # the single strongest signal the gateway produces: a request that both
    # scored >= 0.40 AND was blocked by the WAF contributed nothing extra.
    last_elevated = _sanitize_stored(
        getattr(user, "risk_elevated_at", None) or user.risk_updated_at
    )
    if last_elevated and not bypass_cooldown:
        try:
            since_last = (now - last_elevated).total_seconds()
        except Exception:
            since_last = ELEVATE_COOLDOWN_SECONDS + 1
        if since_last < ELEVATE_COOLDOWN_SECONDS:
            return _decayed(user.risk_score or 0.0, user.risk_updated_at)

    current = _decayed(user.risk_score or 0.0, user.risk_updated_at)
    new_risk = max(0.0, min(1.0, current + amount))
    user.risk_score = new_risk
    user.risk_updated_at = now      # decay anchor
    # Cooldown anchor — see decay_and_persist. This used to sit inside a
    # `try/except Exception: pass` labelled "column absent on a pre-migration
    # DB", which was misleading in two ways: risk_elevated_at IS a declared
    # column on User, so the assignment can never raise AttributeError, and a
    # genuinely missing *database* column raises OperationalError later at
    # flush, well outside this block. The guard therefore caught nothing while
    # implying the case was handled. The real protection is the idempotent
    # `ALTER TABLE users ADD COLUMN risk_elevated_at` in
    # gateway/db/database.py::_apply_column_migrations, which runs on startup.
    user.risk_elevated_at = now

    await apply_risk_policy(db, user, new_risk, ip=ip)

    await db.commit()
    logger.info("Account risk user=%s raised to %.2f (+%.2f)",
                user_id, new_risk, amount)
    return new_risk
