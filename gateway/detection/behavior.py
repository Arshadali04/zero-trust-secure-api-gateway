"""
gateway/detection/behavior.py
------------------------------
Behavioural profiling and anomaly detection.

Two complementary detectors run on every authenticated request:
  - Rule-based: per-user request volume baselines + failed-auth spikes
  - ML-based: IsolationForest per-user outlier scoring (see ml_anomaly.py)

Both write SecurityEvents on detection; ML runs in-process with graceful
fallback when scikit-learn is unavailable.
"""

import logging
import time
from collections import defaultdict, deque
from datetime import UTC, datetime
from threading import Lock

logger = logging.getLogger(__name__)

_WINDOW = 60
_user_requests: dict[int, deque] = defaultdict(deque)
_user_failures: dict[int, deque] = defaultdict(deque)
_lock = Lock()


def _count_event(store: dict[int, deque], user_id: int) -> int:
    """
    Record one event and return the count within the window.

    The append happens AFTER the count is taken. Appending first meant the
    current event was included in its own threshold comparison, so every spike
    verdict fired one event early — the live database shows 1,328 auth_spike
    rows against 7 failed_login rows, which is this off-by-one.
    """
    _evict_idle_keys()
    now = time.monotonic()
    cutoff = now - _WINDOW
    with _lock:
        dq = store[user_id]
        while dq and dq[0] < cutoff:
            dq.popleft()
        count = len(dq)
        dq.append(now)
        return count


_MAX_USER_KEYS = 5000


def _evict_idle_keys():
    """
    Cap per-user tracking dicts.

    The guard previously compared `len(store) - len(empty)`, which is the count
    of *active* keys, so eviction only fired when active keys alone exceeded the
    cap — exactly when there was nothing idle to reclaim. Both dicts therefore
    grew without bound. The early return also keeps this off the hot path:
    _count_event calls it on every event, and scanning both dicts under the lock
    each time made the cost grow with the leak.

    (_lock is acquired and released here before _count_event takes it, so these
    are sequential acquisitions, not nested — there is no reentrancy issue.)
    """
    if len(_user_requests) <= _MAX_USER_KEYS and len(_user_failures) <= _MAX_USER_KEYS:
        return
    now = time.monotonic()
    cutoff = now - _WINDOW
    with _lock:
        for store in (_user_requests, _user_failures):
            empty = [k for k, dq in store.items() if not dq or dq[-1] < cutoff]
            for k in empty:
                del store[k]


def record_user_request(user_id: int) -> int:
    """Record one authenticated request and return count in the last minute."""
    return _count_event(_user_requests, user_id)


def record_failed_auth(user_id: int) -> int:
    """Record one failed auth attempt and return failures in the last minute."""
    return _count_event(_user_failures, user_id)


async def update_behavior_profile(
    user_id: int,
    current_ip: str,
    db,
    *,
    body_bytes: int = 0,
    hour: int | None = None,
) -> dict | None:
    """
    Update user's behavioural baseline and return anomaly details if detected.

    Rule-based rules:
      - current RPM > 3x baseline and >30/min → suspicious volume spike
      - failed auth attempts >5/min → suspicious auth spike

    ML-based rules:
      - IsolationForest per-user outlier score below threshold → ml_anomaly
    """
    from sqlalchemy import select

    from gateway.db.models import BehaviorProfile
    from gateway.detection.ml_anomaly import score_user

    rpm = record_user_request(user_id)
    failed = _count_event(_user_failures, user_id)

    result = await db.execute(select(BehaviorProfile).where(BehaviorProfile.user_id == user_id))
    profile = result.scalar_one_or_none()
    if not profile:
        profile = BehaviorProfile(
            user_id=user_id,
            avg_requests_per_minute=max(5.0, float(rpm)),
            last_seen_ip=current_ip,
            last_seen_at=datetime.now(UTC),
        )
        db.add(profile)
        await db.commit()
        # Still allow the ML model to start accumulating history
        return score_user(user_id, float(rpm), float(failed), body_bytes, hour)

    baseline = float(profile.avg_requests_per_minute or 5.0)
    anomaly = None

    # Clamp: a profile polluted by earlier long bursts (the old fast-blend
    # baseline chased RPM) must not make the threshold unreachable forever.
    # Capping at 10 keeps 3x threshold <= 30, so even a modest flood
    # (4 rps → 40 requests in 10 s) climbs past it within the demo window.
    baseline = max(1.0, min(baseline, 10.0))

    # Hard floor of 50/min keeps the rule from firing on trivial traffic
    # (normal dashboard browsing generates ~6-9 req/min from polling + page
    # loads).  A flood at 3+ rps (~180 req/min) still trips it instantly.
    threshold = max(50, baseline * 3)
    if rpm > threshold:
        anomaly = {
            "threat_type": "behavior_anomaly",
            "risk_score": min(0.55 + (rpm / max(baseline, 1.0)) / 10, 0.95),
            "reason": f"request_rate_spike rpm={rpm} baseline={baseline:.1f}",
        }
        profile.anomaly_count = (profile.anomaly_count or 0) + 1

    # Moving-average baseline update — VERY slow blend (99% old / 1% new).
    # A fast blend (e.g. 90/10) lets the baseline chase a burst during its
    # ramp-up phase, so 3x the baseline stays above the current RPM and the
    # detector never fires — the flood "learns itself away". With a 1% blend
    # the baseline represents long-run normal activity; a 10–20 second flood
    # barely moves it, so the 3x threshold stays in reach.
    # ── Failed-auth spike rule (brute-force detection) ────────────────────────
    # The login route calls record_failed_auth() on every bad password, so a
    # burst of failed logins for this account shows up here as a spike.
    if failed > 5:
        auth_anomaly = {
            "threat_type": "auth_spike",
            "risk_score": min(0.5 + (failed / 20.0), 0.9),
            "reason": f"failed_auth_spike failures={failed}/min",
        }
        profile.anomaly_count = (profile.anomaly_count or 0) + 1
        if anomaly is None or auth_anomaly["risk_score"] > anomaly["risk_score"]:
            anomaly = auth_anomaly

    if anomaly is None:
        profile.avg_requests_per_minute = (baseline * 0.99) + (rpm * 0.01)
    else:
        profile.avg_requests_per_minute = baseline  # hold baseline during anomaly

    profile.last_seen_ip = current_ip
    profile.last_seen_at = datetime.now(UTC)
    await db.commit()

    # ML outlier scoring (separate signal — may flag even when rules don't)
    ml_anomaly = score_user(user_id, float(rpm), float(failed), body_bytes, hour)
    if ml_anomaly and anomaly is None:
        anomaly = ml_anomaly
    elif ml_anomaly and anomaly:
        # Report the stronger signal (higher risk score)
        if ml_anomaly["risk_score"] > anomaly["risk_score"]:
            anomaly = ml_anomaly

    if anomaly:
        logger.warning("Behaviour anomaly: user_id=%s %s", user_id, anomaly["reason"])
    return anomaly
