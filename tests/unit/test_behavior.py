"""
tests/unit/test_behavior.py
---------------------------
Tests for the rule-based behavior anomaly detector.

Exercises the threshold rule against a fake profile + session so no DB or
scikit-learn is required:

  - a sustained burst (flood) must trip behavior_anomaly
  - a polluted baseline (from earlier long floods) must NOT make the
    threshold unreachable — the clamp keeps it triggerable
  - normal low-rate traffic must stay quiet
"""

import asyncio

import pytest


class FakeProfile:
    def __init__(self, baseline: float):
        self.avg_requests_per_minute = baseline
        self.anomaly_count = 0
        self.last_seen_ip = None
        self.last_seen_at = None


class FakeResult:
    def __init__(self, profile):
        self._p = profile

    def scalar_one_or_none(self):
        return self._p


class FakeSession:
    """Minimal session that returns a profile and records commits."""

    def __init__(self, profile):
        self.profile = profile
        self.added = []
        self.commits = 0

    async def execute(self, stmt):
        return FakeResult(self.profile)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        self.commits += 1


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset the in-memory request counters between tests."""
    from gateway.detection.behavior import _user_requests
    _user_requests.clear()
    yield
    _user_requests.clear()


def _simulate_flood(user_id, rps, seconds, baseline):
    """Feed the real detector at a steady request rate and count anomalies."""
    from gateway.detection.behavior import update_behavior_profile

    async def run():
        session = FakeSession(FakeProfile(baseline))
        anomalies = []
        for _ in range(int(rps * seconds)):
            # update_behavior_profile records the request itself and applies
            # the rule — this is the same call the logging middleware makes.
            res = await update_behavior_profile(user_id, "10.0.0.1", session,
                                                body_bytes=400, hour=14)
            if res and res["threat_type"] == "behavior_anomaly":
                anomalies.append(res)
        return anomalies, session

    return asyncio.run(run())


def test_flood_triggers_behavior_anomaly():
    """A 6 rps flood (60 requests) must produce behavior anomalies.

    The hard floor on the threshold is max(50, baseline*3). With baseline=5.0
    the threshold is 50/min, so we need >50 requests in the 60-second window.
    60 requests (6 rps × 10 s) crosses the floor on the 51st request.
    """
    anomalies, session = _simulate_flood(1, rps=6, seconds=10, baseline=5.0)
    assert anomalies, "flood should trip behavior_anomaly at least once"
    assert session.commits > 0


def test_polluted_baseline_still_triggers():
    """A baseline polluted to 250 (old fast-blend behavior) must stay triggerable.

    The clamp caps baseline at 10, so threshold = max(50, 10*3) = 50.
    A 60-request flood (6 rps × 10 s) still trips it.
    """
    anomalies, _ = _simulate_flood(2, rps=6, seconds=10, baseline=250.0)
    assert anomalies, "clamp must keep the threshold reachable"


def test_normal_traffic_stays_quiet():
    """Low-rate sustained traffic must not trigger the detector."""
    from gateway.detection.behavior import update_behavior_profile

    async def run():
        session = FakeSession(FakeProfile(5.0))
        # ~10 requests — far below the 30/min floor
        for _ in range(10):
            res = await update_behavior_profile(3, "10.0.0.2", session,
                                                body_bytes=300, hour=12)
            if res and res["threat_type"] == "behavior_anomaly":
                return False
        return True

    assert asyncio.run(run())
