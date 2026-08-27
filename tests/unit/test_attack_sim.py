"""
tests/unit/test_attack_sim.py
------------------------------
Unit tests for the Attack Lab simulation engine (state machine + counters).
Uses a fake httpx.AsyncClient so it runs without a live gateway.
"""

import asyncio
import types
from unittest.mock import patch

import pytest

# ── Fake httpx so the engine never makes real network calls ──────────────────


class FakeResponse:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


class FakeLimits:
    """attack_sim builds its client with httpx.Limits(...), so the fake module
    has to expose it or _get_client raises AttributeError."""
    def __init__(self, *args, **kwargs):
        pass


class FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def aclose(self):
        # AttackLab.stop() closes the run-scoped client; without this the
        # teardown path raises on the fake.
        return None

    async def request(self, method, url, **kw):
        # The real WAF scans bodies AND headers — mirror that so tests are deterministic
        body = str(kw.get("json", ""))
        headers = str(kw.get("headers", ""))
        scanned = body.lower() + " " + headers.lower()
        if any(k in scanned for k in ("select", "drop", "union", "script", "onerror")):
            return FakeResponse(400, {"X-WAF-Blocked": "sql_injection", "X-Risk-Score": "0.92"})
        if "/auth/login" in url:
            return FakeResponse(401, {"X-Risk-Score": "0.31"})
        return FakeResponse(200, {"X-Risk-Score": "0.18", "X-Risk-Action": "allow"})


@pytest.fixture(autouse=True)
def _fake_httpx():
    """Replace httpx *on the attack_sim module*, not in sys.modules.

    This fixture used to do patch.dict(sys.modules, {"httpx": fake}), which only
    affects `import httpx` statements executed while the patch is active.
    gateway/detection/attack_sim.py:27 imports httpx at module scope, and
    conftest imports gateway.main, which pulls in the attack_lab routes, which
    import attack_sim — all before the first test runs. So the real httpx was
    already bound to attack_sim's globals and the fake never applied: the engine
    fired real requests at BASE_URL 127.0.0.1:8000, nothing was listening under
    pytest, every request errored (blocked stayed 0) and the slow connect
    failures ran the loop past its own deadline so `running` was still True at
    3.5s. That is the whole reason both of these tests failed.

    Patching the attribute works regardless of import order.
    """
    fake = types.ModuleType("httpx")
    fake.AsyncClient = FakeClient
    fake.Limits = FakeLimits
    with patch("gateway.detection.attack_sim.httpx", fake):
        yield


@pytest.mark.asyncio
async def test_sqli_attack_gets_blocked_and_logged():
    from gateway.detection.attack_sim import AttackLab

    lab = AttackLab()
    # AttackLab enforces a minimum duration of 3 seconds; pass 3 explicitly.
    lab.start("sqli", duration=3, intensity=6.0, jwt=None)
    assert lab.running
    await asyncio.sleep(3.5)
    assert not lab.running, "attack should auto-finish"

    snap = lab.snapshot()
    assert snap["total"] > 0
    assert snap["blocked"] > 0
    assert snap["errors"] == 0
    assert any(e["threat_type"] == "sql_injection" for e in snap["events"])
    assert snap["risk_samples"], "expected risk samples"
    assert set(snap["risk_samples"][0].keys()) == {"t", "score", "action"}


@pytest.mark.asyncio
async def test_bruteforce_rejected_as_access_denied():
    from gateway.detection.attack_sim import AttackLab

    lab = AttackLab()
    lab.start("bruteforce", duration=3, intensity=6.0, jwt=None)
    await asyncio.sleep(3.5)
    snap = lab.snapshot()
    assert snap["blocked"] > 0
    assert any(e["threat_type"] == "access_denied" for e in snap["events"])


@pytest.mark.asyncio
async def test_stop_cancels_running_attack():
    from gateway.detection.attack_sim import AttackLab

    lab = AttackLab()
    lab.start("flood", duration=30, intensity=4.0, jwt="FAKE")
    assert lab.running
    lab.stop()
    assert not lab.running
    # allow the task to actually cancel
    await asyncio.sleep(0.1)
