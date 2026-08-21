"""
tests/unit/test_attack_sim.py
------------------------------
Unit tests for the Attack Lab simulation engine (state machine + counters).
Uses a fake httpx.AsyncClient so it runs without a live gateway.
"""

import asyncio
import sys
import types
from unittest.mock import patch

import pytest

# ── Fake httpx so the engine never makes real network calls ──────────────────
class FakeResponse:
    def __init__(self, status, headers=None):
        self.status_code = status
        self.headers = headers or {}


class FakeClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

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
    fake = types.ModuleType("httpx")
    fake.AsyncClient = FakeClient
    with patch.dict(sys.modules, {"httpx": fake}):
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
