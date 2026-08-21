"""
tests/test_health.py
---------------------
Health / readiness endpoint tests.

Uses the async `client` fixture from conftest.py, so these must be
`async def` tests (pytest-asyncio). Both endpoints are exempt from
WAF / risk-scoring / audit-logging middleware.
"""

import pytest


@pytest.mark.asyncio
async def test_root(client):
    response = await client.get("/")
    assert response.status_code == 200
    assert "Zero Trust" in response.json()["message"]


@pytest.mark.asyncio
async def test_health_check(client):
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


@pytest.mark.asyncio
async def test_readiness_check(client):
    response = await client.get("/ready")
    assert response.status_code == 200
    assert response.json()["status"] == "ready"
