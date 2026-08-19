"""Tests verifying middleware execution order and interaction."""

import pytest


@pytest.mark.asyncio
class TestMiddlewareOrdering:
    async def test_waf_blocks_before_auth(self, client):
        """WAF should block malicious requests even without auth."""
        resp = await client.post("/api/v1/data/test", json={
            "query": "SELECT * FROM users; DROP TABLE users;--"
        })
        assert resp.status_code == 400
        assert resp.headers.get("x-waf-blocked")

    async def test_risk_score_header_on_normal_request(self, client):
        """Risk score should be present on non-exempt requests."""
        resp = await client.get("/")
        assert "x-risk-score" in resp.headers
        assert "x-risk-action" in resp.headers

    async def test_security_headers_present(self, client):
        """Security headers should be on every response."""
        resp = await client.get("/")
        assert resp.headers.get("x-content-type-options") == "nosniff"
        assert resp.headers.get("x-frame-options") == "DENY"
        assert "content-security-policy" in resp.headers
        assert resp.headers.get("referrer-policy") == "no-referrer"

    async def test_health_exempt_from_risk_scoring(self, client):
        """Health endpoints should be exempt from risk scoring."""
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "x-risk-score" not in resp.headers

    async def test_rate_limit_before_route(self, client):
        """Rate limiter should fire before the route handler."""
        for _ in range(5):
            await client.post("/auth/forgot-password", json={
                "email": "test@example.com"
            })
        resp = await client.post("/auth/forgot-password", json={
            "email": "test@example.com"
        })
        assert resp.status_code == 429
