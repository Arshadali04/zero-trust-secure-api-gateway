"""Tests for rate limiting middleware."""

import pytest


@pytest.mark.asyncio
class TestRateLimiting:
    async def test_auth_endpoint_rate_limit(self, client):
        """Auth endpoints should be rate-limited at 10 req/60s."""
        for i in range(10):
            await client.post("/auth/login", json={
                "email": "ratelimit@example.com", "password": "wrong12345"
            })
        resp = await client.post("/auth/login", json={
            "email": "ratelimit@example.com", "password": "wrong12345"
        })
        assert resp.status_code == 429
        assert "retry_after_seconds" in resp.json()

    async def test_rate_limit_headers_present(self, client):
        """Responses should include rate limit headers."""
        resp = await client.get("/")
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers
        assert "x-ratelimit-window" in resp.headers

    async def test_options_not_rate_limited(self, client):
        """OPTIONS preflight should never be rate limited."""
        for _ in range(15):
            resp = await client.options("/auth/login")
            assert resp.status_code != 429
