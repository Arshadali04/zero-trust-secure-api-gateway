"""Tests for WAF middleware detection accuracy and bypass resistance.

Blocked requests assert **403**, matching `gateway/middleware/waf.py:218`.
Six assertions here previously expected 400, so every positive-detection test in
this file failed on a clean checkout — the suite was red for a reason unrelated
to detection quality, which is the worst kind of red because it trains you to
ignore it. 403 is also the semantically correct code: the request syntax is
valid, the gateway is refusing to serve it. The docs were aligned to 403 in the
same pass.
"""

import pytest


@pytest.mark.asyncio
class TestWAFDetection:
    async def test_sqli_in_body(self, client):
        resp = await client.post("/auth/login", json={
            "email": "admin' OR 1=1--",
            "password": "test"
        })
        assert resp.status_code == 403
        assert resp.headers.get("x-waf-blocked") == "sql_injection"

    async def test_xss_in_body(self, client):
        resp = await client.post("/auth/register", json={
            "email": "test@test.com",
            "username": "<script>alert(1)</script>",
            "password": "Secure@Pass1",
            "full_name": "Test"
        })
        assert resp.status_code == 403
        assert resp.headers.get("x-waf-blocked") == "xss"

    async def test_path_traversal_in_url(self, client):
        resp = await client.get("/api/v1/data/../../etc/passwd")
        assert resp.status_code == 403
        assert resp.headers.get("x-waf-blocked") == "path_traversal"

    async def test_command_injection_in_header(self, client):
        # Use a payload that triggers command injection but NOT path traversal.
        # "cat /etc/passwd" also matches path_traversal (higher priority), so
        # we use a command that doesn't contain a path traversal indicator.
        resp = await client.get("/auth/mfa/status", headers={
            "User-Agent": "Mozilla/5.0; whoami",
            "Authorization": "Bearer fake"
        })
        assert resp.status_code == 403
        assert resp.headers.get("x-waf-blocked") == "command_injection"

    async def test_exempt_paths_not_scanned(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert "x-waf-blocked" not in resp.headers

    async def test_clean_request_passes(self, client):
        resp = await client.get("/")
        assert resp.status_code == 200
        assert "x-waf-blocked" not in resp.headers

    async def test_sqli_in_query_string(self, client):
        resp = await client.get("/api/v1/data/test?q=1 UNION SELECT 1,2,3--")
        assert resp.status_code == 403

    async def test_encoded_traversal(self, client):
        resp = await client.get("/api/v1/data/%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        assert resp.status_code == 403
