"""Tests for SSRF protection in service registration and proxy routing."""

import pytest


@pytest.fixture(autouse=True)
def _disallow_private_upstreams(monkeypatch):
    """Run SSRF tests in 'production' mode where private/loopback upstreams are blocked."""
    from gateway.config import settings
    monkeypatch.setattr(settings, "ALLOW_UPSTREAM_PRIVATE", False)
    yield


@pytest.mark.asyncio
class TestSSRFProtection:
    """Test that private/internal URLs are rejected by service registration."""

    async def test_loopback_rejected(self, client, auth_headers):
        """127.0.0.1 should be rejected as an upstream URL."""
        resp = await client.post("/services", json={
            "name": "ssrf-test",
            "upstream_url": "http://127.0.0.1:8001/internal",
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "loopback" in resp.json()["detail"].lower()

    async def test_cloud_metadata_rejected(self, client, auth_headers):
        """Cloud metadata endpoint must be blocked."""
        resp = await client.post("/services", json={
            "name": "ssrf-metadata",
            "upstream_url": "http://169.254.169.254/latest/meta-data/",
        }, headers=auth_headers)
        assert resp.status_code == 400

    async def test_invalid_scheme_rejected(self, client, auth_headers):
        """Only http/https schemes allowed."""
        resp = await client.post("/services", json={
            "name": "ssrf-file",
            # NOT file:///etc/passwd — that string trips the WAF's
            # path_traversal rule, which blocks with 403 in middleware before
            # the SSRF validator ever runs, so the test proved nothing about
            # scheme validation. ftp:// is an equally invalid scheme with no
            # traversal indicator, so the request reaches the validator.
            "upstream_url": "ftp://example.com/data",
        }, headers=auth_headers)
        assert resp.status_code == 400
        assert "http" in resp.json()["detail"].lower()

    async def test_missing_hostname_rejected(self, client, auth_headers):
        """URLs without a hostname must be rejected."""
        resp = await client.post("/services", json={
            "name": "ssrf-nohost",
            "upstream_url": "http:///path",
        }, headers=auth_headers)
        assert resp.status_code == 400
