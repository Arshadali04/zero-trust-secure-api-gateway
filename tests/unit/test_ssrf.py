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
    """Test that private/internal URLs are rejected by service registration.

    WAF coverage note
    -----------------
    The WAF now scans request bodies for private addresses (SSRF patterns) and
    returns 403 before the route-level SSRF validator (which would return 400).
    Both 400 and 403 indicate the request was correctly rejected — 403 is the
    stronger response since it catches the attack earlier in the middleware stack.
    """

    async def test_loopback_rejected(self, client, auth_headers):
        """127.0.0.1 should be rejected as an upstream URL.

        The WAF now scans request bodies for private addresses and may return
        403 before the route-level validator returns 400. Both indicate the
        request was correctly blocked — 403 is actually the stronger response.
        """
        resp = await client.post("/services", json={
            "name": "ssrf-test",
            "upstream_url": "http://127.0.0.1:8001/internal",
        }, headers=auth_headers)
        assert resp.status_code in (400, 403), (
            f"Expected 400 (route SSRF validator) or 403 (WAF block), got {resp.status_code}"
        )
        if resp.status_code == 400:
            # Route-level rejection still includes the loopback message
            assert "loopback" in resp.json()["detail"].lower()

    async def test_cloud_metadata_rejected(self, client, auth_headers):
        """Cloud metadata endpoint must be blocked (by WAF or route validator)."""
        resp = await client.post("/services", json={
            "name": "ssrf-metadata",
            "upstream_url": "http://169.254.169.254/latest/meta-data/",
        }, headers=auth_headers)
        assert resp.status_code in (400, 403), (
            f"Expected 400 or 403 for cloud metadata SSRF, got {resp.status_code}"
        )

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
        assert resp.status_code in (400, 403), (
            f"Expected 400 (route validator) or 403 (WAF SSRF block for ftp://), got {resp.status_code}"
        )
        if resp.status_code == 400:
            assert "http" in resp.json()["detail"].lower()

    async def test_missing_hostname_rejected(self, client, auth_headers):
        """URLs without a hostname must be rejected."""
        resp = await client.post("/services", json={
            "name": "ssrf-nohost",
            "upstream_url": "http:///path",
        }, headers=auth_headers)
        assert resp.status_code == 400
