"""
tests/integration/test_api_keys.py
-----------------------------------
Integration tests for the full API-key lifecycle:
  - Create / list / update / revoke / rotate keys
  - Proxy access via X-API-Key
  - Scope enforcement at the proxy
  - Brute-force block after repeated invalid key attempts
"""

import json
import threading
import http.server
import socketserver

import pytest
import pytest_asyncio

from tests.conftest import VALID_USER
from gateway.core.apikeys import reset_ip


# ── Helpers ──────────────────────────────────────────────────────────────────

class _EchoHandler(http.server.BaseHTTPRequestHandler):
    """Return a small JSON payload; logs the upstream headers to .last_headers."""
    last_headers: dict = {}

    def do_GET(self):
        self.__class__.last_headers = dict(self.headers)
        body = json.dumps({"upstream": "ok", "user": self.headers.get("X-Gateway-User", "")})
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.do_GET()

    def log_message(self, *_args):
        pass  # silence


@pytest_asyncio.fixture(scope="module", autouse=True)
def mock_upstream():
    """Start a tiny HTTP server on an ephemeral port as the 'data' upstream."""
    server = socketserver.TCPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    import gateway.routes.proxy as proxy_mod
    original = proxy_mod.UPSTREAM_ROUTES.copy()
    proxy_mod.UPSTREAM_ROUTES["data"] = f"http://127.0.0.1:{port}"
    yield
    proxy_mod.UPSTREAM_ROUTES.update(original)
    server.shutdown()


# ─────────────────────────────────────────────────────────────────────────────
# Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIKeyLifecycle:
    @pytest.mark.asyncio
    async def test_create_list_revoke(self, client, auth_headers):
        # Create
        resp = await client.post(
            "/api-keys",
            headers=auth_headers,
            json={"name": "test-key-1", "scopes": ["proxy:data"], "expires_in_days": 90},
        )
        assert resp.status_code == 201
        body = resp.json()
        assert body["name"] == "test-key-1"
        assert body["key"].startswith("ztg_live_")
        assert body["scopes"] == ["proxy:data"]
        assert body["revoked_at"] is None
        full_key = body["key"]
        key_id = body["id"]

        # List
        resp = await client.get("/api-keys", headers=auth_headers)
        assert resp.status_code == 200
        keys = resp.json()
        assert any(k["id"] == key_id for k in keys)
        # List must never expose the full key
        for k in keys:
            assert "key" not in k

        # Revoke
        resp = await client.post(f"/api-keys/{key_id}/revoke", headers=auth_headers)
        assert resp.status_code == 200
        assert resp.json()["revoked_at"] is not None

        # Revoked key should not work at proxy
        resp = await client.get(
            "/api/v1/data/hello",
            headers={"X-API-Key": full_key},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_rotate(self, client, auth_headers):
        resp = await client.post(
            "/api-keys",
            headers=auth_headers,
            json={"name": "rotate-me"},
        )
        key_id = resp.json()["id"]
        old_key = resp.json()["key"]

        resp = await client.post(f"/api-keys/{key_id}/rotate", headers=auth_headers)
        assert resp.status_code == 200
        new_key = resp.json()["key"]
        assert new_key != old_key
        assert new_key.startswith("ztg_live_")

        # Old key no longer works
        resp = await client.get("/api/v1/data/hello", headers={"X-API-Key": old_key})
        assert resp.status_code == 401

        # New key works
        resp = await client.get("/api/v1/data/hello", headers={"X-API-Key": new_key})
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_update_name_and_scopes(self, client, auth_headers):
        resp = await client.post(
            "/api-keys", headers=auth_headers,
            json={"name": "updatable"},
        )
        key_id = resp.json()["id"]

        resp = await client.patch(
            f"/api-keys/{key_id}", headers=auth_headers,
            json={"name": "renamed", "scopes": ["proxy:data", "proxy:payments"]},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "renamed"
        assert set(resp.json()["scopes"]) == {"proxy:data", "proxy:payments"}

    @pytest.mark.asyncio
    async def test_nonexistent_key_returns_404(self, client, auth_headers):
        resp = await client.get("/api-keys/99999", headers=auth_headers)
        assert resp.status_code == 404


# ─────────────────────────────────────────────────────────────────────────────
# Proxy via API key
# ─────────────────────────────────────────────────────────────────────────────

class TestProxyViaAPIKey:
    async def _create_key(self, client, auth_headers, scopes=None):
        resp = await client.post(
            "/api-keys",
            headers=auth_headers,
            json={"name": "proxy-test", "scopes": scopes or ["all"]},
        )
        assert resp.status_code == 201
        return resp.json()["key"]

    @pytest.mark.asyncio
    async def test_proxy_accessible_with_api_key(self, client, auth_headers, mock_upstream):
        key = await self._create_key(client, auth_headers)
        resp = await client.get("/api/v1/data/hello", headers={"X-API-Key": key})
        assert resp.status_code == 200
        data = resp.json()
        assert data["upstream"] == "ok"

    @pytest.mark.asyncio
    async def test_proxy_scope_enforced(self, client, auth_headers, mock_upstream):
        key = await self._create_key(client, auth_headers, scopes=["proxy:payments"])
        resp = await client.get("/api/v1/data/hello", headers={"X-API-Key": key})
        assert resp.status_code == 403
        assert "not authorized" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_jwt_still_works(self, client, auth_headers, mock_upstream):
        resp = await client.get("/api/v1/data/hello", headers=auth_headers)
        assert resp.status_code == 200


# ─────────────────────────────────────────────────────────────────────────────
# Brute-force block
# ─────────────────────────────────────────────────────────────────────────────

class TestAPIKeyBruteForce:
    def setup_method(self):
        reset_ip("testclient")

    @pytest.mark.asyncio
    async def test_invalid_keys_then_block(self, client):
        from gateway.core.apikeys import FAIL_LIMIT

        for _ in range(FAIL_LIMIT):
            resp = await client.get(
                "/api/v1/data/hello",
                headers={"X-API-Key": "ztg_live_INVALIDKEY0000000000000000"},
            )
            assert resp.status_code == 401

        # Next attempt should be blocked
        resp = await client.get(
            "/api/v1/data/hello",
            headers={"X-API-Key": "ztg_live_INVALIDKEY0000000000000000"},
        )
        assert resp.status_code == 403
        assert "too many" in resp.json()["detail"].lower()
