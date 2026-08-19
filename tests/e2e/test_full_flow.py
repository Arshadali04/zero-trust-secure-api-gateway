"""
tests/e2e/test_full_flow.py
----------------------------
End-to-end test covering the complete user journey:

  1. Register a brand-new account
  2. Log in and obtain a JWT
  3. Register a backend service (duplicate name must be rejected)
  4. Create a scoped API key for that service
  5. Proxy an authenticated request through the gateway using the API key
  6. Revoke the key → the same proxy call must now fail
  7. Delete the service → proxy must return 404

This mirrors exactly what a demonstrator would show at a defense:
register → key → proxy → revoke → blocked.
"""

import json
import threading
import http.server
import socketserver

import pytest
import pytest_asyncio

from tests.conftest import VALID_USER


# ── Tiny upstream used by the proxy ──────────────────────────────────────────

class _EchoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({
            "upstream": "ok",
            "user": self.headers.get("X-Gateway-User", ""),
            "request_id": self.headers.get("X-Request-ID", ""),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.do_GET()

    def log_message(self, *_args):
        pass


@pytest_asyncio.fixture(scope="module", autouse=True)
def mock_upstream():
    """Start the mock backend on an ephemeral port and register it as 'data'."""
    server = socketserver.TCPServer(("127.0.0.1", 0), _EchoHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    import gateway.routes.proxy as proxy_mod
    original = proxy_mod.UPSTREAM_ROUTES.copy()
    proxy_mod.UPSTREAM_ROUTES["data"] = f"http://127.0.0.1:{port}"
    yield f"http://127.0.0.1:{port}"
    proxy_mod.UPSTREAM_ROUTES.update(original)
    server.shutdown()


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _register(client, suffix=""):
    """Register a unique user and return email/password."""
    email = f"e2e{suffix}@example.com"
    user = {
        "email": email,
        "username": f"e2e{suffix}",
        "password": "Secure@Pass1",
        "full_name": f"E2E User {suffix}",
    }
    resp = await client.post("/auth/register", json=user)
    assert resp.status_code == 201, resp.text
    return user


async def _login(client, user):
    resp = await client.post("/auth/login", json={
        "email": user["email"], "password": user["password"],
    })
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


# ── The full journey ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_complete_user_journey(client, mock_upstream):
    # 1. Register
    user = await _register(client, "journey")
    token = await _login(client, user)
    headers = {"Authorization": f"Bearer {token}"}

    # 2. Register a service via the API
    resp = await client.post("/services", headers=headers, json={
        "name": "data",
        "upstream_url": mock_upstream,
        "description": "E2E demo service",
    })
    assert resp.status_code == 201, resp.text
    svc = resp.json()
    assert svc["name"] == "data"

    # 3. Duplicate ACTIVE service name must be rejected
    resp = await client.post("/services", headers=headers, json={
        "name": "data",
        "upstream_url": "http://127.0.0.1:9999",
    })
    assert resp.status_code == 400, resp.text

    # 4. Create a scoped API key
    resp = await client.post("/api-keys", headers=headers, json={
        "name": "e2e-demo-key",
        "scopes": ["proxy:data"],
    })
    assert resp.status_code == 201, resp.text
    api_key = resp.json()["key"]

    # 5. Proxy through the gateway with the API key
    resp = await client.get(
        "/api/v1/data/hello",
        headers={"X-API-Key": api_key},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["upstream"] == "ok"
    assert resp.json()["user"] == user["email"]  # gateway injected the identity

    # 6. Revoke the key
    key_id = resp.json().get("_key_id")  # placeholder (unused); real id fetched below
    list_resp = await client.get("/api-keys", headers=headers)
    key_id = list_resp.json()[0]["id"]
    revoke_resp = await client.post(f"/api-keys/{key_id}/revoke", headers=headers)
    assert revoke_resp.status_code == 200

    # 7. Same proxy call must now be rejected
    resp = await client.get("/api/v1/data/hello", headers={"X-API-Key": api_key})
    assert resp.status_code == 401, resp.text

    # 8. Delete the service
    del_resp = await client.delete(f"/services/{svc['id']}", headers=headers)
    assert del_resp.status_code == 204, del_resp.text

    # 9. Proxy to deleted service must 404
    resp = await client.get("/api/v1/data/hello", headers=headers)
    assert resp.status_code == 404, resp.text
