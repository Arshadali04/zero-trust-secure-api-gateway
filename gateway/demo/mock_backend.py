"""
gateway/demo/mock_backend.py
----------------------------
A tiny mock backend service that runs inside the gateway process.

It lets the reverse proxy demo work out of the box: register the gateway,
issue an API key, and call /api/v1/data/... without needing to run a
separate mock server.

The mock server trusts the gateway completely — it does not perform its own
auth. Any security filtering is done by the gateway, which is exactly the
point of the zero-trust architecture.

Disable with the GATEWAY_DEMO=0 environment variable.
"""

import json
import logging
import socketserver
import threading
from http.server import BaseHTTPRequestHandler

logger = logging.getLogger(__name__)

MOCK_PORT = 8001
SERVICE_NAME = "data"


class _MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def _reply(self, status=200, body=None):
        payload = body or {
            "message": "Hello from the mock backend service.",
            "status": "ok",
            "metadata": {
                "authenticated_user": self.headers.get("X-Gateway-User", "unknown"),
                "request_id": self.headers.get("X-Request-ID", "unknown"),
                "note": "This data was protected by the Zero Trust API Gateway.",
            },
        }
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        # Echo back the gateway-injected identity so the demo is convincing
        if self.path.startswith("/health"):
            self._reply(200, {"status": "healthy"})
            return
        self._reply(200)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        self._reply(200, {
            "message": "Mock backend received your POST.",
            "status": "ok",
            "received": True,
            "authenticated_user": self.headers.get("X-Gateway-User", "unknown"),
        })

    def do_PUT(self):
        self.do_POST()

    def do_DELETE(self):
        self._reply(200, {"status": "deleted"})

    def log_message(self, *_args):
        pass  # silence per-request logging; the gateway already logs everything


class _ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


class MockBackend:
    """Runs the mock backend in a background thread."""

    def __init__(self, host="127.0.0.1", port=MOCK_PORT):
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    @property
    def base_url(self):
        return f"http://{self.host}:{self.port}"

    def start(self) -> bool:
        try:
            self._server = _ReusableTCPServer((self.host, self.port), _MockHandler)
        except OSError as exc:
            logger.warning(
                "Mock backend could not bind %s:%s (%s) — is it already running?",
                self.host, self.port, exc,
            )
            return False

        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
            name="mock-backend",
        )
        self._thread.start()
        logger.info(
            "Mock backend '%s' running at %s (no auth — gateway does all filtering)",
            SERVICE_NAME, self.base_url,
        )
        return True

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            logger.info("Mock backend stopped.")


# Module-level singleton so the lifespan can start/stop it easily
_mock = MockBackend()


def ensure_mock_running() -> str | None:
    """Start the mock backend if not already running. Returns its base URL."""
    if _mock._server is None:
        ok = _mock.start()
        if not ok:
            return None
    return _mock.base_url
