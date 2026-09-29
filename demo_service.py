"""
demo_service.py
---------------
Standalone mock upstream service listening on port 8002.
Use this to demonstrate Zero-Trust reverse proxy routing,
header injection, and API-key scope enforcement.
"""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 8002


class DemoServiceHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        user = self.headers.get("X-Gateway-User", "anonymous")
        req_id = self.headers.get("X-Request-ID", "none")
        client_ip = self.headers.get("X-Forwarded-For", "unknown")
        print(f"[Upstream:8002] GET {self.path} | User: {user} | Request-ID: {req_id[:8]}... | Client IP: {client_ip}", flush=True)

        payload = {
            "status": "success",
            "service": "demo",
            "path": self.path,
            "message": "Hello from upstream service on port 8002!",
            "zero_trust_headers": {
                "authenticated_user": user,
                "request_id": req_id,
                "client_ip": client_ip,
                "hmac_signature": self.headers.get("X-Gateway-Signature", "none"),
                "timestamp": self.headers.get("X-Gateway-Timestamp", "none"),
            },
        }
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else ""

        payload = {
            "status": "success",
            "service": "demo",
            "method": "POST",
            "path": self.path,
            "received_body": body[:200],
            "zero_trust_headers": {
                "authenticated_user": self.headers.get("X-Gateway-User", "anonymous"),
                "request_id": self.headers.get("X-Request-ID", "none"),
            },
        }
        data = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format, *args):
        # Suppress default noisy http.server log in favor of custom formatted log
        pass


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), DemoServiceHandler)
    print("==================================================================", flush=True)
    print(f"  Demo Upstream Service listening on http://127.0.0.1:{PORT}", flush=True)
    print("  Zero-Trust Identity & Request Header Inspector Active", flush=True)
    print("  Press Ctrl+C to stop.", flush=True)
    print("==================================================================\n", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down demo server.", flush=True)
        server.server_close()
