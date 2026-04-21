"""
serve_frontend.py
-----------------
Serves the /frontend directory as a static site on http://127.0.0.1:5500

Run:
    python serve_frontend.py

Then open:
    http://127.0.0.1:5500/login.html
"""

import http.server
import os

PORT = 5500
FRONTEND_DIR = os.path.join(os.path.dirname(__file__), "frontend")


class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=FRONTEND_DIR, **kwargs)

    def log_message(self, format, *args):  # quieter logs
        print(f"[static] {self.address_string()} - {format % args}")


if __name__ == "__main__":
    with http.server.HTTPServer(("127.0.0.1", PORT), Handler) as httpd:
        print(f"[OK] Frontend served at  http://127.0.0.1:{PORT}/login.html")
        print("     Press Ctrl+C to stop.")
        httpd.serve_forever()
