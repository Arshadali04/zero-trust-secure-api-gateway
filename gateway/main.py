import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Load env FIRST — oauth secrets override base .env
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, ".env.oauth"), override=True)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=False)

from gateway.config import APP_VERSION, settings
from gateway.db.database import init_db
from gateway.middleware.ip_blocker import IPBlockerMiddleware
from gateway.middleware.logging import RequestLoggingMiddleware
from gateway.middleware.rate_limit import RateLimitMiddleware
from gateway.middleware.risk_scoring import RiskScoringMiddleware
from gateway.middleware.waf import WAFMiddleware
from gateway.routes import apikeys as apikeys_routes
from gateway.routes import attack_lab as attack_lab_routes
from gateway.routes import auth, health
from gateway.routes import mfa as mfa_routes
from gateway.routes import oauth as oauth_routes
from gateway.routes import proxy as proxy_routes
from gateway.routes import services as services_routes
from gateway.routes import user

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


def _start_demo_backend():
    """Auto-start the mock backend so the proxy demo works out of the box.

    Disable with GATEWAY_DEMO=0. Register the demo 'data' service in the
    static route table so requests to /api/v1/data/... are proxied.
    """
    if os.environ.get("GATEWAY_DEMO", "1").lower() in ("0", "false", "no"):
        logger.info("GATEWAY_DEMO=0 — mock backend disabled.")
        return

    try:
        from gateway.demo.mock_backend import SERVICE_NAME, ensure_mock_running
        base_url = ensure_mock_running()
        if base_url:
            # Register a static demo route so no DB row is needed
            from gateway.routes.proxy import UPSTREAM_ROUTES
            UPSTREAM_ROUTES.setdefault(SERVICE_NAME, base_url)
            logger.info("Demo service '/api/v1/%s/*' → %s", SERVICE_NAME, base_url)
    except Exception as exc:
        logger.warning("Mock backend startup skipped: %s", exc)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("Starting Zero Trust API Gateway...")
    if "127.0.0.1" in getattr(settings, "TRUSTED_PROXIES", []) and getattr(settings, "ENVIRONMENT", "development") != "development":
        logger.warning(
            "SECURITY: TRUSTED_PROXIES includes 127.0.0.1 in non-development mode. "
            "Any local process can forge X-Forwarded-For headers. "
            "Remove loopback from TRUSTED_PROXIES for production."
        )
    await init_db()          # create tables if they don't exist
    logger.info("Database initialised.")
    # Rate-limiter backend. Previously _init_redis() ran at module import, so
    # importing the middleware opened a socket and blocked up to 2s on PING.
    try:
        from gateway.middleware.rate_limit import init_rate_limit_backend
        init_rate_limit_backend()
    except Exception as exc:
        logger.warning("Rate limiter backend init failed (in-memory fallback): %s", exc)
    # Load persisted ML models so anomaly detection resumes after restart
    try:
        from gateway.detection.ml_anomaly import load_persisted_models
        n = load_persisted_models()
        if n:
            logger.info("Loaded %d persisted ML models.", n)
    except Exception as exc:
        logger.warning("ML model load failed (non-fatal): %s", exc)
    _start_demo_backend()
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────────
    try:
        from gateway.demo.mock_backend import _mock
        _mock.stop()
    except Exception as exc:
        # Non-fatal on the way out, but a mock backend that fails to release
        # port 8001 makes the *next* startup fail with EADDRINUSE, and with a
        # silent `pass` the cause was invisible one process later.
        logger.warning(
            "Mock backend shutdown failed (%s: %s) — port 8001 may stay bound",
            type(exc).__name__, exc,
        )
    logger.info("Shutting down API Gateway.")


app = FastAPI(
    title="Zero Trust Secure API Gateway",
    version=APP_VERSION,
    description="Advanced API Gateway with Zero Trust Architecture",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ── Observability (OpenTelemetry + Prometheus) ──────────────────────────────
from gateway.observability import setup_prometheus, setup_telemetry

setup_telemetry(app)
setup_prometheus(app)

# ── Middleware execution order ───────────────────────────────────────────────
#
#   Starlette's add_middleware inserts at index 0, so the LAST middleware added
#   is the OUTERMOST and runs FIRST.  With the add order below, the request
#   flows through:
#
#     Request:  Logging → RiskScoring → RateLimit → WAF → CORS → Session → Route
#     Response: Route → Session → CORS → WAF → RateLimit → RiskScoring → Logging
#
#   RiskScoring MUST run before RateLimit.  Otherwise the rate limiter rejects
#   flood traffic with 429 and the risk engine never sees those requests, so
#   the behaviour-risk score never accumulates (and the attack simulation demo
#   never reaches the block threshold).
#
#   Logging is outermost so it records every outcome (including 429 and 403).

# 1. Session (required for OAuth CSRF state) — innermost
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    same_site="lax",
    https_only=False,
    session_cookie="zt_gateway_session",
)

# 2. CORS
app.add_middleware(
    CORSMiddleware,
    # Read from settings rather than a second hardcoded copy. This list used to
    # be duplicated verbatim here and in `config.py:ALLOWED_ORIGINS`, and only
    # this copy was live — so setting ALLOWED_ORIGINS in .env changed nothing
    # and a deployer editing config would silently fail to widen CORS. Now the
    # config value is the single source of truth and is overridable per
    # environment without a code change, which a gateway fronting production
    # needs. Audit note: the Phase 3 list proposed deleting the dead setting;
    # wiring it up resolves the same finding without losing the knob.
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Request-ID"],
)

# 3. WAF — blocks SQL injection, XSS, path traversal, command injection
app.add_middleware(WAFMiddleware)

# 4. Rate limiting (per-IP, sliding window) — added BEFORE RiskScoring so that
#    RiskScoring (added next) ends up OUTSIDE it and runs first on each request.
app.add_middleware(RateLimitMiddleware)

# 5. Adaptive Risk Scoring — computes per-request risk score, runs BEFORE the
#    rate limiter so it sees every request and its score can accumulate.
app.add_middleware(RiskScoringMiddleware)

# 6. Request logging → AuditLog table — captures every outcome
app.add_middleware(RequestLoggingMiddleware)

# 7. Security headers — outermost so they are applied to every response.
#    CSP is deliberately permissive (the demo frontend uses inline scripts);
#    the other headers provide real hardening.


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("X-XSS-Protection", "0")

        # Prevent browsers from caching JS/CSS so fixes are always picked up.
        path = request.url.path
        if path.startswith("/frontend/") and (path.endswith(".js") or path.endswith(".css")):
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        # Build connect-src dynamically so WebSocket works from any origin
        # the user accesses the gateway from (not just hardcoded 127.0.0.1).
        _host = request.headers.get("host", "127.0.0.1:8000")
        _scheme = "ws" if "https" not in request.scope.get("scheme", "http") else "wss"
        _connect_src = (
            f"'self' "
            f"ws://{_host} {_scheme}://{_host} "
            f"ws://127.0.0.1:8000 ws://localhost:8000 "
            f"http://127.0.0.1:8000 http://localhost:8000"
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            f"connect-src {_connect_src}; "
            "base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
        )
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        return response


app.add_middleware(_SecurityHeadersMiddleware)

# 8. IP Blocklist — absolute outermost; checked before any other middleware.
#    Requests from blocked IPs are rejected here with 403, never reaching WAF
#    or rate limiter.  Blocks are written by the WAF auto-block and admin API.
app.add_middleware(IPBlockerMiddleware)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(oauth_routes.router)
app.include_router(health.router)
app.include_router(user.router)
app.include_router(mfa_routes.router)
app.include_router(proxy_routes.router)
app.include_router(apikeys_routes.router)
app.include_router(services_routes.router)
app.include_router(attack_lab_routes.router)
app.include_router(attack_lab_routes.ws_router)

# Serve frontend static files at /frontend/*
# Must be mounted AFTER routers so API routes take priority.
app.mount("/frontend", StaticFiles(directory=os.path.join(PROJECT_ROOT, "frontend"), html=True), name="frontend")


@app.get("/")
async def root():
    return {
        "message": "Zero Trust Secure API Gateway",
        "version": APP_VERSION,
        "status": "running",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "gateway.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
