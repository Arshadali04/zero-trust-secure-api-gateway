from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
import os
import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load env FIRST — oauth secrets override base .env
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, ".env.oauth"), override=True)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=False)

from gateway.config import settings
from gateway.db.database import init_db
from gateway.routes import auth, oauth as oauth_routes, health, user
from gateway.routes import mfa as mfa_routes
from gateway.routes import proxy as proxy_routes
from gateway.middleware.rate_limit import RateLimitMiddleware
from gateway.middleware.logging import RequestLoggingMiddleware
from gateway.middleware.waf import WAFMiddleware
from gateway.middleware.risk_scoring import RiskScoringMiddleware

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("Starting Zero Trust API Gateway...")
    await init_db()          # create tables if they don't exist
    logger.info("Database initialised.")
    yield
    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("Shutting down API Gateway.")


app = FastAPI(
    title="Zero Trust Secure API Gateway",
    version="1.0.0",
    description="Advanced API Gateway with Zero Trust Architecture",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ── Middleware stack (applied bottom-up, i.e. first added = outermost) ───────

# 1. Session (required for OAuth CSRF state)
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
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. WAF — block SQL injection, XSS, path traversal, command injection
app.add_middleware(WAFMiddleware)

# 4. Adaptive Risk Scoring — computes per-request risk score and blocks/monitors
app.add_middleware(RiskScoringMiddleware)

# 5. Rate limiting (per-IP, sliding window)
app.add_middleware(RateLimitMiddleware)

# 6. Request logging → AuditLog table (outermost so it captures all statuses)
app.add_middleware(RequestLoggingMiddleware)

# ── Routers ──────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(oauth_routes.router)
app.include_router(health.router)
app.include_router(user.router)
app.include_router(mfa_routes.router)
app.include_router(proxy_routes.router)

# Serve frontend static files at /frontend/*
# Must be mounted AFTER routers so API routes take priority.
app.mount("/frontend", StaticFiles(directory=os.path.join(PROJECT_ROOT, "frontend"), html=True), name="frontend")


@app.get("/")
async def root():
    return {
        "message": "Zero Trust Secure API Gateway",
        "version": "1.0.0",
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
