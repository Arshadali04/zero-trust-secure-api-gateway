from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import os
import logging
from contextlib import asynccontextmanager
from dotenv import load_dotenv

# Load env FIRST
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(PROJECT_ROOT, ".env.oauth"), override=True)
load_dotenv(os.path.join(PROJECT_ROOT, ".env"), override=False)

from gateway.config import settings
from gateway.routes import auth, oauth as oauth_routes, health, user

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting Zero Trust API Gateway...")
    yield
    logger.info("Shutting down API Gateway...")

app = FastAPI(
    title="Zero Trust Secure API Gateway",
    version="1.0.0",
    description="Advanced API Gateway with Zero Trust Architecture",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ONE session middleware only (for OAuth state)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.SECRET_KEY,
    same_site="lax",
    https_only=False,
    session_cookie="zt_gateway_session",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:3000",
    ],
    allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(oauth_routes.router)
app.include_router(health.router)
app.include_router(user.router)

@app.get("/")
async def root():
    return {"message": "Zero Trust Secure API Gateway", "version": "1.0.0", "status": "running"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("gateway.main:app", host="0.0.0.0", port=8000, reload=True, log_level="info")
