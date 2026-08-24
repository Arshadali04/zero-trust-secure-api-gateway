from fastapi import APIRouter
import logging

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Health"])

@router.get("/health")
async def health_check():
    """Liveness check — the API process is up."""
    return {
        "status": "healthy",
        "message": "API is running",
        "service": "Zero Trust Gateway"
    }


@router.get("/ready")
async def readiness_check():
    """Readiness check — the API is up and ready to serve traffic."""
    return {
        "status": "ready",
        "message": "API is ready to serve traffic",
        "service": "Zero Trust Gateway"
    }
