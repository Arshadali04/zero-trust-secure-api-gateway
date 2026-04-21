"""
Middleware for request logging and monitoring.
Captures all requests passing through the gateway.
"""
import time
from datetime import datetime
from typing import List
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from models import RequestLog


# In-memory request log store (swap with DB in future phases)
request_logs: List[dict] = []
gateway_start_time: float = time.time()


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request for monitoring and audit purposes."""

    async def dispatch(self, request: Request, call_next):
        start_time = time.time()
        client_ip = request.client.host if request.client else "unknown"

        # Try to extract user from token (non-blocking)
        user = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from auth import verify_token
                payload = verify_token(auth_header.replace("Bearer ", ""))
                user = payload.get("sub")
            except Exception:
                pass

        # Process request
        blocked = False
        block_reason = None
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception as e:
            status_code = 500
            raise e
        finally:
            response_time = (time.time() - start_time) * 1000  # ms

            log_entry = {
                "timestamp": datetime.utcnow().isoformat(),
                "method": request.method,
                "path": str(request.url.path),
                "client_ip": client_ip,
                "user": user,
                "status_code": status_code,
                "response_time_ms": round(response_time, 2),
                "blocked": blocked,
                "block_reason": block_reason,
            }
            request_logs.append(log_entry)

            # Keep only last 1000 logs in memory
            if len(request_logs) > 1000:
                request_logs.pop(0)

        return response


def get_logs() -> List[dict]:
    return list(reversed(request_logs))


def get_stats() -> dict:
    total = len(request_logs)
    blocked = sum(1 for log in request_logs if log.get("blocked"))
    unique_users = len(set(log.get("user") for log in request_logs if log.get("user")))
    uptime = time.time() - gateway_start_time
    return {
        "total_requests": total,
        "blocked_requests": blocked,
        "active_users": unique_users,
        "uptime_seconds": round(uptime, 2),
    }
