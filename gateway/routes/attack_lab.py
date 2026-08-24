"""
gateway/routes/attack_lab.py
----------------------------
Attack Lab control endpoints + live WebSocket feed.

  POST /attack-lab/run     — start an attack simulation
  POST /attack-lab/stop    — stop the running simulation
  GET  /attack-lab/state   — current simulation state (initial render / fallback)
  WS   /ws/attack-lab      — live state snapshots every ~300ms
"""

import asyncio
import time
import logging

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from gateway.dependencies import require_authenticated_user
from gateway.detection.attack_sim import lab

logger = logging.getLogger(__name__)

# REST endpoints live under /attack-lab; the WebSocket stays at /ws/attack-lab
router = APIRouter(prefix="/attack-lab", tags=["Attack Lab"])
ws_router = APIRouter(tags=["Attack Lab"])

ATTACK_LABELS = {
    "sqli": "SQL Injection",
    "xss": "XSS",
    "path_traversal": "Path Traversal",
    "bruteforce": "Brute-force Login",
    "flood": "Request Flood",
}

# ── WebSocket resource limits ────────────────────────────────────────────────
# The Attack Lab socket bypasses every BaseHTTPMiddleware layer, so its limits
# have to be enforced in the handler itself.
_WS_MAX_CONNECTIONS = 20
_WS_MAX_LIFETIME_SECONDS = 900  # 15 min, then the client must reconnect
_ws_connections = 0


class RunAttackRequest(BaseModel):
    attack_type: str = Field(..., description="sqli | xss | path_traversal | bruteforce | flood")
    duration: int = Field(10, ge=3, le=60, description="Seconds to run")
    intensity: float = Field(4.0, ge=1.0, le=20.0, description="Requests per second")
    jwt: str | None = Field(None, description="JWT used by the flood attack (authenticated traffic)")


@router.post("/run")
async def run_attack(
    payload: RunAttackRequest,
    _user=Depends(require_authenticated_user),
):
    """Start a live attack simulation through the real middleware stack."""
    if payload.attack_type not in ATTACK_LABELS:
        raise HTTPException(status_code=400, detail=f"Unknown attack type: {payload.attack_type}")

    if lab.running:
        raise HTTPException(status_code=409, detail="An attack is already running. Stop it first.")

    # Mint a short-lived token from the caller identity so simulation traffic is
    # attributable and account-risk policy (step-up/freeze) can be demonstrated.
    #
    # mfa_verified is deliberately NOT set: this token previously claimed
    # mfa_verified=True, which meant a 5-minute window existed in which a token
    # that satisfies the MFA gate and the step-up gate outlived the caller's own
    # logout. The simulation only needs to be *authenticated*, not MFA-elevated.
    from datetime import timedelta
    from gateway.core.security import SecurityManager

    jwt = SecurityManager.create_user_token(
        _user.email,
        _user.token_version or 1,
        expires_delta=timedelta(minutes=min(5, max(1, (payload.duration // 60) + 1))),
    )
    lab.start(payload.attack_type, payload.duration, payload.intensity, jwt)
    return {
        "message": f"Started {ATTACK_LABELS[payload.attack_type]} attack.",
        "attack_type": payload.attack_type,
        "state": lab.snapshot(),
    }


@router.post("/stop")
async def stop_attack(_user=Depends(require_authenticated_user)):
    """Stop any running simulation."""
    if not lab.running:
        return {"message": "No attack running.", "state": lab.snapshot()}
    lab.stop()
    return {"message": "Attack stopped.", "state": lab.snapshot()}


@router.get("/state")
async def attack_state(_user=Depends(require_authenticated_user)):
    """Return the current Attack Lab state."""
    return lab.snapshot()


@ws_router.websocket("/ws/attack-lab")
async def attack_lab_ws(websocket: WebSocket):
    """
    Stream live state snapshots to the Attack Lab dashboard.

    Authenticated via a `token` query parameter, because browsers cannot set
    Authorization headers on a WebSocket handshake. This endpoint previously
    called accept() unconditionally, which was the single largest hole in the
    gateway: all six middlewares subclass BaseHTTPMiddleware and therefore only
    process scope["type"] == "http", so a WebSocket bypasses IP blocking, rate
    limiting, the WAF, risk scoring and audit logging entirely. An anonymous
    client — including one whose IP was already blocked — could hold unlimited
    sockets open, each pushing a snapshot every 0.3s, with nothing logged.
    """
    token = websocket.query_params.get("token") or ""
    if not token:
        # 1008 = policy violation. Close before accept() so no frames flow.
        await websocket.close(code=1008, reason="authentication required")
        logger.warning("Attack Lab WS rejected: no token")
        return

    from gateway.core.security import SecurityManager

    try:
        payload = SecurityManager.verify_token(token)
    except Exception:
        payload = None
    if not payload or not payload.get("sub"):
        await websocket.close(code=1008, reason="invalid or expired token")
        logger.warning("Attack Lab WS rejected: invalid token")
        return

    # Bound concurrent sockets so an authenticated client cannot exhaust the
    # server either. The counter is guarded by the event loop (single-threaded
    # for async handlers), so a plain int is safe here.
    global _ws_connections
    if _ws_connections >= _WS_MAX_CONNECTIONS:
        await websocket.close(code=1013, reason="too many connections")
        logger.warning(
            "Attack Lab WS rejected: connection cap reached (%s)", _WS_MAX_CONNECTIONS
        )
        return

    await websocket.accept()
    _ws_connections += 1
    subject = payload.get("sub")
    logger.info("Attack Lab WS opened | user=%s active=%s", subject, _ws_connections)

    started = time.monotonic()
    try:
        while True:
            # Idle/lifetime cap: without this a socket lives forever, so a
            # client that navigates away without closing leaks a connection.
            if time.monotonic() - started > _WS_MAX_LIFETIME_SECONDS:
                await websocket.close(code=1000, reason="session expired, reconnect")
                break
            try:
                await websocket.send_json(lab.snapshot())
            except Exception:
                break
            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass
    except Exception as exc:
        logger.warning("Attack Lab WS error | user=%s | %s", subject, exc)
    finally:
        _ws_connections -= 1
        logger.info("Attack Lab WS closed | user=%s active=%s", subject, _ws_connections)
