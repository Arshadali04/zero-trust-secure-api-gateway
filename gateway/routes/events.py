"""
gateway/routes/events.py
--------------------------
Server-Sent Events (SSE) endpoint for real-time security event streaming.

  GET /events/security-feed  — authenticated SSE stream of live SecurityEvents

The endpoint polls the database every 1.5 seconds for new SecurityEvent rows
and pushes them as JSON SSE messages. The client receives events formatted as:

  data: {"id":42,"threat_type":"sql_injection","ip_address":"1.2.3.4",...}

The stream sends a heartbeat comment every 15 seconds to keep the connection
alive through proxies and load balancers.

Security:
  - Requires a valid JWT (Bearer token in Authorization header).
  - Only users and admins may subscribe; anonymous access is refused.
  - Each connected client uses a separate async generator — no shared state.
  - The gateway does NOT hold the DB session open for the lifetime of the stream:
    each poll opens and closes its own session so the connection pool is not
    drained by long-lived SSE clients.
"""

import asyncio
import json
import logging
import time
from datetime import timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from gateway.db.database import AsyncSessionLocal
from gateway.db.models import SecurityEvent
from gateway.dependencies import require_authenticated_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/events", tags=["Events"])

# How often to poll the DB for new events (seconds)
_POLL_INTERVAL = 1.5
# How often to send an SSE keep-alive comment (seconds)
_HEARTBEAT_INTERVAL = 15
# Maximum number of events to fetch per poll (avoid overwhelming the client)
_MAX_PER_POLL = 20


async def _get_latest_event_id() -> int:
    """Return the ID of the most recent SecurityEvent row, or 0."""
    from sqlalchemy import func, select
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(select(func.max(SecurityEvent.id)))
            val = result.scalar()
            return int(val) if val else 0
    except Exception:
        return 0


async def _poll_events_since(last_id: int) -> list[dict]:
    """Return SecurityEvent rows with id > last_id, newest first, capped at _MAX_PER_POLL."""
    from sqlalchemy import select
    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                select(SecurityEvent)
                .where(SecurityEvent.id > last_id)
                .order_by(SecurityEvent.id.asc())
                .limit(_MAX_PER_POLL)
            )
            events = result.scalars().all()
            out = []
            for ev in events:
                ts = ev.timestamp
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                out.append({
                    "id": ev.id,
                    "threat_type": ev.threat_type,
                    "ip_address": ev.ip_address,
                    "endpoint": ev.endpoint,
                    "risk_score": float(ev.risk_score or 0),
                    "status": ev.status,
                    "timestamp": ts.isoformat() if ts else None,
                    "payload_preview": (ev.payload or "")[:120],
                })
            return out
    except Exception as exc:
        logger.warning("SSE poll failed: %s", exc)
        return []


async def _event_stream(request: Request):
    """Async generator that yields SSE-formatted messages."""
    last_id = await _get_latest_event_id()
    last_heartbeat = time.monotonic()

    # Send initial connection confirmation
    yield "event: connected\ndata: {\"status\":\"connected\"}\n\n"

    while True:
        # Check if client disconnected
        if await request.is_disconnected():
            logger.debug("SSE client disconnected")
            break

        now = time.monotonic()

        # Heartbeat to keep connection alive through proxies
        if now - last_heartbeat >= _HEARTBEAT_INTERVAL:
            yield ": heartbeat\n\n"
            last_heartbeat = now

        # Poll for new events
        events = await _poll_events_since(last_id)
        for ev in events:
            last_id = ev["id"]
            try:
                yield f"data: {json.dumps(ev)}\n\n"
            except Exception:
                pass  # Broken connection — loop will detect and break on next iteration

        await asyncio.sleep(_POLL_INTERVAL)


@router.get("/security-feed")
async def security_feed(
    request: Request,
    _user=Depends(require_authenticated_user),
):
    """
    Real-time security event stream (Server-Sent Events).

    Connect with:
      const es = new EventSource('/events/security-feed', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      // Note: EventSource doesn't support headers in browsers.
      // Use the `token` query parameter instead for browser clients:
      const es = new EventSource(`/events/security-feed?token=${token}`);

    Each message is a JSON-serialised SecurityEvent:
      { id, threat_type, ip_address, endpoint, risk_score, status, timestamp }

    The stream sends a keep-alive comment (': heartbeat') every 15 seconds.
    """
    return StreamingResponse(
        _event_stream(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",   # Nginx: disable response buffering
            "Connection": "keep-alive",
        },
    )


@router.get("/security-feed-poll")
async def security_feed_poll(
    since: int = 0,
    limit: int = 20,
    _user=Depends(require_authenticated_user),
):
    """
    JSON polling endpoint — returns SecurityEvent rows with id > `since`.

    Lighter than SSE; used by the dashboard as the primary polling mechanism
    because browsers cannot set Authorization headers on EventSource connections.

    Response: list of SecurityEvent-like dicts ordered by id ascending (oldest first).
    """
    from datetime import timezone

    from sqlalchemy import select as _select

    from gateway.db.database import AsyncSessionLocal
    from gateway.db.models import SecurityEvent as _SE

    limit = min(max(int(limit), 1), 50)
    since = max(int(since), 0)

    try:
        async with AsyncSessionLocal() as session:
            result = await session.execute(
                _select(_SE)
                .where(_SE.id > since)
                .order_by(_SE.id.asc())
                .limit(limit)
            )
            events = result.scalars().all()
            out = []
            for ev in events:
                ts = ev.timestamp
                if ts and ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                out.append({
                    "id": ev.id,
                    "threat_type": ev.threat_type,
                    "ip_address": ev.ip_address,
                    "endpoint": ev.endpoint,
                    "risk_score": float(ev.risk_score or 0),
                    "status": ev.status,
                    "timestamp": ts.isoformat() if ts else None,
                    "payload_preview": (ev.payload or "")[:120],
                })
            return out
    except Exception as exc:
        logger.warning("Feed poll error: %s", exc)
        return []
