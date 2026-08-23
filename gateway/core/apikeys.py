"""
gateway/core/apikeys.py
------------------------
Helpers for API-key authentication:

  - Brute-force guard: tracks failed X-API-Key attempts per IP and blocks
    IPs that exceed the threshold (this is the attack-detection angle for
    API keys).
  - Scope helpers: parse the JSON scope list and check service access.
  - JSON (de)serialisation for the `scopes` column.
"""

import json
import time
import logging
from collections import defaultdict, deque
from threading import Lock
from collections.abc import Iterable

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Brute-force guard configuration
# ---------------------------------------------------------------------------
FAIL_LIMIT = 5          # failed key attempts within the window → block
FAIL_WINDOW_SECONDS = 60
BLOCK_SECONDS = 300     # IP stays blocked for 5 minutes

_failures: dict[str, deque] = defaultdict(deque)
_blocked_until: dict[str, float] = {}
_lock = Lock()


def is_ip_blocked(ip: str) -> bool:
    """Return True if this IP is currently in a brute-force cooldown."""
    with _lock:
        until = _blocked_until.get(ip, 0)
        if time.monotonic() < until:
            return True
        if until:
            _blocked_until.pop(ip, None)   # cooldown expired — clear it
        return False


def record_failure(ip: str) -> bool:
    """
    Record a failed API-key attempt for this IP.

    Returns True if the threshold was crossed (i.e. the IP is now blocked),
    False otherwise. The first 4 failures are tolerated, the 5th triggers
    the block.
    """
    now = time.monotonic()
    with _lock:
        dq = _failures[ip]
        while dq and dq[0] < now - FAIL_WINDOW_SECONDS:
            dq.popleft()
        dq.append(now)
        if len(dq) >= FAIL_LIMIT:
            _blocked_until[ip] = now + BLOCK_SECONDS
            _failures.pop(ip, None)
            logger.warning(
                "API-key brute force suspected from ip=%s — blocked for %ss",
                ip, BLOCK_SECONDS,
            )
            return True
        return False


def reset_ip(ip: str) -> None:
    """Clear failure history and any active block (used by tests / after success)."""
    with _lock:
        _failures.pop(ip, None)
        _blocked_until.pop(ip, None)


# ---------------------------------------------------------------------------
# Scopes
# ---------------------------------------------------------------------------

def serialize_scopes(scopes: Iterable[str]) -> str:
    return json.dumps(list(scopes or []))


def deserialize_scopes(raw: str | None) -> list[str]:
    try:
        data = json.loads(raw or "[]")
        return [str(s) for s in data] if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def scopes_allow(scopes: list[str], service: str) -> bool:
    """
    Does this scope list grant access to the given proxy service?

    A scope of "all" or "*" grants everything; otherwise the service must
    match a "proxy:<service>" scope exactly.
    """
    if not scopes:
        return False
    if "all" in scopes or "*" in scopes:
        return True
    return f"proxy:{service}" in scopes
