"""
gateway/core/client_ip.py
--------------------------
Client IP resolution that does NOT blindly trust X-Forwarded-For.

X-Forwarded-For is attacker-controlled unless the connection actually came
from a trusted reverse proxy (configured in settings.TRUSTED_PROXIES).
Loopback is trusted by default so the Attack Lab (which spoofs attacker IPs
from localhost) keeps working; a real deployment must list only its own
reverse proxies.

Usage:  ip = get_client_ip(request)
"""

import logging

from fastapi import Request

from gateway.config import settings

logger = logging.getLogger(__name__)

# request.client.host is always a numeric address, never a hostname, so a
# "localhost" entry in TRUSTED_PROXIES can never match. Resolved here so the
# setting behaves the way its name implies.
_HOSTNAME_ALIASES = {"localhost": ("127.0.0.1", "::1")}
_TRUSTED: set[str] = set()
for _p in settings.TRUSTED_PROXIES:
    _TRUSTED.update(_HOSTNAME_ALIASES.get(_p, (_p,)))


def get_client_ip(request: Request) -> str:
    """Return the real client IP, honoring XFF only from trusted proxies."""
    peer = request.client.host if request.client else "unknown"

    if peer in _TRUSTED:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Leftmost entry is the original client per RFC 7239.
            return forwarded.split(",")[0].strip() or peer
    elif request.headers.get("X-Forwarded-For"):
        # The header is present but the peer is not trusted, so it is ignored
        # and every request collapses onto the proxy's own address. That is the
        # correct security decision, but it silently disables per-client IP
        # blocking, rate limiting and freeze scoping — so it must be loud.
        #
        # This is the live state of the bundled deployment: TRUSTED_PROXIES
        # defaults to loopback only, while docker-compose puts nginx on the
        # bridge network, so its container IP is untrusted and all traffic is
        # attributed to one address. Set TRUSTED_PROXIES to the nginx address
        # (or the compose subnet) before relying on any IP-based control.
        _warn_untrusted_xff(peer)

    return peer


_warned_peers: set[str] = set()


def _warn_untrusted_xff(peer: str) -> None:
    """Log once per peer so a misconfigured proxy is visible without spamming."""
    if peer in _warned_peers:
        return
    _warned_peers.add(peer)
    logger.warning(
        "X-Forwarded-For received from untrusted peer %s and IGNORED. "
        "All requests via this hop share one IP, so IP blocking / rate limiting "
        "/ freezes are effectively global. Add it to TRUSTED_PROXIES if it is "
        "your reverse proxy. (TRUSTED_PROXIES=%s)",
        peer, sorted(_TRUSTED),
    )
