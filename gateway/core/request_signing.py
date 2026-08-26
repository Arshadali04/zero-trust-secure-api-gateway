"""
gateway/core/request_signing.py
---------------------------------
HMAC request signing for upstream service verification.

Zero-trust principle: upstream services should NEVER blindly trust that a
request came from the gateway. This module adds a cryptographic signature
(X-Gateway-Signature) to every proxied request so the upstream can verify
the request was genuinely forwarded by the gateway and not spoofed.

Signature scheme:
  HMAC-SHA256(
    key = GATEWAY_SIGNING_SECRET,
    message = "{method}\n{path}\n{timestamp}\n{user}\n{request_id}"
  )

Headers added to upstream requests:
  X-Gateway-Signature: sha256={hex_digest}
  X-Gateway-Timestamp: {unix_epoch}

Upstream verification (pseudo-code):
  expected = HMAC-SHA256(shared_secret,
    f"{method}\\n{path}\\n{timestamp}\\n{X-Gateway-User}\\n{X-Request-ID}")
  valid = constant_time_compare(expected, received_signature)
  fresh = abs(now - timestamp) < 300  # 5 min replay window
"""

import hashlib
import hmac
import logging
import os
import time

logger = logging.getLogger(__name__)

SIGNING_SECRET = os.environ.get("GATEWAY_SIGNING_SECRET", "")
REPLAY_WINDOW_SECONDS = 300


def sign_request(method: str, path: str, user_email: str, request_id: str) -> dict:
    """
    Generate signature headers for an outbound proxy request.
    Returns a dict of headers to add to the upstream request.
    If no signing secret is configured, returns empty dict (signing disabled).
    """
    if not SIGNING_SECRET:
        return {}

    timestamp = str(int(time.time()))
    message = f"{method}\n{path}\n{timestamp}\n{user_email}\n{request_id}"

    signature = hmac.new(
        SIGNING_SECRET.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()

    return {
        "X-Gateway-Signature": f"sha256={signature}",
        "X-Gateway-Timestamp": timestamp,
    }


def verify_signature(
    method: str,
    path: str,
    user_email: str,
    request_id: str,
    timestamp: str,
    signature: str,
    secret: str = "",
) -> bool:
    """
    Verify a gateway signature (for upstream services to call).
    Returns True if the signature is valid and within the replay window.
    """
    secret = secret or SIGNING_SECRET
    if not secret or not signature:
        return False

    # Check replay window
    try:
        ts = int(timestamp)
        if abs(time.time() - ts) > REPLAY_WINDOW_SECONDS:
            return False
    except (ValueError, TypeError):
        return False

    # Strip "sha256=" prefix
    if signature.startswith("sha256="):
        signature = signature[7:]

    message = f"{method}\n{path}\n{timestamp}\n{user_email}\n{request_id}"
    expected = hmac.new(
        secret.encode(),
        message.encode(),
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature)
