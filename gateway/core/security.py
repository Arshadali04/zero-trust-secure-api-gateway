import hashlib
import secrets
from passlib.context import CryptContext
from datetime import datetime, timedelta, UTC
import jwt

# Use argon2 instead of bcrypt (no 72-byte limit)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

# Attribute name used to memoise a decoded JWT on request.state.
# Leading underscore so it cannot collide with anything a route sets.
_TOKEN_CACHE_ATTR = "_jwt_payload_cache"


def verify_token_for_request(request, token: str | None) -> dict | None:
    """`SecurityManager.verify_token`, evaluated at most once per request.

    A single authenticated request used to verify the same JWT up to four
    separate times: RequestLoggingMiddleware to attribute the audit entry,
    RiskScoringMiddleware to score it, RiskScoringMiddleware again when the
    outcome was monitor/challenge/block, and finally
    `require_authenticated_user` in the route dependency. Each call is a full
    HMAC-SHA256 verification plus base64 decode plus JSON parse.

    The cost is the lesser reason to fix it. The real problem is that four
    independent decodes can *disagree*: `jwt.decode` checks `exp` against the
    clock at call time, so a token expiring during request handling was accepted
    by the logging middleware and then rejected by the route dependency. The
    audit log recorded an attributed user for a request that came back 401.
    Caching makes one request see one authentication decision.

    Keyed on the token string, so presenting a different token later in the same
    request re-verifies rather than reusing the earlier answer. Negative results
    are cached too — re-verifying a known-bad token three more times is pure
    waste. `request` is duck-typed on `.state` to keep this module free of a
    framework import; pass None to bypass the cache entirely.
    """
    if not token:
        return None
    state = getattr(request, "state", None)
    if state is None:
        return SecurityManager.verify_token(token)
    cached = getattr(state, _TOKEN_CACHE_ATTR, None)
    if cached is not None and cached[0] == token:
        return cached[1]
    payload = SecurityManager.verify_token(token)
    setattr(state, _TOKEN_CACHE_ATTR, (token, payload))
    return payload

class SecurityManager:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using argon2"""
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)

    @staticmethod
    def create_access_token(data: dict, expires_delta: timedelta | None = None, secret_key: str | None = None) -> str:
        """Create JWT access token"""
        from gateway.config import settings

        to_encode = data.copy()
        if expires_delta:
            expire = datetime.now(UTC) + expires_delta
        else:
            expire = datetime.now(UTC) + timedelta(minutes=15)

        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, secret_key or settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        return encoded_jwt

    @staticmethod
    def verify_token(token: str, secret_key: str | None = None) -> dict | None:
        """Verify JWT token"""
        from gateway.config import settings

        try:
            payload = jwt.decode(token, secret_key or settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
            return payload
        except jwt.InvalidTokenError:
            return None

    @staticmethod
    def create_user_token(
        email: str,
        token_version: int = 1,
        *,
        mfa_verified: bool = False,
        mfa_at: float | None = None,
        expires_delta: timedelta | None = None,
    ) -> str:
        """
        Create a JWT for a real account, embedding the user's current
        token_version claim. require_authenticated_user rejects any token
        whose version differs from the stored one, so bumping token_version
        (e.g. on password change/reset) revokes all outstanding tokens.

        mfa_at: epoch seconds when MFA was last verified. Adaptive step-up
        compares it against stepup_since to decide whether a token predates
        the step-up demand (and must be re-verified).
        """
        from gateway.config import settings

        exp = expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        data = {
            "sub": email,
            "mfa_verified": mfa_verified,
            "ver": token_version,
        }
        if mfa_at is not None:
            data["mfa_at"] = mfa_at
        return SecurityManager.create_access_token(data, expires_delta=exp)


# ---------------------------------------------------------------------------
# API key helpers
# ---------------------------------------------------------------------------

API_KEY_PREFIX = "ztg_live_"
API_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
API_KEY_RANDOM_LENGTH = 32


def _random_key_part(length: int = API_KEY_RANDOM_LENGTH) -> str:
    """Cryptographically-secure random string from a URL-safe alphabet."""
    return "".join(secrets.choice(API_KEY_ALPHABET) for _ in range(length))


def hash_api_key(key: str) -> str:
    """SHA-256 of the full key. This is all we ever store."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def generate_api_key() -> tuple[str, str, str]:
    """
    Generate a new API key.

    Returns (key_prefix, plaintext, key_hash).

    The plaintext is shown to the owner exactly once — the database only
    stores the hash.
    """
    random_part = _random_key_part()
    plaintext = API_KEY_PREFIX + random_part
    return API_KEY_PREFIX, plaintext, hash_api_key(plaintext)
