from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator

_DEFAULT_SECRET = "your-secret-key-change-this-in-production-min-32-chars"

# Single source of truth for the application version.
#
# This lived in four places with two different values: main.py's FastAPI
# `version=` said "2.0.0", so /openapi.json and /docs advertised 2.0.0, while
# GET / , the OpenTelemetry resource attribute, and the README badge all said
# "1.0.0". A client that read the OpenAPI schema and a client that read the
# root endpoint disagreed about which build of the gateway they were talking
# to, and traces were tagged with a third opinion. 2.0.0 wins because it is
# the value already published in the schema; the other three were simply never
# updated. Deliberately a module constant and not a Settings field — a build
# should not be able to lie about its own version via an env var. On release,
# bump this and the README badge (the badge is a static image URL).
APP_VERSION = "2.0.0"

class Settings(BaseSettings):
    """Application settings"""

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/gateway.db"
    DATABASE_ECHO: bool = False

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    SECRET_KEY: str = _DEFAULT_SECRET
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # CORS
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
    ]

    # Logging
    LOG_LEVEL: str = "INFO"

    # OAuth
    GOOGLE_CLIENT_ID: str = ""
    GOOGLE_CLIENT_SECRET: str = ""
    GOOGLE_REDIRECT_URI: str = "http://127.0.0.1:8000/auth/callback/google"

    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""
    GITHUB_REDIRECT_URI: str = "http://127.0.0.1:8000/auth/callback/github"

    FRONTEND_BASE_URL: str = "http://127.0.0.1:8000"

    # Only these peers may set X-Forwarded-For. The local loopback is trusted
    # so the Attack Lab (which spoofs attacker IPs from localhost) keeps
    # working; a real deployment should list only its reverse proxies.
    TRUSTED_PROXIES: list[str] = ["127.0.0.1", "::1", "localhost"]

    # When False, an OAuth sign-in whose email already belongs to a
    # password-bearing account is refused with 409 instead of silently linking.
    # Default True preserves the demo flow; set False for any real deployment
    # until registration verifies email ownership.
    OAUTH_ALLOW_AUTOLINK: bool = True

    # ── Adaptive security policy thresholds ─────────────────────────────────
    # Account risk score gates (0.0 – 1.0, see gateway/detection/account_risk.py)
    RISK_STEPUP_THRESHOLD: float = 0.55    # ≥ this → sensitive routes demand fresh MFA
    RISK_CRITICAL_THRESHOLD: float = 0.85  # ≥ this → auto logout + 1h account freeze
    RISK_FREEZE_SECONDS: int = 3600        # duration of the critical freeze
    RISK_LOW_AFTER_DAYS: int = 7           # after this many quiet days, risk resets to 0
    ALLOW_UPSTREAM_PRIVATE: bool = True    # proxy may target RFC1918 upstream URLs (True for demo, False for production)
    RISK_STEPUP_CLEAR: float = 0.35        # risk must drop below this to clear step-up
    # Paths that trigger step-up MFA when the account risk is elevated.
    SENSITIVE_PATH_PREFIXES: list[str] = ["/api/v1", "/admin", "/api-keys", "/services"]

    @model_validator(mode="after")
    def _fail_fast_on_default_secret(self):
        """Never run with the shipped default secret outside development."""
        if self.SECRET_KEY == _DEFAULT_SECRET and self.ENVIRONMENT != "development":
            raise ValueError(
                "SECRET_KEY must be set via .env before running outside development. "
                "Refusing to start with the known default secret."
            )
        if self.SECRET_KEY == _DEFAULT_SECRET:
            import logging
            logging.getLogger(__name__).warning(
                "Using the default SECRET_KEY — set SECRET_KEY in .env for anything "
                "but local development."
            )
        return self

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)

settings = Settings()
