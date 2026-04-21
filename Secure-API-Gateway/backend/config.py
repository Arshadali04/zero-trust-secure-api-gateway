"""
Configuration for Zero Trust API Gateway
All settings centralized here for easy modification during upgrades.
"""
import os

# JWT Settings
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "zero-trust-gateway-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Rate Limiting
RATE_LIMIT_REQUESTS = "10/minute"

# CORS Settings
ALLOWED_ORIGINS = ["http://localhost:5500", "http://127.0.0.1:5500", "http://localhost:8080", "http://127.0.0.1:8080"]

# Roles
ROLES = {
    "admin": ["read", "write", "delete", "manage_users"],
    "user": ["read"],
    "moderator": ["read", "write"],
}
