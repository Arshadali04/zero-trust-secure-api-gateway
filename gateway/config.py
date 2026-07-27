from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    """Application settings"""
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./data/gateway.db"
    DATABASE_ECHO: bool = False
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # JWT
    SECRET_KEY: str = "your-secret-key-change-this-in-production-min-32-chars"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # Environment
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    
    # CORS
    ALLOWED_ORIGINS: List[str] = ["*"]
    
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

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()