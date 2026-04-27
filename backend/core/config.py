"""
WebGuard AI — Core Configuration
Loads environment variables and exposes typed settings.
"""
from pydantic_settings import BaseSettings
from typing import List


class Settings(BaseSettings):
    # App
    APP_NAME: str = "WebGuard AI"
    APP_ENV: str = "development"
    SECRET_KEY: str = "change-me-in-production"
    DEBUG: bool = False

    # MongoDB
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB: str = "webguard"

    # Redis / Celery
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/1"

    # CORS
    CORS_ORIGINS: List[str] = ["*"]

    # Scan limits
    MAX_SCAN_DEPTH: int = 3
    MAX_CONCURRENT_SCANS: int = 10
    SCAN_TIMEOUT_SECONDS: int = 120
    REQUEST_TIMEOUT_SECONDS: int = 10

    # Rate limiting
    RATE_LIMIT_PER_MINUTE: int = 10

    # Safe scanning
    SAFE_MODE: bool = True          # Never use destructive payloads
    USER_AGENT: str = "WebGuardAI/1.0 (security-scanner; safe-mode)"

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
