"""
config.py — Centralised configuration management
Loads all settings from the .env file. Import this module
anywhere in the platform to access validated configuration.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """
    Central configuration class.
    All settings are read from environment variables (loaded from .env).
    Raises a clear error on startup if any required key is missing.
    """

    # ── API Keys ─────────────────────────────────────────────────────────────
    OTX_API_KEY: str       = os.getenv("OTX_API_KEY", "")
    VT_API_KEY: str        = os.getenv("VT_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.getenv("ABUSEIPDB_API_KEY", "")

    # ── Database ──────────────────────────────────────────────────────────────
    DB_HOST: str     = os.getenv("DB_HOST", "localhost")
    DB_PORT: int     = int(os.getenv("DB_PORT", "5432"))
    DB_NAME: str     = os.getenv("DB_NAME", "threat_intel")
    DB_USER: str     = os.getenv("DB_USER", "threat_user")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "changeme")

    # ── Platform Behaviour ────────────────────────────────────────────────────
    LOG_LEVEL: str          = os.getenv("LOG_LEVEL", "INFO")
    RATE_LIMIT_SLEEP: float = float(os.getenv("RATE_LIMIT_SLEEP", "1.0"))
    MAX_RETRIES: int        = int(os.getenv("MAX_RETRIES", "3"))
    RETRY_BACKOFF: float    = float(os.getenv("RETRY_BACKOFF", "2.0"))
    CACHE_TTL: int          = int(os.getenv("CACHE_TTL", "3600"))
    PROCESSING_TIMEOUT: float = float(os.getenv("PROCESSING_TIMEOUT", "5.0"))

    # ── API Endpoints ─────────────────────────────────────────────────────────
    OTX_BASE_URL: str       = "https://otx.alienvault.com/api/v1"
    VT_BASE_URL: str        = "https://www.virustotal.com/api/v3"
    ABUSEIPDB_BASE_URL: str = "https://api.abuseipdb.com/api/v2"

    @classmethod
    def validate(cls) -> None:
        """
        Validate that all required API keys are present.
        Call this once at application startup.
        """
        missing = []
        if not cls.OTX_API_KEY:
            missing.append("OTX_API_KEY")
        if not cls.VT_API_KEY:
            missing.append("VT_API_KEY")
        if not cls.ABUSEIPDB_API_KEY:
            missing.append("ABUSEIPDB_API_KEY")
        if missing:
            raise EnvironmentError(
                f"Missing required environment variables: {', '.join(missing)}. "
                f"Check your .env file."
            )

    @classmethod
    def db_dsn(cls) -> str:
        """Return a PostgreSQL DSN connection string."""
        return (
            f"postgresql://{cls.DB_USER}:{cls.DB_PASSWORD}"
            f"@{cls.DB_HOST}:{cls.DB_PORT}/{cls.DB_NAME}"
        )
