"""Centralised configuration, read from environment variables (and ``.env``).

Every setting has a safe local-development default, and no external
credentials are required. See ``.env.example`` for documentation of each
variable.
"""

from __future__ import annotations

import contextlib
import logging
import os
import secrets
from datetime import timedelta
from pathlib import Path
from typing import ClassVar

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
INSTANCE_DIR = BASE_DIR / "instance"

load_dotenv(BASE_DIR / ".env")

logger = logging.getLogger(__name__)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    try:
        number = int(value)
    except ValueError:
        logger.warning("Ignoring invalid integer for %s; using default %s", name, default)
        return default
    return max(minimum, min(maximum, number))


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _env_str(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else default


def _local_secret_key() -> str:
    """Use SECRET_KEY from the environment, or a random key persisted in instance/.

    Persisting it keeps sessions (and therefore anonymous history ownership)
    stable across restarts on a local machine without committing a secret.
    """
    configured = _env_str("SECRET_KEY")
    if configured:
        return configured
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    key_file = INSTANCE_DIR / "secret_key"
    if key_file.is_file():
        stored = key_file.read_text(encoding="utf-8").strip()
        if len(stored) >= 32:
            return stored
    key = secrets.token_hex(32)
    key_file.write_text(key, encoding="utf-8")
    with contextlib.suppress(OSError):  # Windows ignores POSIX modes
        key_file.chmod(0o600)
    return key


def _default_database_uri() -> str:
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{(INSTANCE_DIR / 'phishguard.db').as_posix()}"


def _resolve_path(value: str | None) -> str | None:
    if not value:
        return None
    path = Path(value)
    return str(path if path.is_absolute() else (BASE_DIR / path))


class Config:
    # --- Flask core ---
    SECRET_KEY: str | None = None  # resolved in get_config()
    MAX_CONTENT_LENGTH = 16 * 1024  # request bodies; a scan request is tiny

    # --- Sessions / cookies ---
    SESSION_COOKIE_NAME = "phishguard_session"
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = _env_bool("SESSION_COOKIE_SECURE", False)  # True only when served over HTTPS
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)

    # --- CSRF (Flask-WTF) ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # token valid for the lifetime of the session
    WTF_CSRF_SSL_STRICT = False

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = _env_str("DATABASE_URL") or _default_database_uri()
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict[str, object]] = {"pool_pre_ping": True}

    # --- Scanner ---
    MAX_URL_LENGTH = _env_int("MAX_URL_LENGTH", 2048, 64, 8192)
    SCAN_RETENTION_DAYS = _env_int("SCAN_RETENTION_DAYS", 7, 1, 365)
    STORE_NORMALIZED_URL = _env_bool("STORE_NORMALIZED_URL", False)
    REQUIRE_REPUTATION_FOR_CLEAN = _env_bool("REQUIRE_REPUTATION_FOR_CLEAN", False)

    # --- Threat intelligence (all optional) ---
    GOOGLE_SAFE_BROWSING_API_KEY = _env_str("GOOGLE_SAFE_BROWSING_API_KEY")
    GOOGLE_WEB_RISK_API_KEY = _env_str("GOOGLE_WEB_RISK_API_KEY")
    PHISHTANK_ENABLED = _env_bool("PHISHTANK_ENABLED", False)
    PHISHTANK_API_KEY = _env_str("PHISHTANK_API_KEY")
    PHISHTANK_USERNAME = _env_str("PHISHTANK_USERNAME")
    INTEL_CONNECT_TIMEOUT = _env_float("INTEL_CONNECT_TIMEOUT", 3.05)
    INTEL_READ_TIMEOUT = _env_float("INTEL_READ_TIMEOUT", 6.0)
    INTEL_CACHE_TTL_SECONDS = _env_int("INTEL_CACHE_TTL_SECONDS", 1800, 0, 86400)
    INTEL_CACHE_MAX_ENTRIES = 2048

    # --- Machine learning (optional) ---
    ML_ENABLED = _env_bool("ML_ENABLED", True)
    ML_MODEL_PATH = _resolve_path(_env_str("ML_MODEL_PATH"))

    # --- Rate limiting (Flask-Limiter) ---
    RATELIMIT_ENABLED = _env_bool("RATELIMIT_ENABLED", True)
    RATELIMIT_STORAGE_URI = _env_str("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = _env_str("RATELIMIT_DEFAULT", "200 per minute;5000 per hour")
    RATELIMIT_HEADERS_ENABLED = True
    SCAN_RATE_LIMIT = _env_str("SCAN_RATE_LIMIT", "20 per minute;300 per day")

    # --- Logging ---
    LOG_LEVEL = (_env_str("LOG_LEVEL", "INFO") or "INFO").upper()

    TESTING = False


class DevelopmentConfig(Config):
    pass


class TestingConfig(Config):
    TESTING = True
    SECRET_KEY = "test-secret-key-not-for-real-use-0123456789abcdef"  # noqa: S105  # nosec B105 - test-only value
    SQLALCHEMY_DATABASE_URI = "sqlite://"
    SQLALCHEMY_ENGINE_OPTIONS: ClassVar[dict[str, object]] = {}
    RATELIMIT_ENABLED = False
    RATELIMIT_STORAGE_URI = "memory://"
    GOOGLE_SAFE_BROWSING_API_KEY = None
    GOOGLE_WEB_RISK_API_KEY = None
    PHISHTANK_ENABLED = False
    PHISHTANK_API_KEY = None
    ML_MODEL_PATH = None
    SCAN_RETENTION_DAYS = 7
    STORE_NORMALIZED_URL = False
    REQUIRE_REPUTATION_FOR_CLEAN = False
    LOG_LEVEL = "WARNING"


CONFIGS: dict[str, type[Config]] = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
}


def get_config(name: str | None = None) -> type[Config]:
    selected = name or os.environ.get("PHISHGUARD_CONFIG", "development")
    config_class = CONFIGS.get(selected, DevelopmentConfig)
    if config_class.SECRET_KEY is None:
        config_class.SECRET_KEY = _local_secret_key()
    return config_class
