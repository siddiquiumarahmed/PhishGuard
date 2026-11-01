"""Flask extension instances (initialised in :func:`phishguard.create_app`)."""

from __future__ import annotations

from flask_limiter import Limiter
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect

from phishguard.security.rate_limits import client_key

db = SQLAlchemy()
migrate = Migrate()
csrf = CSRFProtect()
# Limits and storage come from app.config (RATELIMIT_* keys) at init_app time.
limiter = Limiter(key_func=client_key)
