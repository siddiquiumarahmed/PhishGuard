"""Flask CLI commands: ``flask --app app init-db`` and ``flask --app app purge-expired``."""

from __future__ import annotations

import logging
from pathlib import Path

import click
from flask import Flask, current_app
from sqlalchemy import inspect

from phishguard.extensions import db

logger = logging.getLogger(__name__)


def _migrations_dir() -> Path:
    return Path(current_app.extensions["migrate"].directory)


def init_database(quiet: bool = False) -> str:
    """Create or upgrade the schema. Returns a short description of what happened.

    Preferred path: Alembic migrations (``flask db upgrade``). If the migration
    environment is unavailable, fall back to ``create_all`` and stamp the
    revision so later migrations still apply cleanly.
    """
    from flask_migrate import stamp, upgrade

    has_table = inspect(db.engine).has_table("scan_records")
    migrations = _migrations_dir()
    if (migrations / "env.py").is_file():
        try:
            upgrade(directory=str(migrations))
            outcome = "migrated" if not has_table else "up to date"
            if not quiet:
                logger.info("Database schema %s.", outcome)
            return outcome
        except (Exception, SystemExit):
            logger.exception("Alembic upgrade failed; falling back to create_all()")
            db.session.rollback()
            has_table = inspect(db.engine).has_table("scan_records")
    if has_table:
        return "up to date"
    db.create_all()
    if (migrations / "env.py").is_file():
        try:
            stamp(directory=str(migrations))
        except (Exception, SystemExit):  # noqa: BLE001
            logger.warning("Could not stamp migration revision; run 'flask db stamp head' manually.")
    return "created"


def register_cli(app: Flask) -> None:
    @app.cli.command("init-db")
    def init_db_command() -> None:
        """Create or upgrade the database schema."""
        click.echo(f"Database: {init_database()}")

    @app.cli.command("purge-expired")
    def purge_expired_command() -> None:
        """Delete scan records past their retention period."""
        from phishguard.services.history_service import purge_expired

        click.echo(f"Deleted {purge_expired()} expired record(s).")
