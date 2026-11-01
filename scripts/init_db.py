"""Create or upgrade the PhishGuard database.

Usage (from the project root, virtual environment active):
    python scripts/init_db.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from phishguard import create_app
from phishguard.cli import init_database


def main() -> None:
    app = create_app(overrides={"AUTO_INIT_DB": False})
    with app.app_context():
        outcome = init_database()
        print(f"Database {outcome}: {app.config['SQLALCHEMY_DATABASE_URI']}")


if __name__ == "__main__":
    main()
