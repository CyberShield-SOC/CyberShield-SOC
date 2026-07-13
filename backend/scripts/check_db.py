import sys
from pathlib import Path

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError


# Allow imports from backend/app when this script is run directly.
BACKEND_ROOT = Path(__file__).resolve().parents[1]

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))


from app.db.session import engine  # noqa: E402


def check_database_connection() -> None:
    """Connect to PostgreSQL and execute a minimal test query."""

    try:
        with engine.connect() as connection:
            result = connection.execute(text("SELECT 1"))
            value = result.scalar_one()

        if value != 1:
            raise RuntimeError(
                f"Unexpected database test result: {value!r}"
            )

        print("Database connection successful.")
        print(f"SELECT 1 returned: {value}")

    except SQLAlchemyError as exc:
        print("Database connection failed.")
        print(f"Error type: {type(exc).__name__}")
        print(f"Details: {exc}")
        raise SystemExit(1) from exc


if __name__ == "__main__":
    check_database_connection()