import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.role import Role
from app.models.user import User
from app.security import hash_password


PROJECT_ROOT = Path(__file__).resolve().parents[3]
load_dotenv(PROJECT_ROOT / ".env")

DEFAULT_ROLES = (
    {
        "name": "Admin",
        "description": (
            "Manages users, roles, and CyberShield system settings."
        ),
    },
    {
        "name": "Analyst",
        "description": (
            "Reviews alerts, investigates incidents, and writes notes."
        ),
    },
    {
        "name": "Viewer",
        "description": (
            "Views dashboards and security records without editing them."
        ),
    },
)


def seed_roles_and_admin() -> None:
    """Insert default roles and an optional first Admin account."""

    with SessionLocal() as db:
        existing_names = set(
            db.scalars(select(Role.name)).all()
        )

        added_names: list[str] = []

        for role_data in DEFAULT_ROLES:
            if role_data["name"] in existing_names:
                continue

            db.add(Role(**role_data))
            added_names.append(role_data["name"])

        db.commit()

        admin_password = os.getenv("CYBERSHIELD_ADMIN_PASSWORD")
        admin_username = os.getenv("CYBERSHIELD_ADMIN_USERNAME", "admin")
        admin_email = os.getenv("CYBERSHIELD_ADMIN_EMAIL", "admin@cybershield.local")

        admin_user = db.scalar(
            select(User).where(User.username == admin_username)
        )

        if admin_password and admin_user is None:
            admin_role = db.scalar(select(Role).where(Role.name == "Admin"))
            db.add(
                User(
                    username=admin_username,
                    email=admin_email,
                    full_name="CyberShield Admin",
                    password_hash=hash_password(admin_password),
                    role_id=admin_role.id,
                )
            )
            db.commit()
            print(f"Added admin user: {admin_username}")

    if added_names:
        print(f"Added roles: {', '.join(added_names)}")
    else:
        print("Default roles already exist. No changes made.")


if __name__ == "__main__":
    seed_roles_and_admin()
