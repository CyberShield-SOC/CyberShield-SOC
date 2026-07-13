from sqlalchemy import select

from app.db.session import SessionLocal
from app.models.role import Role


DEFAULT_ROLES = (
    {
        "name": "Administrator",
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


def seed_roles() -> None:
    """Insert default roles without creating duplicates."""

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

    if added_names:
        print(f"Added roles: {', '.join(added_names)}")
    else:
        print("Default roles already exist. No changes made.")


if __name__ == "__main__":
    seed_roles()