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

SEED_ACCOUNT_ENV = {
    "Admin": {
        "username": ("CYBERSHIELD_ADMIN_USERNAME", "admin"),
        "email": ("CYBERSHIELD_ADMIN_EMAIL", "admin@cybershield.io"),
        "password": "CYBERSHIELD_ADMIN_PASSWORD",
        "full_name": "CyberShield Admin",
    },
    "Analyst": {
        "username": ("CYBERSHIELD_ANALYST_USERNAME", "analyst"),
        "email": ("CYBERSHIELD_ANALYST_EMAIL", "analyst@cybershield.io"),
        "password": "CYBERSHIELD_ANALYST_PASSWORD",
        "full_name": "CyberShield Analyst",
    },
    "Viewer": {
        "username": ("CYBERSHIELD_VIEWER_USERNAME", "viewer"),
        "email": ("CYBERSHIELD_VIEWER_EMAIL", "viewer@cybershield.io"),
        "password": "CYBERSHIELD_VIEWER_PASSWORD",
        "full_name": "CyberShield Viewer",
    },
}


def _seed_user_for_role(db, role: Role) -> str | None:
    config = SEED_ACCOUNT_ENV[role.name]
    username_var, username_default = config["username"]
    email_var, email_default = config["email"]
    password_var = config["password"]

    password = os.getenv(password_var)
    username = os.getenv(username_var, username_default)
    email = os.getenv(email_var, email_default)

    existing_user = db.scalar(
        select(User).where(User.username == username)
    )
    if existing_user is not None:
        if existing_user.role_id != role.id:
            raise RuntimeError(
                f"Seed user {username!r} exists but is not assigned to {role.name}."
            )
        return None

    if not password:
        return (
            f"Skipped {role.name} seed account {username!r}; "
            f"{password_var} is not set."
        )

    db.add(
        User(
            username=username,
            email=email,
            full_name=config["full_name"],
            password_hash=hash_password(password),
            role_id=role.id,
        )
    )
    return f"Added {role.name} user: {username}"


def seed_roles_and_admin() -> None:
    """Insert default roles and optional Admin/Analyst/Viewer accounts."""

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

        user_messages: list[str] = []
        for role_name in SEED_ACCOUNT_ENV:
            role = db.scalar(select(Role).where(Role.name == role_name))
            if role is None:
                raise RuntimeError(f"Required role was not seeded: {role_name}")
            message = _seed_user_for_role(db, role)
            if message:
                user_messages.append(message)
        db.commit()

    if added_names:
        print(f"Added roles: {', '.join(added_names)}")
    else:
        print("Default roles already exist. No changes made.")

    for message in user_messages:
        print(message)


def validate_seed_state() -> dict:
    """Return seed-state evidence for migrations and Sprint Review checks."""

    with SessionLocal() as db:
        roles = {
            role.name: role
            for role in db.scalars(select(Role)).all()
        }
        missing_roles = [
            role_data["name"]
            for role_data in DEFAULT_ROLES
            if role_data["name"] not in roles
        ]
        accounts = {}
        for role_name, config in SEED_ACCOUNT_ENV.items():
            username_var, username_default = config["username"]
            username = os.getenv(username_var, username_default)
            user = db.scalar(select(User).where(User.username == username))
            accounts[role_name] = {
                "username": username,
                "configured": bool(os.getenv(config["password"])),
                "present": user is not None,
                "active": bool(user.is_active) if user is not None else False,
                "role_matches": (
                    user is not None
                    and roles.get(role_name) is not None
                    and user.role_id == roles[role_name].id
                ),
            }

    return {
        "roles": {
            "required": [role_data["name"] for role_data in DEFAULT_ROLES],
            "missing": missing_roles,
        },
        "accounts": accounts,
        "valid": (
            not missing_roles
            and all(
                (not account["configured"])
                or (account["present"] and account["active"] and account["role_matches"])
                for account in accounts.values()
            )
        ),
    }


if __name__ == "__main__":
    seed_roles_and_admin()
    evidence = validate_seed_state()
    print(f"Seed validation valid: {evidence['valid']}")
