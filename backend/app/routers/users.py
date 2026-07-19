from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.auth_session import AuthSession
from app.models.role import Role
from app.models.user import User
from app.schemas.user import (
    UserActiveUpdate,
    UserCreate,
    UserPasswordReset,
    UserRoleUpdate,
    UserUpdate,
)
from app.security import hash_password, require_roles


router = APIRouter(prefix="/users", tags=["Users"])


def serialize_user(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "role": user.role.name if user.role else None,
    }


def active_admin_count(db: Session) -> int:
    return db.scalar(
        select(func.count())
        .select_from(User)
        .join(Role)
        .where(Role.name == "Admin")
        .where(User.is_active.is_(True))
    ) or 0


def get_user_or_404(db: Session, user_id: int) -> User:
    existing_user = db.scalar(
        select(User)
        .options(joinedload(User.role))
        .where(User.id == user_id)
    )

    if existing_user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    return existing_user


def get_role_or_400(db: Session, role_name: str) -> Role:
    role = db.scalar(select(Role).where(Role.name == role_name))
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role does not exist. Seed roles before assigning users.",
        )
    return role


def commit_user_change(db: Session) -> None:
    """Commit an account mutation without exposing database constraint details."""

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        ) from exc


def revoke_user_sessions(db: Session, user_id: int) -> int:
    """Revoke every currently active session for a managed account."""

    result = db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id)
        .where(AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now(timezone.utc))
    )
    return max(0, int(result.rowcount or 0))


def ensure_not_final_active_admin(db: Session, target_user: User) -> None:
    if (
        target_user.is_active
        and target_user.role is not None
        and target_user.role.name == "Admin"
        and active_admin_count(db) <= 1
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove the final active Admin",
        )


@router.get("/roles")
def list_roles(user: User = Depends(require_roles("Admin")), db: Session = Depends(get_db)):
    roles = db.scalars(select(Role).order_by(Role.name)).all()
    return {
        "success": True,
        "roles": [
            {
                "id": role.id,
                "name": role.name,
                "description": role.description,
            }
            for role in roles
        ],
    }


@router.get("")
def list_users(user: User = Depends(require_roles("Admin")), db: Session = Depends(get_db)):
    users = db.scalars(
        select(User)
        .options(joinedload(User.role))
        .order_by(User.id)
    ).all()
    return {
        "success": True,
        "users": [serialize_user(existing_user) for existing_user in users],
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    role = get_role_or_400(db, payload.role)

    new_user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=role.id,
    )
    db.add(new_user)

    commit_user_change(db)

    db.refresh(new_user)
    new_user.role = role
    return {
        "success": True,
        "user": serialize_user(new_user),
    }


@router.patch("/{user_id}")
def update_user(
    user_id: int,
    payload: UserUpdate,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """Atomically update identity, role, and enabled state for one account."""

    target_user = get_user_or_404(db, user_id)
    changed_fields = payload.model_fields_set
    next_role = target_user.role

    if "role" in changed_fields:
        next_role = get_role_or_400(db, payload.role)

    next_is_active = payload.is_active if "is_active" in changed_fields else target_user.is_active
    removes_active_admin = (
        target_user.is_active
        and target_user.role is not None
        and target_user.role.name == "Admin"
        and (not next_is_active or next_role is None or next_role.name != "Admin")
    )
    if removes_active_admin:
        ensure_not_final_active_admin(db, target_user)

    if "username" in changed_fields:
        target_user.username = payload.username
    if "email" in changed_fields:
        target_user.email = payload.email
    if "full_name" in changed_fields:
        target_user.full_name = payload.full_name
    if "role" in changed_fields:
        target_user.role_id = next_role.id
        target_user.role = next_role
    if "is_active" in changed_fields:
        target_user.is_active = payload.is_active
        if not payload.is_active:
            revoke_user_sessions(db, target_user.id)

    commit_user_change(db)
    db.refresh(target_user)
    if next_role is not None:
        target_user.role = next_role

    return {
        "success": True,
        "user": serialize_user(target_user),
    }


@router.patch("/{user_id}/password")
def reset_user_password(
    user_id: int,
    payload: UserPasswordReset,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """Replace a password and invalidate every session issued before the reset."""

    target_user = get_user_or_404(db, user_id)
    target_user.password_hash = hash_password(payload.new_password)
    sessions_revoked = revoke_user_sessions(db, target_user.id)
    db.commit()

    return {
        "success": True,
        "user": serialize_user(target_user),
        "sessions_revoked": sessions_revoked,
    }


@router.post("/{user_id}/sessions/revoke")
def revoke_managed_user_sessions(
    user_id: int,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """Give an Admin an explicit containment action without disabling the account."""

    target_user = get_user_or_404(db, user_id)
    sessions_revoked = revoke_user_sessions(db, target_user.id)
    db.commit()

    return {
        "success": True,
        "user": serialize_user(target_user),
        "sessions_revoked": sessions_revoked,
    }


@router.patch("/{user_id}/role")
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    target_user = get_user_or_404(db, user_id)
    role = get_role_or_400(db, payload.role)

    if target_user.role and target_user.role.name != payload.role:
        ensure_not_final_active_admin(db, target_user)

    target_user.role_id = role.id
    db.commit()
    db.refresh(target_user)
    target_user.role = role

    return {
        "success": True,
        "user": serialize_user(target_user),
    }


@router.patch("/{user_id}/active")
def update_user_active(
    user_id: int,
    payload: UserActiveUpdate,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    target_user = get_user_or_404(db, user_id)

    if target_user.is_active and not payload.is_active:
        ensure_not_final_active_admin(db, target_user)

    target_user.is_active = payload.is_active
    if not payload.is_active:
        revoke_user_sessions(db, target_user.id)
    db.commit()
    db.refresh(target_user)

    return {
        "success": True,
        "user": serialize_user(target_user),
    }
