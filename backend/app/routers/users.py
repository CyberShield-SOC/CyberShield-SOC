from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.role import Role
from app.models.user import User
from app.schemas.user import (
    UserActiveUpdate,
    UserCreate,
    UserRoleUpdate,
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
    role = db.scalar(select(Role).where(Role.name == payload.role))
    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role does not exist. Seed roles before creating users.",
        )

    new_user = User(
        username=payload.username,
        email=payload.email,
        full_name=payload.full_name,
        password_hash=hash_password(payload.password),
        role_id=role.id,
    )
    db.add(new_user)

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        ) from exc

    db.refresh(new_user)
    new_user.role = role
    return {
        "success": True,
        "user": serialize_user(new_user),
    }


@router.patch("/{user_id}/role")
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    target_user = get_user_or_404(db, user_id)
    role = db.scalar(select(Role).where(Role.name == payload.role))

    if role is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role does not exist. Seed roles before assigning users.",
        )

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
    db.commit()
    db.refresh(target_user)

    return {
        "success": True,
        "user": serialize_user(target_user),
    }
