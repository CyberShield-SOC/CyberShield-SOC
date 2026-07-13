from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.db.session import get_db
from app.models.role import Role
from app.models.user import User
from app.security import hash_password, require_roles


router = APIRouter(prefix="/users", tags=["Users"])


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8)
    role: str = Field(pattern="^(Admin|Analyst|Viewer)$")
    full_name: str | None = Field(default=None, max_length=100)


def serialize_user(user: User) -> dict:
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "is_active": user.is_active,
        "role": user.role.name if user.role else None,
    }


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
    payload: CreateUserRequest,
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
