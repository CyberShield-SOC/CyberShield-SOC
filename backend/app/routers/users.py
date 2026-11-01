from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, joinedload

from app.core.urls import frontend_base_url
from app.db.session import get_db
from app.dispatch.invite_email import get_invite_email_sender
from app.models.invite_token import InviteToken
from app.models.role import Role
from app.models.user import User
from app.repositories.invite_repository import (
    create_invite_challenge,
    get_pending_invite_or_none,
    list_pending_invites,
    resend_invite,
    revoke_invite,
)
from app.schemas.invite import InviteCreateRequest, InviteCreateResponse, InviteListResponse
from app.schemas.user import (
    UserActiveUpdate,
    UserCreate,
    UserPasswordReset,
    UserRoleUpdate,
    UserUpdate,
)
from app.security import hash_password, require_roles, revoke_user_sessions
from app.validation import password_context_errors


router = APIRouter(prefix="/users", tags=["Users"])

INVITE_EMAIL_SEND_FAILURE_MESSAGE = "We couldn't send the invite email. Please try again shortly."
# Upper bound on how long the request waits for the invite email provider.
# A stuck DNS lookup (e.g. Gmail SMTP from some hosts) ignores socket-level
# timeouts entirely, so the send runs on its own thread and is abandoned
# past this deadline rather than hanging the request indefinitely.
INVITE_EMAIL_SEND_TIMEOUT_SECONDS = 20


def _send_invite_email_with_timeout(send_invite_email, *, to_email: str, invite_link: str, role: str) -> None:
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        future = executor.submit(send_invite_email, to_email=to_email, invite_link=invite_link, role=role)
        future.result(timeout=INVITE_EMAIL_SEND_TIMEOUT_SECONDS)
    finally:
        executor.shutdown(wait=False)


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


def serialize_invite(invite) -> dict:
    return {
        "id": invite.id,
        "email": invite.email,
        "role": invite.role.name if invite.role else None,
        "invited_by": invite.invited_by.full_name or invite.invited_by.username if invite.invited_by else None,
        "created_at": invite.created_at,
        "expires_at": invite.expires_at,
    }


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


@router.get("/assignable")
def list_assignable_users(
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """A minimal, low-privilege directory for incident-assignment pickers.

    Unlike GET /users, this is available to Analysts (who can create and
    manage incidents) as well as Admins — but only exposes the fields a
    picker needs, not email or active-state details.
    """

    users = db.scalars(
        select(User)
        .options(joinedload(User.role))
        .where(User.is_active.is_(True))
        .join(Role, Role.id == User.role_id)
        .where(Role.name.in_(["Admin", "Analyst"]))
        .order_by(User.full_name, User.username)
    ).all()
    return {
        "success": True,
        "users": [
            {
                "id": existing_user.id,
                "username": existing_user.username,
                "full_name": existing_user.full_name,
                "role": existing_user.role.name if existing_user.role else None,
            }
            for existing_user in users
        ],
    }


@router.get("/invites", response_model=InviteListResponse)
def list_invites(user: User = Depends(require_roles("Admin")), db: Session = Depends(get_db)):
    invites = list_pending_invites(db)
    return {"success": True, "invites": [serialize_invite(invite) for invite in invites]}


@router.post("/invites", status_code=status.HTTP_201_CREATED, response_model=InviteCreateResponse)
def create_invite(
    payload: InviteCreateRequest,
    request: Request,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
    send_invite_email=Depends(get_invite_email_sender),
):
    role = get_role_or_400(db, payload.role)
    token = create_invite_challenge(db, email=payload.email, role=role, invited_by=user)

    frontend_base = frontend_base_url(request)
    invite_link = f"{frontend_base}/#/accept-invite?token={quote(token)}"
    try:
        _send_invite_email_with_timeout(send_invite_email, to_email=payload.email, invite_link=invite_link, role=role.name)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=INVITE_EMAIL_SEND_FAILURE_MESSAGE,
        ) from exc

    db.commit()

    invite = db.scalar(
        select(InviteToken)
        .options(joinedload(InviteToken.role), joinedload(InviteToken.invited_by))
        .where(InviteToken.email == payload.email)
        .where(InviteToken.used.is_(False))
        .where(InviteToken.revoked.is_(False))
        .order_by(InviteToken.created_at.desc())
    )
    return {"success": True, "invite": serialize_invite(invite)}


def get_pending_invite_or_404(db: Session, invite_id: int):
    invite = get_pending_invite_or_none(db, invite_id)
    if invite is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invite not found",
        )
    return invite


@router.post("/invites/{invite_id}/resend", response_model=InviteCreateResponse)
def resend_pending_invite(
    invite_id: int,
    request: Request,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
    send_invite_email=Depends(get_invite_email_sender),
):
    invite = get_pending_invite_or_404(db, invite_id)
    token = resend_invite(db, invite, invited_by=user)

    frontend_base = frontend_base_url(request)
    invite_link = f"{frontend_base}/#/accept-invite?token={quote(token)}"
    try:
        _send_invite_email_with_timeout(send_invite_email, to_email=invite.email, invite_link=invite_link, role=invite.role.name)
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=INVITE_EMAIL_SEND_FAILURE_MESSAGE,
        ) from exc

    db.commit()

    refreshed = db.scalar(
        select(InviteToken)
        .options(joinedload(InviteToken.role), joinedload(InviteToken.invited_by))
        .where(InviteToken.email == invite.email)
        .where(InviteToken.used.is_(False))
        .where(InviteToken.revoked.is_(False))
        .order_by(InviteToken.created_at.desc())
    )
    return {"success": True, "invite": serialize_invite(refreshed)}


@router.delete("/invites/{invite_id}")
def revoke_pending_invite(
    invite_id: int,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    invite = get_pending_invite_or_404(db, invite_id)
    revoke_invite(db, invite)
    db.commit()
    return {"success": True}


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

    # The schema enforces the shared policy; identity-derived checks need the
    # stored account, so they run here.
    context_errors = password_context_errors(
        payload.new_password,
        username=target_user.username,
        email=target_user.email,
    )
    if context_errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=[
                {
                    "loc": ["body", "new_password"],
                    "msg": message,
                    "type": "value_error",
                }
                for message in context_errors
            ],
        )

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
