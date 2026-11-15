from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update
from sqlalchemy.orm import Session, joinedload

from app.core.config import settings
from app.models.invite_token import InviteToken
from app.models.role import Role
from app.models.user import User
from app.security import generate_invite_token, token_digest


class InviteTokenInvalidError(Exception):
    """A user-facing invite-token failure, with the exact message to return."""


def create_invite_challenge(db: Session, *, email: str, role: Role, invited_by: User | None) -> str:
    """
    Invalidate any still-active invite for `email` and issue a new one.

    Returns the plaintext token. Only its digest is persisted; the caller is
    responsible for emailing a signup link containing it — it is never
    logged or returned in an API response.
    """

    db.execute(
        update(InviteToken)
        .where(InviteToken.email == email)
        .where(InviteToken.used.is_(False))
        .where(InviteToken.revoked.is_(False))
        .values(used=True)
    )

    token = generate_invite_token()
    db.add(
        InviteToken(
            email=email,
            role_id=role.id,
            invited_by_user_id=invited_by.id if invited_by else None,
            token_hash=token_digest(token),
            expires_at=datetime.now(timezone.utc)
            + timedelta(minutes=settings.invite_token_expiry_minutes),
            used=False,
            revoked=False,
        )
    )
    db.flush()
    return token


INVALID_INVITE_MESSAGE = "This invite link is invalid or has already been used."


def _load_invite(db: Session, token: str) -> InviteToken:
    invite = db.scalar(
        select(InviteToken)
        .options(joinedload(InviteToken.role))
        .where(InviteToken.token_hash == token_digest(token))
    )
    if invite is None:
        raise InviteTokenInvalidError(INVALID_INVITE_MESSAGE)
    if invite.used or invite.revoked:
        raise InviteTokenInvalidError(INVALID_INVITE_MESSAGE)
    if invite.expires_at <= datetime.now(timezone.utc):
        raise InviteTokenInvalidError("This invite link has expired. Ask your administrator to resend it.")
    return invite


def get_invite_details(db: Session, token: str) -> InviteToken:
    """Validate a presented invite token without consuming it."""

    return _load_invite(db, token)


def consume_invite(db: Session, token: str) -> InviteToken:
    """
    Validate a presented invite token and mark it used.

    Raises InviteTokenInvalidError with a ready-to-display message if the
    token is unknown, already used, revoked, or expired. The caller is
    responsible for creating the account and committing.
    """

    invite = _load_invite(db, token)
    invite.used = True
    return invite


def list_pending_invites(db: Session) -> list[InviteToken]:
    return list(
        db.scalars(
            select(InviteToken)
            .options(joinedload(InviteToken.role), joinedload(InviteToken.invited_by))
            .where(InviteToken.used.is_(False))
            .where(InviteToken.revoked.is_(False))
            .order_by(InviteToken.created_at.desc())
        ).all()
    )


def get_pending_invite_or_none(db: Session, invite_id: int) -> InviteToken | None:
    return db.scalar(
        select(InviteToken)
        .options(joinedload(InviteToken.role), joinedload(InviteToken.invited_by))
        .where(InviteToken.id == invite_id)
        .where(InviteToken.used.is_(False))
        .where(InviteToken.revoked.is_(False))
    )


def revoke_invite(db: Session, invite: InviteToken) -> None:
    invite.revoked = True


def resend_invite(db: Session, invite: InviteToken, *, invited_by: User | None) -> str:
    """Supersede `invite` and issue a fresh token for the same email/role."""

    return create_invite_challenge(db, email=invite.email, role=invite.role, invited_by=invited_by or invite.invited_by)
