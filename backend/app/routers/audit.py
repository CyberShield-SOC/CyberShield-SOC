from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.security import require_roles
from app.services.audit import AUDIT_CATEGORIES, audit_page

router = APIRouter(tags=["Audit"])


@router.get("/audit/events")
def list_audit_events(
    category: str | None = Query(default=None, max_length=30),
    actor: str | None = Query(default=None, max_length=100),
    outcome: Literal["SUCCESS", "FAILURE"] | None = Query(default=None),
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = Query(default=None),
    before_id: int | None = Query(default=None, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    """The platform audit trail, newest first. Read-only by design: there is
    no endpoint that edits or removes an audit event."""

    if category is not None and category not in AUDIT_CATEGORIES:
        raise HTTPException(status_code=422, detail=f"Unknown audit category '{category}'.")

    return {
        **audit_page(
            db,
            category=category,
            actor=actor,
            outcome=outcome,
            occurred_from=from_,
            occurred_to=to,
            before_id=before_id,
            limit=limit,
        ),
        "categories": list(AUDIT_CATEGORIES),
    }
