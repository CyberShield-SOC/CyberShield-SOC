from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.models.user import User
from app.repositories.threat_intel_repository import (
    ThreatFeedError,
    delete_feed,
    import_feed,
    list_feeds,
    list_indicators,
)
from app.security import require_roles
from app.services.audit import record_audit
from app.services.stix import STIX_MEDIA_TYPE, export_stix_bundle

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])

MAX_FEED_BYTES = 10 * 1024 * 1024


class ThreatFeedImport(BaseModel):
    source: str = Field(min_length=1, max_length=100)
    content: str = Field(min_length=1, max_length=MAX_FEED_BYTES)
    replace: bool = True
    description: str | None = Field(default=None, max_length=500)


@router.get("/feeds")
def get_feeds(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    return {"success": True, "feeds": list_feeds(db)}


@router.post("/feeds")
def post_feed(
    payload: ThreatFeedImport,
    request: Request,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """Import (or with replace=true, re-import) one named indicator feed.

    `content` is either plain text (one IP, CIDR, or domain per line) or a
    STIX 2.1 bundle as JSON; the format is recognised from the content.

    Takes effect on the next upload: threat_intel_match loads indicators
    fresh for every detection run.
    """

    try:
        result = import_feed(
            db,
            source=payload.source,
            content=payload.content,
            replace=payload.replace,
            description=payload.description,
            created_by=user.id,
        )
        record_audit(
            db,
            request,
            action="threat_intel.feed.import",
            actor=user,
            target_type="threat_feed",
            target_label=payload.source,
            detail={
                "format": result.get("format"),
                "imported": result.get("imported"),
                "rejected_lines": result.get("rejected_lines"),
                "replaced": result.get("replaced"),
            },
        )
        db.commit()
    except ThreatFeedError as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(status_code=500, detail="The threat feed could not be saved.") from exc
    return {"success": True, **result}


@router.get("/indicators")
def get_indicators(
    source: str | None = Query(default=None, max_length=100),
    limit: int = Query(default=200, ge=1, le=1000),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    return {"success": True, "indicators": list_indicators(db, source=source, limit=limit)}


@router.get("/feeds/{source}/stix")
def export_feed_as_stix(
    source: str,
    request: Request,
    user: User = Depends(require_roles("Admin", "Analyst")),
    db: Session = Depends(get_db),
):
    """One feed as a STIX 2.1 bundle of indicators, for sharing with other tools."""

    bundle = export_stix_bundle(db, source)
    if bundle is None:
        raise HTTPException(status_code=404, detail="No threat feed with that name exists.")
    indicator_count = len(bundle["objects"]) - 1
    record_audit(
        db,
        request,
        action="export.threat_feed",
        actor=user,
        target_type="threat_feed",
        target_label=source,
        detail={"format": "stix-2.1", "count": indicator_count},
    )
    db.commit()
    filename = "".join(char if char.isalnum() or char in "._-" else "-" for char in source)
    return JSONResponse(
        bundle,
        media_type=STIX_MEDIA_TYPE,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}.stix.json"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.delete("/feeds/{source}")
def remove_feed(
    source: str,
    request: Request,
    user: User = Depends(require_roles("Admin")),
    db: Session = Depends(get_db),
):
    removed = delete_feed(db, source)
    if not removed:
        db.rollback()
        raise HTTPException(status_code=404, detail="No threat feed with that name exists.")
    record_audit(
        db,
        request,
        action="threat_intel.feed.delete",
        actor=user,
        target_type="threat_feed",
        target_label=source,
        detail={"removed": removed},
    )
    db.commit()
    return {"success": True, "source": source, "removed": removed}
