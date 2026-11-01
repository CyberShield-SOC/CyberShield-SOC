from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.models.user import User
from app.schemas.alert import AlertSeverity
from app.security import require_roles
from app.services.reports import REPORT_BUILDERS, REPORT_BY_ID, REPORT_CATALOG
from app.services.reports.context import ReportContext
from app.services.reports.params import ReportRangePreset, resolve_report_range

router = APIRouter(tags=["Reports"])


@router.get("/reports")
def list_reports(
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
):
    """The four phase-1 reports available for PDF export."""

    return {"success": True, "reports": list(REPORT_CATALOG)}


@router.get("/reports/{report_id}/pdf")
def get_report_pdf(
    report_id: str,
    range: ReportRangePreset | None = Query(
        default=None,
        description="Preset lookback window. Mutually exclusive with from/to.",
    ),
    from_: datetime | None = Query(
        default=None,
        alias="from",
        description="Range start (ISO 8601). Requires `to`.",
    ),
    to: datetime | None = Query(
        default=None,
        description="Range end (ISO 8601). Requires `from`.",
    ),
    severity: AlertSeverity | None = Query(
        default=None,
        description="Optional severity filter applied across the report.",
    ),
    user: User = Depends(require_roles("Admin", "Analyst", "Viewer")),
    db: Session = Depends(get_db),
):
    """Stream one report as a generated PDF."""

    if report_id not in REPORT_BY_ID:
        raise HTTPException(status_code=404, detail=f"Unknown report '{report_id}'.")

    try:
        report_range = resolve_report_range(range_preset=range, from_=from_, to=to)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    ctx = ReportContext(
        report_range=report_range,
        severity=severity,
        generated_at=datetime.now(timezone.utc),
        actor_name=(user.full_name or user.username),
        tz_name=settings.report_timezone,
    )

    builder = REPORT_BUILDERS[report_id]
    pdf_bytes = builder(db, ctx, max_rows=settings.report_max_rows_per_table)

    filename = f"cybershield-{report_id}-{ctx.local(ctx.generated_at).date().isoformat()}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
