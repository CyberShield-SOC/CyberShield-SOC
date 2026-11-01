from __future__ import annotations

from collections.abc import Callable

from sqlalchemy.orm import Session

from app.services.reports.builders import daily_ops, detection_coverage, executive_risk, weekly_incidents
from app.services.reports.catalog import REPORT_BY_ID, REPORT_CATALOG
from app.services.reports.context import ReportContext

REPORT_BUILDERS: dict[str, Callable[[Session, ReportContext], bytes]] = {
    "daily-soc-operations": daily_ops.build,
    "weekly-incident-summary": weekly_incidents.build,
    "detection-coverage": detection_coverage.build,
    "executive-risk-overview": executive_risk.build,
}

__all__ = ["REPORT_BUILDERS", "REPORT_BY_ID", "REPORT_CATALOG", "ReportContext"]
