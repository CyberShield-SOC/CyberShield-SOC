"""Executive risk overview report.

The reference layout for this report includes several figures this backend
has no source for (an overall risk score, SLA targets, compliance-framework
percentages, MFA coverage, a "decisions requested" register). Per policy,
those panels are left out entirely rather than invented — every number
below comes from a real column or query.
"""

from __future__ import annotations

from reportlab.platypus import Spacer
from sqlalchemy.orm import Session

from app.repositories import report_repository as repo
from app.services.reports.charts import empty_chart_placeholder, stacked_bar_chart
from app.services.reports.components import (
    cell,
    data_table,
    format_duration,
    half_width,
    no_data_notice,
    panel,
    stat_row,
    title_block,
    truncation_notice,
    two_up,
)
from app.services.reports.context import ReportContext, common_metadata
from app.services.reports.layout import CONTENT_WIDTH, build_pdf
from app.services.reports.pivot import bucket_unit_for_span, label_bucket, pivot_time_series

REPORT_NAME = "Executive risk overview"


def _percent_change(current: float, previous: float) -> str:
    if previous == 0:
        return "—" if current == 0 else "new"
    change = (current - previous) / previous * 100
    arrow = "▲" if change > 0 else ("▼" if change < 0 else "▬")
    return f"{arrow} {abs(change):.0f}%"


def build(db: Session, ctx: ReportContext, *, max_rows: int) -> bytes:
    start, end = ctx.report_range.start, ctx.report_range.end
    prev_start, prev_end = ctx.report_range.previous_start, ctx.report_range.previous_end
    severity = ctx.severity
    width = CONTENT_WIDTH
    half = half_width(width)

    open_rows, open_total = repo.open_high_critical_incidents(db, limit=max_rows)
    alert_total = repo.alerts_raised_count(db, start=start, end=end, severity=severity)
    resolution = repo.overall_resolution_stats(db, start=start, end=end)
    opened = repo.incidents_opened_count(db, start=start, end=end)
    prev_opened = repo.incidents_opened_count(db, start=prev_start, end=prev_end)

    flowables: list = title_block(
        REPORT_NAME,
        common_metadata(
            ctx,
            time_range_label=f"{ctx.format(start)} – {ctx.format(end)}",
            data_sources=[("alerts", alert_total), ("incidents", opened)],
        ),
        width=width,
    )

    flowables.append(stat_row([
        {"label": "Open high / critical incidents", "value": f"{open_total:,}", "trend": "as of generation time"},
        {"label": "Alerts in range", "value": f"{alert_total:,}"},
        {"label": "Incidents opened", "value": f"{opened:,}", "trend": _percent_change(opened, prev_opened) + " vs previous period"},
        {"label": "Median time to resolve", "value": format_duration(resolution.get("median_seconds")), "trend": f"{int(resolution.get('count') or 0):,} resolved in range"},
    ], width=width))
    flowables.append(Spacer(1, 14))

    unit = bucket_unit_for_span((end - start).total_seconds())
    time_rows = repo.alerts_over_time_by_severity(db, start=start, end=end, tz_name=ctx.tz_name, unit=unit, severity=severity)
    if time_rows:
        buckets, series = pivot_time_series(time_rows, group_key="severity")
        chart = stacked_bar_chart([label_bucket(ctx.local(b), unit) for b in buckets], series, width=width)
    else:
        chart = empty_chart_placeholder(width)
    flowables.append(panel(f"Alert trend per {unit}, by severity", chart, width=width))
    flowables.append(Spacer(1, 14))

    if open_rows:
        open_table = data_table(
            ["ID", "Title", "Severity", "Status", "Opened", "Assignee"],
            [
                [cell(f"INC-{row['id']}"), cell(row["title"], max_len=70), cell(row["priority"]), cell(row["status"]), cell(ctx.format(row["opened_at"])), cell(row["assignee"] or "Unassigned")]
                for row in open_rows
            ],
            col_widths=[width * 0.08, width * 0.34, width * 0.12, width * 0.14, width * 0.16, width * 0.16],
        )
        open_body = [open_table] + ([Spacer(1, 4), truncation_notice(len(open_rows), open_total)] if open_total > len(open_rows) else [])
    else:
        open_body = [no_data_notice("No open high- or critical-severity incidents.")]
    flowables.append(panel(f"Open high / critical incidents ({open_total:,})", open_body, width=width))
    flowables.append(Spacer(1, 14))

    host_rows = repo.most_affected_hosts(db, start=start, end=end, limit=8)
    host_table = (
        data_table(["Host", "Incidents"], [[cell(row["hostname"]), cell(f"{row['count']:,}")] for row in host_rows], col_widths=[half * 0.7, half * 0.3], align=[None, "RIGHT"])
        if host_rows else no_data_notice()
    )
    user_rows = repo.most_affected_users(db, start=start, end=end, limit=8)
    user_table = (
        data_table(["User", "Incidents"], [[cell(row["username"]), cell(f"{row['count']:,}")] for row in user_rows], col_widths=[half * 0.7, half * 0.3], align=[None, "RIGHT"])
        if user_rows else no_data_notice()
    )
    flowables.append(two_up(panel("Most affected hosts", host_table, width=half), panel("Most affected users", user_table, width=half), width=width))
    flowables.append(Spacer(1, 14))

    ttr_rows = repo.time_to_resolve_by_priority(db, start=start, end=end)
    if ttr_rows:
        ttr_table = data_table(
            ["Severity", "Resolved", "Avg resolve", "Median resolve"],
            [[cell(row["priority"]), cell(f"{row['count']:,}"), cell(format_duration(row["avg_seconds"])), cell(format_duration(row["median_seconds"]))] for row in ttr_rows],
            col_widths=[width * 0.25, width * 0.25, width * 0.25, width * 0.25],
            align=[None, "RIGHT", "RIGHT", "RIGHT"],
        )
    else:
        ttr_table = no_data_notice()
    flowables.append(panel("Resolution performance, by severity", ttr_table, width=width))
    flowables.append(Spacer(1, 14))

    prev_critical = repo.incidents_opened_count(db, start=prev_start, end=prev_end, priority="CRITICAL")
    curr_critical = repo.incidents_opened_count(db, start=start, end=end, priority="CRITICAL")
    prev_alerts = repo.alerts_raised_count(db, start=prev_start, end=prev_end)
    comparison_rows = [
        ("Incidents opened", opened, prev_opened),
        ("Critical incidents opened", curr_critical, prev_critical),
        ("Alerts raised", alert_total, prev_alerts),
    ]
    comparison_table = data_table(
        ["Metric", "This period", "Previous period", "Change"],
        [[cell(label), cell(f"{current:,}"), cell(f"{previous:,}"), cell(_percent_change(current, previous))] for label, current, previous in comparison_rows],
        col_widths=[width * 0.4, width * 0.2, width * 0.2, width * 0.2],
        align=[None, "RIGHT", "RIGHT", "RIGHT"],
    )
    flowables.append(panel(f"Comparison with previous period ({ctx.format(prev_start)} – {ctx.format(prev_end)})", comparison_table, width=width))

    return build_pdf(REPORT_NAME, f"Generated {ctx.format(ctx.generated_at)} · {ctx.actor_name}", flowables)
