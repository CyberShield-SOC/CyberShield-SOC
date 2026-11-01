"""Weekly incident summary report."""

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

REPORT_NAME = "Weekly incident summary"


def _percent_change(current: float, previous: float) -> str:
    if previous == 0:
        return "—" if current == 0 else "new"
    change = (current - previous) / previous * 100
    arrow = "▲" if change > 0 else ("▼" if change < 0 else "▬")
    return f"{arrow} {abs(change):.0f}%"


def build(db: Session, ctx: ReportContext, *, max_rows: int) -> bytes:
    start, end = ctx.report_range.start, ctx.report_range.end
    prev_start, prev_end = ctx.report_range.previous_start, ctx.report_range.previous_end
    priority = ctx.severity
    width = CONTENT_WIDTH
    half = half_width(width)

    opened = repo.incidents_opened_count(db, start=start, end=end, priority=priority)
    closed = repo.incidents_closed_count(db, start=start, end=end, priority=priority)
    if priority:
        critical_high = opened if priority in ("CRITICAL", "HIGH") else 0
    else:
        critical_high = (
            repo.incidents_opened_count(db, start=start, end=end, priority="CRITICAL")
            + repo.incidents_opened_count(db, start=start, end=end, priority="HIGH")
        )
    resolution = repo.overall_resolution_stats(db, start=start, end=end)

    flowables: list = title_block(
        REPORT_NAME,
        common_metadata(
            ctx,
            time_range_label=f"{ctx.format(start)} – {ctx.format(end)}",
            data_sources=[("incidents", opened), ("alerts", repo.alerts_raised_count(db, start=start, end=end))],
        ),
        width=width,
    )

    flowables.append(stat_row([
        {"label": "Incidents opened", "value": f"{opened:,}"},
        {"label": "Incidents closed", "value": f"{closed:,}"},
        {"label": "Critical / High opened", "value": f"{critical_high:,}"},
        {"label": "Median time to resolve", "value": format_duration(resolution.get("median_seconds")), "trend": f"{int(resolution.get('count') or 0):,} resolved in range"},
    ], width=width))
    flowables.append(Spacer(1, 14))

    unit = bucket_unit_for_span((end - start).total_seconds())
    time_rows = repo.incidents_over_time_by_priority(db, start=start, end=end, tz_name=ctx.tz_name, unit=unit, priority=priority)
    if time_rows:
        buckets, series = pivot_time_series(time_rows, group_key="priority")
        chart = stacked_bar_chart([label_bucket(ctx.local(b), unit) for b in buckets], series, width=width)
    else:
        chart = empty_chart_placeholder(width)
    flowables.append(panel(f"Incidents per {unit}, by severity", chart, width=width))
    flowables.append(Spacer(1, 14))

    rule_rows = repo.incidents_by_rule(db, start=start, end=end, priority=priority)
    if rule_rows:
        total_rule_incidents = sum(row["count"] for row in rule_rows)
        rule_table = data_table(
            ["Rule", "Incidents", "%"],
            [[cell(row["rule"]), cell(f"{row['count']:,}"), cell(f"{row['count'] / total_rule_incidents * 100:.0f}%")] for row in rule_rows],
            col_widths=[half * 0.55, half * 0.25, half * 0.2],
            align=[None, "RIGHT", "RIGHT"],
        )
    else:
        rule_table = no_data_notice()

    ttr_rows = repo.time_to_resolve_by_priority(db, start=start, end=end)
    if ttr_rows:
        ttr_table = data_table(
            ["Severity", "Resolved", "Avg resolve", "Median resolve"],
            [[cell(row["priority"]), cell(f"{row['count']:,}"), cell(format_duration(row["avg_seconds"])), cell(format_duration(row["median_seconds"]))] for row in ttr_rows],
            col_widths=[half * 0.28, half * 0.22, half * 0.25, half * 0.25],
            align=[None, "RIGHT", "RIGHT", "RIGHT"],
        )
    else:
        ttr_table = no_data_notice()
    flowables.append(two_up(panel("Incidents by rule", rule_table, width=half), panel("Time to resolve, by severity", ttr_table, width=half), width=width))
    flowables.append(Spacer(1, 14))

    incident_rows, incident_total = repo.incidents_in_range(db, start=start, end=end, priority=priority, limit=max_rows)
    if incident_rows:
        incident_table = data_table(
            ["ID", "Opened", "Title", "Rule", "Severity", "Assignee", "Status"],
            [
                [
                    cell(f"INC-{row['id']}"),
                    cell(ctx.format(row["opened_at"])),
                    cell(row["title"], max_len=60),
                    cell(row["rule"]),
                    cell(row["priority"]),
                    cell(row["assignee"] or "Unassigned"),
                    cell(row["status"]),
                ]
                for row in incident_rows
            ],
            col_widths=[width * 0.08, width * 0.14, width * 0.28, width * 0.16, width * 0.1, width * 0.14, width * 0.1],
        )
        incident_body = [incident_table] + ([Spacer(1, 4), truncation_notice(len(incident_rows), incident_total)] if incident_total > len(incident_rows) else [])
    else:
        incident_body = [no_data_notice()]
    flowables.append(panel(f"Incident list ({incident_total:,})", incident_body, width=width))
    flowables.append(Spacer(1, 14))

    host_rows = repo.most_affected_hosts(db, start=start, end=end, limit=10)
    host_table = (
        data_table(["Host", "Incidents"], [[cell(row["hostname"]), cell(f"{row['count']:,}")] for row in host_rows], col_widths=[half * 0.7, half * 0.3], align=[None, "RIGHT"])
        if host_rows else no_data_notice()
    )
    user_rows = repo.most_affected_users(db, start=start, end=end, limit=10)
    user_table = (
        data_table(["User", "Incidents"], [[cell(row["username"]), cell(f"{row['count']:,}")] for row in user_rows], col_widths=[half * 0.7, half * 0.3], align=[None, "RIGHT"])
        if user_rows else no_data_notice()
    )
    flowables.append(two_up(panel("Most affected hosts", host_table, width=half), panel("Most affected users", user_table, width=half), width=width))
    flowables.append(Spacer(1, 14))

    prev_opened = repo.incidents_opened_count(db, start=prev_start, end=prev_end, priority=priority)
    prev_closed = repo.incidents_closed_count(db, start=prev_start, end=prev_end, priority=priority)
    prev_critical = repo.incidents_opened_count(db, start=prev_start, end=prev_end, priority="CRITICAL")
    curr_critical = repo.incidents_opened_count(db, start=start, end=end, priority="CRITICAL")
    prev_alerts = repo.alerts_raised_count(db, start=prev_start, end=prev_end)
    curr_alerts = repo.alerts_raised_count(db, start=start, end=end)
    comparison_rows = [
        ("Incidents opened", opened, prev_opened),
        ("Incidents closed", closed, prev_closed),
        ("Critical incidents opened", curr_critical, prev_critical),
        ("Alerts raised", curr_alerts, prev_alerts),
    ]
    comparison_table = data_table(
        ["Metric", "This period", "Previous period", "Change"],
        [[cell(label), cell(f"{current:,}"), cell(f"{previous:,}"), cell(_percent_change(current, previous))] for label, current, previous in comparison_rows],
        col_widths=[width * 0.4, width * 0.2, width * 0.2, width * 0.2],
        align=[None, "RIGHT", "RIGHT", "RIGHT"],
    )
    flowables.append(panel(f"Comparison with previous period ({ctx.format(prev_start)} – {ctx.format(prev_end)})", comparison_table, width=width))

    return build_pdf(REPORT_NAME, f"Generated {ctx.format(ctx.generated_at)} · {ctx.actor_name}", flowables)
