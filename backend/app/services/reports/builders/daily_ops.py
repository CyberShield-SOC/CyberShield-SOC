"""Daily SOC operations report."""

from __future__ import annotations

from reportlab.platypus import Spacer
from sqlalchemy.orm import Session

from app.repositories import report_repository as repo
from app.services.reports.charts import empty_chart_placeholder, stacked_bar_chart
from app.services.reports.components import (
    cell,
    data_table,
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

REPORT_NAME = "Daily SOC operations"


def _count_table(rows: list[dict], key: str, label: str, *, width: float, value_label: str = "Count"):
    if not rows:
        return no_data_notice()
    body_rows = [[cell(row[key] if row[key] is not None else "Unknown"), cell(f"{row['count']:,}")] for row in rows]
    return data_table([label, value_label], body_rows, col_widths=[width * 0.7, width * 0.3], align=[None, "RIGHT"])


def build(db: Session, ctx: ReportContext, *, max_rows: int) -> bytes:
    start, end = ctx.report_range.start, ctx.report_range.end
    severity = ctx.severity
    width = CONTENT_WIDTH
    half = half_width(width)

    alert_total = repo.alerts_raised_count(db, start=start, end=end, severity=severity)
    status_rows = repo.alerts_by_status(db, start=start, end=end, severity=severity)
    new_count = next((row["count"] for row in status_rows if row["status"] == "NEW"), 0)
    incidents_opened = repo.incidents_opened_count(db, start=start, end=end)
    hosts = repo.host_heartbeat_status(db, now=ctx.generated_at)
    hosts_silent = sum(1 for host in hosts if host["status"] == "Silent")

    flowables: list = title_block(
        REPORT_NAME,
        common_metadata(
            ctx,
            time_range_label=f"{ctx.format(start)} – {ctx.format(end)}",
            data_sources=[("alerts", alert_total), ("incidents", incidents_opened), ("host_heartbeats", len(hosts))],
        ),
        width=width,
    )

    flowables.append(stat_row([
        {"label": "Alerts in range", "value": f"{alert_total:,}"},
        {"label": "New / unreviewed", "value": f"{new_count:,}"},
        {"label": "Incidents opened", "value": f"{incidents_opened:,}"},
        {"label": "Hosts silent", "value": f"{hosts_silent:,}", "trend": f"of {len(hosts):,} reporting hosts"},
    ], width=width))
    flowables.append(Spacer(1, 14))

    unit = bucket_unit_for_span((end - start).total_seconds())
    time_rows = repo.alerts_over_time_by_severity(db, start=start, end=end, tz_name=ctx.tz_name, unit=unit, severity=severity)
    if time_rows:
        buckets, series = pivot_time_series(time_rows, group_key="severity")
        chart = stacked_bar_chart([label_bucket(ctx.local(b), unit) for b in buckets], series, width=width)
    else:
        chart = empty_chart_placeholder(width)
    flowables.append(panel(f"Alerts per {unit}, by severity", chart, width=width))
    flowables.append(Spacer(1, 14))

    status_table = _count_table(status_rows, "status", "Status", width=half)
    rules_rows = repo.top_rules(db, start=start, end=end, severity=severity, limit=10)
    rules_table = _count_table(rules_rows, "rule", "Rule", width=half, value_label="Alerts")
    flowables.append(two_up(panel("Alerts by status", status_table, width=half), panel("Top rules", rules_table, width=half), width=width))
    flowables.append(Spacer(1, 14))

    ip_rows = repo.top_source_ips(db, start=start, end=end, severity=severity, limit=10)
    ip_table = _count_table(ip_rows, "source_ip", "Source IP", width=half, value_label="Alerts")
    assignee_rows = repo.incidents_per_assignee(db, start=start, end=end)
    assignee_rows = [{**row, "assignee": row["assignee"] or "Unassigned"} for row in assignee_rows]
    assignee_table = _count_table(assignee_rows, "assignee", "Assignee", width=half, value_label="Incidents")
    flowables.append(two_up(panel("Top source IPs", ip_table, width=half), panel("Incidents opened per assignee", assignee_table, width=half), width=width))
    flowables.append(Spacer(1, 14))

    host_cap = hosts[:max_rows]
    if host_cap:
        host_rows = [
            [cell(host["hostname"]), cell(host["status"]), cell(ctx.format(host["last_seen_at"])), cell(f"{host['event_count']:,}")]
            for host in host_cap
        ]
        host_table = data_table(
            ["Hostname", "Status", "Last seen", "Events"],
            host_rows,
            col_widths=[width * 0.3, width * 0.18, width * 0.32, width * 0.2],
            align=[None, None, None, "RIGHT"],
        )
        host_body = [host_table] + ([Spacer(1, 4), truncation_notice(len(host_cap), len(hosts))] if len(hosts) > len(host_cap) else [])
    else:
        host_body = [no_data_notice("No hosts have reported yet.")]
    flowables.append(panel("Host and log-source status", host_body, width=width))

    return build_pdf(REPORT_NAME, f"Generated {ctx.format(ctx.generated_at)} · {ctx.actor_name}", flowables)
