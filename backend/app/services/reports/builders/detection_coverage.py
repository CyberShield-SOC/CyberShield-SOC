"""Detection coverage report."""

from __future__ import annotations

from reportlab.platypus import Spacer
from sqlalchemy.orm import Session

from app.repositories import report_repository as repo
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

REPORT_NAME = "Detection coverage"


def build(db: Session, ctx: ReportContext, *, max_rows: int) -> bytes:
    start, end = ctx.report_range.start, ctx.report_range.end
    width = CONTENT_WIDTH
    half = half_width(width)

    catalog = repo.rule_catalog_status(db)
    enabled = sum(1 for row in catalog if row["status"] == "Enabled")
    shadow = sum(1 for row in catalog if row["status"] == "Shadow mode")
    disabled = sum(1 for row in catalog if row["status"] == "Disabled")
    no_hits = repo.rules_with_no_hits(db, start=start, end=end)
    hosts = repo.host_heartbeat_status(db, now=ctx.generated_at)

    flowables: list = title_block(
        REPORT_NAME,
        common_metadata(
            ctx,
            time_range_label=f"{ctx.format(start)} – {ctx.format(end)}",
            data_sources=[("detection rule catalog", len(catalog)), ("host_heartbeats", len(hosts))],
        ),
        width=width,
    )

    flowables.append(stat_row([
        {"label": "Enabled rules", "value": f"{enabled:,}", "trend": f"of {len(catalog):,} built-in rules"},
        {"label": "Shadow-mode rules", "value": f"{shadow:,}"},
        {"label": "Disabled rules", "value": f"{disabled:,}"},
        {"label": "No hits in range", "value": f"{len(no_hits):,}", "trend": "among enabled rules"},
    ], width=width))
    flowables.append(Spacer(1, 14))

    coverage = repo.mitre_coverage(db)
    if coverage:
        coverage_table = data_table(
            ["MITRE technique", "Rules"],
            # Rule-name lists are internal, not attacker text — let the cell
            # wrap to multiple lines instead of truncating at the default
            # single-line length.
            [[cell(row["technique"]), cell(", ".join(row["rules"]), max_len=400)] for row in coverage],
            col_widths=[width * 0.2, width * 0.8],
        )
    else:
        coverage_table = no_data_notice("No enabled rule declares a MITRE technique.")
    flowables.append(panel("MITRE ATT&CK technique coverage", coverage_table, width=width))
    flowables.append(Spacer(1, 14))

    catalog_sorted = sorted(catalog, key=lambda row: (row["status"] != "Enabled", row["name"]))
    catalog_cap = catalog_sorted[:max_rows]
    catalog_table = data_table(
        ["Rule", "MITRE", "Status"],
        [[cell(row["name"]), cell(row["mitre_technique"] or "—"), cell(row["status"])] for row in catalog_cap],
        col_widths=[half * 0.55, half * 0.2, half * 0.25],
    )
    catalog_body = [catalog_table] + ([Spacer(1, 4), truncation_notice(len(catalog_cap), len(catalog_sorted))] if len(catalog_sorted) > len(catalog_cap) else [])

    active_rows = repo.most_active_rules(db, start=start, end=end, limit=10)
    active_table = (
        data_table(["Rule", "Alerts"], [[cell(row["rule"]), cell(f"{row['count']:,}")] for row in active_rows], col_widths=[half * 0.7, half * 0.3], align=[None, "RIGHT"])
        if active_rows else no_data_notice()
    )
    flowables.append(two_up(panel("Rule catalog", catalog_body, width=half), panel("Most active rules", active_table, width=half), width=width))
    flowables.append(Spacer(1, 14))

    if no_hits:
        no_hits_table = data_table(["Rule with no hits in range"], [[cell(name)] for name in no_hits], col_widths=[width])
    else:
        no_hits_table = no_data_notice("Every enabled rule raised at least one alert in this period.")
    flowables.append(panel("Rules with no hits in range", no_hits_table, width=width))
    flowables.append(Spacer(1, 14))

    host_cap = hosts[:max_rows]
    if host_cap:
        host_table = data_table(
            ["Hostname", "Status", "Last seen", "Events"],
            [[cell(host["hostname"]), cell(host["status"]), cell(ctx.format(host["last_seen_at"])), cell(f"{host['event_count']:,}")] for host in host_cap],
            col_widths=[width * 0.3, width * 0.18, width * 0.32, width * 0.2],
            align=[None, None, None, "RIGHT"],
        )
        host_body = [host_table] + ([Spacer(1, 4), truncation_notice(len(host_cap), len(hosts))] if len(hosts) > len(host_cap) else [])
    else:
        host_body = [no_data_notice("No hosts have reported yet.")]
    flowables.append(panel("Host and log-source health", host_body, width=width))

    return build_pdf(REPORT_NAME, f"Generated {ctx.format(ctx.generated_at)} · {ctx.actor_name}", flowables)
