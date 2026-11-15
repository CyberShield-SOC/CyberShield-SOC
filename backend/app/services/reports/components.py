"""Reusable styled flowables shared by every report builder: colors, text
escaping/truncation, tables, the title block, and stat rows.
"""

from __future__ import annotations

from datetime import datetime
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import HRFlowable, Paragraph, Spacer, Table, TableStyle

TEAL = colors.HexColor("#1a9c8c")
TEAL_LIGHT = colors.HexColor("#e3f3f1")
TEXT_DARK = colors.HexColor("#1b2430")
TEXT_MUTED = colors.HexColor("#5b6472")
BORDER = colors.HexColor("#d8dee6")
PANEL_BG = colors.HexColor("#f4f6f8")

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#c0392b"),
    "HIGH": colors.HexColor("#e67e22"),
    "MEDIUM": colors.HexColor("#d4ac0d"),
    "LOW": colors.HexColor("#3b82c4"),
}
SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

TITLE_STYLE = ParagraphStyle("ReportTitle", fontName="Helvetica-Bold", fontSize=20, textColor=TEXT_DARK, spaceAfter=10)
SECTION_STYLE = ParagraphStyle("SectionTitle", fontName="Helvetica-Bold", fontSize=11, textColor=TEXT_DARK)
BODY_STYLE = ParagraphStyle("Body", fontName="Helvetica", fontSize=8.5, textColor=TEXT_DARK, leading=11)
MUTED_STYLE = ParagraphStyle("Muted", fontName="Helvetica", fontSize=8.5, textColor=TEXT_MUTED, leading=11)
HEADER_CELL_STYLE = ParagraphStyle("HeaderCell", fontName="Helvetica-Bold", fontSize=8.5, textColor=colors.white, leading=11)
META_LABEL_STYLE = ParagraphStyle("MetaLabel", fontName="Helvetica-Bold", fontSize=8, textColor=TEXT_MUTED)
META_VALUE_STYLE = ParagraphStyle("MetaValue", fontName="Helvetica", fontSize=9, textColor=TEXT_DARK, leading=12)
STAT_LABEL_STYLE = ParagraphStyle("StatLabel", fontName="Helvetica-Bold", fontSize=7, textColor=TEXT_MUTED, leading=9)
STAT_VALUE_STYLE = ParagraphStyle("StatValue", fontName="Helvetica-Bold", fontSize=18, textColor=TEXT_DARK, leading=21)
STAT_TREND_STYLE = ParagraphStyle("StatTrend", fontName="Helvetica", fontSize=7.5, textColor=TEXT_MUTED, leading=10)
NOTICE_STYLE = ParagraphStyle("Notice", fontName="Helvetica-Oblique", fontSize=9, textColor=TEXT_MUTED)


def safe_text(value, *, max_len: int = 120) -> str:
    """Escape attacker-controlled text (alert titles, usernames, hostnames,
    custom rule names, ...) before it reaches a Paragraph, and truncate it
    so one long field can't blow out a table's layout.
    """

    text = "" if value is None else str(value)
    text = text.replace("\r", " ").replace("\n", " ").strip()
    if len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return _xml_escape(text)


def cell(value, *, style: ParagraphStyle = BODY_STYLE, max_len: int = 120) -> Paragraph:
    """A table cell safe for untrusted text: always escaped, never raw markup."""

    return Paragraph(safe_text(value, max_len=max_len), style)


def header_cell(value: str) -> Paragraph:
    return Paragraph(_xml_escape(str(value)), HEADER_CELL_STYLE)


def format_generated_label(generated_at: datetime, actor: str, tz_label: str) -> str:
    return f"Generated {generated_at.strftime('%b %d, %Y %H:%M')} {tz_label} by {actor} · Internal data"


def format_timestamp(value: datetime, tz_label: str) -> str:
    return f"{value.strftime('%b %d, %Y %H:%M')} {tz_label}"


def format_duration(seconds: float | None) -> str:
    if seconds is None:
        return "—"
    seconds = int(round(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, secs = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m"
    if minutes:
        return f"{minutes}m {secs:02d}s"
    return f"{secs}s"


def section_title(text: str) -> Paragraph:
    return Paragraph(_xml_escape(text), SECTION_STYLE)


def no_data_notice(label: str = "No data in this period.") -> Paragraph:
    return Paragraph(_xml_escape(label), NOTICE_STYLE)


def truncation_notice(shown: int, total: int) -> Paragraph:
    return Paragraph(f"Showing {shown:,} of {total:,}.", MUTED_STYLE)


def metadata_table(pairs: list[tuple[str, str]], *, width: float) -> Table:
    """A dense two-column label/value grid, matching the reference layout's
    title-block metadata.
    """

    rows: list[list] = []
    for index in range(0, len(pairs), 2):
        left_label, left_value = pairs[index]
        if index + 1 < len(pairs):
            right_label, right_value = pairs[index + 1]
        else:
            right_label, right_value = "", ""
        rows.append([
            Paragraph(_xml_escape(left_label), META_LABEL_STYLE),
            cell(left_value, style=META_VALUE_STYLE, max_len=200),
            Paragraph(_xml_escape(right_label), META_LABEL_STYLE) if right_label else "",
            cell(right_value, style=META_VALUE_STYLE, max_len=200) if right_label else "",
        ])
    column_width = width / 4
    table = Table(rows, colWidths=[column_width * 0.62, column_width * 1.38] * 2)
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
    ]))
    return table


def stat_row(stats: list[dict], *, width: float) -> Table:
    """A row of stat tiles: label, big number, optional trend/sub-label."""

    cells = []
    for stat in stats:
        column = [Paragraph(_xml_escape(stat["label"].upper()), STAT_LABEL_STYLE), Spacer(1, 3), Paragraph(_xml_escape(stat["value"]), STAT_VALUE_STYLE)]
        if stat.get("trend"):
            column.append(Spacer(1, 2))
            column.append(Paragraph(_xml_escape(stat["trend"]), STAT_TREND_STYLE))
        cells.append(column)
    column_width = width / len(cells)
    table = Table([cells], colWidths=[column_width] * len(cells))
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
        ("INNERGRID", (0, 0), (-1, -1), 0.75, BORDER),
        ("BACKGROUND", (0, 0), (-1, -1), colors.white),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return table


def data_table(headers: list[str], rows: list[list], *, col_widths: list[float], align: list[str] | None = None) -> Table:
    """A dense, repeating-header table for tabular report data."""

    table_rows = [[header_cell(header) for header in headers], *rows]
    table = Table(table_rows, colWidths=col_widths, repeatRows=1)
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), TEAL),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, TEAL),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, PANEL_BG]),
        ("LINEBELOW", (0, 1), (-1, -1), 0.5, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]
    for index, alignment in enumerate(align or []):
        if alignment:
            style.append(("ALIGN", (index, 0), (index, -1), alignment))
    table.setStyle(TableStyle(style))
    return table


def title_block(report_name: str, metadata_pairs: list[tuple[str, str]], *, width: float) -> list:
    """Report title, metadata grid, and the teal divider that opens every
    report in the reference layout.
    """

    return [
        Paragraph(_xml_escape(report_name), TITLE_STYLE),
        metadata_table(metadata_pairs, width=width),
        Spacer(1, 10),
        HRFlowable(width=width, thickness=1.2, color=TEAL, spaceBefore=0, spaceAfter=0),
        Spacer(1, 14),
    ]


PANEL_GUTTER = 12.0


def half_width(width: float, *, gutter: float = PANEL_GUTTER) -> float:
    """The width available to each side of a two_up() pair for this width.

    Callers must build each half's content at this exact width — a plain
    padding-based gutter would make the nested content wider than its cell
    and overflow, since Table columns don't shrink to fit their content.
    """

    return (width - gutter) / 2


def two_up(left, right, *, width: float, gutter: float = PANEL_GUTTER) -> Table:
    """Two flowables side by side with a real spacer column between them —
    each must already be built at half_width(width, gutter=gutter).
    """

    column_width = half_width(width, gutter=gutter)
    table = Table([[left, "", right]], colWidths=[column_width, gutter, column_width])
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    return table


def panel(title: str, body, *, width: float) -> Table:
    """A titled panel: a teal-accented header bar over arbitrary content.

    `body` (a flowable, or a list of flowables) must already be built at
    exactly `width` — the body row carries zero horizontal padding so a
    nested fixed-width table (e.g. data_table) never overflows its cell.
    Only the title row gets horizontal padding; a bare Paragraph always
    wraps to fit, so padding there can't cause an overflow.
    """

    body_rows = [[item] for item in body] if isinstance(body, list) else [[body]]
    table = Table([[Paragraph(_xml_escape(title), SECTION_STYLE)], *body_rows], colWidths=[width])
    last_row = len(body_rows)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), TEAL_LIGHT),
        ("BOX", (0, 0), (-1, -1), 0.75, BORDER),
        ("LINEBELOW", (0, 0), (-1, 0), 0.75, BORDER),
        ("TOPPADDING", (0, 0), (-1, 0), 6),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 6),
        ("LEFTPADDING", (0, 0), (-1, 0), 10),
        ("RIGHTPADDING", (0, 0), (-1, 0), 10),
        ("TOPPADDING", (0, 1), (-1, last_row), 8),
        ("BOTTOMPADDING", (0, 1), (-1, last_row), 8),
        ("LEFTPADDING", (0, 1), (-1, last_row), 0),
        ("RIGHTPADDING", (0, 1), (-1, last_row), 0),
    ]))
    return table
