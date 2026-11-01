"""Shared page layout: running header/footer, page numbering, and the
title-block metadata table every report opens with.
"""

from __future__ import annotations

from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas as canvas_module
from reportlab.platypus import SimpleDocTemplate

from app.services.reports.components import TEAL, TEXT_DARK, TEXT_MUTED

PAGE_SIZE = letter
SIDE_MARGIN = 0.5 * inch
TOP_MARGIN = 0.75 * inch
BOTTOM_MARGIN = 0.65 * inch
CONTENT_WIDTH = PAGE_SIZE[0] - 2 * SIDE_MARGIN


def _make_canvas_class(report_name: str, generated_label: str):
    class ReportCanvas(canvas_module.Canvas):
        """Buffers every page so the footer can print 'Page X of Y' — the
        total page count isn't known until the whole document is built.
        """

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states: list[dict] = []

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self._saved_page_states)
            for index, state in enumerate(self._saved_page_states, start=1):
                self.__dict__.update(state)
                self._draw_chrome(index, total_pages)
                super().showPage()
            super().save()

        def _draw_chrome(self, page_number: int, total_pages: int) -> None:
            width, height = PAGE_SIZE

            self.setFont("Helvetica-Bold", 9)
            self.setFillColor(TEAL)
            self.drawString(SIDE_MARGIN, height - 0.45 * inch, "CyberShield SOC")
            self.setFont("Helvetica", 9)
            self.setFillColor(TEXT_MUTED)
            self.drawString(
                SIDE_MARGIN + self.stringWidth("CyberShield SOC ", "Helvetica-Bold", 9),
                height - 0.45 * inch,
                "· Reports",
            )
            self.setFont("Helvetica", 9)
            self.setFillColor(TEXT_DARK)
            self.drawRightString(width - SIDE_MARGIN, height - 0.45 * inch, report_name)
            self.setStrokeColor(TEAL)
            self.setLineWidth(1.2)
            self.line(SIDE_MARGIN, height - 0.52 * inch, width - SIDE_MARGIN, height - 0.52 * inch)

            self.setFont("Helvetica", 7.5)
            self.setFillColor(TEXT_MUTED)
            self.drawString(SIDE_MARGIN, 0.4 * inch, generated_label)
            self.drawCentredString(width / 2, 0.4 * inch, "Confidential · internal use only")
            self.drawRightString(width - SIDE_MARGIN, 0.4 * inch, f"Page {page_number} of {total_pages}")

    return ReportCanvas


def build_pdf(report_name: str, generated_label: str, flowables: list) -> bytes:
    """Render a flowable list into a complete PDF using the shared chrome."""

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=PAGE_SIZE,
        leftMargin=SIDE_MARGIN,
        rightMargin=SIDE_MARGIN,
        topMargin=TOP_MARGIN,
        bottomMargin=BOTTOM_MARGIN,
        title=report_name,
    )
    doc.build(flowables, canvasmaker=_make_canvas_class(report_name, generated_label))
    return buffer.getvalue()
