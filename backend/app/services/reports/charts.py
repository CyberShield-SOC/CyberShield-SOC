"""reportlab.graphics charts shared by every report builder.

One chart type covers every "over time, by severity/priority" panel in the
brief: a stacked vertical bar chart with real axes and a legend.
"""

from __future__ import annotations

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.charts.legends import Legend
from reportlab.graphics.shapes import Drawing

from app.services.reports.components import SEVERITY_COLORS, SEVERITY_ORDER, TEXT_DARK, TEXT_MUTED


def stacked_bar_chart(
    categories: list[str],
    series_by_label: dict[str, list[float]],
    *,
    width: float,
    height: float = 170,
) -> Drawing:
    """A stacked bar chart with one series per severity/priority label.

    `series_by_label` keys must be a subset of SEVERITY_ORDER so color and
    legend order stay consistent across every report that uses this chart.
    """

    drawing = Drawing(width, height)
    labels = [label for label in SEVERITY_ORDER if label in series_by_label]

    chart = VerticalBarChart()
    chart.x = 35
    chart.y = 28
    chart.width = width - 150
    chart.height = height - 45
    chart.data = [series_by_label[label] for label in labels]
    chart.categoryAxis.categoryNames = categories
    chart.categoryAxis.labels.fontSize = 6.5
    chart.categoryAxis.labels.fillColor = TEXT_MUTED
    chart.categoryAxis.labels.angle = 30 if len(categories) > 8 else 0
    chart.categoryAxis.labels.dy = -8 if chart.categoryAxis.labels.angle else -2
    chart.categoryAxis.style = "stacked"
    chart.valueAxis.valueMin = 0
    chart.valueAxis.labels.fontSize = 6.5
    chart.valueAxis.labels.fillColor = TEXT_MUTED
    chart.barSpacing = 2
    chart.groupSpacing = 6
    for index, label in enumerate(labels):
        chart.bars[index].fillColor = SEVERITY_COLORS[label]
        chart.bars[index].strokeColor = None
    drawing.add(chart)

    legend = Legend()
    legend.x = width - 95
    legend.y = height - 14
    legend.dx = 7
    legend.dy = 7
    legend.fontName = "Helvetica"
    legend.fontSize = 7
    legend.deltay = 11
    legend.columnMaximum = len(labels)
    legend.colorNamePairs = [(SEVERITY_COLORS[label], label.title()) for label in labels]
    drawing.add(legend)

    return drawing


def empty_chart_placeholder(width: float, height: float = 60) -> Drawing:
    from reportlab.graphics.shapes import String

    drawing = Drawing(width, height)
    drawing.add(String(width / 2, height / 2, "No data in this period.", textAnchor="middle", fontName="Helvetica-Oblique", fontSize=9, fillColor=TEXT_MUTED))
    return drawing
