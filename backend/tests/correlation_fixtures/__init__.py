"""Repeatable correlation fixtures (Sprint 6 KK-01) and their evaluator (KK-02)."""

from .cases import FIXTURES, CorrelationFixture, ExpectedGroup
from .evaluate import FixtureResult, evaluate_all, evaluate_fixture, render_report, summarize

__all__ = [
    "FIXTURES",
    "CorrelationFixture",
    "ExpectedGroup",
    "FixtureResult",
    "evaluate_all",
    "evaluate_fixture",
    "render_report",
    "summarize",
]
