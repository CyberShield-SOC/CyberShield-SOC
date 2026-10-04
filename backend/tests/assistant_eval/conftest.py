"""Collection gate and end-of-run report for the live assistant eval.

The eval spends real API money and talks to the real model, so it is not
collected unless RUN_ASSISTANT_EVAL=1. A normal `pytest tests` run is
unaffected.
"""

from __future__ import annotations

import os

ENABLED = os.environ.get("RUN_ASSISTANT_EVAL") == "1"

collect_ignore_glob = [] if ENABLED else ["test_*.py"]


def pytest_terminal_summary(terminalreporter):
    if not ENABLED:
        return
    from tests.assistant_eval import report

    text = report.render_terminal()
    if text:
        terminalreporter.write_sep("=", "assistant eval report")
        terminalreporter.write_line(text)
