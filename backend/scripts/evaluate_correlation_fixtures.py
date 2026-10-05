"""Run the KK-01 correlation fixtures and print the KK-02 evaluation report.

    cd backend && python scripts/evaluate_correlation_fixtures.py [--out report.txt]

Exit status is 1 when any fixture fails, so CI or a script can gate on it.
Failed fixtures list the exact group keys so a defect can be handed to the
backend owner with a reproducible input (the fixture name in
tests/correlation_fixtures/cases.py).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.correlation_fixtures import FIXTURES, evaluate_all, render_report  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, help="also write the report to this file")
    args = parser.parse_args()

    results = evaluate_all(FIXTURES)
    report = render_report(results)
    print(report)
    if args.out:
        args.out.write_text(report + "\n", encoding="utf-8")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
