#!/usr/bin/env python3
"""CLI: parse a log file and print all detection alerts.

Usage:
    python scripts/run_detection.py <logfile>

Example:
    python scripts/run_detection.py ../sample_logs/auth.log
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.detection import DetectionEngine
from app.detection.models import LogRecord
from app.parsers.log_parser import parse_log


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"Error: file not found: {path}")
        sys.exit(1)

    content = path.read_text(encoding="utf-8", errors="replace")
    parsed = parse_log(content, path.name)

    records = [
        LogRecord(
            line_number=e["line_number"],
            timestamp=e["parsed"].get("timestamp"),
            ip_address=e["parsed"].get("ip_address") or None,
            username=e["parsed"].get("username") or None,
            event_type=e["parsed"].get("event_type"),
            status=e["parsed"].get("status"),
        )
        for e in parsed["entries"]
    ]

    engine = DetectionEngine()
    alerts = engine.run(records)

    print(f"\n{'=' * 50}")
    print(f"  CyberShield SOC — Detection Report")
    print(f"{'=' * 50}")
    print(f"  File   : {path.name}")
    print(f"  Format : {parsed['format']}")
    print(f"  Entries: {len(records)}")
    print(f"  Alerts : {len(alerts)}")
    print(f"{'=' * 50}\n")

    if not alerts:
        print("  No threats detected.\n")
        return

    for i, a in enumerate(alerts, 1):
        print(f"[{i}] {a.rule.upper().replace('_', ' ')}  [{a.severity}]")
        print(f"     {a.description}")
        if a.source_ip:
            print(f"     Source IP  : {a.source_ip}")
        if a.username:
            print(f"     Username   : {a.username}")
        print(f"     Count      : {a.count} events in {a.time_window_seconds}s window")
        print(f"     First seen : {a.first_seen}")
        print(f"     Last seen  : {a.last_seen}")
        print(f"     Log lines  : {a.matched_line_numbers}")
        print()


if __name__ == "__main__":
    main()
