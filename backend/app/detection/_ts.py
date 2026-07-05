from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def parse_ts(ts: str | None) -> Optional[datetime]:
    """Parse a log timestamp string into a timezone-aware datetime, or None."""
    if not ts:
        return None
    # Python 3.11+ fromisoformat handles "Z", but replace for safety across envs
    clean = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
    try:
        return datetime.fromisoformat(clean)
    except ValueError:
        pass
    # Fallbacks for raw syslog / generic parser output
    for fmt in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"):
        try:
            dt = datetime.strptime(ts.strip(), fmt)
            return dt.replace(year=datetime.now().year, tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def ts_to_str(dt: datetime) -> str:
    """Format a datetime as a UTC ISO 8601 string with Z suffix."""
    utc = dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")
