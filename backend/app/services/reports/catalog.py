"""Static catalog of the four phase-1 reports. No scheduling or run history —
see frontend/docs/BACKEND_CONTRACT.md for what phase 2 would add.
"""

from __future__ import annotations

REPORT_CATALOG: tuple[dict[str, str], ...] = (
    {
        "id": "daily-soc-operations",
        "name": "Daily SOC operations",
        "description": (
            "Hourly alert volume by severity, status mix, top rules and source "
            "IPs, host/log-source health, and incidents opened and assigned "
            "during the selected period."
        ),
    },
    {
        "id": "weekly-incident-summary",
        "name": "Weekly incident summary",
        "description": (
            "Incident volume by severity and rule, time-to-resolve, the full "
            "incident list, the most affected hosts and users, and a "
            "comparison against the previous period."
        ),
    },
    {
        "id": "detection-coverage",
        "name": "Detection coverage",
        "description": (
            "Built-in detection rule status (enabled, shadow-mode, disabled), "
            "MITRE ATT&CK technique coverage, rule activity, and host "
            "heartbeat health."
        ),
    },
    {
        "id": "executive-risk-overview",
        "name": "Executive risk overview",
        "description": (
            "Open high- and critical-severity incidents, alert trend by "
            "severity, the most affected hosts and users, and resolution "
            "performance for leadership review."
        ),
    },
)

REPORT_BY_ID: dict[str, dict[str, str]] = {report["id"]: report for report in REPORT_CATALOG}
