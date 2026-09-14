from __future__ import annotations

from app.detection.models import Alert


_RULE_TITLES = {
    "brute_force_login": (
        "Possible brute-force login activity"
    ),
    "invalid_user_enumeration": (
        "Possible username enumeration"
    ),
    "sudo_failure": (
        "Repeated sudo authentication failures"
    ),
    "password_spraying": (
        "Possible password spraying"
    ),
    "credential_stuffing_success": (
        "Possible account takeover after credential stuffing"
    ),
    "port_scan": (
        "Possible port scan activity"
    ),
    "multi_ip_successful_login": (
        "Account used from multiple source IPs"
    ),
    "sudo_after_login": (
        "Rapid privilege escalation after login"
    ),
    "new_account_created": (
        "New account created"
    ),
    "privileged_group_modified": (
        "Account added to a privileged group"
    ),
    "cron_persistence": (
        "Scheduled-task persistence mechanism created"
    ),
    "security_control_disabled": (
        "Security control disabled or flushed"
    ),
    "log_tampering": (
        "Audit or logging service tampered with"
    ),
    "direct_root_login": (
        "Direct root login"
    ),
    "service_account_interactive": (
        "Service account used interactively"
    ),
    "login_to_nonexistent_account": (
        "Login attempt against a decommissioned account"
    ),
    "off_hours_login": (
        "Login outside the configured business-hours window"
    ),
    "dormant_account_activity": (
        "Dormant account suddenly active"
    ),
    "lateral_movement_chain": (
        "Account authenticated across multiple hosts in sequence"
    ),
    "ssh_key_added": "SSH authorized key modified",
    "host_log_silence": "Host stopped sending logs",
    "impossible_travel": "Impossible travel between logins",
    "first_seen_geo_asn": "Login from a new country or network",
    "host_sweep": "Possible host sweep",
    "outbound_beaconing": "Possible command-and-control beaconing",
    "dns_tunneling": "Possible DNS tunneling",
    "egress_volume_anomaly": "Unusual outbound data volume",
    "threat_intel_match": "Threat intelligence indicator match",
    "behavioral_anomaly_login": "Unusual login behavior (ML)",
    "behavioral_anomaly_egress": "Unusual egress behavior (ML)",
}


def serialize_alert(alert: Alert) -> dict:
    """Convert a detection alert into a transportable dictionary."""

    data = (
        alert.model_dump()
        if hasattr(alert, "model_dump")
        else alert.dict()
    )

    return {
        **data,
        "title": _RULE_TITLES.get(
            alert.rule,
            "Security alert",
        ),
        "ip_address": alert.source_ip,
        "user": alert.username,
        "reason": alert.description,
        "timestamp_range": {
            "start": alert.first_seen,
            "end": alert.last_seen,
        },
    }