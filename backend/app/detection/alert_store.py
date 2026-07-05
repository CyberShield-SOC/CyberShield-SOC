from typing import Any

_alerts: list[dict[str, Any]] = []


def replace_alerts(alerts: list[dict[str, Any]]) -> None:
    global _alerts
    _alerts = alerts


def get_alerts() -> list[dict[str, Any]]:
    return _alerts
