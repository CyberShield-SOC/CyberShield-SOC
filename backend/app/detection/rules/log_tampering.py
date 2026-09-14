from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules._audit import merge_audit_events
from app.detection.rules._host_alerts import host_alert, merge_host_alerts
from app.detection.rules._host_event_patterns import (
    DEFAULT_LOG_SERVICES,
    HISTORY_FILE,
    LOG_TAMPER_COMMANDS,
    SYSTEM_LOG_FILE,
    extract_stopped_service,
    is_journal_vacuum,
    match_command,
    stopped_service_in_command,
)
from app.detection.rules.base import BaseRule


class LogTamperingRule(BaseRule):
    """Fires when logging or audit evidence is destroyed or switched off:

    - systemd stops a watched logging/audit service, or journald reports a
      vacuum (syslog);
    - a command deletes/truncates shell history or /var/log files, clears
      `history`, disables HISTFILE, vacuums the journal, deletes audit
      rules, or stops a logging service (sudo COMMAND= or audit EXECVE);
    - an audit record shows a history/system log file deleted or truncated,
      audit rules removed (CONFIG_CHANGE), or auditd halting (DAEMON_END).

    `history -c` typed directly in an interactive shell is a builtin that no
    log records; it is only caught when run through `bash -c` under auditd.
    Processes in params.ignored_processes (logrotate by default) may rotate
    and delete log files without alerting.
    """

    name = "log_tampering"
    description = "Audit/log evidence was deleted, truncated, or its service stopped."
    severity = "CRITICAL"
    mitre_technique = "T1070"
    entity_type = "host"
    confidence = 80
    DEFAULT_PARAMS = {"ignored_processes": "logrotate,systemd-tmpfiles,journald"}

    def __init__(
        self,
        cooldown_seconds: int = 900,
        allowlist: list[str] | None = None,
        params: dict | None = None,
    ):
        self.cooldown_seconds = cooldown_seconds
        self.allowlist = allowlist
        self.params = self.merge_params(params)
        self._watched = tuple(s.lower() for s in allowlist) if allowlist else DEFAULT_LOG_SERVICES
        self._ignored = {
            name.strip().lower() for name in str(self.params["ignored_processes"]).split(",") if name.strip()
        }

    def _alert(self, record_like, lines, reason, evidence) -> Alert:
        return host_alert(
            self,
            hostname=record_like.hostname,
            timestamp=record_like.timestamp,
            line_numbers=lines,
            username=record_like.username,
            prefix="Possible log tampering",
            reason=reason,
            evidence=evidence,
        )

    def _command_reason(self, command: str | None) -> str | None:
        reason = match_command(command, LOG_TAMPER_COMMANDS)
        if reason:
            return reason
        service = stopped_service_in_command(command, self._watched)
        return f"logging service '{service}' stopped by command" if service else None

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        alerts: list[Alert] = []

        for record in records:
            if record.audit_event_id:
                continue
            service = extract_stopped_service(record.process, record.message)
            if service is not None and any(watched in service.lower() for watched in self._watched):
                alerts.append(self._alert(record, [record.line_number], f"logging/audit service '{service}' was stopped", {"service": service}))
            elif is_journal_vacuum(record.process, record.message):
                alerts.append(self._alert(record, [record.line_number], "the systemd journal was vacuumed (cleared)", {}))
            else:
                reason = self._command_reason(record.command)
                if reason:
                    alerts.append(self._alert(record, [record.line_number], reason, {"command": record.command}))

        for event in merge_audit_events(records):
            process = (event.fields.get("comm") or "").lower()
            if process in self._ignored:
                continue
            evidence: dict = {"audit_event_id": event.event_id}
            reason = None

            if "DAEMON_END" in event.types:
                reason = "the audit daemon stopped (DAEMON_END)"
            elif "CONFIG_CHANGE" in event.types and (
                event.fields.get("op") == "remove_rule" or event.fields.get("audit_enabled") == "0"
            ):
                reason = "audit rules were removed or auditing was disabled"
            else:
                reason = self._command_reason(event.command)
                if reason:
                    evidence["command"] = event.command
                elif event.is_truncation_or_delete():
                    touched = [
                        path for path in event.target_paths()
                        if HISTORY_FILE.search(path) or SYSTEM_LOG_FILE.match(path)
                    ]
                    if touched:
                        reason = f"'{touched[0]}' was deleted or truncated"
                        evidence["file_path"] = touched[0]
                        evidence["process"] = event.fields.get("comm")

            if reason:
                alerts.append(self._alert(event, event.line_numbers, reason, evidence))

        return merge_host_alerts(self, alerts, self.cooldown_seconds)
