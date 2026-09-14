from __future__ import annotations

from app.detection.models import Alert, LogRecord
from app.detection.rules._audit import merge_audit_events
from app.detection.rules._host_alerts import host_alert, merge_host_alerts
from app.detection.rules._host_event_patterns import (
    AUTHORIZED_KEYS_FILE,
    AUTHORIZED_KEYS_WRITE_COMMAND,
)
from app.detection.rules.base import BaseRule


class SshKeyAddedRule(BaseRule):
    """Fires when an SSH authorized_keys file is written, created, replaced,
    deleted, or re-permissioned.

    sshd never logs changes to authorized_keys, so this needs one of:
    - Linux audit events touching the file (raw audit.log or audit via
      syslog). With a `-w ~/.ssh/authorized_keys -p wa -k ssh_keys` watch,
      any event carrying a watched key counts; otherwise the syscall and
      open flags decide whether it was a write. Plain reads (sshd checking
      keys at login) are ignored.
    - A command line that writes to the file (sudo COMMAND= or audit EXECVE),
      e.g. `tee -a /root/.ssh/authorized_keys` or `ssh-copy-id`.
    """

    name = "ssh_key_added"
    description = "An SSH authorized_keys file was modified."
    severity = "HIGH"
    mitre_technique = "T1098.004"
    entity_type = "host"
    confidence = 80
    DEFAULT_PARAMS = {"watch_keys": "ssh_keys,ssh_key,sshd_keys,authorized_keys"}

    def __init__(self, cooldown_seconds: int = 900, params: dict | None = None):
        self.cooldown_seconds = cooldown_seconds
        self.params = self.merge_params(params)
        self._watch_keys = {k.strip() for k in str(self.params["watch_keys"]).split(",") if k.strip()}

    def _alert(self, record_like, lines, path, how, evidence) -> Alert:
        actor = f" by '{record_like.username}'" if record_like.username else ""
        return host_alert(
            self,
            hostname=record_like.hostname,
            timestamp=record_like.timestamp,
            line_numbers=lines,
            username=record_like.username,
            prefix="SSH authorized_keys modified",
            reason=f"{path}{actor} ({how})",
            evidence={"file_path": path, **evidence},
        )

    def analyze(self, records: list[LogRecord], db=None) -> list[Alert]:
        alerts: list[Alert] = []

        for record in records:
            if record.audit_event_id or not record.command:
                continue
            if AUTHORIZED_KEYS_WRITE_COMMAND.search(record.command):
                alerts.append(self._alert(
                    record, [record.line_number], _path_in(record.command), "written by command",
                    {"command": record.command},
                ))

        for event in merge_audit_events(records):
            key_paths = [path for path in event.target_paths() if AUTHORIZED_KEYS_FILE.search(path)]
            command_write = bool(event.command and AUTHORIZED_KEYS_WRITE_COMMAND.search(event.command))
            if not key_paths and not command_write:
                continue

            how = None
            if command_write:
                how = "written by command"
            elif event.is_modification():
                how = f"{_syscall_label(event)} on the file"
            elif event.audit_key in self._watch_keys and not event.is_read_only_open():
                how = f"matched audit watch '{event.audit_key}'"
            if how is None:
                continue

            path = key_paths[0] if key_paths else _path_in(event.command)
            evidence = {
                "audit_event_id": event.event_id,
                "process": event.fields.get("comm"),
                "exe": event.fields.get("exe"),
            }
            if event.command:
                evidence["command"] = event.command
            alerts.append(self._alert(event, event.line_numbers, path, how, {k: v for k, v in evidence.items() if v}))

        return merge_host_alerts(self, alerts, self.cooldown_seconds)


def _path_in(command: str | None) -> str:
    for token in (command or "").replace(">", " ").split():
        if AUTHORIZED_KEYS_FILE.search(token):
            return token
    return "authorized_keys"


def _syscall_label(event) -> str:
    if any(p.get("nametype") == "CREATE" for p in event.paths):
        return "file created"
    if any(p.get("nametype") == "DELETE" for p in event.paths):
        return "file deleted"
    return f"syscall {event.syscall}" if event.syscall else "write"
