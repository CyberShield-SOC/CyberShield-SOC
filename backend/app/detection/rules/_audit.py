"""
Linux audit helpers shared by host-integrity rules.

An audit event may reach the engine either as one merged entry (raw
audit.log via auditd_parser.py) or as one LogRecord per record line (audit
forwarded through syslog). merge_audit_events() gives rules the same merged
view in both cases so each rule only has to reason about whole events.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.detection.models import LogRecord

# x86_64 syscall numbers and names for calls that modify a path.
_MODIFY_SYSCALLS = {
    "85": "creat", "76": "truncate", "77": "ftruncate", "82": "rename", "264": "renameat",
    "316": "renameat2", "87": "unlink", "263": "unlinkat", "86": "link", "265": "linkat",
    "88": "symlink", "266": "symlinkat", "90": "chmod", "91": "fchmod", "268": "fchmodat",
    "92": "chown", "93": "fchown", "94": "lchown", "260": "fchownat", "188": "setxattr",
    "189": "lsetxattr", "190": "fsetxattr",
}
_MODIFY_SYSCALL_NAMES = set(_MODIFY_SYSCALLS.values())
_OPEN_SYSCALLS = {"2": ("open", "a1"), "257": ("openat", "a2"), "open": ("open", "a1"), "openat": ("openat", "a2")}
# O_WRONLY | O_RDWR | O_CREAT | O_TRUNC | O_APPEND
_WRITE_FLAG_MASK = 0x1 | 0x2 | 0x40 | 0x200 | 0x400
_TRUNCATE_FLAG = 0x200


@dataclass
class AuditEvent:
    event_id: str
    hostname: str | None
    timestamp: str | None
    username: str | None
    line_numbers: list[int] = field(default_factory=list)
    types: set[str] = field(default_factory=set)
    fields: dict[str, str] = field(default_factory=dict)
    paths: list[dict] = field(default_factory=list)
    command: str | None = None
    audit_key: str | None = None

    @property
    def syscall(self) -> str | None:
        return self.fields.get("syscall")

    def open_flags(self) -> int | None:
        entry = _OPEN_SYSCALLS.get(str(self.syscall))
        if entry is None:
            return None
        raw = self.fields.get(entry[1])
        if raw is None:
            return None
        try:
            return int(raw, 16)
        except ValueError:
            return None

    def is_modification(self) -> bool:
        """Did this event write, create, delete, rename, or re-permission a path?"""

        if any(p.get("nametype") in ("CREATE", "DELETE") for p in self.paths):
            return True
        syscall = str(self.syscall or "")
        if syscall in _MODIFY_SYSCALLS or syscall in _MODIFY_SYSCALL_NAMES:
            return True
        flags = self.open_flags()
        return flags is not None and bool(flags & _WRITE_FLAG_MASK)

    def is_read_only_open(self) -> bool:
        flags = self.open_flags()
        return flags is not None and not flags & _WRITE_FLAG_MASK

    def is_truncation_or_delete(self) -> bool:
        if any(p.get("nametype") == "DELETE" for p in self.paths):
            return True
        syscall = str(self.syscall or "")
        if _MODIFY_SYSCALLS.get(syscall, syscall) in ("truncate", "ftruncate", "unlink", "unlinkat"):
            return True
        flags = self.open_flags()
        return flags is not None and bool(flags & _TRUNCATE_FLAG)

    def target_paths(self) -> list[str]:
        return [p["name"] for p in self.paths if p.get("name") and p.get("nametype") != "PARENT"]


def merge_audit_events(records: list[LogRecord]) -> list[AuditEvent]:
    events: dict[tuple[str | None, str], AuditEvent] = {}
    for record in records:
        if not record.audit_event_id:
            continue
        key = (record.hostname, record.audit_event_id)
        event = events.get(key)
        if event is None:
            event = AuditEvent(
                event_id=record.audit_event_id,
                hostname=record.hostname,
                timestamp=record.timestamp,
                username=record.username,
            )
            events[key] = event

        event.line_numbers.append(record.line_number)
        event.types.update(t for t in (record.audit_type or "").split(",") if t)
        for name, value in (record.extra.get("audit_fields") or {}).items():
            event.fields.setdefault(name, value)
        merged_paths = record.extra.get("audit_paths")
        if merged_paths:
            event.paths.extend(merged_paths)
        elif record.file_path and "PATH" in (record.audit_type or ""):
            event.paths.append({
                "name": record.file_path,
                "nametype": (record.extra.get("audit_fields") or {}).get("nametype"),
            })
        event.command = event.command or record.command
        event.audit_key = event.audit_key or record.audit_key
        event.username = event.username or record.username
    return list(events.values())
