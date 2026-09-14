"""
Pattern matching for Group A (post-compromise / log-integrity) rules, over
the `process`/`message`/`command` fields syslog_parser.py and
auditd_parser.py extract.

These patterns match real auth.log / syslog line shapes from useradd,
adduser, usermod, gpasswd, crontab, and systemd — not every possible Linux
distribution's exact wording, so a real deployment should expect to extend
these over time rather than treat them as exhaustive. Each function returns
None/False on no match rather than guessing.
"""

from __future__ import annotations

import re

DEFAULT_PRIVILEGED_GROUPS = ("sudo", "wheel", "admin", "root", "docker")
DEFAULT_SECURITY_SERVICES = ("auditd", "apparmor", "fail2ban", "ufw", "firewalld", "clamav-daemon")
DEFAULT_LOG_SERVICES = ("auditd", "rsyslog", "rsyslogd", "syslog-ng", "systemd-journald")

_USERADD_NAME_RE = re.compile(r"\bname=([A-Za-z0-9_.\-]+)")
_ADDUSER_NAME_RE = re.compile(r"[Aa]dding user `([A-Za-z0-9_.\-]+)'")

_USERMOD_GROUP_RE = re.compile(
    r"add '?([A-Za-z0-9_.\-]+)'? to group '?([A-Za-z0-9_.\-]+)'?"
)
_GPASSWD_GROUP_RE = re.compile(
    r"user ([A-Za-z0-9_.\-]+) added by \S+ to group ([A-Za-z0-9_.\-]+)"
)

_CRONTAB_EDIT_RE = re.compile(r"\(([A-Za-z0-9_.\-]+)\)\s+(REPLACE|BEGIN EDIT|EDIT)\b")
_SYSTEMD_TIMER_RE = re.compile(r"^Started\s+(\S+\.timer)\.?$")

_SYSTEMD_STOPPED_RE = re.compile(r"^Stopp(?:ed|ing)\s+(.+?)\.?$")


def extract_created_account(process: str | None, message: str | None) -> str | None:
    """Return the created username for a useradd/adduser event, else None."""

    if not message:
        return None
    process = (process or "").lower()

    if process in ("useradd",):
        match = _USERADD_NAME_RE.search(message)
        if match:
            return match.group(1)

    if process in ("adduser",):
        match = _ADDUSER_NAME_RE.search(message)
        if match:
            return match.group(1)
        match = _USERADD_NAME_RE.search(message)
        if match:
            return match.group(1)

    return None


def extract_privileged_group_addition(
    process: str | None,
    message: str | None,
    *,
    privileged_groups: tuple[str, ...] = DEFAULT_PRIVILEGED_GROUPS,
) -> tuple[str, str] | None:
    """Return (username, group) if this event adds an account to a
    configured privileged group, else None."""

    if not message:
        return None
    process = (process or "").lower()
    groups_lower = {g.lower() for g in privileged_groups}

    match = None
    if process == "usermod":
        match = _USERMOD_GROUP_RE.search(message)
    elif process == "gpasswd":
        match = _GPASSWD_GROUP_RE.search(message)

    if not match:
        return None

    username, group = match.group(1), match.group(2)
    if group.lower() not in groups_lower:
        return None
    return username, group


def extract_cron_persistence(process: str | None, message: str | None) -> str | None:
    """Return a short description of the cron/timer persistence event, else None."""

    if not message:
        return None
    process = (process or "").lower()

    if process == "crontab":
        match = _CRONTAB_EDIT_RE.search(message)
        if match:
            return f"crontab edited for {match.group(1)}"

    if process == "systemd":
        match = _SYSTEMD_TIMER_RE.match(message.strip())
        if match:
            return f"systemd timer started: {match.group(1)}"

    return None


def extract_stopped_service(process: str | None, message: str | None) -> str | None:
    """Return the service name systemd reports stopping/stopped, else None.

    Shared by security_control_disabled (security agents/firewalls) and
    log_tampering (audit/logging services) — each rule matches the returned
    name against its own configured service list.
    """

    if not message or (process or "").lower() != "systemd":
        return None
    match = _SYSTEMD_STOPPED_RE.match(message.strip())
    return match.group(1) if match else None


# ── Command-line patterns (sudo COMMAND=, audit EXECVE/PROCTITLE) ────────────
# Each entry is (compiled pattern, human-readable reason).

_SERVICE_STOP_COMMAND = re.compile(
    r"\b(?:systemctl|service)\b(?P<args>.*)", re.IGNORECASE
)
_STOP_VERB = re.compile(r"\b(?:stop|disable|mask|kill)\b", re.IGNORECASE)

SECURITY_DISABLE_COMMANDS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\b(?:ip6?tables(?:-legacy|-nft)?)\b.*\s(?:-F|--flush|-X|--delete-chain)(?:\s|$)"), "firewall rules flushed"),
    (re.compile(r"\b(?:ip6?tables(?:-legacy|-nft)?)\b.*\s(?:-P|--policy)\s+(?:INPUT|FORWARD|OUTPUT)\s+ACCEPT\b"), "firewall default policy set to ACCEPT"),
    (re.compile(r"\bnft\s+(?:flush\s+ruleset|delete\s+table)\b"), "nftables ruleset flushed"),
    (re.compile(r"\bufw\s+(?:--force\s+)?(?:disable|reset)\b"), "ufw firewall disabled"),
    (re.compile(r"\bsetenforce\s+(?:0|permissive)\b", re.IGNORECASE), "SELinux switched to permissive"),
    (re.compile(r"\bSELINUX=(?:disabled|permissive)\b"), "SELinux configuration set to disabled/permissive"),
    (re.compile(r"\b(?:aa-teardown|aa-disable|aa-complain)\b"), "AppArmor profiles disabled or set to complain"),
)

LOG_TAMPER_COMMANDS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(r"\bauditctl\s+(?:-e\s*0|-D)\b"), "audit rules deleted or auditing disabled"),
    (re.compile(r"\bjournalctl\b.*--vacuum-(?:time|size|files)"), "system journal vacuumed"),
    (re.compile(r"\b(?:rm|shred|truncate|unlink|srm|wipe)\b.*(?:\.(?:bash|zsh|sh|ksh|ash)_history\b|\bfish_history\b|\.history\b)"), "shell history file deleted or truncated"),
    (re.compile(r"\bln\s+-\w*s\w*\s+/dev/null\s+\S*history"), "shell history redirected to /dev/null"),
    (re.compile(r"\b(?:cat|cp)\s+/dev/null\s+>?\s*\S*history"), "shell history truncated"),
    (re.compile(r"\bhistory\s+-[cw]\b"), "shell history cleared"),
    (re.compile(r"\bunset\s+HISTFILE\b|\bHISTFILE=/dev/null\b|\bHISTSIZE=0\b"), "shell history recording disabled"),
    (re.compile(r"\b(?:rm|shred|truncate|srm|wipe)\b.*/var/log/"), "system log files deleted or truncated"),
    (re.compile(r"(?:^|[;&|]\s*|\bsh\s+-c\s+['\"]?)(?:cat\s+/dev/null\s*)?>\s*/var/log/\S+"), "system log file truncated"),
)

HISTORY_FILE = re.compile(r"(?:^|/)\.?(?:bash|zsh|sh|ksh|ash|python|mysql|psql|lesshst)?_?history$|(?:^|/)fish_history$")
SYSTEM_LOG_FILE = re.compile(r"^/var/log/(?:auth\.log|secure|syslog|messages|kern\.log|audit/audit\.log|wtmp|btmp|lastlog|journal/.*)$")
AUTHORIZED_KEYS_FILE = re.compile(r"(?:^|/)\.ssh/authorized_keys2?$")
AUTHORIZED_KEYS_WRITE_COMMAND = re.compile(
    r"(?:\b(?:tee|cp|mv|install|sed\s+-i|ssh-copy-id|chmod|chattr|chown|rm|truncate|dd|ln)\b.*authorized_keys"
    r"|>>?\s*\S*authorized_keys)"
)


def match_command(command: str | None, patterns: tuple[tuple[re.Pattern, str], ...]) -> str | None:
    if not command:
        return None
    for pattern, reason in patterns:
        if pattern.search(command):
            return reason
    return None


def stopped_service_in_command(command: str | None, watched: tuple[str, ...]) -> str | None:
    """Return the watched service a `systemctl/service ... stop` command targets."""

    if not command:
        return None
    match = _SERVICE_STOP_COMMAND.search(command)
    if not match or not _STOP_VERB.search(match.group("args")):
        return None
    args = match.group("args").lower()
    return next((service for service in watched if re.search(rf"\b{re.escape(service)}\b", args)), None)


def is_journal_vacuum(process: str | None, message: str | None) -> bool:
    """True when systemd-journald reports vacuuming (clearing) the journal."""

    if not message:
        return False
    if (process or "").lower() != "systemd-journald":
        return False
    return "vacuum" in message.lower()
