"""
Structured-field extraction from free-text log messages.

syslog_parser.py only splits a line into timestamp/host/process/message. The
message body of several well-known daemons carries fields detection rules
need — firewall 5-tuples, DNS queries, sudo command lines, Linux audit
records — so this module pulls those out into named keys that
app/detection/normalize.py maps onto LogRecord. Every extractor returns {}
when the message isn't its format; nothing is guessed.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

_IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"

# ── Netfilter / UFW / firewalld kernel log lines ─────────────────────────────
# kernel: [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=203.0.113.9 DST=10.0.0.5 LEN=60 ... PROTO=TCP SPT=4444 DPT=22
_NETFILTER_KV = re.compile(r"\b(SRC|DST|SPT|DPT|PROTO|LEN|IN|OUT)=(\S*)")
_NETFILTER_ACTION = re.compile(r"\[(?:UFW\s+)?(BLOCK|ALLOW|AUDIT|LIMIT BLOCK|DROP|ACCEPT|REJECT)\]|\b(DROP|ACCEPT|REJECT|BLOCK)\b")

# ── DNS resolvers ────────────────────────────────────────────────────────────
_DNSMASQ_QUERY = re.compile(rf"^query\[(\w+)\]\s+(\S+)\s+from\s+({_IPV4})")
_BIND_QUERY = re.compile(rf"client\s+(?:@\S+\s+)?({_IPV4})#\d+.*?query:\s+(\S+)\s+IN\s+(\w+)")
_UNBOUND_QUERY = re.compile(rf"^(?:info:\s+)?({_IPV4})\s+(\S+?)\.?\s+(\w+)\s+IN\s*$")

# ── sudo ─────────────────────────────────────────────────────────────────────
_SUDO_COMMAND = re.compile(r"COMMAND=(.+?)\s*$")

# ── Linux audit ──────────────────────────────────────────────────────────────
_AUDIT_HEADER = re.compile(r"(?:node=(\S+)\s+)?type=(\w+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$")
_AUDIT_KV = re.compile(r"""([\w-]+)=("(?:[^"\\]|\\.)*"|'[^']*'|\S+)""")
_HEX_ARG = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _decode_audit_arg(raw: str) -> str:
    """Audit encodes args containing spaces/specials as unquoted hex."""

    if raw.startswith('"'):
        return _unquote(raw)
    if raw != "(null)" and _HEX_ARG.match(raw) and len(raw) >= 4:
        try:
            return bytes.fromhex(raw).decode("utf-8", "replace").replace("\x00", " ")
        except ValueError:
            return raw
    return raw


def extract_netfilter(message: str) -> dict:
    fields = {key: value for key, value in _NETFILTER_KV.findall(message or "")}
    if not fields.get("SRC") or not fields.get("DST"):
        return {}
    action_match = _NETFILTER_ACTION.search(message)
    action = (action_match.group(1) or action_match.group(2)).upper() if action_match else None
    result = {
        "ip_address": fields["SRC"],
        "dest_ip": fields["DST"],
        "protocol": (fields.get("PROTO") or "").lower() or None,
        "event_type": "network_connection",
        "firewall_action": action,
    }
    if fields.get("DPT", "").isdigit():
        result["destination_port"] = int(fields["DPT"])
    if fields.get("SPT", "").isdigit():
        result["source_port"] = int(fields["SPT"])
    if fields.get("LEN", "").isdigit():
        # Packet length, not a flow byte count — deliberately not bytes_out.
        result["packet_length"] = int(fields["LEN"])
    if action in ("BLOCK", "LIMIT BLOCK", "DROP", "REJECT"):
        result["status"] = "FAILED"
    elif action in ("ALLOW", "ACCEPT"):
        result["status"] = "SUCCESS"
    return result


def extract_dns_query(process: str | None, message: str) -> dict:
    process = (process or "").lower()
    message = (message or "").strip()

    match = _DNSMASQ_QUERY.match(message) if "dnsmasq" in process else None
    if match:
        qtype, name, client = match.groups()
        return {"dns_query": name.rstrip("."), "dns_query_type": qtype.upper(), "ip_address": client, "event_type": "dns_query"}

    match = _BIND_QUERY.search(message) if process in ("named", "bind", "bind9") else None
    if match:
        client, name, qtype = match.groups()
        return {"dns_query": name.rstrip("."), "dns_query_type": qtype.upper(), "ip_address": client, "event_type": "dns_query"}

    match = _UNBOUND_QUERY.match(message) if "unbound" in process else None
    if match:
        client, name, qtype = match.groups()
        return {"dns_query": name.rstrip("."), "dns_query_type": qtype.upper(), "ip_address": client, "event_type": "dns_query"}

    return {}


def extract_sudo_command(process: str | None, message: str) -> dict:
    if (process or "").lower() != "sudo":
        return {}
    match = _SUDO_COMMAND.search(message or "")
    return {"command": match.group(1)} if match else {}


def parse_audit_record(text: str) -> dict:
    """Parse one `type=X msg=audit(epoch:serial): k=v ...` record."""

    match = _AUDIT_HEADER.search(text or "")
    if not match:
        return {}
    node, audit_type, epoch, serial, body = match.groups()
    fields: dict[str, str] = {}
    exec_args: dict[int, str] = {}
    for key, raw in _AUDIT_KV.findall(body):
        if audit_type == "EXECVE" and re.fullmatch(r"a\d+", key):
            exec_args[int(key[1:])] = _decode_audit_arg(raw)
        else:
            fields[key] = _unquote(raw)

    timestamp = datetime.fromtimestamp(float(epoch), tz=timezone.utc).isoformat().replace("+00:00", "Z")
    record: dict = {
        "audit_type": audit_type,
        "audit_event_id": f"{epoch}:{serial}",
        "audit_timestamp": timestamp,
        "audit_fields": fields,
    }
    if node:
        record["hostname"] = node
    if exec_args:
        record["command"] = " ".join(exec_args[index] for index in sorted(exec_args))
    if audit_type == "PROCTITLE" and fields.get("proctitle"):
        record["command"] = _decode_audit_arg(fields["proctitle"])
    if audit_type == "PATH" and fields.get("name") not in (None, "(null)"):
        record["file_path"] = _decode_audit_arg(fields["name"])
    key = fields.get("key")
    if key and key != "(null)":
        record["audit_key"] = key
    for name_field in ("AUID", "UID"):
        if fields.get(name_field) and fields[name_field] not in ("unset", "4294967295"):
            record["username"] = fields[name_field]
            break
    if fields.get("addr") and re.fullmatch(_IPV4, fields["addr"]):
        record["ip_address"] = fields["addr"]
    return record


def extract_from_message(process: str | None, message: str | None) -> dict:
    """Best structured interpretation of one syslog message body, or {}."""

    if not message:
        return {}
    if "msg=audit(" in message:
        return parse_audit_record(message)
    for extractor in (
        lambda: extract_netfilter(message) if "SRC=" in message and "DST=" in message else {},
        lambda: extract_dns_query(process, message),
        lambda: extract_sudo_command(process, message),
    ):
        fields = extractor()
        if fields:
            return fields
    return {}
