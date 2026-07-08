import re
import csv
import json
import sys
from pathlib import Path

"""
CyberShield SOC - Sprint 2 Parser Schema Fix

Output schema:
{
    "timestamp": "",
    "host": "",
    "source": "",
    "ip": "",
    "user": "",
    "event_type": "",
    "status": ""
}
"""

SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<source>[A-Za-z0-9_\-/]+)(?:\[\d+\])?:\s*'
    r'(?P<message>.*)$'
)

LEGACY_PATTERN = re.compile(
    r'^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<message>.*)$'
)

IP_PATTERN = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')

FIELDNAMES = ["timestamp", "host", "source", "ip", "user", "event_type", "status"]


def empty_record():
    return {
        "timestamp": "",
        "host": "",
        "source": "",
        "ip": "",
        "user": "",
        "event_type": "",
        "status": ""
    }


def normalize_source(source, message):
    source = (source or "").lower()
    message_lower = message.lower()

    if "sshd" in source or "sshd" in message_lower:
        return "sshd"
    if "sudo" in source or "sudo" in message_lower:
        return "sudo"
    return source


def extract_user(message, event_type):
    patterns = []

    if event_type == "failed_login":
        patterns = [
            r'Failed password for invalid user\s+(\S+)',
            r'Failed password for\s+(\S+)'
        ]
    elif event_type == "invalid_user":
        patterns = [r'Invalid user\s+(\S+)']
    elif event_type == "successful_login":
        patterns = [r'Accepted password for\s+(\S+)']
    elif event_type == "sudo_auth_failure":
        patterns = [
            r'user=(\S+)',
            r'for user\s+(\S+)',
            r'authentication failure.*?ruser=(\S+)'
        ]

    for pattern in patterns:
        match = re.search(pattern, message)
        if match:
            return match.group(1).strip(',;')
    return ""


def classify_event(message):
    msg = message.lower()

    if "failed password" in msg:
        return "failed_login", "failure"
    if "invalid user" in msg:
        return "invalid_user", "failure"
    if "accepted password" in msg or "accepted publickey" in msg:
        return "successful_login", "success"
    if "sudo" in msg and ("authentication failure" in msg or "auth failure" in msg or "pam_unix" in msg):
        return "sudo_auth_failure", "failure"
    if "connection closed" in msg:
        return "connection_closed", "closed"

    return "unknown", "unknown"


def parse_line(line):
    line = line.strip()
    if not line:
        return None

    record = empty_record()

    match = SYSLOG_PATTERN.match(line)
    if match:
        record["timestamp"] = match.group("timestamp")
        record["host"] = match.group("host")
        record["source"] = match.group("source")
        message = match.group("message")
    else:
        match = LEGACY_PATTERN.match(line)
        if not match:
            return None
        record["timestamp"] = match.group("timestamp")
        message = match.group("message")

    record["source"] = normalize_source(record["source"], message)

    ip_match = IP_PATTERN.search(message)
    if ip_match:
        record["ip"] = ip_match.group(1)

    event_type, status = classify_event(message)
    record["event_type"] = event_type
    record["status"] = status
    record["user"] = extract_user(message, event_type)

    # Keep useful connection events but ignore unknown/unclassified noise.
    if record["event_type"] == "unknown":
        return None

    return record


def parse_log_file(file_path):
    parsed = []
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            record = parse_line(line)
            if record:
                parsed.append(record)
    return parsed


def parse_csv_file(file_path):
    parsed = []
    with open(file_path, "r", encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            record = empty_record()
            record["timestamp"] = row.get("timestamp", "")
            record["host"] = row.get("host", "")
            record["source"] = normalize_source(row.get("source", ""), row.get("event_type", ""))
            record["ip"] = row.get("ip", "")
            record["user"] = row.get("user", row.get("username", ""))
            record["event_type"] = row.get("event_type", row.get("event", "")).lower().replace(" ", "_")
            status = row.get("status", "").lower()
            if status in ["fail", "failed"]:
                status = "failure"
            elif status in ["ok", "success", "successful"]:
                status = "success"
            record["status"] = status
            parsed.append(record)
    return parsed


def save_json(data, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)


def save_csv(data, output_file):
    with open(output_file, "w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(data)


def main():
    if len(sys.argv) < 2:
        print("Usage: python parser/log_parser.py sample_logs/auth_sprint2.log")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: file not found -> {input_path}")
        sys.exit(1)

    if input_path.suffix.lower() == ".csv":
        parsed_logs = parse_csv_file(input_path)
    else:
        parsed_logs = parse_log_file(input_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    json_path = output_dir / "parsed_logs_sprint2.json"
    csv_path = output_dir / "parsed_logs_sprint2.csv"

    save_json(parsed_logs, json_path)
    save_csv(parsed_logs, csv_path)

    print("Sprint 2 parser schema fix complete.")
    print(f"Records parsed: {len(parsed_logs)}")
    print(f"JSON saved as {json_path}")
    print(f"CSV saved as {csv_path}")


if __name__ == "__main__":
    main()
