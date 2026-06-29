import re
import csv
import json
import sys
from pathlib import Path

IP_PATTERN = r'(\d{1,3}(?:\.\d{1,3}){3})'
TIMESTAMP_PATTERN = r'^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'

def parse_log_file(file_path):
    parsed = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            record = {"timestamp": "", "ip": "", "username": "", "event": "", "status": ""}

            timestamp_match = re.search(TIMESTAMP_PATTERN, line)
            if timestamp_match:
                record["timestamp"] = timestamp_match.group(1)

            ip_match = re.search(IP_PATTERN, line)
            if ip_match:
                record["ip"] = ip_match.group(1)

            if "Failed password for" in line:
                user_match = re.search(r'Failed password for (\w+)', line)
                if user_match:
                    record["username"] = user_match.group(1)
                record["event"] = "Failed Password"
                record["status"] = "FAIL"

            elif "Invalid user" in line:
                user_match = re.search(r'Invalid user (\w+)', line)
                if user_match:
                    record["username"] = user_match.group(1)
                record["event"] = "Invalid User"
                record["status"] = "FAIL"

            elif "Accepted password for" in line:
                user_match = re.search(r'Accepted password for (\w+)', line)
                if user_match:
                    record["username"] = user_match.group(1)
                record["event"] = "Login Success"
                record["status"] = "SUCCESS"

            elif "sudo auth failure" in line:
                record["event"] = "Sudo Authentication Failure"
                record["status"] = "FAIL"

            if record["event"]:
                parsed.append(record)

    return parsed

def save_json(data, output_file):
    with open(output_file, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)

def save_csv(data, output_file):
    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=["timestamp", "ip", "username", "event", "status"])
        writer.writeheader()
        writer.writerows(data)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parser/log_parser.py sample-logs/auth.log")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    if not input_path.exists():
        print(f"Error: file not found -> {input_path}")
        sys.exit(1)

    parsed_logs = parse_log_file(input_path)

    output_dir = Path("output")
    output_dir.mkdir(exist_ok=True)

    json_path = output_dir / "parsed_logs.json"
    csv_path = output_dir / "parsed_logs.csv"

    save_json(parsed_logs, json_path)
    save_csv(parsed_logs, csv_path)

    print("Parsing complete.")
    print(f"JSON saved as {json_path}")
    print(f"CSV saved as {csv_path}")
