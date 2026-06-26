# CyberShield SOC — Backend Sprint 1

Log Upload & Parsing API built with Python FastAPI.

Sprint 1 goal: upload `.log` or `.csv` security logs, validate the file, parse basic fields, return JSON, and show parsed results in a simple table.

---

## What this backend covers

| Sprint 1 requirement | Included |
|---|---|
| Backend project setup | Yes |
| `POST /upload` endpoint | Yes |
| `.log` and `.csv` file validation | Yes |
| Uploaded file reading | Yes |
| Parser handoff | Yes |
| Parsed JSON response | Yes |
| Error handling for unsupported/empty/large/bad files | Yes |
| Basic fields: timestamp, IP address, username, event type, status | Yes |
| Simple table display | Yes, preview page at `/` |
| Sample security logs for testing | Not included yet |

---

## Tech stack

| Layer | Choice |
|---|---|
| Language | Python 3.11+ |
| Framework | FastAPI |
| Server | Uvicorn |
| Testing | Pytest + HTTPX |

---

## Project structure

```text
CyberShiled-SOC/
├── backend/
│   ├── main.py                   # PyCharm/script launcher
│   ├── requirements.txt
│   └── app/
│       ├── main.py               # FastAPI app, / page, /health, router setup
│       ├── routers/
│       │   └── upload.py         # POST /upload and POST /api/upload
│       ├── middleware/
│       │   └── file_validation.py
│       └── parsers/
│           ├── field_normalizer.py
│           ├── log_parser.py
│           ├── syslog_parser.py
│           ├── apache_parser.py
│           ├── csv_parser.py
│           └── generic_parser.py
└── README.md
```

---

## Setup

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

macOS/Linux:

```bash
source venv/bin/activate
```

Install dependencies:

```bash
pip install -r backend/requirements.txt
```

Run the server:

```bash
cd backend
uvicorn app.main:app --reload --port 3000
```

You can also run the script launcher from the repository root:

```bash
python backend/main.py
```

Open:

- Simple upload/table page: `http://localhost:3000/`
- API docs: `http://localhost:3000/docs`
- Health check: `http://localhost:3000/health`

---

## API endpoints

### `POST /upload`

Uploads and parses a log file.

The project also supports `POST /api/upload` for frontend/API routing.

Request:

- Content type: `multipart/form-data`
- Field name: `logfile`
- Accepted extensions: `.log`, `.csv`
- Max size: 10 MB

Example:

```bash
curl -X POST http://localhost:3000/upload \
  -F "logfile=@sample_auth.log"
```

Successful response:

```json
{
  "success": true,
  "upload": {
    "upload_id": "generated-id",
    "filename": "sample_auth.log",
    "mime_type": "text/plain",
    "size_bytes": 512,
    "uploaded_at": "2026-06-25T00:00:00+00:00"
  },
  "parsing": {
    "format": "syslog",
    "total_lines": 9,
    "parsed_entries": 9,
    "skipped_lines": 0,
    "fields": [
      "timestamp",
      "ip_address",
      "username",
      "event_type",
      "status"
    ]
  },
  "entries": [
    {
      "line_number": 1,
      "raw": "Jan 10 08:00:01 server01 sshd[1234]: Failed password for root from 192.168.1.10 port 22 ssh2",
      "parsed": {
        "timestamp": "2026-01-10T08:00:01Z",
        "ip_address": "192.168.1.10",
        "username": "root",
        "event_type": "login_attempt",
        "status": "FAILED",
        "hostname": "server01",
        "process": "sshd",
        "pid": 1234,
        "message": "Failed password for root from 192.168.1.10 port 22 ssh2",
        "severity": "WARNING"
      }
    }
  ],
  "skipped_lines": []
}
```

### `GET /upload/formats`

Returns accepted upload formats.

### `GET /`

Displays a simple browser page where users can upload a log and see parsed results in a table.

---

## Error handling

| Status | Code | Reason |
|---|---|---|
| 400 | `EMPTY_FILE` | Uploaded file has no content |
| 400 | `ENCODING_ERROR` | File is not valid UTF-8 text |
| 413 | `FILE_TOO_LARGE` | File is over 10 MB |
| 415 | `INVALID_FILE_TYPE` | File is not `.log` or `.csv` |
| 415 | `INVALID_MIME_TYPE` | File MIME type is unsupported |
| 422 | FastAPI validation | Required file field is missing |
| 500 | `INTERNAL_ERROR` | Unexpected server error |

---

## Parsed fields

Every parsed row includes these Sprint 1 fields:

```json
{
  "timestamp": "...",
  "ip_address": "...",
  "username": "...",
  "event_type": "...",
  "status": "..."
}
```

Parsers may also return extra details like hostname, process, message, severity, HTTP method, path, and status code.

---

## Tests

Automated tests are not included in this checkout yet.

---

## Sprint 2 ready

The normalized parsed fields make the backend ready for future threat detection rules such as brute-force login detection, suspicious IP tracking, dashboard alerts, and incident creation.
