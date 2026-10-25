# CyberShield watched-directory collector

Sprint 7, PBI-28 — S7-02.1 (collector), S7-02.4 (deduplication and retry), S7-02.5 (pipeline integration). Owner: Kapil Khanal.

The collector watches one or more directories and sends new log lines to `POST /api/ingest` (the authenticated ingestion path from S7-02.2/S7-02.3). Collected logs go through the same parser, normalization, built-in and custom detection, correlation, ML scoring, and alert storage as manual uploads. Each batch is stored with `source_name`, `source_type` (`agent` by default), `source_host`, and `ingested_by`.

It uses only the Python standard library (3.10+), so it runs on a monitored host without the backend's dependencies.

## Quick start (PowerShell)

```powershell
cd collector
Copy-Item collector.example.json collector.json   # edit api_url, source_host, sources[].path
python -m cybershield_collector login --config collector.json   # username, password, emailed 2FA code
python -m cybershield_collector run --config collector.json     # watch continuously (Ctrl+C to stop)
```

Other commands: `once` runs a single scan and prints counters; `status` shows how many bytes of each file have been shipped and the last batch ID.

## Authentication

The collector uses the existing login → email two-factor → refresh flow. It does not add a shared secret or bypass 2FA, and no password is ever written to disk.

- `login` signs in with "remember me" and saves only the refresh token to `<state_dir>/session.json` (created with `0600` permissions on Linux/macOS; on Windows keep `state_dir` in a folder only the collector's account can read).
- `run` exchanges the refresh token for 10-minute access tokens and saves each rotated refresh token immediately. The remembered session slides forward while the collector keeps refreshing (default 7 days, `AUTH_REMEMBER_TTL_DAYS`).
- The account must be Admin or Analyst. If the session expires, is revoked, or the role is lowered, the collector stops with exit code 3 and asks for `login` again. Nothing is skipped; collection resumes where it stopped.
- For a short test, `CYBERSHIELD_ACCESS_TOKEN` can supply an access token directly (it cannot be refreshed).

## Configuration

| Key | Default | Meaning |
| --- | --- | --- |
| `api_url` | required | Backend base URL including `/api`. `CYBERSHIELD_API_URL` overrides it. |
| `state_dir` | `.cybershield-collector` | Offsets, session, shipment ledger, quarantine. Never inside a watched path. |
| `source_host` | machine hostname | Stored as the batch's `source_host`. |
| `poll_interval_seconds` | 2 | Time between scans. |
| `settle_seconds` | 5 | How long a file must be unchanged before an unterminated last line (or a `.json` file) is treated as final. |
| `max_chunk_bytes` | 1 MiB | Batch size cap; batches are cut on line boundaries. |
| `request_timeout_seconds` | 60 | Per request. |
| `max_backoff_seconds` | 300 | Upper bound on retry backoff. |
| `sources[].name` | required | Stored as `source_name`; unique per config. |
| `sources[].path` | required | Directory to watch (relative paths resolve from the config file). |
| `sources[].include` / `exclude` | `*.log *.txt *.csv *.json *.jsonl` plus rotated `*.log.1`, `*.log-YYYYMMDD` / archives, temp and hidden files | Filename globs. |
| `sources[].recursive` | false | Also watch subdirectories. |
| `sources[].source_type` | `agent` | `agent`, `file`, `syslog`, or `api`. |
| `sources[].format` | inferred | Forces the parser (`log`, `txt`, `csv`, `json`, `jsonl`) for files without a usable extension. Otherwise `auth.log.1` is sent as `auth.log` and extensionless files as `.log`. |
| `sources[].start_at` | `beginning` | `end` tails files that already exist at first start instead of sending their history. |

## How collection works

- **New and growing files.** Each scan sends the bytes after the last acknowledged offset. Only complete lines are sent; a trailing partial line waits for its newline, or for `settle_seconds` of quiet.
- **CSV.** The header row is resent in front of every later batch so each batch parses on its own. Delimited `.txt` exports are detected the same way the backend does.
- **JSON documents** (`.json`) cannot be split, so they ship whole once stable. Use `.jsonl` for files that grow.
- **Rotation.** Renamed files (`auth.log` → `auth.log.1`) and truncated files (`copytruncate`) are recognized and handled without resending or losing lines.

## Deduplication (S7-02.4)

- The offset advances only after the server acknowledges a batch and is saved atomically, so restarts never resend acknowledged data.
- Files are identified by content, not name: a SHA-256 of the bytes already shipped. A renamed or copied file whose beginning matches an already-collected stream resumes after that point. Two different CSV exports that share a header are still treated as different files.
- Identical `.json` documents are sent once, by content hash.
- Identical lines inside a file are **not** dropped. Repeated identical events (for example, failed logins in the same second) are real signal for brute-force detection.

## Retry handling (S7-02.4)

| Failure | What the collector does |
| --- | --- |
| Connection refused, HTTP 408/429/500/503 | Nothing was stored. Keeps the offset and retries the identical batch with exponential backoff and jitter (2 s doubling, capped at `max_backoff_seconds`). |
| Timeout or dropped connection after sending, HTTP 502/504 | The server may have stored the batch, and `/api/ingest` is not idempotent. The collector checks `/api/upload/history` for a matching batch (same source, host, filename, byte size, recent, not already known). If found, it is counted as delivered. If not, the attempt is marked pending (persisted) and checked again before the next resend, at least 30 s later. |
| HTTP 400/413/415/422 (e.g. nothing parseable) | Resending will not help. The batch is saved to `<state_dir>/rejected/` with the reason, and collection continues after it. |
| HTTP 401 | Refreshes the access token once and retries. If the refresh fails, the collector stops for `login`. |
| HTTP 403, unexpected 4xx | Stops with a clear message (wrong role or wrong `api_url`). |

Every acknowledged batch is appended to `<state_dir>/shipments.jsonl` (file, byte range, upload ID, stored events/alerts) for audit.

## Tests

```powershell
python -m pytest collector/tests -q                       # unit tests, no database
cd backend; python -m pytest tests/test_collector_pipeline.py -q   # needs PostgreSQL at alembic head
```

`backend/tests/test_collector_pipeline.py` drives the collector against the real FastAPI app and PostgreSQL. It checks that a watched file produces a batch with provenance, normalized log rows, and the expected alerts (`04_all_rules_combined.log` → brute force, username enumeration, sudo failure; `05_no_alert_control.log` → none). It also covers rescans, appends, rotation and restart without duplicate rows, the real refresh and CSRF flow, and reconciling a lost response through upload history.

## Known limits

- Polling, not OS file events: new lines arrive within `poll_interval_seconds`.
- If the network drops right after `/auth/refresh` rotates the token but before the response arrives, the saved token is already revoked and `login` is needed again.
- Reconciliation is a best-effort match on source, host, filename, size, and time. A server-side idempotency key on `/api/ingest` would make retries exact.
- Compressed rotated logs (`.gz`) are skipped; collect lines before compression (logrotate `delaycompress`).
