# CyberShield SOC

AI-Powered Log Monitoring and Threat Detection Platform

## Overview

CyberShield SOC is a full security-operations platform: a FastAPI backend that ingests and parses security logs, runs them through a rule-based detection engine, and persists logs, alerts, incidents, and analyst notes in PostgreSQL; and a React/Vite SOC dashboard for upload, investigation, incident workflows, and administration. Authentication uses JWT access tokens, refresh-token sessions, email-based two-factor verification, and role-based access control (Admin, Analyst, Viewer).

## Detection Rules

The `DetectionEngine` (`backend/app/detection/engine.py`) runs every enabled rule against each uploaded batch of parsed log entries. Rules are configurable per-deployment (`DETECTION_RULE_CONFIG`) and, for the built-in set below, also live-configurable by an Admin/Analyst through `GET`/`PATCH /detection/rules` without a restart. Analysts can additionally author custom rules at runtime through the Rule Builder (`POST/PATCH/DELETE /custom-rules`), which run alongside these built-ins.

Every alert carries a severity (how bad it would be if true), a separate confidence score (0–100, how sure the rule is), a MITRE ATT&CK technique, and the entity it pivots on (`source_ip`, `account`, or `host`).

### Rule catalog

Defaults are shown for each tunable; see [Tuning](#tuning) for how to change them.

| Rule | Severity | Detects | MITRE | Log source | Tunables (default) |
| --- | --- | --- | --- | --- | --- |
| `brute_force_login` | High | Repeated failed logins from one source IP | T1110.001 | Any auth | `threshold` 5, `window_seconds` 60 |
| `invalid_user_enumeration` | Medium | One source IP trying several distinct usernames | T1087 | Any auth | `threshold` 3, `window_seconds` 600 |
| `sudo_failure` | Medium | Repeated failed sudo attempts by one user (or source) | T1548 | Auth/syslog | `threshold` 3, `window_seconds` 300 |
| `password_spraying` | High | One account failing from many distinct source IPs | T1110.003 | Any auth | `threshold` 5, `window_seconds` 600 |
| `credential_stuffing_success` | High | A failed-login burst followed by a success from the same IP | T1110 | Any auth | `fail_threshold` 5, `window_seconds` 60, `success_window_seconds` 120 |
| `port_scan` | Medium | A burst of port-scan events from one source IP | T1046 | Firewall/IDS export | `threshold` 10, `window_seconds` 60 |
| `multi_ip_successful_login` | Medium | One account logging in from several IPs in a short window | T1078 | Any auth | `threshold` 3, `window_seconds` 300 |
| `sudo_after_login` | Medium | A login quickly followed by successful sudo for that account | T1078 | Auth/syslog | `window_seconds` 120 |
| `new_account_created` | High | `useradd`/`adduser` created an OS account | T1136 | Syslog | `cooldown_seconds` 1800 |
| `privileged_group_modified` | High | `usermod`/`gpasswd` added an account to a privileged group | T1098 | Syslog | `cooldown_seconds` 1800, `allowlist` (groups) `sudo, wheel, admin, root, docker` |
| `cron_persistence` | Medium | A crontab was replaced/edited, or a systemd timer started | T1053.003 | Syslog | `cooldown_seconds` 1800 |
| `security_control_disabled` | High | systemd stopped a watched security service | T1562 | Syslog | `cooldown_seconds` 900, `allowlist` (services) `auditd, apparmor, fail2ban, ufw, firewalld, clamav-daemon` |
| `log_tampering` | Critical | systemd stopped an audit/logging service, or journald vacuumed the journal | T1070 | Syslog | `cooldown_seconds` 900, `allowlist` (services) `auditd, rsyslog, rsyslogd` |
| `direct_root_login` | High | A successful direct login to a superuser account | T1078.003 | Any auth | `allowlist` (accounts) `root` |
| `service_account_interactive` | High | A listed service account completed an interactive login | T1078 | Any auth | `allowlist` (accounts) — **empty, rule is off until set** |
| `login_to_nonexistent_account` | Medium | A failed login against a listed decommissioned account | T1078 | Any auth | `allowlist` (accounts) — **empty, rule is off until set** |
| `off_hours_login` | Low | A successful login outside a fixed business-hours window (UTC) | T1078 | Any auth | `start_hour` 6, `end_hour` 20 |
| `dormant_account_activity` | Medium | An account logging in after a long idle period, tracked across uploads | T1078 | Any auth | `threshold` 30 (days) |
| `lateral_movement_chain` | High | One account logging in to several distinct hosts in sequence, tracked across uploads | T1021.004 | Syslog | `threshold` 3 (hosts), `window_seconds` 600 |
| `ssh_key_added` | High | An `authorized_keys` file was written/created/deleted | T1098.004 | auditd (+ sudo `COMMAND=` via syslog) | `cooldown_seconds` 900, `params.watch_keys` |
| `host_log_silence` | High | A host with an established reporting cadence stopped sending logs | T1562.006 | Any source with a hostname | `threshold` 5×, `window_seconds` 1800, `params.min_events` 20 |
| `impossible_travel` | High | Consecutive logins too far apart for the elapsed time, tracked across uploads | T1078 | Auth log with geo columns, or local GeoIP DB | `params.max_speed_kmh` 1000, `params.min_distance_km` 500 |
| `first_seen_geo_asn` | Medium | Login from a country/ASN never seen before for that account | T1078 | Auth log with geo columns, or local GeoIP DB | `params.min_history` 5 |
| `host_sweep` | Medium | One source IP probes the same port on 10+ hosts | T1046 | Firewall logs or flow exports | `threshold` 10, `window_seconds` 300 |
| `outbound_beaconing` | High | Regular, low-jitter connections from one host to one external destination | T1071 | Firewall logs or flow/proxy exports | `threshold` 10, `params.max_jitter_percent` 15 |
| `dns_tunneling` | High | Many long, high-entropy DNS queries under one parent domain | T1071.004 | DNS server logs (dnsmasq/BIND/Unbound) or DNS exports | `threshold` 20, `params.min_entropy` 3.5 |
| `egress_volume_anomaly` | High | A host's outbound bytes far exceed its own trained baseline | T1041 | Flow/proxy exports with byte counts | `params.multiplier` 5, `params.min_bytes` 50 MB |
| `threat_intel_match` | High | Traffic/DNS activity matched an imported threat-intel indicator | T1071 | Firewall, flow, proxy, or DNS logs + an imported feed | `cooldown_seconds` 3600, `allowlist` (indicators to suppress) |
| `behavioral_anomaly_login` | Low | A login's time/geo combination scored as unusual by a trained IsolationForest model | T1078 | Any auth | `cooldown_seconds` 3600, `params.score_threshold` -0.02, `params.shadow_mode` true |
| `behavioral_anomaly_egress` | Low | A host's hourly egress pattern (bytes, connections, destinations, time of day) scored as unusual by a trained IsolationForest model | T1041 | Flow/proxy exports with byte counts | `cooldown_seconds` 3600, `params.score_threshold` -0.02, `params.shadow_mode` true |

Every rule also accepts `enabled`, `confidence`, and `cooldown_seconds`.

Both `behavioral_anomaly_*` rules default to `shadow_mode: true`: once a model exists they score and store every event (visible at `GET /ml/scores`) but never raise an alert until an admin reviews the scores and turns shadow mode off for that rule. See [`docs/ml/isolation_forest_feasibility.md`](docs/ml/isolation_forest_feasibility.md).

### Required log sources

Rules only see fields the parser for that upload's format extracts:

- **Any auth log** (syslog, CSV, JSON, or generic `.txt` with username/status/event type): `brute_force_login`, `invalid_user_enumeration`, `password_spraying`, `credential_stuffing_success`, `multi_ip_successful_login`, `direct_root_login`, `service_account_interactive`, `login_to_nonexistent_account`, `off_hours_login`, `dormant_account_activity`, `behavioral_anomaly_login`. `sudo_failure` and `sudo_after_login` also belong here, but they need sudo events classified as `privilege_escalation`. Syslog does that automatically; CSV/JSON need an explicit event type column.
- **Syslog only**: `new_account_created`, `privileged_group_modified`, `cron_persistence`, `security_control_disabled`, `log_tampering`, and `lateral_movement_chain` need the `hostname`, `process`, and `message` fields that only the syslog parser extracts.
- **auditd** (raw `audit.log`, auto-detected, or audit lines forwarded through syslog): `ssh_key_added` and the file-integrity half of `log_tampering` — sshd never logs writes to `authorized_keys`, only reads, so there's no syslog-only path to this one.
- **Firewall/flow logs** (UFW/iptables kernel lines via syslog, or CSV/JSON flow exports with `dest_ip`/`dest_port`/`bytes_out` columns): `port_scan`'s connection-based path, `host_sweep`, `outbound_beaconing`, `egress_volume_anomaly`, `behavioral_anomaly_egress`.
- **DNS server logs** (dnsmasq/BIND/Unbound via syslog, or a `dns_query` column in CSV/JSON): `dns_tunneling`.
- **Geo data**: `impossible_travel` and `first_seen_geo_asn` need `country`/`asn`/`latitude`/`longitude` — either present in the log itself, or filled in from an optional local MaxMind-format database (`GEOIP_CITY_DB_PATH`/`GEOIP_ASN_DB_PATH`; see `backend/app/detection/geoip.py`). No network geolocation lookups are ever made.
- **An imported threat-intel feed**: `threat_intel_match` matches nothing until a feed is imported via `POST /threat-intel/feeds` (plain text, one IP/CIDR/domain per line — see [Full endpoint list](#full-endpoint-list)).

Rules whose source is missing don't error. They just never fire. For example, uploading an Apache access log won't produce any syslog-only alerts, and that doesn't mean the hosts are clean.

`dormant_account_activity`, `lateral_movement_chain`, `impossible_travel`, `first_seen_geo_asn`, `egress_volume_anomaly`, and both `behavioral_anomaly_*` rules' training data all keep history across uploads (`entity_baselines` for the first five; `ml_feature_snapshots` for the last two). That means most of them never fire the first time they see an entity — there's nothing to compare against yet.

### Not yet implemented

One real gap remains — the rest of the original list has since been built (see the catalog above):

| Rule | Blocked on |
| --- | --- |
| Interactive shell-history truncation (part of `log_tampering`) | An interactive `history -c` is a shell builtin — it produces no log record at all. Only caught when run through a logged command path (`bash -c "history -c"`, an audited script) — see `log_tampering.py`'s docstring. |

`off_hours_login` uses a fixed window, not a per-account learned baseline — `behavioral_anomaly_login` (above) is the learned version of that same idea, run as a separate advisory rule rather than replacing it. See [`docs/ml/isolation_forest_feasibility.md`](docs/ml/isolation_forest_feasibility.md) for why it's a separate pilot and what it took to build.

### Tuning

Each rule's settings are merged in order, later layers winning:

1. The rule's class defaults (the table above).
2. The `DETECTION_RULE_CONFIG` environment variable, a JSON object keyed by rule name:

   ```json
   {
     "service_account_interactive": {"allowlist": ["www-data", "postgres", "svc-backup"]},
     "login_to_nonexistent_account": {"allowlist": ["former-contractor"]},
     "off_hours_login": {"start_hour": 7, "end_hour": 19},
     "brute_force_login": {"threshold": 8, "cooldown_seconds": 600},
     "cron_persistence": {"enabled": false}
   }
   ```

3. Admin/Analyst overrides saved through `PATCH /detection/rules/{rule_name}`, stored in `detection_rule_settings`. These take effect on the next upload.

Tunable fields:

- `threshold`, `fail_threshold`, `window_seconds`, `success_window_seconds`: count and window limits. Each rule uses the subset shown in the catalog.
- `cooldown_seconds`: after an alert fires, repeat alerts for the same rule and entity within this many seconds are dropped, including across uploads. This is how the host-event rules stay quiet when a sysadmin creates several accounts or edits cron in one sitting. It's off (unset) by default for the original eight rules.
- `allowlist`: a list of names. What the names mean depends on the rule (groups, services, or accounts; see the catalog). Setting it replaces the default list rather than adding to it.
- `start_hour`, `end_hour`: the `off_hours_login` business-hours window (0–23, end exclusive, may wrap past midnight). If your log timestamps aren't UTC, set these in the logs' timezone.
- `confidence`: overrides the confidence reported on that rule's alerts.
- `enabled`: turns the rule off entirely.

### How to add a detection rule

1. **Create the rule** in `backend/app/detection/rules/<rule_name>.py` by subclassing `BaseRule`. Set these class attributes:
   - `name`, the stable identifier.
   - `description`.
   - `severity`: `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
   - `mitre_technique`, e.g. `"T1136"`.
   - `entity_type`: `source_ip`, `account`, or `host`.
   - `confidence`, 0–100.
2. **Take tunables as `__init__` keyword arguments** named after `RuleConfig` fields (`threshold`, `window_seconds`, `cooldown_seconds`, `allowlist`, …), with defaults, and store them on `self`. The engine passes config values only to parameters whose names match. Never hardcode a threshold, window, or roster in the rule body. If you truly need a new kind of setting, add it to `RuleConfig`, `DetectionRuleSetting` (with a migration), `DetectionRuleUpdate`, and `_OVERRIDE_FIELDS`.
3. **Implement `analyze(self, records, db=None)`.** It returns a list of `Alert`, and each alert must set `mitre_technique`, `confidence`, `entity_type`, and `entity_id` (the actual IP, username, or hostname). Most rules ignore `db`. Use it only through `app/repositories/baseline_repository.py` when you need history across uploads, and return `[]` when `db` is `None`. Available record fields are `timestamp`, `ip_address`, `username`, `event_type`, `status`, and `port`, plus `hostname`, `process`, and `message` for syslog uploads.
4. **Register the rule** by adding the class to `_RULE_CLASSES` in `backend/app/detection/engine.py`, and add a display title to `_RULE_TITLES` in `backend/app/detection/alert_store.py`.
5. **Test it** in `backend/tests/test_<rule_name>.py`. Include at least one fixture that triggers the rule and one near-miss that looks similar but must not trigger it, such as routine admin activity. Build records directly as `LogRecord(...)` and mark the module `pytestmark = pytest.mark.no_db`. If the rule depends on parser fields, also feed one raw log line through that parser (see `test_new_account_created.py`). Rules that use baselines take the `db_session` fixture instead (see `test_baseline_rules.py`).
6. **Update this catalog.**

## One-time local setup

Install these prerequisites before continuing:

- Docker Desktop with the Docker engine running
- Python 3.13
- Node.js 24 and npm

For the deployment/demo checklist, environment variable reference, migration commands, seeded account details, and verification commands, see [`docs/deployment_and_documentation.md`](docs/deployment_and_documentation.md).

For Kapil's Sprint 5 detection rules, sample logs, ML evaluation plan, and deployment verification checklist, see [`docs/kapil_sprint5_dds.md`](docs/kapil_sprint5_dds.md).

From the repository root, create the local environment file:

```powershell
Copy-Item .env.example .env
```

On macOS or Linux, use:

```bash
cp .env.example .env
```

Open `.env` and replace every `replace_me` value. Use a local-only database password and a strong initial Admin password. The `.env` file is ignored by Git and must never be committed. `frontend/.env.local` is optional; browser code must not contain secrets because all `VITE_*` values are public.

Install the backend dependencies on Windows:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
cd ..
```

On macOS or Linux, replace the backend setup commands with:

```bash
cd backend
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt
cd ..
```

Install the frontend dependencies:

```bash
cd frontend
npm install
cd ..
```

## Start the complete application

On Windows, open the repository root in VS Code, ensure Docker Desktop is running, and select **Terminal > Run Task > Start CyberShield SOC (both servers)**.

The startup task runs `start.ps1`, which:

1. Validates the local `.env`, backend virtual environment, and frontend dependencies.
2. Starts the PostgreSQL container and waits for it to become healthy.
3. Applies Alembic database migrations and creates the configured initial Admin when needed.
4. Starts FastAPI on `http://127.0.0.1:3000` and Vite on `http://127.0.0.1:5173`.
5. Opens the application in the browser.

The VS Code startup task is currently Windows-specific. On macOS or Linux, start PostgreSQL and prepare the database from the repository root:

```bash
docker compose up -d --wait database
cd backend
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m app.db.seed
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 3000
```

Then open a second terminal and start the frontend:

```bash
cd frontend
npm run dev -- --host 127.0.0.1
```

To verify the local PostgreSQL-backed backend on Windows:

```powershell
docker compose up -d --wait database
cd backend
.\.venv\Scripts\python.exe -m alembic upgrade head
.\.venv\Scripts\python.exe scripts\check_db.py
.\.venv\Scripts\python.exe -m pytest tests -q -p no:cacheprovider
```

Backend tests require the configured PostgreSQL database and current Alembic schema. They fail fast with setup instructions when PostgreSQL is unavailable or stale; PostgreSQL-specific schema types are never replaced with an SQLite fallback.

## Run the Standalone Parser Script

`parser/log_parser.py` is a legacy standalone CLI utility kept for quick, dependency-free parsing of a single log file outside the running application. The live backend uses its own parser (`backend/app/parsers/`), not this script.

```bash
python parser/log_parser.py sample-logs/auth.log
```

## Run the Backend API

If you are not using the complete startup task, install backend dependencies:

```bash
pip install -r backend/requirements.txt
```

Run the server:

```bash
cd backend
python main.py
```

Open:

- Frontend dashboard: `http://localhost:5173` (with Vite dev server running)
- API docs: `http://localhost:3000/docs`
- Health check: `http://localhost:3000/health`

## Run the Frontend

From the repository root:

```bash
cd frontend
npm install
npm run dev
```

Then open `http://localhost:5173` in your browser. The Vite development server proxies `/api` requests to the FastAPI service on port `3000`.

Connected authentication requires PostgreSQL and FastAPI to be running. The complete startup task described above starts the database, applies migrations, seeds the initial Admin, and launches both application servers.

On Windows PowerShell, use the `.cmd` executable if script execution policy blocks `npm.ps1`:

```powershell
Set-Location frontend
npm.cmd install
npm.cmd run dev
```

Useful frontend checks:

```bash
npm test
npm run build
npm run preview
```

Copy `frontend/.env.example` to `frontend/.env.local` when local API settings need to be customized. Never store secrets in a `VITE_*` variable because Vite exposes those values to the browser bundle.

## Backend API

### `POST /upload`

Uploads and parses a log file.

Request:

- Content type: `multipart/form-data`
- Field name: `logfile`
- Accepted extensions: `.log`, `.csv`, `.txt`, `.json`, `.jsonl`
- Max size: 50 MB

Every route is also served under an `/api` prefix (e.g. `POST /api/upload`) for frontend/API routing.

Authentication and RBAC backend handoff details are documented in
[`docs/backend-auth-rbac.md`](docs/backend-auth-rbac.md).

### `GET /upload/formats`

Returns accepted upload formats.

### `GET /health`

Returns backend service health.

### Full endpoint list

| Area | Endpoints |
| --- | --- |
| Auth | `POST /auth/login`, `/auth/2fa/verify`, `/auth/2fa/resend`, `/auth/refresh`, `/auth/logout`, `GET /auth/me` |
| Users | `GET/POST /users`, `PATCH /users/{id}`, role/active/password management |
| Upload | `POST /upload`, `GET /upload/latest`, `/upload/history`, `/upload/batches/{id}`, `/upload/formats` |
| Detection | `GET /detection/rules`, `PATCH /detection/rules/{name}`, `GET /detection/host-heartbeats`, `POST /detection/host-silence/check` |
| Threat intel | `GET/POST /threat-intel/feeds`, `DELETE /threat-intel/feeds/{source}`, `GET /threat-intel/indicators` |
| Custom rules | `GET/POST /custom-rules`, `PATCH/DELETE /custom-rules/{id}`, `POST /custom-rules/test` |
| Alerts / Incidents / Notes | `GET/PATCH /alerts`, `GET/POST/PATCH /incidents`, `GET/POST/PATCH/DELETE /notes` |
| ML models | `GET /ml/models`, `POST /ml/models/{feature_set}/train`, `POST /ml/models/{model_id}/activate`, `GET /ml/scores` |

Full request/response contracts and RBAC rules are in [`docs/backend-auth-rbac.md`](docs/backend-auth-rbac.md) and the backend test suite (`backend/tests/`).

## Output

The standalone parser script writes `output/parsed_logs_sprint2.json` and `output/parsed_logs_sprint2.csv`.

The backend API returns JSON containing:

- Upload metadata
- Parsing summary
- Parsed entries
- Skipped lines
- Error details when validation fails

## Frontend

The production-oriented frontend is a React, Vite, and Tailwind CSS security-operations workspace based on the CyberShield Figma design. It contains authentication, role-aware navigation, operational dashboards, event and alert investigation, incident workflows, analyst notes, AI-assisted analysis, administration, and backend-ready repository adapters.

### Frontend features

- Responsive light and dark themes with accessible keyboard navigation and reduced-motion support
- Login, MFA, recovery, UTA SSO, support, logout, session-expiration, and protected-route experiences
- Viewer, Analyst, and Admin permissions with unauthorized actions hidden or disabled
- Backend-connected dashboard metrics, interactive time-series and severity charts, telemetry health, security grade, IP statistics, threat analysis, and analyst workload
- Event ingestion for `.log`, `.csv`, `.json`, and `.jsonl`, with validation, filters, search, pagination, exports, and normalized evidence detail
- Alert investigation with severity, source IP, affected user, detection rule, reason, time range, evidence, and recommended response actions
- Incident creation and tracking with Open, Investigating, Resolved, and False Positive states, analyst notes, history, attribution, and quick-resolve workflow
- AI analysis, analyst-note storage and history, integrations, system management, settings, help, notifications, loading, empty, and error states
- Replaceable mock and HTTP repository adapters that keep browser-only demonstration data separate from connected production behavior

### Frontend documentation

- [Frontend architecture](frontend/docs/ARCHITECTURE.md)
- [Frontend/backend contract](frontend/docs/BACKEND_CONTRACT.md)
- [Connected local setup](frontend/docs/CONNECTED_BACKEND.md)
- [Deployment and documentation checklist](docs/deployment_and_documentation.md)
- [Workflow validation](frontend/docs/WORKFLOW_VALIDATION.md)
- [Interaction test report](frontend/docs/INTERACTION_TEST_REPORT.md)
- [Security policy and frontend boundary](SECURITY.md)

## Tech Stack

- React.js
- Vite
- Tailwind CSS
- FastAPI (Python)
- Docker
- PostgreSQL
- Alembic

## Folder Structure

- `parser/` - parser source code
- `sample-logs/` - test input logs
- `output/` - generated parsed files
- `docs/` - backend and Sprint documentation
- `backend/` - FastAPI backend upload, authentication, RBAC, alert, incident, note, and user APIs
- `frontend/` - React/Vite/Tailwind SOC application
- `frontend/docs/` - frontend architecture, integration, workflow, and test documentation
- `frontend/tests/` - frontend validation, permissions, workflow, chart, repository, and utility tests

## Team Members

| Name | Role |
| --- | --- |
| Yugal Limbu | Project Manager / Documentation Lead |
| Marvellous Obasanya | Scrum Master |
| Paul Truong | Frontend Developer |
| Samin Rijal | Backend Developer |
| Kapil Khanal | ML / DevOps / Testing Lead |
