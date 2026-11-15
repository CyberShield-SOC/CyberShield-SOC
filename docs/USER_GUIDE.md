# CyberShield SOC User Guide

Nov 13, 2026 · @Yoyo

## Contents

1. [Overview](#1-overview)
2. [Install and start the app](#2-install-and-start-the-app)
3. [Sign in, sessions and roles](#3-sign-in-sessions-and-roles)
4. [Tour of the workspace](#4-tour-of-the-workspace)
5. [Upload logs](#5-upload-logs)
6. [Detection rules](#6-detection-rules)
7. [Triage alerts and run incidents](#7-triage-alerts-and-run-incidents)
8. [Build your own rules](#8-build-your-own-rules)
9. [Collect logs automatically](#9-collect-logs-automatically)
10. [AI Analysis and reports](#10-ai-analysis-and-reports)
11. [Admin tasks](#11-admin-tasks)
12. [Deploy to Railway](#12-deploy-to-railway)
13. [Try it, fix it, look it up](#13-try-it-fix-it-look-it-up)

## 1. Overview

CyberShield SOC turns raw security logs into alerts, investigations and incidents you can act on. You upload a log file (or let a collector ship logs for you), a rule engine flags suspicious activity, and the dashboard lets your team triage, investigate and resolve what it finds.

**What it does**

- Ingests logs in `.log`, `.csv`, `.txt`, `.json` and `.jsonl`, by manual upload or through a watched-directory collector.
- Detects threats with 30 built-in rules plus your own custom rules. Every alert has a severity, a separate 0–100 confidence score, a MITRE ATT&CK technique, and the entity it pivots on (source IP, account or host).
- Correlates and preserves evidence, so each alert links back to the exact log events that triggered it.
- Tracks investigations and incidents with states, assignment, notes, resolution and reopening, all with an audit history.
- Answers questions through a read-only AI assistant, and exports reports as PDFs.

**How the pieces fit**

- A FastAPI backend parses logs, runs detection and stores results in PostgreSQL.
- A React dashboard is the workspace analysts use day to day.
- Sign-in uses a password plus an emailed one-time code, and every action is limited by role: Admin, Analyst or Viewer.

**Who should read what**

| You are | Start with |
| --- | --- |
| Setting it up | Sections 2, 3 and 12 |
| An analyst | Sections 4–8 and 10 |
| Connecting log sources | Sections 5 and 9 |
| An admin | Sections 3 and 11 |

## 2. Install and start the app

A local install takes about six steps. You need Docker Desktop (running), Python 3.13, Node.js 24 with npm, and Git.

**1. Create your environment file.** From the repository root:

```bash
cp .env.example .env          # macOS / Linux
```

```powershell
Copy-Item .env.example .env   # Windows PowerShell
```

**2. Fill in `.env`.** Replace every `replace_me` value. The ones that matter most:

| Variable | What to put |
| --- | --- |
| `POSTGRES_USER`, `POSTGRES_PASSWORD` | A local-only database login. Use the same values inside `DATABASE_URL`. |
| `JWT_SECRET_KEY`, `OTP_SECRET` | Long random values. Generate with `python -c "import secrets; print(secrets.token_urlsafe(64))"`. |
| `CYBERSHIELD_ADMIN_PASSWORD` | A strong password for the first Admin. Minimum length is 12 by default (`PASSWORD_MIN_LENGTH`). |
| `CYBERSHIELD_ADMIN_EMAIL` | An address you can read. The sign-in code is emailed here. |
| `RESEND_API_KEY`, `RESEND_FROM_EMAIL` | Needed to send sign-in codes. Resend's shared sandbox sender only delivers to your own Resend account email. |

Never commit `.env`. Never put secrets in a `VITE_*` variable, because those are bundled into browser code.

**3. Install backend dependencies.**

```bash
cd backend
python3 -m venv .venv
./.venv/bin/python -m pip install -r requirements.txt   # Windows: .\.venv\Scripts\python.exe
cd ..
```

**4. Install frontend dependencies.**

```bash
cd frontend && npm install && cd ..
```

**5. Start everything.**

- **Windows:** in VS Code, choose Terminal > Run Task > Start CyberShield SOC (both servers), or run `.\start.ps1`. It checks your setup, starts PostgreSQL, applies migrations, creates the Admin, starts both servers and opens the browser.
- **macOS / Linux:** the VS Code task is Windows-only, so run these from the repository root, then start the frontend in a second terminal.

```bash
docker compose up -d --wait database
cd backend
./.venv/bin/python -m alembic upgrade head
./.venv/bin/python -m app.db.seed
./.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 3000
```

```bash
cd frontend
npm run dev -- --host 127.0.0.1
```

**6. Open the app.**

| What | Address |
| --- | --- |
| Dashboard | https://127.0.0.1:5173 (the dev server uses a self-signed certificate; see [frontend/.cert/README.md](../frontend/.cert/README.md)) |
| API docs | http://localhost:3000/docs |
| Health check | http://localhost:3000/health |

Log in as the Admin from your `.env` (username `admin` unless you changed `CYBERSHIELD_ADMIN_USERNAME`).

**Check your install.** From `backend/`, run `python -m alembic upgrade head`, then `python scripts/check_db.py`, then `python -m pytest tests -q -p no:cacheprovider`. The tests need the PostgreSQL container running and the schema at the latest migration.

## 3. Sign in, sessions and roles

```
┌─────────────────────────────────────────────────────────────┐
│                 Client HTTP Request / Session               │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 Authentication & RBAC Barrier               │
│ - JWT Bearer Verification (10-minute validity)              │
│ - Argon2id Password + HMAC-SHA256 Two-Factor OTP            │
│ - Role Hierarchy Enforcement (Admin > Analyst > Viewer)     │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
        Allowed Action                 Denied Action
               │                              │
               ▼                              ▼
┌──────────────────────────────┐       ┌──────────────────────┐
│ Route Execution & Logic      │       │ HTTP 401 / 403 Error │
│ - Audit Trail Generation     │       └──────────────────────┘
│ - Atomic DB Transactions     │
└──────────────────────────────┘
```

Every sign-in requires your password and a one-time verification code (2FA OTP) sent to your email.

1. **Credentials verification:** Enter your username and password. Password verification uses Argon2id hashing with unique random salts. Tick "Remember me" if you want a longer session.
2. **Two-Factor OTP:** Enter the emailed code. Codes expire after 5 minutes, permit up to 5 attempts, and can be resent after a 60-second cooldown. OTP codes are stored exclusively as keyed HMAC-SHA256 digests in PostgreSQL.
3. **Session initiation:** You land in the workspace. Authentication uses a token dual-model:
   - **Access Token:** Short-lived JWT (10-minute expiration) carrying user claims and assigned roles.
   - **Refresh Token:** Cryptographically secure 64-byte random string stored in `auth_sessions`. Refresh requests invoke atomic rotation using row-level database locks (`with_for_update`) to prevent concurrent token replay.

A normal session lasts 60 minutes. With remember me it lasts 7 days. If you forget your password, use the recovery link on the sign-in screen; the reset link it emails you is valid for 30 minutes. These limits come from `.env` and your admin can change them.

**Role-Based Access Control (RBAC) Matrix**

| Workspace Capability / Endpoint | Admin | Analyst | Viewer |
| :--- | :---: | :---: | :---: |
| View Dashboards, Event Logs, Alerts, Incidents, Notes | Yes | Yes | Yes |
| Export Server-Side PDF Reports (`GET /reports/*/pdf`) | Yes | Yes | Yes |
| Query AI Analysis Assistant (`POST /assistant/chat`) | Yes | Yes | Yes |
| Ingest & Upload Log Batches (`POST /upload`) | Yes | Yes | No |
| Update Alert Investigation Status & Triage Notes | Yes | Yes | No |
| Create, Assign, Transition & Resolve Incidents | Yes | Yes | No |
| Create & Tune Custom Detection Rules (`/custom-rules`) | Yes | Yes | No |
| Override Built-in Detection Rules (`PATCH /detection/rules/*`) | Yes | Yes | No |
| Trigger ML Model Training (`POST /ml/models/*/train`) | Yes | No | No |
| Activate / Roll Back ML Models (`POST /ml/models/*/activate`) | Yes | No | No |
| User Provisioning, Role Modification, Account Revocation | Yes | No | No |
| Manage Threat Intelligence Feeds (`/threat-intel/feeds`) | Yes | No | No |

The interface hides or disables what your role cannot do, but the backend enforces the same limits on every request. Hiding a button is a convenience, not the security boundary.

**Good to know**

- Deactivating a user blocks them on their very next request.
- Resetting a password or revoking sessions stops new tokens from being issued, but a token already issued keeps working until it expires, at most 10 minutes by default.
- The system will not let the last active Admin be removed or demoted.

## 4. Tour of the workspace

The left sidebar groups every page under three headings, with a Help center link for task guides and a role reference.

| Group | Page | Use it to |
| --- | --- | --- |
| Monitor | Dashboard | See events over time, events by severity, top sources, port monitoring, alert volume by severity, MITRE ATT&CK coverage, recent alerts and suspicious IPs. |
| Monitor | Event Logs | Upload logs, then search, filter, export and inspect normalized events. |
| Monitor | Threat Detection | Browse the rule inventory, read each rule's details, and (Admin or Analyst) change its settings. |
| Monitor | Alerts | Triage alerts with severity, source IP, affected user, matched rule, evidence and recommended actions. |
| Monitor | Incidents | Work the incident queue. |
| Monitor | Incident Tracking | Coordinate response on one incident: playbook, control panel, timeline and notes. |
| Analyze | Quick Resolve | Handle one alert end to end: evidence, response workflow, checklist, note and AI guidance. |
| Analyze | AI Analysis | Ask the assistant questions about your workspace. |
| Analyze | Analyst Notes | Search, edit and archive notes, with version history. |
| Analyze | Reports | Export the four built-in reports as PDF. |
| Manage | Manage | Workspace operations and live environment health. |
| Manage | Users | Add users, change roles, deactivate accounts (Admin only). |
| Manage | Integrations | Inspect the telemetry sources seen in your data (read-only). |
| Manage | Settings | Theme, density, text size, contrast, motion, notification routing and assistant settings. |

**The top bar**

- A time range control scopes the dashboard and lists.
- Auto-refresh and a notification center keep you current.
- Search accepts section names, so typing "users" or "quick resolve" jumps straight there.
- A service status badge reads Operational, Refreshing, Offline or Demo mode.

**Demo mode.** If `VITE_API_BASE_URL` is empty, the app uses a local sample dataset instead of your backend, and changes live only in that browser tab. Set it to `/api` in `frontend/.env.local` to use the real backend through the Vite proxy.

The interface has light and dark themes, keyboard navigation and reduced-motion support.

## 5. Upload logs

Upload is how most data enters the system. Analysts and Admins can do it; Viewers cannot. Open Event Logs and choose a file.

**What you can upload**

| Rule | Limit |
| --- | --- |
| File types | `.log`, `.csv`, `.txt`, `.json`, `.jsonl` |
| Maximum size | 50 MB |
| Content | Text only. Binary content is rejected. |

The API field name is `logfile`. `GET /upload/formats` returns the accepted formats.

**What happens after upload**

1. The file is parsed into normalized events. Lines the parser cannot read are reported as skipped, and the response lists them.
2. Every enabled built-in rule and custom rule runs against the batch.
3. Events, alerts and correlation groups are stored, and a batch record keeps the filename, source type and who uploaded it.
4. The dashboard, Event Logs and Alerts pages update.

**Why a rule might not fire.** Rules only see fields the parser extracts from your format. A syslog-only rule will never fire on a CSV that has no hostname, process or message columns. Section 6 lists which log source each rule needs. A rule with a missing source does not error. It simply stays silent, so an empty result is not proof a host is clean.

**Tips for CSV and JSON**

- Auth logs need username, status and an event type. Sudo rules need sudo events classified as `privilege_escalation`; syslog does this for you, but CSV and JSON need an explicit event type column.
- Network rules need columns such as `dest_ip`, `dest_port` and `bytes_out`. DNS rules need a `dns_query` column.
- Geo rules need `country`, `asn`, `latitude` and `longitude` columns, or a local MaxMind-format database set with `GEOIP_CITY_DB_PATH` and `GEOIP_ASN_DB_PATH`. No network geolocation lookups are ever made.

**Reviewing events.** Event Logs supports filters, search, pagination and export, and shows the normalized evidence for each event. CSV exports neutralize spreadsheet-formula prefixes so they are safe to open in Excel.

**Upload history.** `GET /upload/history` and `GET /upload/batches/{id}` list past batches with their source name, type, host and uploader.

## 6. Detection rules

The CyberShield SOC detection subsystem operates as a layered stream and batch analytics engine. Every uploaded or collected log batch passes through field normalization, sliding-window aggregation, custom rule evaluation, built-in threat detection, and automated evidence correlation.

```
Raw Logs (.log, .csv, .json, .jsonl)
       │
       ▼
┌──────────────────────────────┐
│  Log Ingestion & Normalizer  │ ──► Structured Event Fields
└──────────────┬───────────────┘
               │
       ┌───────┴────────────────────────┐
       ▼                                ▼
┌────────────────────────────┐   ┌────────────────────────────┐
│ 30+ Built-In Engine Rules  │   │ Custom Condition Evaluator │
└──────────────┬─────────────┘   └──────────────┬─────────────┘
               │                                │
               └───────────────┬────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│          Correlation & Evidence Generation Engine           │
│   - Multi-event Evidence Linking (Log IDs preserved)        │
│   - Sliding Window Deduplication & Cooldown Tracking        │
│   - MITRE ATT&CK Tactic / Technique Tagging                 │
│   - Severity & Confidence Calculation (0–100 Score)         │
└──────────────────────────────┬──────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────┐
│ Database Storage (Alerts, Correlation Groups, Audit Log)    │
│ Optional Webhook Dispatch (Slack / Automated Incident)      │
└─────────────────────────────────────────────────────────────┘
```

Thirty built-in rules run on every upload or collected batch. Each alert carries a severity (how bad it would be if true), a separate 0–100 confidence score, a MITRE ATT&CK tactic/technique mapping, and the entity it pivots on (source IP, account, or host).

**Rule catalog**

| Rule | Severity | Default Window / Threshold | MITRE ATT&CK | Required Log Sources & Fields |
| :--- | :--- | :--- | :--- | :--- |
| `brute_force_login` | High | 5 failures in 60s per `ip_address` | `T1110.001` (Brute Force) | Auth/Syslog (`ip_address`, `status=failed`) |
| `invalid_user_enumeration` | Medium | 3+ distinct usernames in 10m | `T1087` (Account Discovery) | Auth logs (`username`, `ip_address`) |
| `password_spraying` | High | 1 user failing from 5+ IPs in 10m | `T1110.003` (Password Spraying) | Auth logs (`username`, `ip_address`) |
| `credential_stuffing_success` | High | Failed burst followed by success within 5m | `T1110.004` (Credential Stuffing) | Auth logs (`ip_address`, `status`) |
| `direct_root_login` | High | 1 successful login directly as `root` | `T1078.001` (Valid Accounts: Default) | Auth/SSH logs (`username=root`, `status=success`) |
| `multi_ip_successful_login` | Medium | 1 account logging in from 3+ IPs in 5m | `T1078` (Valid Accounts) | Auth logs (`username`, `ip_address`, `status=success`) |
| `sudo_failure` | Medium | 3 failed sudo executions in 5m | `T1548.003` (Sudo / Elevation) | Syslog/Auth (`event_type=privilege_escalation`) |
| `sudo_after_login` | Medium | Successful login followed by sudo within 60s | `T1078` / `T1548.003` | Syslog/Auth (`username`, `event_type`) |
| `new_account_created` | High | Local user creation (`useradd`/`adduser`) | `T1136.001` (Create Local Account) | Linux Syslog/Auditd |
| `privileged_group_modified` | High | User added to `sudo`, `wheel`, `admin`, `docker` | `T1098` (Account Manipulation) | Linux Syslog/Auditd |
| `cron_persistence` | Medium | Crontab updated or systemd timer created | `T1053.003` (Scheduled Task/Job: Cron) | Linux Syslog/Auditd |
| `security_control_disabled` | High | `auditd`, `ufw`, `fail2ban`, `clamav` stopped | `T1562.001` (Disable Security Tools) | Linux Syslog/Service logs |
| `log_tampering` | Critical | Logging daemon killed, journal logs vacuumed | `T1562.002` (Disable or Clear Logs) | Linux Syslog/Auditd |
| `ssh_key_added` | High | Modification to `~/.ssh/authorized_keys` | `T1098.004` (SSH Authorized Keys) | Linux Auditd (`EXECVE`/`PATH`) |
| `port_scan` | Medium | 10 port-probes from single IP in 60s | `T1046` (Network Service Discovery) | Firewall / IDS / Netfilter logs |
| `host_sweep` | Medium | Single IP probing same port on 10+ hosts in 2m | `T1046` (Network Service Discovery) | Netfilter / Firewall Flow logs |
| `dns_tunneling` | High | 20+ high-entropy / long subdomains in 5m | `T1071.004` (Application Layer: DNS) | DNS logs (`dns_query`, `dnsmasq`, `bind`) |
| `outbound_beaconing` | High | Regular, low-jitter periodic external egress | `T1071` (C2 Protocol) | Flow logs (`dest_ip`, `dest_port`, `timestamp`) |
| `egress_volume_anomaly` | High | Host outbound volume > 3x rolling baseline | `T1048` (Exfiltration Over Protocol) | Netflow / Proxy logs (`bytes_out`, `source_host`) |
| `impossible_travel` | High | Consecutive logins with speed > 900 km/h | `T1078` (Valid Accounts) | Auth logs with Geo coordinates / GeoIP DB |
| `first_seen_geo_asn` | Medium | First login from country/ASN for account | `T1078` (Valid Accounts) | Auth logs with Geo/ASN metadata |
| `dormant_account_activity` | Medium | Login after 30+ consecutive days of inactivity | `T1078` (Valid Accounts) | Auth history across batches (`username`) |
| `lateral_movement_chain` | High | 1 account authenticating to 3+ hosts in 10m | `T1021` (Remote Services) | Syslog / Kerberos / Auth logs |
| `service_account_interactive` | High | Interactive login by configured service accounts | `T1078.002` (Service Accounts) | Auth logs + configured service account list |
| `login_to_nonexistent_account` | Medium | Failed login to listed decommissioned account | `T1078` (Valid Accounts) | Auth logs + decommissioned account list |
| `off_hours_login` | Low | Successful login outside 06:00–20:00 UTC | `T1078` (Valid Accounts) | Any auth log with timestamp |
| `host_log_silence` | High | Monitored host heartbeat cadence interrupted | `T1562` (Impair Defenses) | All logs carrying `source_host` |
| `threat_intel_match` | High | Traffic/DNS matches imported threat feed | Multiple | Network / DNS logs + Imported Feeds |
| `behavioral_anomaly_login` | Low | Model scores login hour/geo as an anomaly | `T1078` (Valid Accounts) | Auth logs (`timestamp`, `ip_address`, `username`) |
| `behavioral_anomaly_egress` | Low | Model scores hourly egress byte pattern as anomaly | `T1048` (Exfiltration) | Flow logs (`bytes_out`, `source_host`) |

**Things that surprise people**

- Rules that keep history across uploads (dormant account, lateral movement, impossible travel, first-seen geo, egress volume, and both behavioral rules) never fire the first time they see an entity. They have nothing to compare against yet.
- `host_log_silence` watches every host the deployment has ever seen, not just the hosts in your latest file, so an unrelated upload can surface it for other hosts.
- Both `behavioral_anomaly_*` rules start in shadow mode. They score and store events (see `GET /ml/scores`) but raise no alerts until an Admin reviews the scores and turns shadow mode off.
- Interactive `history -c` is a shell builtin that writes no log record, so it is only caught when run through a logged command path.
- Only imported threat-intel feeds can trigger `threat_intel_match`. See section 11.

**Tuning a rule (Configuration Precedence)**

Settings resolve at runtime using a 3-tier override hierarchy, where later layers win:

1. **Engine Defaults:** Embedded baseline values inside Python rule classes.
2. **Environment Overrides:** Global JSON object defined in the `DETECTION_RULE_CONFIG` environment variable.
3. **Database Runtime Overrides:** Admin or Analyst overrides saved from the Threat Detection page (or via `PATCH /detection/rules/{name}`). Stored in PostgreSQL (`detection_rule_settings`), they take effect immediately on the next upload with zero server downtime.

```json
{
  "service_account_interactive": {"allowlist": ["www-data", "postgres", "svc-backup"]},
  "off_hours_login": {"start_hour": 7, "end_hour": 19},
  "brute_force_login": {"threshold": 8, "cooldown_seconds": 600},
  "cron_persistence": {"enabled": false}
}
```

| Setting | Meaning |
| --- | --- |
| `threshold`, `fail_threshold` | How many events trigger the rule. |
| `window_seconds`, `success_window_seconds` | The time window for those events. |
| `cooldown_seconds` | After an alert, repeats for the same rule and entity within this time are dropped, even across uploads. |
| `allowlist` | Names the rule treats specially (groups, services or accounts, depending on the rule). Setting it replaces the default list. |
| `start_hour`, `end_hour` | The `off_hours_login` window, 0–23, in the logs' own timezone. |
| `confidence` | Overrides the confidence shown on that rule's alerts. |
| `enabled` | Turns the rule off entirely. |

## 7. Triage alerts and run incidents

The typical flow is: read the alert, check the evidence, decide, then either close it or promote it to an incident.

**Step by step**

1. Open Alerts. Filter by severity, source IP, affected user, rule or time range. Each alert shows the rule that fired, the reason, and recommended response actions.
2. Check the evidence. An alert links to the exact log events that triggered it, with a completeness report. Correlation groups tie together events and alerts that share a source IP, username, host, upload batch or rule context inside a time window, and explain why they were grouped.
3. Set the investigation state. Choose from New, Investigating, Escalated, Resolved or False Positive. Only valid transitions are allowed, and each change records who made it, when, and the before and after values. This history cannot be edited.
4. Add notes. Notes attach to the investigation or incident and keep a version history.
5. Escalate to an incident when it needs a response. An incident can link several alerts while keeping the primary one.
6. Assign and work the incident. Pick an eligible analyst, follow the response playbook on Incident Tracking, and watch the timeline of assignments, status changes, linked alerts and notes.
7. Resolve it. Resolution requires a reason or note, and records who resolved it and when. Linked alerts take the matching outcome.
8. Reopen if needed. Reopening requires a reason and keeps the earlier resolution on record.

Incident statuses in the interface are Open, Investigating, Resolved and False Positive.

**Quick Resolve** puts the whole path on one screen. Select an alert, review its evidence, use the response controls, tick the resolution checklist, add a note, and optionally run AI guidance. Use it for routine alerts and Incident Tracking for larger work.

**Limits and safeguards**

- Each incident holds up to 5 notes. If you hit the limit, delete an existing note in Analyst Notes before adding another.
- Updates are version-checked. If a teammate changed the same alert or incident first, your change is rejected as stale so you can reload and retry.
- The response playbook and resolution checklist are working aids that live in your session; the incident status, notes and history are what gets saved.
- Viewers can read all of this but cannot change anything.

## 8. Build your own rules

The Rule Builder lets Admins and Analysts add detection rules without touching code. Custom rules run alongside the 30 built-in rules on every upload. Open it from Threat Detection with the new-rule button, or choose Edit rule on an existing custom rule.

**Anatomy of a rule**

| Part | Options |
| --- | --- |
| Category | generic detection, threat hunting, emerging threat, compliance, placeholder |
| Severity | Low, Medium, High, Critical |
| Status | Draft, Enabled, Disabled |
| Conditions | One or more field tests. All must match (AND). |
| Group by | `ip_address`, `username`, or none |
| Time window | 5 min, 10 min, 30 min, 1 hour or 24 hours |
| MITRE tactic | Optional, in the form `TA0001` |
| Actions | create alert, notify Slack, auto-create incident, suggest playbook |

**Custom Rule Schema Definition**

Admins and Analysts can create and update rules via the UI or directly via the REST API (`POST /custom-rules`).

```json
{
  "name": "Suspicious_Dev_Ssh_Burst",
  "category": "threat hunting",
  "severity": "High",
  "status": "Enabled",
  "conditions": [
    {"field": "event_type", "operator": "equals", "value": "ssh_login"},
    {"field": "status", "operator": "equals", "value": "failed"},
    {"field": "port", "operator": "equals", "value": "22"},
    {"field": "timestamp", "operator": "between", "value": "22:00-06:00"}
  ],
  "group_by": "ip_address",
  "threshold": 5,
  "window_seconds": 300,
  "mitre_tactic": "TA0001",
  "mitre_technique": "T1110.001",
  "actions": {
    "create_alert": true,
    "notify_slack": true,
    "auto_create_incident": false,
    "suggested_playbook": "Contain Host & Block IP"
  }
}
```

**Conditions & Operators**

Custom rules can test these fields only: `event_type`, `status`, `ip_address`, `username`, `port` and `timestamp`.

| Field type | Supported Operators | Description |
| --- | --- | --- |
| Text fields (`event_type`, `status`, `ip_address`, `username`) | `equals`, `not equals`, `contains`, `in` | Case-insensitive and trims surrounding spaces. `in` accepts a comma-separated list. |
| Numeric fields (`port`) | `equals`, `>`, `<`, `in` | Integer comparison. Validates ports (1–65535). |
| Temporal fields (`timestamp`) | `between`, `before`, `after` | `between` accepts `HH:MM-HH:MM` ranges (e.g. `22:00-06:00` wrapping overnight) in UTC or named timezones. |

- Invalid ports, empty list items, blank values and malformed times are rejected before the rule is saved.

**How matching and windows work**

- The alert window is measured from the first matching event, so a chain of closely spaced events cannot stretch one window forever.
- A rule with no conditions can never match everything.
- Editing actions keeps the ones you did not change.

**Slack alerts.** To use notify Slack, set `SLACK_WEBHOOK_URL` in `.env`. Delivery is HTTPS only, and webhook secrets are hidden in error messages.

**Test before you enable.** Use the test option (`POST /custom-rules/test`) against sample events, save the rule as Draft, then switch it to Enabled when you are happy. Deleting a rule asks for confirmation.

## 9. Collect logs automatically

The collector watches folders on a monitored host and sends new log lines to the backend as they appear, so you do not have to upload files by hand. It uses only the Python standard library (3.10 or newer), so it runs without the backend's dependencies. Collected logs go through the same parsing, detection, correlation and storage as manual uploads. Each batch records its source name, source type (`agent` by default), source host and who ingested it.

**Set it up**

```powershell
cd collector
Copy-Item collector.example.json collector.json   # then edit api_url, source_host, sources[].path
python -m cybershield_collector login --config collector.json
python -m cybershield_collector run --config collector.json
```

- `login` asks for your username, password and the emailed 2FA code. It saves only a refresh token, never your password.
- `run` watches continuously. Stop it with Ctrl+C.
- `once` does a single scan and prints counters. `status` shows how many bytes of each file were shipped and the last batch ID.

The account must be an Admin or Analyst. If the session expires, is revoked or loses its role, the collector stops with exit code 3 and asks you to run `login` again. Nothing is skipped; collection resumes where it stopped. Keep `state_dir` somewhere only the collector's account can read.

**Key settings (in `collector.json`)**

| Setting | Default | Meaning |
| --- | --- | --- |
| `api_url` | required | Backend URL including `/api`. |
| `source_host` | machine hostname | Stored on each batch. |
| `poll_interval_seconds` | 2 | How often it scans. |
| `settle_seconds` | 5 | How long a file must be quiet before an unfinished last line (or a `.json` file) counts as final. |
| `max_chunk_bytes` | 1 MiB | Batch size cap, cut on line boundaries. |
| `sources[].name` | required | Stored as the source name. Must be unique. |
| `sources[].path` | required | Folder to watch. |
| `sources[].recursive` | false | Also watch subfolders. |
| `sources[].source_type` | agent | `agent`, `file`, `syslog` or `api`. |
| `sources[].format` | inferred | Force the parser for files without a usable extension. |
| `sources[].start_at` | beginning | Set to `end` to skip history in files that already exist. |

**How it behaves**

- It sends only complete lines, and resends a CSV's header with every batch so each batch parses alone.
- `.json` documents cannot be split, so they ship whole once stable. Use `.jsonl` for files that keep growing.
- Rotated files (`auth.log.1`) and truncated files are handled without resending or losing lines. Compressed `.gz` rotations are skipped, so collect lines before compression.
- Restarts never resend acknowledged data. Files are recognized by content, so a renamed or copied file is not sent twice. Identical lines inside one file are kept, because repeated events are real signal for brute-force detection.
- If the server is down, it retries with growing delays up to `max_backoff_seconds` (default 300). If a reply is lost, it checks upload history before resending. Batches the server rejects as unparseable are saved in `<state_dir>/rejected/` and collection continues.
- Every delivered batch is logged in `<state_dir>/shipments.jsonl`.

Collection is by polling, so new lines arrive within one poll interval.

## 10. AI Analysis and reports

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CyberShield SOC Reporting Subsystem                  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
┌──────────────────────────────┐                         ┌──────────────────────────────┐
│   Server-Side PDF Engine     │                         │   AI Investigation Assistant │
│   - ReportLab & PyPDF        │                         │   - Claude Model Tool-Calls  │
│   - Parameterized Lookbacks  │                         │   - Read-Only SQL Inquiries  │
│   - Context-Aware Layouts    │                         │   - Prompt Injection Defense │
└──────────────┬───────────────┘                         └──────────────┬───────────────┘
               │                                                         │
               ▼                                                         ▼
┌──────────────────────────────┐                         ┌──────────────────────────────┐
│ Downloadable PDF Exports     │                         │ Contextual Analyst Guidance  │
│ (Daily, Weekly, Coverage,    │                         │ (Quick Resolve, AI Assistant │
│ Executive Risk)              │                         │ Recommendations)             │
└──────────────────────────────┘                         └──────────────────────────────┘
```

**Server-Side PDF Reporting Engine**

Open Reports to export any of four built-in reports as a server-rendered vector PDF. The reporting subsystem is powered by `reportlab` and `pypdf`, generating parameterized documents on demand via `GET /reports/{report_id}/pdf`. PDF export requires a connected backend and is unavailable in demo mode.

| Report Archetype | Lookback & Focus | Detailed Contents |
| :--- | :--- | :--- |
| **Daily SOC Operations** (`daily-operations`) | Past 24 Hours | Hourly alert volume by severity, triage status mix, top 10 offending source IPs and targeted users, host and log-source health, analyst incident assignment distribution. |
| **Weekly Incident Summary** (`weekly-incidents`) | Past 7 Days | MTTR (Mean Time to Resolution) metrics, incident severity breakdown against prior-week historical baselines, itemized index of open, resolved, and false-positive incidents. |
| **Detection Coverage & MITRE Matrix** (`detection-coverage`) | Deployment Lifecycle | Active, shadow-mode, and disabled rule distribution; MITRE ATT&CK tactic/technique coverage percentage; host heartbeat cadence and dead-agent reporting. |
| **Executive Risk Overview** (`executive-risk`) | Past 30 Days | High-level threat trend indicators, open critical exposure summaries, resolution performance, and systemic vulnerability hotspots across monitored infrastructure. |

Reports are generated dynamically on demand without persistent queue delays.

**AI Security Analysis Assistant**

Integrated through Anthropic's Claude API (`ANTHROPIC_API_KEY`), the assistant provides real-time analyst support across alerts, incidents, events, sign-in activity, users, and detection rules. It operates under strict security boundaries:

- **Strict Read-Only Enforcement:** The assistant queries workspace telemetry using structured read-only tool calls (`query_alerts`, `query_incidents`, `get_host_telemetry`). It cannot mutate database records, alter firewall rules, or close incidents.
- **Turn it on:** Set `ANTHROPIC_API_KEY` in `.env`. If it is empty, the assistant is disabled and the endpoint returns 503. `ASSISTANT_MODEL` and `ASSISTANT_MAX_TOKENS` tune the model and answer length. Never commit a real key.
- **Ask specific questions:** For example, which IPs caused the failed logins in the current time range. The assistant looks up the data with tools before answering and respects the time range you have selected.
- **Read the answer critically:** It cites concrete values (IPs, counts, rule IDs, hosts), says when a lookup returned nothing, and notes when results were truncated. A filtered lookup covers only that filter.
- **Evidence-Backed Recommendations:** Recommendations map to concrete response playbooks (e.g., *Isolate Host*, *Block CIDR*, *Rotate Credentials*, *Revoke Session*) framed as options tied to specific evidence log IDs.
- **Prompt Injection Defense:** Text inside logs is treated strictly as data. If a log row attempts instruction hijacking or prompt manipulation, the assistant isolates the text, names the event, quotes a short fragment, and flags it as suspicious attack evidence.
- **Quick Resolve Integration:** The **Analyze Alert** module in Quick Resolve invokes the assistant with pre-scoped alert context to generate immediate, tailored investigation checklists.

## 11. Admin tasks

**Users and roles (Admin only, Manage > Users)**

- Invite users and assign them Admin, Analyst or Viewer. Pending invites are listed on the page.
- Change a role, deactivate or reactivate an account, reset a password, or revoke a user's sessions.
- Passwords must meet the minimum length (12 by default, set by `PASSWORD_MIN_LENGTH`). Set `EMAIL_VERIFY_DELIVERABILITY=true` to also check that a new user's email domain resolves in DNS; leave it false offline.
- Passwords are hashed with Argon2. Resetting a password or disabling an account revokes that user's sessions.
- The system refuses any change that would remove the last active Admin. The interface also stops you from demoting or disabling your own account.

**Machine Learning & Behavioral Anomaly Detection**

CyberShield integrates unsupervised behavioral anomaly detection using scikit-learn Isolation Forests to identify subtle, low-and-slow threats that evade static threshold rules.

```
Batch Ingestion Stream
       │
       ▼
┌─────────────────────────────────┐
│   ML Feature Extractor Pipeline │
│   - Rolling Temporal Windows    │
│   - Geolocation & ASN Vectors   │
│   - Egress Volume Aggregations  │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ PostgreSQL Feature Snapshots    │ ◄─── Accumulated Baseline Data
│ (`ml_feature_snapshots`)        │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Isolation Forest Engine         │
│ - Fit Model (Contamination: 2%) │
│ - Decision Function Scoring     │
│ - Anomaly Score Scaling (0-100) │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Attribution & Deviation Engine  │ ──► Deviation Breakdown (Top Feature Drivers)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│ Shadow Mode Review / Live Alert │
└─────────────────────────────────┘
```

*Feature Sets & Extraction Pipelines:*

| Feature Set Key | Monitored Entity | Feature Dimensions Extracted | Minimum Samples (`min_samples`) |
| :--- | :--- | :--- | :--- |
| `login_temporal_geo` | `username` / `account` | `login_hour_sin`, `login_hour_cos`, `day_of_week`, `is_weekend`, `geo_distance_km`, `asn_novelty_score` | 50 snapshots |
| `egress_volume_hourly` | `source_host` | `bytes_out_mean`, `bytes_out_std`, `flow_count`, `dest_port_entropy`, `peak_to_average_ratio` | 100 snapshots |
| `source_ip_window` | `ip_address` | `event_rate_per_min`, `unique_usernames_probed`, `failure_ratio`, `distinct_dest_ports` | 75 snapshots |

*Model Architecture & Scoring:*
- **Model Type:** Scikit-learn `IsolationForest(n_estimators=100, contamination=0.02, random_state=42)`.
- **Score Normalization:** Raw tree decision function outputs are mapped linearly to a normalized `0–100` Anomaly Score:
  $$\text{Anomaly Score} = \min\left(100, \max\left(0, \frac{-\text{decision\_function}(X) - \text{threshold}}{\text{scale\_factor}} \times 100\right)\right)$$
- **Explainability & Attribution:** Feature-level deviations against baseline mean and variance are computed via `feature_deviations()`, highlighting which specific metric (e.g. `bytes_out` spike or anomalous login hour) drove the score.

*Model Training & Shadow Mode Lifecycle:*
1. **Accumulate History:** Feature snapshots are saved automatically in `ml_feature_snapshots` during standard log ingestion.
2. **Train Model:** Trigger training per feature set via `POST /ml/models/{feature_set}/train`. Serialized artifacts and parameters are versioned in `ml_models`.
3. **Audit Shadow Mode Scores:** Evaluate live scoring at `GET /ml/scores`. In shadow mode, events are scored and recorded without raising noisy alerts.
4. **Activate & Alert:** Activate the model via `POST /ml/models/{model_id}/activate` and disable shadow mode in rule settings when anomaly scoring is calibrated.

**Threat-intel feeds**

`threat_intel_match` stays silent until you import a feed. A feed is a plain text file with one IP, CIDR range or domain per line. Import it from Threat Detection > Threat Intelligence > Import Feed, or through the API (`POST /threat-intel/feeds`), list indicators with `GET /threat-intel/indicators`, and remove a feed with `DELETE /threat-intel/feeds/{source}`. To suppress an indicator you trust, add it to that rule's allowlist.

**Host heartbeats & cadence tracking**

`host_log_silence` learns each host's reporting cadence from ingested telemetry batches. View tracked hosts at `GET /detection/host-heartbeats`, and run a silence check on demand with `POST /detection/host-silence/check`. Inactivity exceeding learned thresholds triggers `host_log_silence` alerts.

**Audit trails & concurrency safeguards**

- **Immutable Audit Logging:** Incident state transitions record exact timestamps, originating user IDs, prior states, and resolution reasons.
- **Incident Capacity Rules:** Incidents store up to 5 concurrent investigative notes.
- **Optimistic Concurrency Control:** State updates validate entity version timestamps, rejecting stale writes with HTTP 409 if another analyst modified the record concurrently.

**Settings and notifications.** Only Admins can change workspace settings. Session lifetime, MFA and privileged re-authentication are controlled by the backend (`.env`), not by the Settings page. Each person can pick which live events appear in their notification center, plus theme, density, text size, contrast and motion.

**Tuning noise.** If a rule is too chatty, raise its threshold or set a `cooldown_seconds`. If it is irrelevant, set `enabled` to false. Do this per rule from Threat Detection, or for the whole deployment with `DETECTION_RULE_CONFIG`.

## 12. Deploy to Railway

The repository deploys as one Railway service. The Dockerfile builds the frontend, installs the backend, runs migrations, creates the initial Admin, and starts FastAPI, which also serves the built frontend. You do not need a separate frontend service or CORS settings.

1. Create a Railway project from the repository.
2. Add a Railway PostgreSQL plugin.
3. In the service Variables tab, set the three required values:

   | Variable | Value |
   | --- | --- |
   | `DATABASE_URL` | The plugin's connection string with the scheme changed to `postgresql+psycopg://` (not `postgresql://`), because the app uses the psycopg v3 driver. |
   | `JWT_SECRET_KEY` | A long random value from `python -c "import secrets; print(secrets.token_urlsafe(64))"`. |
   | `OTP_SECRET` | A random value of at least 16 characters. |

4. Also set `CYBERSHIELD_ADMIN_PASSWORD` to seed the first Admin, `AUTH_COOKIE_SECURE=true` (Railway serves HTTPS), and `RESEND_API_KEY` with `RESEND_FROM_EMAIL` so sign-in codes can be emailed.
5. Set `CORS_ALLOWED_ORIGINS` only if you host the frontend as a separate service.
6. Deploy. Railway supplies `PORT`, and the `/health` check is already configured.

Without the three required variables, the container fails at startup with a validation error during the migration step. Check Railway's build logs on the first deploy; the project notes say it has not been verified on a live Railway environment.

Before going to production, serve everything over HTTPS, rate-limit the public login endpoint at your edge, add a strict Content Security Policy at the host, and keep secrets out of `VITE_*` variables. [SECURITY.md](../SECURITY.md) has the full checklist.

## 13. Try it, fix it, look it up

**Try it with the sample logs**

The `sample-logs/` folder has a fixture for most rules. Upload one file at a time from Event Logs and watch the matching alert appear. Each file mixes lines that should trigger the rule with normal lines that should not. [sample-logs/NEW_RULES_README.txt](../sample-logs/NEW_RULES_README.txt) lists what each one should produce.

| File | Expected result with default settings |
| --- | --- |
| `direct_root_login.txt` | 2 alerts for successful root logins from one IP |
| `cron_persistence.log` | 1 alert on host `batch01` |
| `dns_tunneling.log` | 1 alert for client `10.0.5.77` |
| `dormant_account_activity.csv` | 1 alert for account `mward` after about 105 idle days |
| `first_seen_geo_asn.csv` | 1 alert for account `priya` logging in from Germany |

For `threat_intel_match.csv`, import `threat_intel_feed_import.txt` as a feed first (Threat Detection > Threat Intelligence > Import Feed). It should then produce 2 alerts. If your database already holds other hosts, you may also see unrelated `host_log_silence` alerts. That is expected.

**Troubleshooting**

| Problem | Likely cause and fix |
| --- | --- |
| Sign-in code never arrives | Check `RESEND_API_KEY` and `RESEND_FROM_EMAIL`. The sandbox sender only delivers to your own Resend account email. Confirm the user's email address is one you can read. A failed send returns a 502. |
| Backend crashes at startup with a validation error | `DATABASE_URL`, `JWT_SECRET_KEY` and `OTP_SECRET` have no defaults and must be set. |
| Cannot connect to the database on Railway | The URL must start with `postgresql+psycopg://`. |
| Tests stop with setup instructions | PostgreSQL is not running or the schema is old. Start Docker, run `docker compose up -d --wait database`, then `python -m alembic upgrade head`. |
| Browser warns about the certificate | The dev server uses a self-signed certificate. See [frontend/.cert/README.md](../frontend/.cert/README.md). |
| `npm.ps1` is blocked on Windows | Use `npm.cmd install` and `npm.cmd run dev`. |
| Badge says Demo mode | `VITE_API_BASE_URL` is empty. Set it to `/api` in `frontend/.env.local`. |
| Upload rejected | Check the extension (`.log`, `.csv`, `.txt`, `.json`, `.jsonl`), the 50 MB limit, and that the file is text. |
| A rule never fires | Check the log source in section 6, whether the rule needs history from earlier uploads, and whether it needs an allowlist before it turns on. |
| Collector stops with exit code 3 | The session expired or the role changed. Run `login` again. |
| 401 or 403 from the API | 401 means the token expired or is missing. 403 means your role is not allowed. |
| AI Analysis returns 503 | `ANTHROPIC_API_KEY` is empty. |

**Where to read more (all in the repository)**

| Topic | File |
| --- | --- |
| Project charter, architecture scope, milestones and KPIs | [docs/PROJECT_CHARTER.md](PROJECT_CHARTER.md) |
| Full environment variable table and demo checklist | [docs/deployment_and_documentation.md](deployment_and_documentation.md) |
| Authentication, roles and endpoint permissions | [docs/backend-auth-rbac.md](backend-auth-rbac.md) |
| Correlation, evidence and incident lifecycle | [docs/sprint6.md](sprint6.md) |
| Ingestion API and custom-rule rules | [docs/SPRINT7_INGESTION_AND_RULES.md](SPRINT7_INGESTION_AND_RULES.md) |
| Collector reference | [collector/README.md](../collector/README.md) |
| Writing a new built-in rule | "How to add a detection rule" in [README.md](../README.md) |
| Security notes | [SECURITY.md](../SECURITY.md) |
| Interactive API docs | http://localhost:3000/docs when the backend is running |
