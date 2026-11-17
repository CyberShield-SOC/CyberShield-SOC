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

Every sign-in needs your password and a second factor: a one-time code sent to your email, or, if you have set one up, the code from an authenticator app.

1. Enter your username and password. Tick remember me if you want a longer session.
2. Enter the six-digit code. An emailed code expires after 5 minutes and can be resent after a 60-second wait. With an authenticator app, nothing is emailed: type the code the app shows, or choose **Use a recovery code** if you no longer have the device. Either way you get 5 attempts.
3. You land in the workspace. Your access token lasts 10 minutes and renews itself in the background.

**Set up an authenticator app (optional, recommended).** Open Settings > Security > Sign-in verification and choose **Set up authenticator app**. Scan the QR code with Google Authenticator, Microsoft Authenticator, 1Password or any TOTP app (or type the setup key shown under it), then enter the code the app shows. You are then given 8 recovery codes. They are shown once; copy or download them and keep them away from your password. Each one signs you in once. From the same panel you can generate a new set (needs a current code) or turn the app off (needs your password and a code). An authenticator works offline and does not depend on email delivery.

Sign-in attempts are rate limited. Too many from one address, or five wrong passwords for one account within 15 minutes, return "Too many requests" with a time to wait.

A normal session lasts 60 minutes. With remember me it lasts 7 days. If you forget your password, use the recovery link on the sign-in screen; the reset link it emails you is valid for 30 minutes. These limits come from `.env` and your admin can change them.

**What each role can do**

| Action | Admin | Analyst | Viewer |
| --- | --- | --- | --- |
| View dashboard, logs, alerts, incidents, notes, evidence | Yes | Yes | Yes |
| Upload logs | Yes | Yes | No |
| Update alerts and investigations, create and resolve incidents, add notes | Yes | Yes | No |
| Tune built-in rules and build custom rules | Yes | Yes | No |
| Manage users and roles | Yes | No | No |

The interface hides or disables what your role cannot do, but the backend enforces the same limits on every request. Hiding a button is a convenience, not the security boundary.

**Good to know**

- Deactivating a user blocks them on their very next request.
- Resetting a password or revoking sessions stops new tokens from being issued, but a token already issued keeps working until it expires, at most 10 minutes by default.
- The system will not let the last active Admin be removed or demoted.
- Lost your authenticator and your recovery codes? An Admin can reset it (section 11). Your next sign-in then uses an emailed code.

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

**Formats recognised from the content.** The extension only decides whether a file is accepted; the parser is chosen by what the lines look like:

| Format | Example start of a line |
| --- | --- |
| Syslog, RFC 3164 | `Jan 10 08:00:01 server01 sshd[1234]: ...`, optionally prefixed with `<34>` |
| Syslog, RFC 5424 | `<34>1 2026-01-10T08:00:01Z server01 sshd 1234 ID47 [origin@32473 ip="..."] ...` |
| ArcSight CEF | `CEF:0\|Vendor\|Product\|1.0\|100\|Name\|7\|src=203.0.113.5 duser=root ...`, bare or after a syslog header |
| IBM LEEF 1.0 / 2.0 | `LEEF:1.0\|Vendor\|Product\|1.0\|EventID\|src=...<tab>usrName=...` |
| auditd, Apache/Nginx, CSV, JSON, NDJSON, `key=value` | as before |

For syslog the severity comes from the `<PRI>` value, raised when the message itself says more (sshd logs a failed password as informational, which is shown as a warning). CEF and LEEF severities 0-10 map to Low (0-3), Medium (4-6), High (7-8) and Critical (9-10). Lines that start with `#` or `;` followed by a non-digit are comments and are listed as skipped.

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

**Export to another SIEM (ECS).** Export ECS on Event Logs downloads every stored event of the upload on screen as Elastic Common Schema documents, one JSON object per line (NDJSON), ready for Elasticsearch, OpenSearch or any tool that reads ECS. Unlike Export CSV it ignores the on-screen filters: it exports the whole stored upload. Analysts and Admins can export; Viewers cannot. Alerts export the same way through `GET /alerts/export?format=ecs`. An export stops at 50,000 records; the response header `X-Export-Truncated: true` says when, so narrow it with `upload_id`, `from` and `to`. Every export is recorded in the audit log.

**Upload history.** `GET /upload/history` and `GET /upload/batches/{id}` list past batches with their source name, type, host and uploader.

## 6. Detection rules

Thirty built-in rules run on every upload or collected batch. Each alert carries a severity (how bad it would be if true), a separate confidence score, a MITRE ATT&CK technique and the entity it pivots on.

**Rule catalog**

| Rule | Severity | Detects | Needs |
| --- | --- | --- | --- |
| `brute_force_login` | High | 5 failed logins from one IP in 60 s | Any auth log |
| `invalid_user_enumeration` | Medium | One IP trying 3 or more usernames in 10 min | Any auth log |
| `sudo_failure` | Medium | 3 failed sudo attempts in 5 min | Auth or syslog |
| `password_spraying` | High | One account failing from 5 or more IPs in 10 min | Any auth log |
| `credential_stuffing_success` | High | A failure burst followed by a success from the same IP | Any auth log |
| `port_scan` | Medium | 10 port-scan events from one IP in 60 s | Firewall or IDS export |
| `multi_ip_successful_login` | Medium | One account logging in from 3 IPs in 5 min | Any auth log |
| `sudo_after_login` | Medium | A login quickly followed by successful sudo | Auth or syslog |
| `new_account_created` | High | `useradd` or `adduser` created an account | Syslog |
| `privileged_group_modified` | High | An account added to sudo, wheel, admin, root or docker | Syslog |
| `cron_persistence` | Medium | A crontab edited or a systemd timer started | Syslog |
| `security_control_disabled` | High | auditd, apparmor, fail2ban, ufw, firewalld or clamav stopped | Syslog |
| `log_tampering` | Critical | An audit or logging service stopped, or the journal vacuumed | Syslog, auditd |
| `direct_root_login` | High | A successful direct login to root | Any auth log |
| `service_account_interactive` | High | A listed service account logged in interactively | Any auth log; off until you list accounts |
| `login_to_nonexistent_account` | Medium | A failed login to a listed decommissioned account | Any auth log; off until you list accounts |
| `off_hours_login` | Low | A successful login outside 06:00–20:00 UTC | Any auth log |
| `dormant_account_activity` | Medium | A login after 30 or more idle days | Any auth log, history across uploads |
| `lateral_movement_chain` | High | One account reaching 3 or more hosts in 10 min | Syslog, history across uploads |
| `ssh_key_added` | High | An `authorized_keys` file written, created or deleted | auditd |
| `host_log_silence` | High | A host with a steady cadence stopped sending logs | Any source with a hostname |
| `impossible_travel` | High | Consecutive logins too far apart for the time elapsed | Geo columns or GeoIP database |
| `first_seen_geo_asn` | Medium | A login from a country or ASN new to that account | Geo columns or GeoIP database |
| `host_sweep` | Medium | One IP probing the same port on 10 or more hosts | Firewall or flow logs |
| `outbound_beaconing` | High | Regular, low-jitter connections to one external destination | Firewall, flow or proxy logs |
| `dns_tunneling` | High | 20 or more long, high-entropy queries under one domain | DNS server logs |
| `egress_volume_anomaly` | High | Outbound bytes far above a host's own baseline | Flow or proxy exports with bytes |
| `threat_intel_match` | High | Traffic or DNS matching an imported indicator | Network logs plus an imported feed |
| `behavioral_anomaly_login` | Low | A login time and location scored unusual by a trained model | Any auth log |
| `behavioral_anomaly_egress` | Low | An hourly egress pattern scored unusual by a trained model | Flow or proxy exports with bytes |

**Things that surprise people**

- Rules that keep history across uploads (dormant account, lateral movement, impossible travel, first-seen geo, egress volume, and both behavioral rules) never fire the first time they see an entity. They have nothing to compare against yet.
- `host_log_silence` watches every host the deployment has ever seen, not just the hosts in your latest file, so an unrelated upload can surface it for other hosts.
- Both `behavioral_anomaly_*` rules start in shadow mode. They score and store events (see `GET /ml/scores`) but raise no alerts until an Admin reviews the scores and turns shadow mode off.
- Interactive `history -c` is a shell builtin that writes no log record, so it is only caught when run through a logged command path.
- Only imported threat-intel feeds can trigger `threat_intel_match`. See section 11.

**Tuning a rule**

Settings stack in this order, and later layers win:

1. The rule's built-in defaults.
2. The `DETECTION_RULE_CONFIG` environment variable, a JSON object keyed by rule name.
3. Admin or Analyst overrides saved from the Threat Detection page (or `PATCH /detection/rules/{name}`). They apply from the next upload, with no restart.

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
| Time window | 5 min, 10 min, 30 min, 1 hour or 24 hours (an imported Sigma rule may use any whole number of seconds from 60 to 86,400) |
| At least N events | Alert only when a window holds this many matches. Default 1. |
| MITRE tactic | Optional, in the form `TA0001` |
| ATT&CK technique | Optional, in the form `T1110` or `T1110.001`. Alerts from the rule carry it. |
| Actions | create alert, notify Slack, auto-create incident, suggest playbook |

**Conditions**

Custom rules can test these fields: `event_type`, `status`, `ip_address`, `username`, `hostname`, `process`, `command`, `message`, `file_path`, `dest_ip`, `protocol`, `domain`, `dns_query`, `port` and `timestamp`. A field your log format does not fill is simply empty, so a condition on it does not match.

| Field type | Operators |
| --- | --- |
| Text fields | equals, not equals, contains, startswith, endswith, in (comma-separated list) |
| `port` | equals, >, <, in |
| `timestamp` | between, before, after |

- Text comparisons ignore case and surrounding spaces.
- **Any of.** Put several alternatives in one value, separated by `|`: `command endswith /bin/bash | /bin/sh` matches either. Write `\|` for a literal pipe. Works for every text operator except `in`, and for `port equals`.
- **NOT.** The NOT button before a condition inverts it. NOT on a field the event does not have counts as a match, so `NOT ip_address equals 198.51.100.250` also matches events with no address. A rule cannot be made only of NOT conditions.
- A timestamp between takes an hour range such as 00:00 – 06:00. The start is included, the end is excluded, and a range like 22:00 – 06:00 wraps past midnight. The default zone is UTC; pick any named zone to account for daylight saving time.
- Invalid ports, empty list items, blank values and malformed times are rejected before the rule is saved.

**How matching and windows work**

- The alert window is measured from the first matching event, so a chain of closely spaced events cannot stretch one window forever.
- A rule with no conditions can never match everything.
- Editing actions keeps the ones you did not change.

**Slack alerts.** To use notify Slack, set `SLACK_WEBHOOK_URL` in `.env`. Delivery is HTTPS only, and webhook secrets are hidden in error messages.

**Test before you enable.** Use the test option (`POST /custom-rules/test`) against sample events, save the rule as Draft, then switch it to Enabled when you are happy. Deleting a rule asks for confirmation.

**Import Sigma rules.** Choose Import Sigma on the new-rule screen, then paste YAML or load a `.yml` file (several rules separated by `---`, up to 50 and 256 KB). Each rule comes back as one of:

- **Draft created**, with its new rule id and any note about the translation (for example that the `logsource` is not used, because a custom rule runs on every upload). Choose **Review and test** to open it in the builder, run a test, and enable it.
- **Already imported**, when a rule with the same Sigma `id` exists.
- **Not imported**, with the reason. The engine can express selections joined by `and`, `not` filters on a single field, `1 of` / `all of`, lists of values, the `contains`, `startswith`, `endswith`, `all`, `gt`, `gte`, `lt` and `lte` modifiers, `*` at either end of a value, `timeframe`, and `count() [by SourceIp|User] > N`. It refuses rather than approximates: regular expressions (`|re`), `or` between selections, a `not` over several fields, fields with no CyberShield equivalent (such as `Hashes`), and Sigma correlation rules.

`level` sets the severity (informational counts as Low), and `attack.*` tags set the tactic and technique. The original YAML stays attached to the rule. Common Sigma field names are mapped automatically: `SourceIp`, `DestinationIp`, `DestinationPort`, `User`/`TargetUserName`, `Computer`, `Image`, `CommandLine`, `TargetFilename`, `QueryName`, `DestinationHostname`, `Protocol`, and ECS names such as `source.ip` and `process.command_line`. `sample-logs/sigma/` has example rules and a log to test them on.

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

**AI Analysis**

The assistant answers questions about your workspace's alerts, incidents, events, sign-in activity, users and rules. It is read-only: it advises and prepares recommendations, and you decide and act. It never blocks an IP, locks an account or resolves an alert.

- **Turn it on.** Set `ANTHROPIC_API_KEY` in `.env`. If it is empty, the assistant is disabled and the endpoint returns 503. `ASSISTANT_MODEL` and `ASSISTANT_MAX_TOKENS` tune the model and answer length. Never commit a real key.
- **Ask specific questions.** For example, which IPs caused the failed logins in the current time range. The assistant looks up the data with tools before answering and respects the time range you have selected.
- **Read the answer critically.** It cites concrete values (IPs, counts, rule IDs, hosts), says when a lookup returned nothing, and notes when results were truncated. A filtered lookup covers only that filter.
- **Recommendations** map to platform actions such as Block IP, Lock account, Enable MFA, Reset password and Investigate host, and are framed as options tied to evidence.
- **Prompt-injection guard.** Text inside logs is treated as data. If a log row looks like an attempt to instruct the assistant, it names the event, quotes a short fragment and flags it as possible attack evidence.
- Quick Resolve has an Analyze alert button that uses the same assistant for one alert. Settings has an AI assistant boundaries panel, and Quick Resolve shows a warning if the assistant is switched off.

**Reports**

Open Reports to export any of four built-in reports as a server-rendered PDF. PDF export needs a connected backend and is unavailable in demo mode.

| Report | What it covers |
| --- | --- |
| Daily SOC operations | Hourly alert volume by severity, status mix, top rules and source IPs, host and log-source health, incidents opened and assigned. |
| Weekly incident summary | Incident volume by severity and rule, time to resolve, the full incident list, most affected hosts and users, comparison with the previous period. |
| Detection coverage | Which built-in rules are enabled, in shadow mode or disabled, MITRE ATT&CK coverage, rule activity and host heartbeat health. |
| Executive risk overview | Open high and critical incidents, alert trend by severity, most affected hosts and users, resolution performance. |

Reports are on demand. There is no scheduling or run history yet.

## 11. Admin tasks

**Users and roles (Admin only, Manage > Users)**

- Invite users and assign them Admin, Analyst or Viewer. Pending invites are listed on the page.
- Change a role, deactivate or reactivate an account, reset a password, or revoke a user's sessions.
- Passwords must meet the minimum length (12 by default, set by `PASSWORD_MIN_LENGTH`). Set `EMAIL_VERIFY_DELIVERABILITY=true` to also check that a new user's email domain resolves in DNS; leave it false offline.
- Passwords are hashed with Argon2. Resetting a password or disabling an account revokes that user's sessions.
- The system refuses any change that would remove the last active Admin. The interface also stops you from demoting or disabling your own account.
- **Reset authenticator.** When a user with an authenticator app has lost the device and their recovery codes, select them and choose Reset authenticator. This removes the app and the codes, signs them out everywhere, and their next sign-in uses an emailed code. The user's details show which method they use.

**Audit log (Admin only, Manage > Audit Log)**

Every security-relevant action is recorded with who did it, their role, the time, the address and browser it came from, what it was done to, and whether it succeeded. That covers sign-ins (both steps, including failures), sign-outs, password resets, invites, authenticator changes, every user-management action, rule changes and Sigma imports, threat-feed imports, deletions and exports, model training and activation, uploads and collector ingests, and report and ECS exports. Alert and incident changes are not repeated here; they are in each alert's and incident's own history.

Filter by category, person, outcome and time range, and page back with Load older entries. The log is read-only: there is no way to edit or delete an entry through the app. A failed sign-in for a name that is not an account is recorded without the typed name, because people sometimes type a password into the username box. The API is `GET /audit/events`.

**Threat-intel feeds**

`threat_intel_match` stays silent until you import a feed. A feed is either a plain text list with one IP, CIDR range or domain per line, or a STIX 2.1 bundle (JSON) such as an ISAC or MISP export. Paste it or choose Load from file in Threat Detection > Threat Intelligence, or use the API (`POST /threat-intel/feeds`). From a STIX bundle, the `ipv4-addr`, `ipv6-addr` and `domain-name` indicators are imported; revoked or expired indicators and other kinds (file hashes, URLs, email addresses) are skipped and counted in the result. List indicators with `GET /threat-intel/indicators`, and remove a feed with `DELETE /threat-intel/feeds/{source}`. To suppress an indicator you trust, add it to that rule's allowlist.

Export STIX on a feed downloads it as a STIX 2.1 bundle (`GET /threat-intel/feeds/{source}/stix`) to share with another tool. Its ids are stable, so exporting the same feed twice gives the same objects.

**Host heartbeats**

`host_log_silence` learns each host's reporting rhythm. View the tracked hosts at `GET /detection/host-heartbeats`, and run a silence check on demand with `POST /detection/host-silence/check`.

**ML models (the two `behavioral_anomaly_*` rules)**

1. Collect enough history first. The models train from snapshots stored across uploads.
2. Train a model per feature set (`POST /ml/models/{feature_set}/train`) and activate it (`POST /ml/models/{model_id}/activate`). List models with `GET /ml/models`.
3. Leave the rule in shadow mode and review stored scores at `GET /ml/scores`.
4. When the scores look sensible, turn shadow mode off for that rule so it can raise alerts.

**Settings and notifications.** Only Admins can change workspace settings. Session lifetime, rate limits and privileged re-authentication are controlled by the backend (`.env`), not by the Settings page; each person sets up their own authenticator app in Settings > Security. Each person can pick which live events appear in their notification center, plus theme, density, text size, contrast and motion.

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
| Full environment variable table and demo checklist | [docs/deployment_and_documentation.md](deployment_and_documentation.md) |
| Authentication, roles and endpoint permissions | [docs/backend-auth-rbac.md](backend-auth-rbac.md) |
| Correlation, evidence and incident lifecycle | [docs/sprint6.md](sprint6.md) |
| Ingestion API and custom-rule rules | [docs/SPRINT7_INGESTION_AND_RULES.md](SPRINT7_INGESTION_AND_RULES.md) |
| Collector reference | [collector/README.md](../collector/README.md) |
| Writing a new built-in rule | "How to add a detection rule" in [README.md](../README.md) |
| Security notes | [SECURITY.md](../SECURITY.md) |
| Interactive API docs | http://localhost:3000/docs when the backend is running |
