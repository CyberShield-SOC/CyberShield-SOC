# Sprint 2 Product Backlog

## Goal

Extend CyberShield SOC from log upload and parsing into rule-based threat detection with dashboard-ready alerts.

## Backlog Items

| ID | Backlog Item | Priority | Status | Notes |
|---|---|---|---|---|
| PBI-1 | Validate uploaded log file types before parsing | High | Done | Backend accepts `.log` and `.csv` only. |
| PBI-2 | Return clear upload errors for unsupported files | High | Done | API returns structured JSON error details. |
| PBI-3 | Connect uploaded files to parser workflow | High | Done | `/upload` calls parser integration through `parse_log`. |
| PBI-4 | Return parsed log results as JSON | High | Done | Upload response includes `entries`, `parsing`, and `skipped_lines`. |
| PBI-5 | Add backend detection engine structure | High | Done | Detection engine and rule modules exist under `backend/app/detection`. |
| PBI-6 | Implement brute-force login detection | High | Done | Rule detects repeated failed login attempts from the same source IP. |
| PBI-7 | Generate alert objects for dashboard | High | Done | Alerts include title, severity, IP, user, reason, and timestamp range. |
| PBI-8 | Add alerts API endpoint | High | Done | Dashboard can call `/alerts` or `/api/alerts`. |
| PBI-9 | Retest parser with `.log` and `.csv` samples | Medium | Done | Smoke tests passed for upload, parser, detection, and invalid files. |
| PBI-10 | Add persistent alert storage | Medium | Future | Current alert store is in-memory for the latest generated alerts. |
| PBI-11 | Add authentication for dashboard APIs | Medium | Future | Not required for current Sprint 2 scope. |
| PBI-12 | Add more detection rules | Medium | In Progress | Invalid user and sudo-failure rules exist; more rules can be added later. |

## Current Sprint 2 Completion Summary

The backend now supports upload validation, parser integration, rule execution, alert generation, and dashboard alert retrieval. The remaining work is mostly hardening and future enhancements such as persistence, authentication, and expanded rule coverage.
