# Detection Rule Draft

## Purpose

Sprint 2 adds backend detection rules that run after uploaded logs are parsed. The goal is to identify suspicious authentication behavior and return dashboard-ready alerts.

## Detection Engine Structure

Detection code is located under:

```text
backend/app/detection/
```

Main files:

- `engine.py` - runs all registered detection rules.
- `models.py` - defines `LogRecord` and `Alert`.
- `rules/base.py` - shared rule interface.
- `rules/brute_force.py` - brute-force login rule.
- `rules/invalid_user.py` - invalid-user enumeration rule.
- `rules/sudo_failure.py` - sudo-failure rule.
- `alert_store.py` - stores latest generated alerts for dashboard retrieval.

## Rule 1: Brute-Force Login

### Rule ID

`brute_force_login`

### Objective

Detect repeated failed login attempts from the same source IP within a short time window.

### Input Fields

- `timestamp`
- `ip_address`
- `username`
- `event_type`
- `status`
- `line_number`

### Trigger Logic

The rule triggers when:

- `status` is `FAILED`
- `event_type` is `login_attempt`
- `ip_address` exists
- Failed attempts from the same IP meet or exceed the configured threshold inside the configured time window

Current default:

- Threshold: `5` failed attempts
- Window: `60` seconds

### Alert Output

The upload API serializes alerts with dashboard-friendly fields:

```json
{
  "title": "Possible brute-force login activity",
  "severity": "HIGH",
  "ip_address": "203.0.113.4",
  "user": "root",
  "reason": "Brute-force detected from 203.0.113.4: 5 failed login attempts within 60s.",
  "timestamp_range": {
    "start": "2026-06-14T02:11:43Z",
    "end": "2026-06-14T02:11:51Z"
  }
}
```

## Future Rule Ideas

- Suspicious source IP repeated across multiple users
- Repeated failed sudo attempts
- Impossible travel login pattern
- High volume of denied firewall events
- Repeated authentication failures followed by one success
