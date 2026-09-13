CyberShield SOC Detection Rule Test Files

01_brute_force_login.log
Expected:
- HIGH — Brute-Force Login
- 5 failed login attempts
- source IP 203.0.113.40
- 60-second rule window

02_username_enumeration.log
Expected:
- MEDIUM — Username Enumeration
- 3 distinct usernames
- source IP 198.51.100.77
- 600-second rule window

This test assumes the parser classifies "invalid user" records as:
event_type = "invalid_user"

and InvalidUserRule checks:
r.event_type == "invalid_user"

03_sudo_failure.log
Expected:
- MEDIUM — Sudo Failure
- 3 failures for jdoe
- 300-second rule window

04_all_rules_combined.log
Expected:
- Exactly 3 alerts:
  1. Brute-Force Login
  2. Username Enumeration
  3. Sudo Failure
- The final successful login should not generate an alert.

05_no_alert_control.log
Expected:
- No Threats Detected
- Every suspicious category remains below its configured threshold.

Sprint 5 additions (multi_ip_successful_login, sudo_after_login) have their
own fixtures: sample-logs/kk_normal.csv and sample-logs/kk_suspicious.csv,
exercised by backend/tests/test_kapil_sprint5_rules.py.

Current registered rules:
- BruteForceLoginRule
- InvalidUserRule
- SudoFailureRule
- PasswordSprayingRule
- CredentialStuffingRule
- PortScanRule
- MultiIPLoginRule (Sprint 5)
- SudoAfterLoginRule (Sprint 5)
