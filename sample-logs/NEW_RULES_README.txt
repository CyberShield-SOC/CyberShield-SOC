CyberShield SOC — Sample Fixtures for the 22 Newer Detection Rules
====================================================================

One file per rule in backend/app/detection/rules/, each with ~30-40 lines/
rows of realistic log data: a mix of lines that SHOULD trigger the rule and
normal/benign "noise" lines that should NOT. Upload each file individually
through the app's log-upload feature to see that rule fire.

All results below were verified against the REAL parser + DetectionEngine
(backend/app/detection/engine.py) running with default rule thresholds, in
an isolated DB transaction that was rolled back afterward — every alert
listed is exactly what the app will show, not a guess.

A note on host_log_silence noise: that rule checks the reporting cadence of
EVERY host this deployment has ever seen (not just the uploaded file's own
hosts — see HostLogSilenceRule.load_states). If your dev/demo database
already has other hosts in it (e.g. from sample-logs/detection/*.csv/*.log),
uploading ANY of these files may also raise unrelated host_log_silence
alerts for those other hosts. That's expected app behavior, not a defect in
these fixtures.

Usernames/hostnames/IPs are fictional and unique per file so uploading
several files together will not cause unexpected cross-file collisions.


1. cron_persistence.log
   Rule: CronPersistenceRule (MEDIUM, host entity, T1053.003)
   Expected: 1 alert — host batch01, 2 merged actions ("crontab edited for
   svc-deploy" + "systemd timer started: data-sync.timer"). Noise: routine
   crontab LIST, CRON jobs, unrelated sudo/ssh activity.

2. direct_root_login.log
   Rule: DirectRootLoginRule (HIGH, account entity, T1078.003)
   Expected: 2 alerts — direct successful root logins (password, then
   publickey) from 45.33.12.9 on host prod-db01. Noise: normal non-root
   logins (some failed) for 5 other users.

3. dns_tunneling.log
   Rule: DnsTunnelingRule (HIGH, source_ip entity, T1071.004)
   Expected: 1 alert — client 10.0.5.77, 20 distinct long/high-entropy TXT
   queries under data-relay.net within 600s (avg ~52 chars, ~4.5 bits/char
   entropy, threshold is 3.5). Noise: normal A-record queries to real CDNs.

4. dormant_account_activity.csv (CSV: timestamp,username,ip_address,
   event_type,status)
   Rule: DormantAccountActivityRule (MEDIUM, account entity, T1078)
   Expected: 1 alert — account 'mward' authenticates after ~105 days idle
   (threshold 30). Control: 'sylee' logs in again after only 9 days — no
   alert. Noise: ~28 unrelated single logins for other users.

5. egress_volume_anomaly.csv (CSV: timestamp,hostname,src_ip,dest_ip,
   dest_port,protocol,bytes_out,bytes_in,action — netflow-style)
   Rule: EgressVolumeAnomalyRule (HIGH, host entity, T1041)
   Expected: 1 alert — host fs-07 sends ~285 MB in one hour vs. a ~20 MB/hr
   baseline built from the 7 preceding hourly buckets (needs
   min_samples=6). Noise: host fs-08 with steady, unremarkable traffic.

6. first_seen_geo_asn.csv (CSV: timestamp,username,ip_address,event_type,
   status,country,asn,latitude,longitude)
   Rule: FirstSeenGeoAsnRule (MEDIUM, account entity, T1078)
   Expected: 1 alert — 'priya' logs in from Germany/ASN 3320 after 6 prior
   US/ASN-7018 logins (min_history=5). Control: 'omar' only has 3 prior
   logins before a new-country login — below min_history, no alert. Noise:
   ~24 rows of other users logging in consistently from the US.

7. host_log_silence.log
   Rule: HostLogSilenceRule (HIGH, host entity, T1562.006)
   Expected: 1 alert for THIS file's own host — core-sw01 reports every
   ~60s for 20 events (establishing cadence, min_events=20), then goes
   quiet for ~46 minutes (over the 1800s/30-min floor) before resuming.
   Noise: host edge-sw02 with a steady, gap-free cadence. (See the
   cross-host note above about other hosts also appearing.)

8. host_sweep.log (UFW/iptables kernel syslog, [UFW BLOCK]/[UFW ALLOW]
   SRC=/DST=/DPT= lines)
   Rule: HostSweepRule (MEDIUM, source_ip entity, T1046)
   Expected: 1 alert — 203.0.113.150 probes port 22 on 10 distinct internal
   hosts (10.0.9.1-10) within 300s. Noise: normal allowed web traffic, and
   a "near miss" scan of only 6 hosts (below the threshold=10) on port 3389.

9. impossible_travel.csv (CSV: timestamp,username,ip_address,event_type,
   status,country,asn,latitude,longitude)
   Rule: ImpossibleTravelRule (HIGH, account entity, T1078)
   Expected: 1 alert — 'ktanaka' logs in from New York then Tokyo 25 minutes
   later (~10,852 km, ~26,044 km/h). Control: 'bsingh' travels New
   York -> Boston over 3 hours (~300 km, ~100 km/h) — no alert. Noise: ~30
   rows of other users logging in from one consistent location.

10. lateral_movement_chain.log
    Rule: LateralMovementChainRule (HIGH, account entity, T1021.004)
    Expected: 1 alert — account 'nrai' authenticates (publickey) to web05,
    app05, and db05 within 8 minutes (threshold=3 hosts/600s). Noise:
    'wgarcia' logging into the same host twice, plus ~27 unrelated
    single-host logins for other users across 4 hosts.

11. log_tampering.log
    Rule: LogTamperingRule (CRITICAL, host entity, T1070)
    Expected: 1 alert — host edge01, 3 merged actions: `rm -f
    /var/log/auth.log`, `history -c`, and systemd stopping auditd. Noise:
    routine sudo commands, systemd starting (not stopping) services.

12. login_to_nonexistent_account.log
    Rule: LoginToNonexistentAccountRule (MEDIUM, account entity, T1078)
    ** Configuration required before this rule will alert: ** it only
    matches usernames in its configured `allowlist` (no default roster —
    fails safe). Before uploading, set the rule's allowlist to
    ["jsmith-old", "old-svc-2019"] via PATCH /detection/rules (or the
    Threat Detection rule-settings UI).
    Expected once configured: 2 alerts — failed logins targeting
    jsmith-old and old-svc-2019 on host gateway01. Without that config the
    upload produces zero alerts from this rule, by design. Noise: normal
    logins/failures for 4 other real accounts.

13. new_account_created.log
    Rule: NewAccountCreatedRule (HIGH, host entity, T1136)
    Expected: 1 alert — host web09, 2 merged actions: useradd creates
    'contractor7', adduser creates 'tempuser9'. Noise: routine cron/sudo/ssh
    admin activity.

14. off_hours_login.log
    Rule: OffHoursLoginRule (LOW, account entity, T1078)
    Expected: 2 alerts — successful logins at 02:15 UTC (gwolski) and 23:40
    UTC (hchavez), both outside the default 06:00-20:00 UTC window. Noise:
    ~30 logins kept inside business hours.

15. outbound_beaconing.csv (CSV: timestamp,hostname,src_ip,dest_ip,
    dest_port,protocol,bytes_out,bytes_in,action — netflow-style)
    Rule: OutboundBeaconingRule (HIGH, host entity, T1071)
    Expected: 1 alert — host ws-311 connects to 185.199.108.153:443 every
    ~90s for 14 connections (threshold=10) with ~2.8% jitter (well under
    the 15% cap). Noise: ws-312 with irregular human-browsing intervals
    (high jitter, no alert) and ws-313 with one-off connections to 4
    different destinations.

16. privileged_group_modified.log
    Rule: PrivilegedGroupModifiedRule (HIGH, host entity, T1098)
    Expected: 1 alert — host app11, 2 merged actions: 'contractor7' added
    to 'sudo' (usermod) and to 'docker' (gpasswd). Noise: an addition to a
    non-privileged 'developers' group, plus routine admin activity.

17. security_control_disabled.log
    Rule: SecurityControlDisabledRule (HIGH, host entity, T1562)
    Expected: 1 alert — host fw02, 3 merged actions: `iptables -F`, `ufw
    --force disable`, and systemd stopping clamav-daemon. Noise: routine
    firewall inspection commands and clamav-daemon starting.

18. service_account_interactive.log
    Rule: ServiceAccountInteractiveRule (HIGH, account entity, T1078)
    ** Configuration required before this rule will alert: ** no default
    service-account roster. Before uploading, set the rule's allowlist to
    ["svc-etl", "svc-backup2"] via PATCH /detection/rules (or the rule
    settings UI).
    Expected once configured: 2 alerts — interactive logins for svc-etl and
    svc-backup2 on host batch-host. Without that config, zero alerts from
    this rule, by design. Noise: ~28 logins for 3 other, non-service users.

19. ssh_key_added.log
    Rule: SshKeyAddedRule (HIGH, host entity, T1098.004)
    Expected: 1 alert — host jump01, 2 merged actions: `tee -a
    /home/intern/.ssh/authorized_keys` then `chmod 600` on the same file.
    Noise: unrelated sudo commands and normal ssh logins.

20. threat_intel_match.csv (CSV: timestamp,hostname,src_ip,dest_ip,
    dest_port,protocol,bytes_out,bytes_in,domain,action) + companion file
    threat_intel_feed_import.txt
    Rule: ThreatIntelMatchRule (HIGH, host entity, T1071)
    ** Configuration required before this rule will alert: ** it needs at
    least one imported threat-intel feed with a matching indicator — with
    none imported it correctly produces zero alerts (verified). Import
    sample-logs/threat_intel_feed_import.txt via Threat Detection > Threat
    Intelligence > Import Feed BEFORE uploading threat_intel_match.csv.
    Expected once imported: 2 alerts — host ws-401 (4 connections to
    indicator IP 198.51.100.222) and host ws-402 (2 connections resolving
    indicator domain malicious-c2-example.net). Verified directly against
    the engine with a temporary matching indicator. Noise: ~28 rows of
    outbound traffic to legitimate destinations (GitHub, Cloudflare, etc.)
    from several other hosts.

21. behavioral_anomaly_login.csv (CSV: timestamp,username,ip_address,
    event_type,status,country,asn,latitude,longitude)
    Rule: BehavioralAnomalyLoginRule — ML pilot #1 (LOW, account entity,
    T1078; see docs/ml/isolation_forest_feasibility.md)
    ** This file is a raw training/scoring FEED, not a guaranteed
    single-upload trigger. ** Every successful login always gets a feature
    snapshot recorded (for the population an admin later trains on;
    app/ml/train_login_behavior.py requires MIN_SAMPLES=50 snapshots), but
    this rule only raises an Alert once (a) an admin has actually run that
    training script to produce an active model, AND (b) an admin has
    explicitly set this rule's params.shadow_mode to false — before that,
    it silently scores and stores (reviewable via GET /ml/scores) but never
    alerts, even against this file. With no model yet, uploading this file
    produces zero behavioral_anomaly_login alerts (verified). It contains
    ~15 in-hours logins for 'dpearce' from a consistent US ASN (population
    data) plus one illustrative 03:00 UTC login from a brand-new country
    (RU) — the kind of combination this rule is meant to eventually catch —
    plus ~18 more population rows for a second user, fnakamura. Because
    this reuses the geo-CSV shape, first_seen_geo_asn and off_hours_login
    also legitimately fire on dpearce's anomalous row — that's expected,
    not a bug.

22. behavioral_anomaly_egress.csv (CSV: timestamp,hostname,src_ip,dest_ip,
    dest_port,protocol,bytes_out,bytes_in,action — netflow-style)
    Rule: BehavioralAnomalyEgressRule — ML pilot #2 (LOW, host entity,
    T1041; see docs/ml/isolation_forest_feasibility.md)
    ** Same raw feed caveat as #21: ** needs a trained model
    (app/ml/train_egress_volume.py, MIN_SAMPLES=50) and shadow_mode=false
    before it will ever raise an Alert; with neither, uploading this file
    produces zero behavioral_anomaly_egress alerts (verified). It contains
    ~9 hours of typical hourly egress buckets for host app-node9 (varied
    bytes/connections/distinct destinations — population data) plus one
    illustrative 03:00 UTC hour with more connections/destinations than
    the rest, the kind of multi-feature combination this rule is meant to
    eventually catch.


Rules that need a one-time configuration step before they will alert
----------------------------------------------------------------------
- login_to_nonexistent_account (#12): configure allowlist =
  ["jsmith-old", "old-svc-2019"]
- service_account_interactive (#18): configure allowlist =
  ["svc-etl", "svc-backup2"]
- threat_intel_match (#20): import sample-logs/threat_intel_feed_import.txt
  as a threat-intel feed
- behavioral_anomaly_login (#21) / behavioral_anomaly_egress (#22): train a
  model (see backend/app/ml/train_login_behavior.py /
  train_egress_volume.py) and set params.shadow_mode=false — these are
  fundamentally raw feeds, not single-upload triggers, and no fixture file
  alone can complete this without an admin action outside the upload flow.

None of the above were "guessed" — each is a documented, deliberate design
choice in the rule's own source (fail-safe with no default roster, or a
two-step ML shadow-mode rollout), confirmed by running the fixture through
the real engine and observing zero alerts until the prerequisite is met.
