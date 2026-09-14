"""
Regenerate the detection sample logs in this folder.

    python sample-logs/detection/generate_samples.py

Output is deterministic (fixed seed), so the files and the expectations in
backend/tests/test_sample_logs_e2e.py stay in sync. Syslog-format files have
no year; the parser assumes the current one. CSV and audit files carry full
UTC timestamps on 2026-09-10.
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent
rng = random.Random(20260910)
DAY = datetime(2026, 9, 10, tzinfo=timezone.utc)


def syslog_ts(dt: datetime) -> str:
    return dt.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if dt.day < 10 else dt.strftime("%b %d %H:%M:%S")


def at(hour: int, minute: int = 0, second: int = 0) -> datetime:
    return DAY.replace(hour=hour, minute=minute, second=second)


def write(name: str, lines: list[str]) -> None:
    (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def pid() -> int:
    return rng.randint(1000, 60000)


# ── Group A: host integrity (syslog) ─────────────────────────────────────────

def group_a_host_integrity() -> None:
    t = at(14, 0)
    lines = [
        f"{syslog_ts(t)} web01 sshd[{pid()}]: Accepted publickey for alice from 10.10.0.21 port 50122 ssh2",
        f"{syslog_ts(t + timedelta(seconds=40))} web01 useradd[{pid()}]: new user: name=support2, UID=1012, GID=1012, home=/home/support2, shell=/bin/bash",
        f"{syslog_ts(t + timedelta(seconds=55))} web01 usermod[{pid()}]: add 'support2' to group 'sudo'",
        f"{syslog_ts(t + timedelta(minutes=2))} web01 crontab[{pid()}]: (support2) REPLACE (support2)",
        f"{syslog_ts(t + timedelta(minutes=2, seconds=30))} web01 systemd[1]: Started sys-update.timer.",
        f"{syslog_ts(t + timedelta(minutes=3))} web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/tee -a /root/.ssh/authorized_keys",
        f"{syslog_ts(t + timedelta(minutes=4))} web01 sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/sbin/iptables -F",
        f"{syslog_ts(t + timedelta(minutes=4, seconds=20))} web01 systemd[1]: Stopped Fail2Ban Service (fail2ban).",
        f"{syslog_ts(t + timedelta(minutes=5))} app01 sudo:    alice : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/setenforce 0",
        f"{syslog_ts(t + timedelta(minutes=6))} app01 systemd[1]: Stopped Security Auditing Service (auditd).",
        f"{syslog_ts(t + timedelta(minutes=6, seconds=30))} app01 systemd-journald[412]: Vacuuming done, freed 2.1G of archived journals from /var/log/journal.",
        f"{syslog_ts(t + timedelta(minutes=7))} app01 sudo:    alice : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/truncate -s 0 /root/.bash_history",
    ]
    write("group-a-host-integrity.log", lines)


def group_a_normal_admin() -> None:
    t = at(10, 0)
    lines = [
        f"{syslog_ts(t)} web02 sshd[{pid()}]: Accepted publickey for bob from 10.10.0.30 port 51000 ssh2",
        f"{syslog_ts(t + timedelta(minutes=1))} web02 CRON[{pid()}]: (root) CMD (run-parts /etc/cron.hourly)",
        f"{syslog_ts(t + timedelta(minutes=2))} web02 crontab[{pid()}]: (bob) LIST (bob)",
        f"{syslog_ts(t + timedelta(minutes=3))} web02 usermod[{pid()}]: add 'bob' to group 'developers'",
        f"{syslog_ts(t + timedelta(minutes=4))} web02 sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/apt-get update",
        f"{syslog_ts(t + timedelta(minutes=5))} web02 sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/bin/cat /root/.ssh/authorized_keys",
        f"{syslog_ts(t + timedelta(minutes=6))} web02 sudo:    bob : TTY=pts/0 ; PWD=/home/bob ; USER=root ; COMMAND=/usr/sbin/iptables -L -n",
        f"{syslog_ts(t + timedelta(minutes=7))} web02 systemd[1]: Stopped A high performance web server and a reverse proxy server (nginx).",
        f"{syslog_ts(t + timedelta(minutes=7, seconds=2))} web02 systemd[1]: Started A high performance web server and a reverse proxy server (nginx).",
        f"{syslog_ts(t + timedelta(minutes=8))} web02 systemd[1]: Started logrotate.service - Rotate log files.",
        f"{syslog_ts(t + timedelta(minutes=9))} web02 systemd-journald[398]: Journal started",
        f"{syslog_ts(t + timedelta(minutes=10))} web02 systemd[1]: Started fail2ban.service - Fail2Ban Service.",
    ]
    write("group-a-normal-admin.log", lines)


def audit_log() -> None:
    base = int(at(14, 30).timestamp())
    serial = 81000

    def stamp(offset: int) -> str:
        nonlocal serial
        serial += 1
        return f"{base + offset}.{rng.randint(100, 999)}:{serial}"

    lines = []
    s = stamp(0)  # attacker appends a key (write-mode open, audit watch key)
    lines += [
        f'node=app01 type=SYSCALL msg=audit({s}): arch=c000003e syscall=257 success=yes exit=3 a0=ffffff9c a1=55d1c0 a2=441 a3=1b6 items=2 ppid=4100 pid=4121 auid=1003 uid=0 gid=0 euid=0 tty=pts1 ses=7 comm="bash" exe="/usr/bin/bash" key="ssh_keys" AUID="mallory" UID="root"',
        f'node=app01 type=CWD msg=audit({s}): cwd="/root"',
        f'node=app01 type=PATH msg=audit({s}): item=0 name="/root/.ssh/" inode=131090 dev=08:01 mode=040700 ouid=0 ogid=0 nametype=PARENT',
        f'node=app01 type=PATH msg=audit({s}): item=1 name="/root/.ssh/authorized_keys" inode=131095 dev=08:01 mode=0100600 ouid=0 ogid=0 nametype=NORMAL',
    ]
    s = stamp(20)  # sshd reading the same file at login: must NOT alert
    lines += [
        f'node=app01 type=SYSCALL msg=audit({s}): arch=c000003e syscall=257 success=yes exit=5 a0=ffffff9c a1=7ffd10 a2=0 a3=0 items=1 ppid=1 pid=4200 auid=4294967295 uid=0 gid=0 euid=0 tty=(none) ses=4294967295 comm="sshd" exe="/usr/sbin/sshd" key="ssh_keys"',
        f'node=app01 type=PATH msg=audit({s}): item=0 name="/root/.ssh/authorized_keys" inode=131095 dev=08:01 mode=0100600 ouid=0 ogid=0 nametype=NORMAL',
    ]
    s = stamp(60)  # history truncation via exec
    lines += [
        f'node=app01 type=SYSCALL msg=audit({s}): arch=c000003e syscall=59 success=yes exit=0 a0=55d2 a1=55d3 a2=55d4 a3=0 items=2 ppid=4121 pid=4300 auid=1003 uid=0 comm="truncate" exe="/usr/bin/truncate" key="exec"',
        f'node=app01 type=EXECVE msg=audit({s}): argc=3 a0="truncate" a1="-s0" a2="/root/.bash_history"',
    ]
    s = stamp(90)  # SELinux enforcement switched off
    lines += [f"node=app01 type=MAC_STATUS msg=audit({s}): enforcing=0 old_enforcing=1 auid=1003 ses=7 enabled=1 old-enabled=1 lsm=selinux res=1"]
    s = stamp(120)  # audit rules removed
    lines += [f'node=app01 type=CONFIG_CHANGE msg=audit({s}): auid=1003 ses=7 op=remove_rule key="ssh_keys" list=4 res=1']
    s = stamp(150)  # routine command: must NOT alert
    lines += [
        f'node=app01 type=SYSCALL msg=audit({s}): arch=c000003e syscall=59 success=yes exit=0 a0=1 a1=2 a2=3 a3=0 items=2 ppid=4121 pid=4400 auid=1003 uid=0 comm="ls" exe="/usr/bin/ls" key="exec"',
        f'node=app01 type=EXECVE msg=audit({s}): argc=2 a0="ls" a1="-la"',
    ]
    write("audit.log", lines)


def host_heartbeats() -> None:
    """db02 goes quiet and comes back; cache01 goes quiet for good; web03 is healthy."""

    lines = []
    for minute in range(0, 221):
        t = at(9, 0) + timedelta(minutes=minute)
        lines.append((t, f"{syslog_ts(t)} web03 CRON[{pid()}]: (root) CMD (/usr/local/bin/healthcheck web03)"))
        if minute <= 60 or minute >= 210:
            lines.append((t + timedelta(seconds=5), f"{syslog_ts(t + timedelta(seconds=5))} db02 CRON[{pid()}]: (root) CMD (/usr/local/bin/healthcheck db02)"))
        if minute <= 90:
            lines.append((t + timedelta(seconds=9), f"{syslog_ts(t + timedelta(seconds=9))} cache01 CRON[{pid()}]: (root) CMD (/usr/local/bin/healthcheck cache01)"))
    write("group-a-heartbeat.log", [line for _, line in sorted(lines)])


# ── Group B: identity context ────────────────────────────────────────────────

def group_b_identity() -> None:
    lines = [
        f"{syslog_ts(at(2, 47, 13))} bastion01 sshd[{pid()}]: Accepted password for dave from 10.20.0.31 port 53311 ssh2",
        f"{syslog_ts(at(14, 5))} bastion01 sshd[{pid()}]: Accepted publickey for root from 198.51.100.23 port 51122 ssh2",
        f"{syslog_ts(at(14, 6))} bastion01 sshd[{pid()}]: Accepted password for svc-backup from 10.20.0.15 port 40220 ssh2",
        f"{syslog_ts(at(14, 7))} bastion01 sshd[{pid()}]: Failed password for invalid user jsmith-old from 203.0.113.50 port 60021 ssh2",
        f"{syslog_ts(at(14, 10))} web01 sshd[{pid()}]: Accepted publickey for erin from 10.20.0.40 port 50001 ssh2",
        f"{syslog_ts(at(14, 12))} db01 sshd[{pid()}]: Accepted publickey for erin from 10.10.0.21 port 50002 ssh2",
        f"{syslog_ts(at(14, 14))} backup01 sshd[{pid()}]: Accepted publickey for erin from 10.10.1.5 port 50003 ssh2",
    ]
    write("group-b-identity.log", lines)


def group_b_normal_logins() -> None:
    lines = [
        f"{syslog_ts(at(9, 1))} web01 sshd[{pid()}]: Accepted publickey for alice from 10.20.0.21 port 50100 ssh2",
        f"{syslog_ts(at(9, 30))} web01 sshd[{pid()}]: Accepted publickey for alice from 10.20.0.21 port 50101 ssh2",
        f"{syslog_ts(at(11, 2))} db01 sshd[{pid()}]: Accepted password for bob from 10.20.0.30 port 50200 ssh2",
        f"{syslog_ts(at(11, 3))} db01 sshd[{pid()}]: Failed password for bob from 10.20.0.30 port 50201 ssh2",
        f"{syslog_ts(at(13, 45))} web01 sshd[{pid()}]: Accepted publickey for rootkit-scanner from 10.20.0.50 port 50300 ssh2",
        f"{syslog_ts(at(15, 20))} db01 sshd[{pid()}]: Accepted publickey for alice from 10.20.0.21 port 50102 ssh2",
        f"{syslog_ts(at(19, 55))} web01 sshd[{pid()}]: Accepted publickey for carol from 10.20.0.60 port 50400 ssh2",
    ]
    write("group-b-normal-logins.log", lines)


def group_b_geo_logins() -> None:
    header = "timestamp,username,ip_address,event_type,status,country,asn,latitude,longitude"
    rows = []
    new_york = ("US", "7922", 40.7128, -74.0060)
    for day in range(6, 0, -1):  # six earlier logins build carol's and bob's history
        ts = (at(14, 0) - timedelta(days=day)).strftime("%Y-%m-%dT%H:%M:%SZ")
        rows.append(f"{ts},carol,73.12.44.{day},login_attempt,SUCCESS,{','.join(map(str, new_york))}")
        rows.append(f"{ts},bob,73.12.45.{day},login_attempt,SUCCESS,{','.join(map(str, new_york))}")
    rows += [
        # carol: New York then Amsterdam 40 minutes later — impossible travel
        # and a first-seen country/ASN.
        f"{at(14, 0):%Y-%m-%dT%H:%M:%SZ},carol,73.12.44.9,login_attempt,SUCCESS,US,7922,40.7128,-74.0060",
        f"{at(14, 40):%Y-%m-%dT%H:%M:%SZ},carol,185.107.56.10,login_attempt,SUCCESS,NL,9009,52.3676,4.9041",
        # bob: New York then Boston (300 km) 2 hours later, same ASN — normal.
        f"{at(12, 0):%Y-%m-%dT%H:%M:%SZ},bob,73.12.45.9,login_attempt,SUCCESS,US,7922,40.7128,-74.0060",
        f"{at(14, 0):%Y-%m-%dT%H:%M:%SZ},bob,73.61.2.14,login_attempt,SUCCESS,US,7922,42.3601,-71.0589",
        # dan: brand-new account, first login ever from abroad — no history, no alert.
        f"{at(14, 15):%Y-%m-%dT%H:%M:%SZ},dan,81.2.69.160,login_attempt,SUCCESS,GB,20712,51.5074,-0.1278",
        # A failed attempt from far away doesn't count as the account travelling.
        f"{at(14, 20):%Y-%m-%dT%H:%M:%SZ},bob,202.14.81.3,login_attempt,FAILED,AU,4739,-33.8688,151.2093",
    ]
    write("group-b-geo-logins.csv", [header, *rows])


def group_b_dormant() -> None:
    header = "timestamp,username,ip_address,event_type,status"
    write("group-b-dormant-part1.csv", [
        header,
        "2026-06-01T14:00:00Z,frank,10.30.0.11,login_attempt,SUCCESS",
        "2026-08-25T14:00:00Z,gina,10.30.0.12,login_attempt,SUCCESS",
    ])
    write("group-b-dormant-part2.csv", [
        header,
        # frank: idle 101 days, then active — dormant account.
        "2026-09-10T14:00:00Z,frank,10.30.0.11,login_attempt,SUCCESS",
        # gina: idle 16 days — below the 30-day threshold.
        "2026-09-10T14:05:00Z,gina,10.30.0.12,login_attempt,SUCCESS",
    ])


# ── Group C: network (firewall syslog, flow CSV, DNS syslog) ─────────────────

def ufw(dt: datetime, action: str, src: str, dst: str, dport: int, proto: str = "TCP") -> str:
    uptime = f"{rng.uniform(10000, 99999):.6f}"
    return (
        f"{syslog_ts(dt)} fw01 kernel: [{uptime}] [UFW {action}] IN=eth0 OUT= "
        f"MAC=00:16:3e:5e:6c:00:00:16:3e:00:00:01:08:00 SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 "
        f"TTL=52 ID={rng.randint(1000, 65000)} DF PROTO={proto} SPT={rng.randint(32768, 60999)} DPT={dport} "
        f"WINDOW=1024 RES=0x00 SYN URGP=0"
    )


def group_c_firewall() -> None:
    events = []
    # Background: steady allowed web traffic so fw01 reports continuously.
    for second in range(0, 1800, 20):
        t = at(14, 0) + timedelta(seconds=second)
        events.append((t, ufw(t, "ALLOW", f"10.0.3.{rng.randint(10, 60)}", "10.0.1.80", 443)))
    # Host sweep: one external IP tries SSH on 12 hosts in 2 minutes.
    for index in range(12):
        t = at(14, 10) + timedelta(seconds=index * 10)
        events.append((t, ufw(t, "BLOCK", "203.0.113.77", f"10.0.1.{index + 1}", 22)))
    # Vertical port scan: 15 ports on one host in 30 seconds.
    for index, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080]):
        t = at(14, 15) + timedelta(seconds=index * 2)
        events.append((t, ufw(t, "BLOCK", "198.51.100.200", "10.0.1.5", port)))
    # Near miss: internal monitoring hits 443 on only 5 hosts.
    for index in range(5):
        t = at(14, 20) + timedelta(seconds=index * 5)
        events.append((t, ufw(t, "ALLOW", "10.0.0.10", f"10.0.1.{index + 1}", 443)))
    # Outbound connection to a threat-feed IP.
    t = at(14, 25)
    events.append((t, ufw(t, "ALLOW", "10.0.2.44", "185.220.101.45", 443)))
    write("group-c-firewall.log", [line for _, line in sorted(events, key=lambda e: e[0])])


def group_c_netflow() -> None:
    header = "timestamp,hostname,src_ip,dest_ip,dest_port,protocol,bytes_out,bytes_in,action"
    rows = []

    def row(dt, host, src, dst, port, out_bytes, in_bytes):
        rows.append((dt, f"{dt:%Y-%m-%dT%H:%M:%SZ},{host},{src},{dst},{port},tcp,{out_bytes},{in_bytes},allow"))

    # Beaconing: ws-114 calls home every ~60s (±2s) for 30 minutes.
    t = at(14, 0)
    for _ in range(30):
        row(t, "ws-114", "10.0.3.14", "45.33.32.156", 8443, rng.randint(310, 360), rng.randint(500, 700))
        t += timedelta(seconds=60 + rng.randint(-2, 2))
    # Near miss: human browsing from ws-120 at irregular intervals.
    t = at(14, 0)
    for _ in range(30):
        row(t, "ws-120", "10.0.3.20", "140.82.112.3", 443, rng.randint(2_000, 90_000), rng.randint(20_000, 900_000))
        t += timedelta(seconds=rng.choice([5, 12, 40, 75, 30, 90, 20]))
    # Egress: fs-02 sends ~20 MB/hour for 8 hours, then 900 MB in one hour.
    # Irregular minutes within each hour, so these scheduled-looking syncs
    # don't themselves read as a low-jitter beacon.
    for hour in range(5, 13):
        for low, high in ((0, 14), (20, 34), (40, 55)):
            row(at(hour, rng.randint(low, high), rng.randint(0, 59)), "fs-02", "10.0.4.2", "52.95.110.1", 443, rng.randint(6_000_000, 7_500_000), 40_000)
    for low, high in ((0, 14), (20, 34), (40, 55)):
        row(at(13, rng.randint(low, high), rng.randint(0, 59)), "fs-02", "10.0.4.2", "91.198.174.192", 443, 300_000_000, 80_000)
    # Near miss: ws-121's volume varies but stays in its normal range.
    for hour in range(5, 14):
        row(at(hour, rng.randint(0, 59)), "ws-121", "10.0.3.21", "52.95.110.1", 443, rng.randint(1_000_000, 4_000_000), 90_000)
    # One flow to a threat-feed CIDR.
    row(at(14, 12), "ws-130", "10.0.3.30", "45.155.205.99", 443, 1200, 3400)
    write("group-c-netflow.csv", [header, *[line for _, line in sorted(rows, key=lambda r: r[0])]])


def random_label(length: int) -> str:
    return "".join(rng.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(length))


def group_c_dns() -> None:
    events = []
    normal = ["www.google.com", "outlook.office365.com", "e3130.dscb.akamaiedge.net", "api.github.com",
              "slack.com", "d1a2b3c4.cloudfront.net", "time.cloudflare.com"]
    for second in range(0, 1800, 15):
        t = at(14, 0) + timedelta(seconds=second)
        events.append((t, f"{syslog_ts(t)} dns01 dnsmasq[812]: query[A] {rng.choice(normal)} from 10.0.5.{rng.randint(10, 60)}"))
    # Tunneling: 30 distinct long base32 labels under one domain in ~5 minutes.
    for index in range(30):
        t = at(14, 10) + timedelta(seconds=index * 10)
        name = f"{random_label(44)}.{random_label(8)}.data.exfil-tunnel.net"
        events.append((t, f"{syslog_ts(t)} dns01 dnsmasq[812]: query[TXT] {name} from 10.0.5.23"))
    # Near miss: long-ish but low-entropy / few queries under a CDN.
    for index in range(5):
        t = at(14, 20) + timedelta(seconds=index)
        events.append((t, f"{syslog_ts(t)} dns01 dnsmasq[812]: query[A] {random_label(40)}.telemetry.vendor-cdn.com from 10.0.5.31"))
    # Threat-feed domain.
    t = at(14, 22)
    events.append((t, f"{syslog_ts(t)} dns01 dnsmasq[812]: query[A] cdn.badactor-c2.com from 10.0.5.40"))
    write("group-c-dns.log", [line for _, line in sorted(events, key=lambda e: e[0])])


def threat_feed() -> None:
    write("threat-intel-feed.txt", [
        "# CyberShield sample threat-intel feed — import via Threat Detection > Threat intelligence",
        "# One IP, CIDR, or domain per line. Text after # or ; is ignored.",
        "185.220.101.45    # known Tor exit used in phishing kits",
        "45.155.205.0/24   ; bulletproof hosting range",
        "badactor-c2.com",
        "not an indicator",
    ])


if __name__ == "__main__":
    for build in (
        group_a_host_integrity, group_a_normal_admin, audit_log, host_heartbeats,
        group_b_identity, group_b_normal_logins, group_b_geo_logins, group_b_dormant,
        group_c_firewall, group_c_netflow, group_c_dns, threat_feed,
    ):
        build()
    print(f"Wrote samples to {OUT}")
