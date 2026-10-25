"""Command line: ``python -m cybershield_collector {login,run,once,status} --config FILE``."""
from __future__ import annotations

import argparse
import getpass
import json
import logging
import sys

from .api import ApiError, CyberShieldClient
from .config import ConfigError, load_config
from .state import StateStore
from .watcher import Collector, CollectorStopped

EXIT_OK, EXIT_CONFIG, EXIT_AUTH, EXIT_ERROR = 0, 2, 3, 1


def _login(config, args) -> int:
    client = CyberShieldClient(config)
    username = args.username or input("CyberShield username or email: ").strip()
    password = getpass.getpass("Password: ")
    user = client.login(username, password,
                        lambda email: input(f"Verification code sent to {email}: ").strip())
    role = (user.get("role") or {}).get("name") if isinstance(user.get("role"), dict) else user.get("role")
    print(f"Logged in as {user.get('username', username)} ({role or 'unknown role'}). "
          f"Session saved to {config.session_file} (no password is stored).")
    if role and role not in ("Admin", "Analyst"):
        print("Warning: only Admin or Analyst accounts can ingest logs.", file=sys.stderr)
    return EXIT_OK


def _status(config) -> int:
    store = StateStore(config.state_dir)
    rows = sorted(store.records.values(), key=lambda r: (r.source, r.path))
    print(json.dumps({
        "api_url": config.api_url,
        "source_host": config.source_host,
        "session_saved": config.session_file.exists(),
        "files": [{"source": r.source, "path": r.path, "shipped_bytes": r.offset,
                   "chunks": r.shipped_chunks, "last_upload_id": r.last_upload_id,
                   "awaiting_reconciliation": r.pending_offset is not None} for r in rows],
    }, indent=2))
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cybershield_collector",
                                     description="Watch directories and ship new logs to CyberShield SOC.")
    parser.add_argument("command", choices=["login", "run", "once", "status"],
                        help="login: sign in once (2FA) and save a refresh session; run: watch continuously; "
                             "once: one scan then exit; status: show collection progress")
    parser.add_argument("--config", "-c", required=True, help="Path to the collector JSON config")
    parser.add_argument("--username", help="Account for login (prompted if omitted)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    try:
        config = load_config(args.config)
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        if args.command == "login":
            return _login(config, args)
        if args.command == "status":
            return _status(config)
        collector = Collector(config, CyberShieldClient(config))
        if args.command == "once":
            print(json.dumps(collector.scan_once(), indent=2))
        else:
            collector.run()
        return EXIT_OK
    except CollectorStopped as exc:
        logging.getLogger("cybershield_collector").error("Collector stopped: %s", exc)
        return EXIT_AUTH
    except ApiError as exc:
        print(f"{exc} {exc.detail or ''}".strip(), file=sys.stderr)
        return EXIT_AUTH if exc.kind in ("auth", "forbidden") else EXIT_ERROR
    except KeyboardInterrupt:
        return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
