"""Collector configuration: a small JSON file, validated on load."""
from __future__ import annotations

import json
import os
import socket
from dataclasses import dataclass, field
from pathlib import Path

# Mirrors backend/app/schemas/ingestion.py and file_validation.ALLOWED_EXTENSIONS.
SUPPORTED_FORMATS = ("log", "txt", "csv", "json", "jsonl")
SOURCE_TYPES = ("agent", "file", "syslog", "api")
SERVER_CONTENT_LIMIT = 10 * 1024 * 1024  # characters accepted by IngestionRequest.content

DEFAULT_INCLUDE = ["*.log", "*.txt", "*.csv", "*.json", "*.jsonl",
                   # rotated logs: auth.log.1, auth.log.12, auth.log-20261025
                   "*.log.[0-9]", "*.log.[0-9][0-9]", "*.log-[0-9]*"]
DEFAULT_EXCLUDE = ["*.gz", "*.zip", "*.bz2", "*.xz", "*.7z", "*.tmp", "*.swp", "~*", ".*"]


class ConfigError(ValueError):
    """Raised for an invalid collector configuration."""


@dataclass
class SourceConfig:
    """One watched directory."""

    name: str
    path: Path
    include: list[str] = field(default_factory=lambda: list(DEFAULT_INCLUDE))
    exclude: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE))
    recursive: bool = False
    source_type: str = "agent"
    # Forces the parser format for files whose names carry no supported
    # extension (e.g. a rotated "auth.log.1" is detected automatically, but
    # "messages" is not). None means "infer from the filename, else log".
    format: str | None = None
    # "beginning": ship existing files in full on first sight.
    # "end": files already present when the collector first starts are only
    # tailed from their current size; files that appear later ship in full.
    start_at: str = "beginning"


@dataclass
class CollectorConfig:
    api_url: str
    sources: list[SourceConfig]
    state_dir: Path = Path(".cybershield-collector")
    source_host: str = field(default_factory=socket.gethostname)
    poll_interval_seconds: float = 2.0
    settle_seconds: float = 5.0
    max_chunk_bytes: int = 1024 * 1024
    request_timeout_seconds: float = 60.0
    max_backoff_seconds: float = 300.0
    auth_cookie_name: str = "cybershield_session"
    auth_csrf_cookie_name: str = "cybershield_csrf"
    otp_pending_cookie_name: str = "cybershield_2fa_pending"

    @property
    def session_file(self) -> Path:
        return self.state_dir / "session.json"


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ConfigError(message)


def parse_config(raw: dict, *, base_dir: Path | None = None) -> CollectorConfig:
    """Validate a decoded JSON config. Relative paths resolve against base_dir."""

    base_dir = base_dir or Path.cwd()
    _require(isinstance(raw, dict), "Config must be a JSON object.")

    api_url = os.environ.get("CYBERSHIELD_API_URL") or raw.get("api_url")
    _require(isinstance(api_url, str) and api_url.startswith(("http://", "https://")),
             "api_url must be an http(s) URL such as http://127.0.0.1:3000/api")

    raw_sources = raw.get("sources")
    _require(isinstance(raw_sources, list) and raw_sources, "sources must list at least one watched directory.")
    sources: list[SourceConfig] = []
    names: set[str] = set()
    for index, item in enumerate(raw_sources):
        where = f"sources[{index}]"
        _require(isinstance(item, dict), f"{where} must be an object.")
        name = str(item.get("name", "")).strip()
        _require(bool(name) and len(name) <= 255 and all(ord(c) >= 32 for c in name),
                 f"{where}.name must be printable, nonblank text (max 255).")
        _require(name not in names, f"{where}.name '{name}' is used twice.")
        names.add(name)
        _require(isinstance(item.get("path"), str) and item["path"].strip(), f"{where}.path is required.")
        path = Path(os.path.expandvars(os.path.expanduser(item["path"])))
        if not path.is_absolute():
            path = base_dir / path
        source_type = item.get("source_type", "agent")
        _require(source_type in SOURCE_TYPES, f"{where}.source_type must be one of {', '.join(SOURCE_TYPES)}.")
        fmt = item.get("format")
        _require(fmt is None or fmt in SUPPORTED_FORMATS, f"{where}.format must be one of {', '.join(SUPPORTED_FORMATS)}.")
        start_at = item.get("start_at", "beginning")
        _require(start_at in ("beginning", "end"), f"{where}.start_at must be 'beginning' or 'end'.")
        include = item.get("include", DEFAULT_INCLUDE)
        exclude = item.get("exclude", DEFAULT_EXCLUDE)
        for key, value in (("include", include), ("exclude", exclude)):
            _require(isinstance(value, list) and all(isinstance(v, str) and v for v in value),
                     f"{where}.{key} must be a list of glob patterns.")
        sources.append(SourceConfig(
            name=name, path=path, include=list(include), exclude=list(exclude),
            recursive=bool(item.get("recursive", False)), source_type=source_type,
            format=fmt, start_at=start_at,
        ))

    state_dir = Path(os.path.expanduser(raw.get("state_dir", ".cybershield-collector")))
    if not state_dir.is_absolute():
        state_dir = base_dir / state_dir

    host = raw.get("source_host") or socket.gethostname()
    _require(isinstance(host, str) and host.strip() and len(host) <= 255 and all(ord(c) >= 32 for c in host),
             "source_host must be printable, nonblank text (max 255).")

    def number(key: str, default: float, minimum: float, maximum: float) -> float:
        value = raw.get(key, default)
        _require(isinstance(value, (int, float)) and not isinstance(value, bool) and minimum <= value <= maximum,
                 f"{key} must be a number between {minimum} and {maximum}.")
        return value

    config = CollectorConfig(
        api_url=api_url.rstrip("/"),
        sources=sources,
        state_dir=state_dir,
        source_host=host.strip(),
        poll_interval_seconds=number("poll_interval_seconds", 2.0, 0.1, 3600),
        settle_seconds=number("settle_seconds", 5.0, 0, 3600),
        max_chunk_bytes=int(number("max_chunk_bytes", 1024 * 1024, 1024, SERVER_CONTENT_LIMIT // 2)),
        request_timeout_seconds=number("request_timeout_seconds", 60.0, 1, 3600),
        max_backoff_seconds=number("max_backoff_seconds", 300.0, 1, 86400),
    )
    for key in ("auth_cookie_name", "auth_csrf_cookie_name", "otp_pending_cookie_name"):
        if key in raw:
            _require(isinstance(raw[key], str) and raw[key], f"{key} must be a nonblank string.")
            setattr(config, key, raw[key])

    # Never watch our own state directory (it holds the session and quarantine).
    for source in sources:
        try:
            state_dir.resolve().relative_to(source.path.resolve())
        except ValueError:
            continue
        source.exclude.append(state_dir.name)
    return config


def load_config(path: str | os.PathLike) -> CollectorConfig:
    config_path = Path(path)
    try:
        raw = json.loads(config_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"Config file not found: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file is not valid JSON: {exc}") from exc
    return parse_config(raw, base_dir=config_path.resolve().parent)
