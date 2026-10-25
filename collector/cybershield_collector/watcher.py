"""Watched-directory collection loop (S7-02.1) with deduplication and retry (S7-02.4).

Each poll cycle lists the configured directories, and for every matching file
ships the bytes after the last acknowledged offset to ``/api/ingest``:

* Only complete lines are sent. A trailing partial line waits until the file
  has been quiet for ``settle_seconds`` (then it is treated as final).
* Chunks are cut at newline boundaries and capped at ``max_chunk_bytes``.
  CSV (and delimited .txt) headers are replayed in front of later chunks so
  the backend's CSV parser still sees the column names.
* ``.json`` documents cannot be split, so they ship whole once stable and are
  deduplicated by content hash.
* The offset only advances after the server acknowledges a batch, so a failed
  attempt simply resends the identical chunk later (exponential backoff).
* Ambiguous failures (timeouts, gateway errors) are reconciled against
  ``/upload/history`` before resending, because the backend creates a new
  batch per request and is not idempotent on its own.
* Content the server rejects (e.g. nothing parseable) is quarantined to
  ``<state_dir>/rejected/`` and skipped, so one bad chunk cannot block a file.
"""
from __future__ import annotations

import csv
import fnmatch
import hashlib
import json
import logging
import os
import random
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterator

from .api import ApiError, CyberShieldClient
from .config import SERVER_CONTENT_LIMIT, SUPPORTED_FORMATS, CollectorConfig, SourceConfig
from .state import FileRecord, StateStore

log = logging.getLogger("cybershield_collector")

FATAL_KINDS = {"auth", "forbidden", "config"}
AMBIGUOUS_MIN_DELAY = 30.0
_ROTATED = re.compile(r"^(?P<base>.+?\.(?:jsonl|json|log|txt|csv))[.\-_]\d[\w.\-]*$", re.IGNORECASE)
_DELIMITERS = ",\t;|"


class CollectorStopped(Exception):
    """An operator must act (log in again, fix permissions or api_url)."""


class RetryLater(Exception):
    def __init__(self, error: ApiError):
        super().__init__(str(error))
        self.error = error


def upload_filename(name: str, forced_format: str | None = None) -> str:
    """The filename sent to the backend, whose suffix selects the parser.

    ``auth.log.1`` and ``auth.log-20261025`` become ``auth.log``; names with no
    supported suffix get one (the source's ``format`` or ``log``).
    """

    if forced_format:
        return name if name.lower().endswith(f".{forced_format}") else f"{name}.{forced_format}"
    suffix = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if suffix in SUPPORTED_FORMATS:
        return name
    rotated = _ROTATED.match(name)
    if rotated:
        return rotated.group("base")
    return f"{name}.log"


def _format_of(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower()


def detect_header(fmt: str, text: str) -> str | None:
    """Header row to replay for delimited formats, mirroring the backend parser."""

    lines = [line for line in text.splitlines() if line.strip()]
    if not lines:
        return None
    if fmt == "csv":
        return lines[0]
    if fmt == "txt":
        sample = "\n".join(lines[:20])
        try:
            csv.Sniffer().sniff(sample, delimiters=_DELIMITERS)
            if csv.Sniffer().has_header(sample):
                return lines[0]
        except csv.Error:
            return None
    return None


class Collector:
    def __init__(self, config: CollectorConfig, client: CyberShieldClient, *,
                 store: StateStore | None = None, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep, rng: random.Random | None = None):
        self.config = config
        self.client = client
        self.store = store or StateStore(config.state_dir)
        self.clock = clock
        self.sleep = sleep
        self.rng = rng or random.Random()
        self.failures = 0
        self.retry_at = 0.0
        self._started_sources: set[str] = set()
        self._missing_warned: set[str] = set()
        self.stats = {"batches": 0, "bytes": 0, "stored_entries": 0, "stored_alerts": 0,
                      "rejected": 0, "duplicates_skipped": 0, "reconciled": 0, "retries": 0}

    # ------------------------------------------------------------------ loop

    def run(self, *, max_cycles: int | None = None) -> None:
        cycles = 0
        log.info("Collector started: %d source(s), host=%s, api=%s",
                 len(self.config.sources), self.config.source_host, self.config.api_url)
        while max_cycles is None or cycles < max_cycles:
            self.scan_once()
            cycles += 1
            if max_cycles is None or cycles < max_cycles:
                self.sleep(self.config.poll_interval_seconds)

    def scan_once(self) -> dict:
        """One poll cycle. Raises CollectorStopped when operator action is needed."""

        now = self.clock()
        if now < self.retry_at:
            return self.stats
        try:
            for source in self.config.sources:
                for path in self.discover(source):
                    self._process(source, path)
                self._started_sources.add(source.name)
            self.failures = 0
        except RetryLater as exc:
            self._schedule_retry(exc.error)
        finally:
            self.store.forget_missing()
            self.store.save()
        return self.stats

    def _schedule_retry(self, error: ApiError) -> None:
        self.failures += 1
        self.stats["retries"] += 1
        delay = min(self.config.max_backoff_seconds, 2.0 ** self.failures)
        delay *= 0.5 + self.rng.random() / 2
        if error.kind == "ambiguous":
            delay = max(delay, AMBIGUOUS_MIN_DELAY)
        self.retry_at = self.clock() + delay
        log.warning("Ingestion failed (%s); retrying in %.0fs (attempt %d).", error, delay, self.failures)

    # ------------------------------------------------------------------ discovery

    def discover(self, source: SourceConfig) -> Iterator[str]:
        root = source.path
        if not root.is_dir():
            if source.name not in self._missing_warned:
                log.warning("Watched path for %s does not exist or is not a directory: %s", source.name, root)
                self._missing_warned.add(source.name)
            return
        self._missing_warned.discard(source.name)
        found: list[str] = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = sorted(d for d in dirnames
                                 if source.recursive and not self._excluded(source, d))
            for name in filenames:
                full = os.path.join(dirpath, name)
                if self._excluded(source, name) or os.path.islink(full):
                    continue
                if any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in source.include):
                    found.append(full)
        # Oldest first, so rotated files (auth.log.1) ship before their successors.
        found.sort(key=lambda p: (self._mtime(p), p))
        yield from found

    @staticmethod
    def _excluded(source: SourceConfig, name: str) -> bool:
        return any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in source.exclude)

    @staticmethod
    def _mtime(path: str) -> float:
        try:
            return os.stat(path).st_mtime
        except OSError:
            return 0.0

    # ------------------------------------------------------------------ per file

    def _process(self, source: SourceConfig, path: str) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return  # removed between listing and stat
        record, how = self.store.match(source.name, path, st)
        record.last_seen = self.clock()
        filename = upload_filename(os.path.basename(path), source.format)
        fmt = _format_of(filename)
        if how in ("renamed", "copy"):
            self.stats["duplicates_skipped"] += 1
            log.info("%s: recognized as %s of an already-collected stream; resuming at byte %d.",
                     path, "a rename" if how == "renamed" else "a copy", record.offset)
        elif how == "truncated":
            log.info("%s: truncated or rewritten; collecting from the beginning.", path)
        elif how == "new" and source.start_at == "end" and source.name not in self._started_sources:
            self._skip_existing(record, fmt, st.st_size)
            log.info("%s: start_at=end, skipping %d existing bytes.", path, st.st_size)
            return

        if fmt == "json":
            self._process_whole(source, record, filename, st)
        else:
            while self._ship_next_chunk(source, record, filename, fmt):
                pass

    def _skip_existing(self, record: FileRecord, fmt: str, size: int) -> None:
        if fmt in ("csv", "txt"):
            with open(record.path, "rb") as handle:
                record.header = detect_header(fmt, handle.read(64 * 1024).decode("utf-8", "replace").lstrip("﻿"))
            record.header_checked = True
        self.store.skip_to(record, size)

    def _stable(self, st: os.stat_result) -> bool:
        return self.clock() - st.st_mtime >= self.config.settle_seconds

    def _read_chunk(self, record: FileRecord, st: os.stat_result) -> tuple[bytes, bool] | None:
        """Bytes to ship next and whether they exceed the server limit."""

        if st.st_size <= record.offset:
            return None
        with open(record.path, "rb") as handle:
            handle.seek(record.offset)
            data = handle.read(self.config.max_chunk_bytes)
            cut = data.rfind(b"\n") + 1
            if cut == 0 and len(data) == self.config.max_chunk_bytes:
                # One very long line: keep reading to its end, within the server limit.
                while b"\n" not in data and len(data) < SERVER_CONTENT_LIMIT:
                    more = handle.read(self.config.max_chunk_bytes)
                    if not more:
                        break
                    data += more
                newline = data.find(b"\n")
                if newline >= 0:
                    cut = newline + 1
                elif len(data) >= SERVER_CONTENT_LIMIT:
                    return data[:SERVER_CONTENT_LIMIT], True
        if cut == 0:
            if not self._stable(st):
                return None  # writer is mid-line; wait for the newline
            cut = len(data)
        return data[:cut], False

    def _ship_next_chunk(self, source: SourceConfig, record: FileRecord, filename: str, fmt: str) -> bool:
        st = os.stat(record.path)
        chunk = self._read_chunk(record, st)
        if chunk is None:
            return False
        piece, oversize = chunk
        text = piece.decode("utf-8", "replace")
        at_start = record.offset == 0
        if at_start:
            text = text.lstrip("﻿")
        if oversize:
            self._quarantine(source, record, filename, text, "A single line exceeds the server's 10 MiB content limit.")
            self.store.advance(record, piece, upload_id=None)
            self.store.save()
            return True

        if at_start and not record.header_checked and fmt in ("csv", "txt"):
            record.header = detect_header(fmt, text)
            record.header_checked = True
        lines = [line for line in text.splitlines() if line.strip()]
        if at_start and record.header and lines and lines[0] == record.header:
            data_lines = lines[1:]
            content = text
        elif record.header:
            data_lines = lines
            content = f"{record.header}\n{text}"
        else:
            data_lines = lines
            content = text
        if not data_lines:
            self.store.advance(record, piece, upload_id=None)  # blank lines or header only
            self.store.save()
            return True

        self._deliver(source, record, filename, content, piece)
        return True

    def _process_whole(self, source: SourceConfig, record: FileRecord, filename: str, st: os.stat_result) -> None:
        if record.offset == st.st_size and st.st_size > 0:
            return
        if st.st_size == 0 or not self._stable(st):
            return
        with open(record.path, "rb") as handle:
            data = handle.read(SERVER_CONTENT_LIMIT * 4 + 1)
        digest = hashlib.sha256(data).hexdigest()
        if digest in self.store.whole_hashes:
            self.stats["duplicates_skipped"] += 1
            log.info("%s: identical content was already collected; skipping.", record.path)
            self.store.skip_to(record, len(data))
            return
        text = data.decode("utf-8", "replace").lstrip("﻿")
        if len(text) > SERVER_CONTENT_LIMIT:
            self._quarantine(source, record, filename, None,
                             "JSON document exceeds the server's 10 MiB content limit; split it or use .jsonl.")
        elif text.strip():
            self._deliver(source, record, filename, text, None)
        self.store.whole_hashes.append(digest)
        self.store.skip_to(record, len(data))
        self.store.save()

    # ------------------------------------------------------------------ delivery

    def _deliver(self, source: SourceConfig, record: FileRecord, filename: str,
                 content: str, piece: bytes | None) -> None:
        """Send one batch. Advances the record only once the server has it."""

        size_bytes = len(content.encode("utf-8"))
        identity = dict(source_name=source.name, source_host=self.config.source_host, filename=filename)
        result, reconciled = None, False
        if (record.pending_offset, record.pending_size) == (record.offset, size_bytes):
            # The previous attempt for this exact chunk ended ambiguously.
            result = self._reconcile(identity, size_bytes, record)
            reconciled = result is not None
        if result is None:
            started = datetime.now(timezone.utc)
            try:
                result = self.client.ingest(source_type=source.source_type, content=content, **identity)
            except ApiError as error:
                if error.kind == "ambiguous":
                    record.pending_offset, record.pending_size = record.offset, size_bytes
                    record.pending_since = started.isoformat()
                    self.store.save()
                    found = self._reconcile(identity, size_bytes, record, not_before=started)
                    if found is None:
                        raise RetryLater(error) from error
                    result, reconciled = found, True
                elif error.kind == "unavailable":
                    raise RetryLater(error) from error
                elif error.kind == "rejected":
                    self._quarantine(source, record, filename, content, f"{error} {error.detail}")
                    self._advance(record, piece, None, content)
                    return
                else:
                    raise CollectorStopped(f"{error} {error.detail or ''}".strip()) from error

        record.pending_offset = record.pending_size = record.pending_since = None
        upload = result.get("upload") or {}
        upload_id = upload.get("upload_id")
        self._advance(record, piece, upload_id, content)
        parsing = result.get("parsing") or {}
        entries = parsing.get("stored_entries", upload.get("stored_entries", 0)) or 0
        alerts = parsing.get("stored_alerts", upload.get("stored_alerts", 0)) or 0
        self.stats["batches"] += 1
        self.stats["bytes"] += size_bytes
        self.stats["stored_entries"] += entries
        self.stats["stored_alerts"] += alerts
        if reconciled:
            self.stats["reconciled"] += 1
        self._ledger({"source": source.name, "path": record.path, "filename": filename,
                      "to_offset": record.offset, "bytes": size_bytes, "upload_id": upload_id,
                      "stored_entries": entries, "stored_alerts": alerts, "reconciled": reconciled})
        log.info("%s: shipped %d bytes -> batch %s (%d events, %d alerts)%s",
                 record.path, size_bytes, upload_id, entries, alerts, " [reconciled]" if reconciled else "")

    def _advance(self, record: FileRecord, piece: bytes | None, upload_id: str | None, content: str) -> None:
        if piece is not None:
            self.store.advance(record, piece, upload_id=upload_id)
        elif upload_id:
            record.last_upload_id = upload_id
            record.shipped_chunks += 1
            self.store.remember_upload(upload_id)
        self.store.save()

    def _reconcile(self, identity: dict, size_bytes: int, record: FileRecord,
                   not_before: datetime | None = None) -> dict | None:
        if not_before is None:
            not_before = (datetime.fromisoformat(record.pending_since) if record.pending_since
                          else datetime.now(timezone.utc))
        try:
            upload = self.client.find_unacknowledged_batch(
                size_bytes=size_bytes, not_before=not_before,
                known_upload_ids=self.store.known_uploads, **identity)
        except ApiError as error:
            if error.kind in FATAL_KINDS:
                raise CollectorStopped(str(error)) from error
            return None
        if upload is None:
            return None
        log.info("%s: server already stored batch %s from the interrupted attempt; not resending.",
                 record.path, upload.get("upload_id"))
        return {"upload": upload, "parsing": {"stored_entries": upload.get("stored_entries", 0),
                                              "stored_alerts": upload.get("stored_alerts", 0)}}

    def _quarantine(self, source: SourceConfig, record: FileRecord, filename: str,
                    content: str | None, reason: str) -> None:
        self.stats["rejected"] += 1
        folder = self.config.state_dir / "rejected"
        folder.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        safe = re.sub(r"[^\w.\-]", "_", f"{source.name}_{filename}")
        base = folder / f"{stamp}_{safe}_{record.offset}"
        if content is not None:
            base.with_suffix(".chunk").write_text(content, encoding="utf-8")
        base.with_suffix(".json").write_text(json.dumps({
            "source": source.name, "path": record.path, "filename": filename,
            "offset": record.offset, "reason": reason,
        }, indent=1), encoding="utf-8")
        log.warning("%s: chunk at byte %d rejected and quarantined (%s): %s",
                    record.path, record.offset, base.name, reason)

    def _ledger(self, entry: dict) -> None:
        entry = {"at": datetime.now(timezone.utc).isoformat(), **entry}
        self.config.state_dir.mkdir(parents=True, exist_ok=True)
        with open(self.config.state_dir / "shipments.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry) + "\n")
