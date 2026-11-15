"""Durable collector state: what has been shipped from which file.

A tracked stream is identified by its content, not just its name. Each record
stores how many bytes were shipped (``offset``) plus a SHA-256 of exactly those
bytes. When a file shows up under a new name or inode (log rotation, a copy
dropped into the watched folder) and its first ``offset`` bytes hash the same,
it is the same stream and collection resumes after them instead of resending.

State is written atomically (temp file + rename) after every successful
shipment, so a crash can at worst resend the one chunk that was in flight.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path

STATE_VERSION = 1
HEAD_BYTES = 1024
MAX_KNOWN_UPLOADS = 500
MAX_WHOLE_HASHES = 10_000
FORGET_MISSING_AFTER_SECONDS = 14 * 24 * 3600


@dataclass
class FileRecord:
    id: str
    source: str
    path: str
    dev: int
    ino: int
    offset: int = 0
    head_sha: str = ""          # sha256 of the first min(offset, HEAD_BYTES) bytes
    prefix_sha: str = hashlib.sha256(b"").hexdigest()  # sha256 of bytes [0, offset)
    header: str | None = None   # CSV/delimited header replayed before later chunks
    header_checked: bool = False
    last_seen: float = field(default_factory=time.time)
    last_upload_id: str | None = None
    shipped_chunks: int = 0
    # Set when an attempt ended ambiguously (timeout/gateway error): the next
    # attempt for the same chunk first checks whether the server stored it.
    pending_offset: int | None = None
    pending_size: int | None = None
    pending_since: str | None = None

    @classmethod
    def new(cls, source: str, path: str, st: os.stat_result) -> "FileRecord":
        return cls(id=uuid.uuid4().hex, source=source, path=path, dev=st.st_dev, ino=st.st_ino)


def sha256_file_range(path: str, length: int) -> tuple[str, "hashlib._Hash"]:
    """Hash the first ``length`` bytes of a file; returns (hexdigest, live hasher)."""

    hasher = hashlib.sha256()
    remaining = length
    with open(path, "rb") as handle:
        while remaining > 0:
            block = handle.read(min(1024 * 1024, remaining))
            if not block:
                break
            hasher.update(block)
            remaining -= len(block)
    return hasher.hexdigest(), hasher


class StateStore:
    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir)
        self.path = self.state_dir / "state.json"
        self.records: dict[str, FileRecord] = {}
        self.whole_hashes: deque[str] = deque(maxlen=MAX_WHOLE_HASHES)
        self.known_uploads: deque[str] = deque(maxlen=MAX_KNOWN_UPLOADS)
        # Running hashers for prefix_sha so shipping never rereads the whole file.
        self._hashers: dict[str, "hashlib._Hash"] = {}
        self.load()

    # ---- persistence

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Collector state file is corrupt: {self.path} ({exc}). "
                               "Move it aside to start over; that will resend existing files.") from exc
        if raw.get("version") != STATE_VERSION:
            raise RuntimeError(f"Unsupported collector state version in {self.path}.")
        known_fields = set(FileRecord.__dataclass_fields__)
        for item in raw.get("files", []):
            record = FileRecord(**{k: v for k, v in item.items() if k in known_fields})
            self.records[record.id] = record
        self.whole_hashes.extend(raw.get("whole_hashes", []))
        self.known_uploads.extend(raw.get("known_uploads", []))

    def save(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        data = {
            "version": STATE_VERSION,
            "files": [asdict(record) for record in self.records.values()],
            "whole_hashes": list(self.whole_hashes),
            "known_uploads": list(self.known_uploads),
        }
        tmp = self.path.with_name(f".state.{os.getpid()}.tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=1)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)

    # ---- identity

    def match(self, source: str, path: str, st: os.stat_result) -> tuple[FileRecord, str]:
        """Find or create the record for a file. Returns (record, how) where how is
        'known', 'renamed', 'copy', 'truncated' or 'new'."""

        same_inode = [r for r in self.records.values()
                      if r.source == source and r.dev == st.st_dev and r.ino == st.st_ino]
        for record in same_inode:
            if record.path == path:
                # copytruncate-style rotation: smaller than what we shipped, or
                # rewritten so the start no longer matches (cheap 1 KiB check).
                if st.st_size < record.offset or (record.offset and not self._head_matches(record, path)):
                    self.reset(record)
                    return record, "truncated"
                return record, "known"
        for record in same_inode:
            # Same inode under a new name: a rename (e.g. auth.log -> auth.log.1).
            if self._prefix_matches(record, path, st):
                record.path = path
                return record, "renamed"

        candidates = [r for r in self.records.values()
                      if r.source == source and 0 < r.offset <= st.st_size
                      and not (r.dev == st.st_dev and r.ino == st.st_ino)]
        # Prefer the longest shipped stream so a copy resumes as late as possible.
        for record in sorted(candidates, key=lambda r: r.offset, reverse=True):
            if not self._prefix_matches(record, path, st):
                continue
            try:
                original = os.stat(record.path)
                original_alive = (original.st_dev, original.st_ino) == (record.dev, record.ino)
            except OSError:
                original_alive = False
            if not original_alive:
                # Moved across filesystems or rewritten under a new inode.
                record.path, record.dev, record.ino = path, st.st_dev, st.st_ino
                return record, "renamed"
            # A copy of a stream we are still tailing: inherit what was shipped.
            clone = FileRecord(**{**asdict(record), "id": uuid.uuid4().hex, "path": path,
                                  "dev": st.st_dev, "ino": st.st_ino, "shipped_chunks": 0,
                                  "last_upload_id": None})
            self.records[clone.id] = clone
            return clone, "copy"

        # Same inode reused by an unrelated file (or same path rewritten): start fresh.
        for record in same_inode:
            self.records.pop(record.id, None)
            self._hashers.pop(record.id, None)
        # An older record for this path (file deleted and recreated) is kept until
        # forget_missing() so a renamed copy of it elsewhere is still recognized.
        record = FileRecord.new(source, path, st)
        self.records[record.id] = record
        return record, "new"

    def _head_matches(self, record: FileRecord, path: str) -> bool:
        try:
            with open(path, "rb") as handle:
                head = handle.read(min(record.offset, HEAD_BYTES))
        except OSError:
            return False
        return hashlib.sha256(head).hexdigest() == record.head_sha

    def _prefix_matches(self, record: FileRecord, path: str, st: os.stat_result) -> bool:
        if record.offset == 0 or st.st_size < record.offset:
            return False
        try:
            if not self._head_matches(record, path):
                return False
            if record.offset <= HEAD_BYTES:
                return True
            digest, _ = sha256_file_range(path, record.offset)
        except OSError:
            return False
        return digest == record.prefix_sha

    def reset(self, record: FileRecord) -> None:
        record.offset = 0
        record.head_sha = ""
        record.prefix_sha = hashlib.sha256(b"").hexdigest()
        record.header = None
        record.header_checked = False
        self._hashers.pop(record.id, None)

    # ---- progress

    def advance(self, record: FileRecord, shipped: bytes, *, upload_id: str | None) -> None:
        """Record that ``shipped`` (the bytes at [offset, offset+len)) reached the server."""

        hasher = self._hashers.get(record.id)
        if hasher is None:
            digest, hasher = (sha256_file_range(record.path, record.offset) if record.offset
                              else (hashlib.sha256(b"").hexdigest(), hashlib.sha256()))
            self._hashers[record.id] = hasher
        if record.offset < HEAD_BYTES:
            with open(record.path, "rb") as handle:
                head_prefix = handle.read(record.offset)
            head = (head_prefix + shipped)[:HEAD_BYTES]
            record.head_sha = hashlib.sha256(head).hexdigest()
        hasher.update(shipped)
        record.offset += len(shipped)
        record.prefix_sha = hasher.hexdigest()
        if upload_id:
            record.last_upload_id = upload_id
            record.shipped_chunks += 1
            self.remember_upload(upload_id)

    def skip_to(self, record: FileRecord, size: int) -> None:
        """Mark [0, size) as already handled without shipping it (start_at='end')."""

        digest, hasher = sha256_file_range(record.path, size)
        with open(record.path, "rb") as handle:
            record.head_sha = hashlib.sha256(handle.read(min(size, HEAD_BYTES))).hexdigest()
        record.offset, record.prefix_sha = size, digest
        self._hashers[record.id] = hasher

    def remember_upload(self, upload_id: str) -> None:
        if upload_id not in self.known_uploads:
            self.known_uploads.append(upload_id)

    def forget_missing(self, now: float | None = None) -> None:
        now = now or time.time()
        for record in list(self.records.values()):
            if not os.path.exists(record.path) and now - record.last_seen > FORGET_MISSING_AFTER_SECONDS:
                self.records.pop(record.id, None)
                self._hashers.pop(record.id, None)
