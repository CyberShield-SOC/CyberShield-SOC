"""HTTP access to the CyberShield backend: authentication and ingestion.

Authentication reuses the existing login -> email two-factor -> refresh flow.
The collector never stores a password. ``login`` saves only the rotating
refresh token (in a 0600 session file); ``run`` exchanges it for 10-minute
access tokens and persists every rotated refresh token immediately.
"""
from __future__ import annotations

import json
import logging
import os
import secrets
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable

from .config import CollectorConfig

log = logging.getLogger("cybershield_collector")


# --------------------------------------------------------------------------- transport


@dataclass
class HttpResponse:
    status: int
    headers: list[tuple[str, str]]
    body: bytes

    def header_values(self, name: str) -> list[str]:
        name = name.lower()
        return [value for key, value in self.headers if key.lower() == name]

    def json(self) -> dict:
        try:
            value = json.loads(self.body.decode("utf-8") or "null")
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return value if isinstance(value, dict) else {"value": value}


class TransportError(Exception):
    """Network failure. ``maybe_delivered`` is True when the request may have reached the server."""

    def __init__(self, message: str, *, maybe_delivered: bool):
        super().__init__(message)
        self.maybe_delivered = maybe_delivered


Transport = Callable[[str, str, dict, "bytes | None", float], HttpResponse]


def urllib_transport(method: str, url: str, headers: dict, body: bytes | None, timeout: float) -> HttpResponse:
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return HttpResponse(response.status, list(response.headers.items()), response.read())
    except urllib.error.HTTPError as exc:
        return HttpResponse(exc.code, list(exc.headers.items()) if exc.headers else [], exc.read() or b"")
    except urllib.error.URLError as exc:
        reason = exc.reason
        # Refused connections and DNS failures never reached the application.
        not_delivered = isinstance(reason, (ConnectionRefusedError, socket.gaierror))
        raise TransportError(f"{url}: {reason}", maybe_delivered=not not_delivered) from exc
    except (TimeoutError, socket.timeout, ConnectionError, OSError) as exc:
        raise TransportError(f"{url}: {exc}", maybe_delivered=True) from exc


# --------------------------------------------------------------------------- errors


class ApiError(Exception):
    """A classified failure. ``kind`` drives the collector's retry decision.

    unavailable  - nothing was stored; safe to resend the same chunk later
    ambiguous    - the server may have stored the batch; reconcile before resending
    rejected     - the server refused this content; resending will not help
    auth         - no usable session; an operator must run ``login`` again
    forbidden    - the account may not ingest (Viewer or unknown role)
    config       - wrong api_url or incompatible server
    """

    def __init__(self, kind: str, message: str, *, status: int | None = None, detail=None):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.detail = detail


RETRYABLE_STATUS = {408, 425, 429, 500, 503}
AMBIGUOUS_STATUS = {502, 504}
REJECTED_STATUS = {400, 413, 415, 422}


def _error_detail(response: HttpResponse):
    detail = response.json().get("detail")
    return detail if detail is not None else response.body[:300].decode("utf-8", "replace")


def classify(response: HttpResponse) -> ApiError:
    detail = _error_detail(response)
    status = response.status
    if status == 401:
        return ApiError("auth", "Authentication required or session expired.", status=status, detail=detail)
    if status == 403:
        return ApiError("forbidden", "This account is not allowed to ingest logs (Admin or Analyst required).", status=status, detail=detail)
    if status in REJECTED_STATUS:
        return ApiError("rejected", f"Server rejected the content (HTTP {status}).", status=status, detail=detail)
    if status in AMBIGUOUS_STATUS:
        return ApiError("ambiguous", f"Gateway error HTTP {status}; the batch may have been stored.", status=status, detail=detail)
    if status in RETRYABLE_STATUS or status >= 500:
        return ApiError("unavailable", f"Server unavailable (HTTP {status}).", status=status, detail=detail)
    return ApiError("config", f"Unexpected HTTP {status}; check api_url.", status=status, detail=detail)


# --------------------------------------------------------------------------- cookies / session file


def cookies_from(response: HttpResponse) -> dict[str, str]:
    """Extract name=value pairs from Set-Cookie headers (attributes ignored)."""

    cookies: dict[str, str] = {}
    for header in response.header_values("set-cookie"):
        pair = header.split(";", 1)[0]
        if "=" not in pair:
            continue
        name, value = pair.split("=", 1)
        value = value.strip().strip('"')
        if value:
            cookies[name.strip()] = value
    return cookies


def write_private_json(path: Path, data: dict) -> None:
    """Atomically write a JSON file readable only by the current user."""

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


# --------------------------------------------------------------------------- client


class CyberShieldClient:
    def __init__(self, config: CollectorConfig, transport: Transport = urllib_transport,
                 clock: Callable[[], float] = time.time):
        self.config = config
        self.transport = transport
        self.clock = clock
        self._access_token: str | None = os.environ.get("CYBERSHIELD_ACCESS_TOKEN") or None
        self._static_token = self._access_token is not None
        self._access_expires_at = float("inf") if self._static_token else 0.0

    # ---- low level

    def _url(self, path: str, query: dict | None = None) -> str:
        url = f"{self.config.api_url}{path}"
        return f"{url}?{urllib.parse.urlencode(query)}" if query else url

    def _send(self, method: str, path: str, *, payload=None, headers: dict | None = None,
              query: dict | None = None) -> HttpResponse:
        all_headers = {"Accept": "application/json", "User-Agent": "cybershield-collector/0.1"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            all_headers["Content-Type"] = "application/json"
        all_headers.update(headers or {})
        return self.transport(method, self._url(path, query), all_headers, body,
                              self.config.request_timeout_seconds)

    # ---- authentication

    def login(self, username: str, password: str, read_code: Callable[[str], str]) -> dict:
        """Interactive login with email two-factor. Saves only the refresh token."""

        try:
            started = self._send("POST", "/auth/login",
                                 payload={"username": username, "password": password, "remember_me": True})
        except TransportError as exc:
            raise ApiError("unavailable", f"Could not reach the backend: {exc}") from exc
        if started.status != 200:
            raise ApiError("auth", f"Login failed (HTTP {started.status}): {_error_detail(started)}", status=started.status)
        pending = cookies_from(started).get(self.config.otp_pending_cookie_name)
        if not pending:
            raise ApiError("config", "Server did not start a two-factor challenge; check api_url and cookie names.")
        code = read_code(started.json().get("email") or "your email")
        try:
            verified = self._send("POST", "/auth/2fa/verify", payload={"code": code},
                                  headers={"Cookie": f"{self.config.otp_pending_cookie_name}={pending}"})
        except TransportError as exc:
            raise ApiError("unavailable", f"Could not reach the backend: {exc}") from exc
        if verified.status != 200:
            raise ApiError("auth", f"Verification failed (HTTP {verified.status}): {_error_detail(verified)}", status=verified.status)
        refresh_token = cookies_from(verified).get(self.config.auth_cookie_name)
        if not refresh_token:
            raise ApiError("config", "Server did not issue a refresh session cookie.")
        body = verified.json()
        user = body.get("user") or {}
        self._save_session(refresh_token, username=user.get("username") or username)
        self._remember_access(body)
        return user

    def _save_session(self, refresh_token: str, *, username: str | None = None) -> None:
        previous = self._load_session() or {}
        write_private_json(self.config.session_file, {
            "api_url": self.config.api_url,
            "username": username or previous.get("username"),
            "refresh_token": refresh_token,
            "saved_at": datetime.now(timezone.utc).isoformat(),
        })

    def _load_session(self) -> dict | None:
        try:
            data = json.loads(self.config.session_file.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) and data.get("refresh_token") else None

    def _remember_access(self, body: dict) -> None:
        token = body.get("access_token")
        if not token:
            raise ApiError("config", "Server response did not include an access token.")
        self._access_token = token
        # Renew a minute early so a token never expires mid-request.
        self._access_expires_at = self.clock() + max(30, int(body.get("expires_in") or 600) - 60)

    def refresh(self) -> None:
        if self._static_token:
            raise ApiError("auth", "CYBERSHIELD_ACCESS_TOKEN was rejected or expired; it cannot be refreshed.")
        session = self._load_session()
        if session is None:
            raise ApiError("auth", "No collector session. Run: python -m cybershield_collector login --config <file>")
        if session.get("api_url") not in (None, self.config.api_url):
            raise ApiError("auth", "The saved session belongs to a different api_url. Run login again.")
        csrf = secrets.token_urlsafe(24)  # double-submit pair the middleware compares
        cookie = (f"{self.config.auth_cookie_name}={session['refresh_token']}; "
                  f"{self.config.auth_csrf_cookie_name}={csrf}")
        try:
            response = self._send("POST", "/auth/refresh", headers={"Cookie": cookie, "X-CSRF-Token": csrf})
        except TransportError as exc:
            raise ApiError("unavailable", f"Could not reach the backend: {exc}") from exc
        if response.status == 401:
            raise ApiError("auth", "Collector session expired or was revoked. Run login again.", status=401)
        if response.status != 200:
            raise classify(response)
        rotated = cookies_from(response).get(self.config.auth_cookie_name)
        if rotated:
            # The previous refresh token is revoked server-side; persist the new one first.
            self._save_session(rotated)
        self._remember_access(response.json())

    def _bearer(self) -> dict:
        if not self._access_token or self.clock() >= self._access_expires_at:
            self.refresh()
        return {"Authorization": f"Bearer {self._access_token}"}

    def _authorized(self, method: str, path: str, **kwargs) -> HttpResponse:
        response = self._send(method, path, headers=self._bearer(), **kwargs)
        if response.status == 401 and not self._static_token:
            # Role demotion or early expiry: renew once, then give up.
            self._access_token = None
            response = self._send(method, path, headers=self._bearer(), **kwargs)
        return response

    # ---- ingestion

    def ingest(self, *, source_name: str, source_type: str, source_host: str,
               filename: str, content: str) -> dict:
        payload = {"source_name": source_name, "source_type": source_type,
                   "source_host": source_host, "filename": filename, "content": content}
        try:
            response = self._authorized("POST", "/ingest", payload=payload)
        except TransportError as exc:
            kind = "ambiguous" if exc.maybe_delivered else "unavailable"
            raise ApiError(kind, str(exc)) from exc
        if response.status != 200:
            raise classify(response)
        return response.json()

    def find_unacknowledged_batch(self, *, source_name: str, source_host: str, filename: str,
                                  size_bytes: int, not_before: datetime,
                                  known_upload_ids: Iterable[str]) -> dict | None:
        """After an ambiguous failure, look for a batch the server stored but we never heard about.

        A match needs the same source name, host, filename and byte size, an
        upload time after the attempt started (minus clock-skew slack), and an
        upload ID this collector has not already recorded as its own.
        """

        known = set(known_upload_ids)
        try:
            response = self._authorized("GET", "/upload/history",
                                        query={"query": filename[:100], "page_size": 100, "page": 1})
        except TransportError as exc:
            raise ApiError("unavailable", str(exc)) from exc
        if response.status != 200:
            raise classify(response)
        for upload in response.json().get("uploads") or []:
            if (upload.get("upload_id") in known
                    or upload.get("source_name") != source_name
                    or upload.get("source_host") != source_host
                    or upload.get("filename") != filename
                    or upload.get("size_bytes") != size_bytes):
                continue
            try:
                uploaded_at = datetime.fromisoformat(str(upload.get("uploaded_at")))
            except ValueError:
                continue
            if uploaded_at.tzinfo is None:
                uploaded_at = uploaded_at.replace(tzinfo=timezone.utc)
            if uploaded_at >= not_before - timedelta(minutes=5):
                return upload
        return None
