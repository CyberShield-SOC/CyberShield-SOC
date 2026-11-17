"""In-process request rate limiting.

The app is deployed as a single uvicorn process with no shared cache, so the
counters live in memory: they are per process and reset on restart. That is
enough to blunt credential guessing and accidental floods; a multi-replica
deployment would need the same interface backed by a shared store.

Limits are read from settings on every call so they can be tuned (and tests
can adjust them) without rebuilding the dependency objects.
"""

from __future__ import annotations

import ipaddress
import math
import threading
import time
from collections import deque
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app.core.config import settings
from app.models.user import User
from app.security import current_user


# Sweep idle keys once the table grows past this, so one-off client addresses
# cannot accumulate forever.
_SWEEP_THRESHOLD = 10_000


class SlidingWindowLimiter:
    """Exact sliding-window counter keyed by an arbitrary string."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()
        self.enabled = True

    def _prune(self, hits: deque[float], cutoff: float) -> None:
        while hits and hits[0] <= cutoff:
            hits.popleft()

    def _sweep(self, now: float, window_seconds: float) -> None:
        cutoff = now - window_seconds
        for key in [k for k, hits in self._hits.items() if not hits or hits[-1] <= cutoff]:
            del self._hits[key]

    def retry_after(self, key: str, limit: int, window_seconds: float) -> int:
        """Seconds until ``key`` may act again; 0 when it is under the limit."""

        if not self.enabled:
            return 0
        now = self._clock()
        with self._lock:
            hits = self._hits.get(key)
            if not hits:
                return 0
            self._prune(hits, now - window_seconds)
            if len(hits) < limit:
                return 0
            return max(1, math.ceil(hits[0] + window_seconds - now))

    def record(self, key: str, window_seconds: float) -> None:
        if not self.enabled:
            return
        now = self._clock()
        with self._lock:
            if len(self._hits) >= _SWEEP_THRESHOLD:
                self._sweep(now, window_seconds)
            self._hits.setdefault(key, deque()).append(now)

    def hit(self, key: str, limit: int, window_seconds: float) -> int:
        """Count one action. Returns 0 if allowed, else seconds to wait."""

        wait = self.retry_after(key, limit, window_seconds)
        if wait == 0:
            self.record(key, window_seconds)
        return wait

    def clear(self, key: str) -> None:
        with self._lock:
            self._hits.pop(key, None)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


limiter = SlidingWindowLimiter()


def client_ip(request: Request) -> str:
    """The caller's address, for bucketing and for the audit trail.

    Directly exposed, this is the socket peer. Behind a reverse proxy the
    peer is the proxy, so ``RATE_LIMIT_CLIENT_IP_HEADER`` names the single
    header that proxy *overwrites* with the real client address (Railway's
    edge sets ``X-Real-IP``). Only set it when such a proxy is the sole way
    in: otherwise a caller can supply the header and pick their own bucket.
    """

    header = settings.rate_limit_client_ip_header
    if header:
        candidate = request.headers.get(header, "").strip()
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"


def too_many_requests(retry_after: int) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=f"Too many requests. Try again in {retry_after} seconds.",
        headers={"Retry-After": str(retry_after)},
    )


def _active() -> bool:
    return settings.rate_limit_enabled and limiter.enabled


def limit_by_ip(bucket: str, limit_setting: str, window_seconds: int = 60):
    """Dependency: at most ``settings.<limit_setting>`` calls per window per IP."""

    def dependency(request: Request) -> None:
        if not _active():
            return
        wait = limiter.hit(
            f"{bucket}:ip:{client_ip(request)}",
            getattr(settings, limit_setting),
            window_seconds,
        )
        if wait:
            raise too_many_requests(wait)

    return dependency


def limit_by_user(bucket: str, limit_setting: str, window_seconds: int = 60):
    """Dependency: at most ``settings.<limit_setting>`` calls per window per account."""

    def dependency(user: User = Depends(current_user)) -> None:
        if not _active():
            return
        wait = limiter.hit(
            f"{bucket}:user:{user.id}",
            getattr(settings, limit_setting),
            window_seconds,
        )
        if wait:
            raise too_many_requests(wait)

    return dependency


def _login_failure_key(identifier: str) -> str:
    return f"login-failure:{identifier.strip().lower()}"


def _login_failure_window() -> int:
    return settings.rate_limit_login_failure_window_minutes * 60


def check_login_failures(identifier: str) -> None:
    """Refuse further password attempts for an identifier that keeps failing."""

    if not _active():
        return
    wait = limiter.retry_after(
        _login_failure_key(identifier),
        settings.rate_limit_login_failures,
        _login_failure_window(),
    )
    if wait:
        raise too_many_requests(wait)


def record_login_failure(identifier: str) -> None:
    if _active():
        limiter.record(_login_failure_key(identifier), _login_failure_window())


def clear_login_failures(identifier: str) -> None:
    limiter.clear(_login_failure_key(identifier))
