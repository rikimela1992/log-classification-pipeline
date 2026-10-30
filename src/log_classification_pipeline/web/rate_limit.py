"""Bounded, privacy-minimal login throttling for the local web adapter."""

from __future__ import annotations

import hashlib
import math
import secrets
import threading
import time
from collections import deque
from collections.abc import Callable


class LoginRateLimiter:
    """Track recent authentication failures without retaining submitted names."""

    def __init__(
        self,
        *,
        account_limit: int,
        source_limit: int,
        window_seconds: int,
        max_account_buckets: int = 4_096,
        max_source_buckets: int = 256,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        for name, value in (
            ("account_limit", account_limit),
            ("source_limit", source_limit),
            ("window_seconds", window_seconds),
            ("max_account_buckets", max_account_buckets),
            ("max_source_buckets", max_source_buckets),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if source_limit < account_limit:
            raise ValueError("source_limit must be greater than or equal to account_limit")

        self._account_limit = account_limit
        self._source_limit = source_limit
        self._window_seconds = window_seconds
        self._max_account_buckets = max_account_buckets
        self._max_source_buckets = max_source_buckets
        self._clock = clock
        self._secret = secrets.token_bytes(32)
        self._accounts: dict[bytes, deque[float]] = {}
        self._sources: dict[bytes, deque[float]] = {}
        self._overflow_until = 0.0
        self._lock = threading.Lock()

    def retry_after(
        self,
        source: str,
        organization: str,
        username: str,
    ) -> int | None:
        """Return a positive delay when authentication must not be attempted."""

        now = self._clock()
        account_key, source_key = self._keys(source, organization, username)
        with self._lock:
            self._prune(now)
            return self._current_delay(account_key, source_key, now)

    def reserve(
        self,
        source: str,
        organization: str,
        username: str,
    ) -> int | None:
        """Atomically check the limits and count one attempt before it runs.

        Returns a delay when the attempt must not run. Otherwise the attempt
        already counts as a failure until `release` takes it back, so concurrent
        attempts cannot all pass the same check.
        """

        now = self._clock()
        account_key, source_key = self._keys(source, organization, username)
        with self._lock:
            self._prune(now)
            delay = self._current_delay(account_key, source_key, now)
            if delay is not None:
                return delay
            self._count(account_key, source_key, now)
            return None

    def release(
        self,
        source: str,
        organization: str,
        username: str,
    ) -> None:
        """Take back one reserved attempt that did not end as a failure."""

        account_key, source_key = self._keys(source, organization, username)
        with self._lock:
            for buckets, key in (
                (self._accounts, account_key),
                (self._sources, source_key),
            ):
                failures = buckets.get(key)
                if failures:
                    failures.pop()
                    if not failures:
                        del buckets[key]

    def record_failure(
        self,
        source: str,
        organization: str,
        username: str,
    ) -> int | None:
        """Record one failure and return the resulting retry delay, if limited."""

        now = self._clock()
        account_key, source_key = self._keys(source, organization, username)
        with self._lock:
            self._prune(now)
            self._count(account_key, source_key, now)
            return self._current_delay(account_key, source_key, now)

    def record_success(
        self,
        source: str,
        organization: str,
        username: str,
    ) -> None:
        """Clear only the successful account bucket; retain source pressure."""

        account_key, _source_key = self._keys(source, organization, username)
        with self._lock:
            self._accounts.pop(account_key, None)

    def _count(self, account_key: bytes, source_key: bytes, now: float) -> None:
        if (
            account_key not in self._accounts
            and len(self._accounts) >= self._max_account_buckets
        ):
            self._overflow_until = max(
                self._overflow_until,
                now + self._window_seconds,
            )
        else:
            self._accounts.setdefault(account_key, deque()).append(now)
        if (
            source_key not in self._sources
            and len(self._sources) >= self._max_source_buckets
        ):
            self._overflow_until = max(
                self._overflow_until,
                now + self._window_seconds,
            )
        else:
            self._sources.setdefault(source_key, deque()).append(now)

    def _current_delay(
        self,
        account_key: bytes,
        source_key: bytes,
        now: float,
    ) -> int | None:
        delays = [
            self._bucket_retry_after(
                self._accounts.get(account_key),
                self._account_limit,
                now,
            ),
            self._bucket_retry_after(
                self._sources.get(source_key),
                self._source_limit,
                now,
            ),
        ]
        if self._overflow_until > now:
            delays.append(math.ceil(self._overflow_until - now))
        active = [delay for delay in delays if delay is not None]
        return max(active) if active else None

    def _keys(
        self,
        source: str,
        organization: str,
        username: str,
    ) -> tuple[bytes, bytes]:
        normalized_source = source.strip().casefold() or "unknown"
        normalized_identity = (
            f"{organization.strip().casefold()}\0{username.strip().casefold()}"
        )
        return (
            self._digest(b"account\0" + normalized_identity.encode("utf-8")),
            self._digest(b"source\0" + normalized_source.encode("utf-8")),
        )

    def _digest(self, value: bytes) -> bytes:
        return hashlib.blake2b(
            value,
            key=self._secret,
            digest_size=16,
        ).digest()

    def _prune(self, now: float) -> None:
        cutoff = now - self._window_seconds
        for buckets in (self._accounts, self._sources):
            empty: list[bytes] = []
            for key, failures in buckets.items():
                while failures and failures[0] <= cutoff:
                    failures.popleft()
                if not failures:
                    empty.append(key)
            for key in empty:
                del buckets[key]
        if self._overflow_until <= now:
            self._overflow_until = 0.0

    def _bucket_retry_after(
        self,
        failures: deque[float] | None,
        limit: int,
        now: float,
    ) -> int | None:
        if failures is None or len(failures) < limit:
            return None
        return max(1, math.ceil(failures[0] + self._window_seconds - now))


__all__ = ["LoginRateLimiter"]
