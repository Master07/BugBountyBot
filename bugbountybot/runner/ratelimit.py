"""Per-host rate limiter — token bucket shared across all modules.

Every outbound request to a host consumes a token; if the bucket is empty the
caller blocks until the next token. 429/403 responses honor Retry-After and
apply exponential backoff with jitter. A light circuit breaker skips a host
after N consecutive errors so one bad host can't stall a scan.

The bucket is keyed by hostname, so multiple modules scanning the same host
share one rate limit (per VulnPolicy.max_rate).
"""
from __future__ import annotations

import random
import threading
import time
from urllib.parse import urlparse


class TokenBucket:
    """Token bucket with refill. Thread-safe."""

    def __init__(self, rate: float, capacity: int | None = None):
        self.rate = max(0.1, float(rate))  # tokens per second
        self.capacity = capacity or max(1, int(rate * 2))
        self._tokens = float(self.capacity)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self, timeout: float = 30.0) -> bool:
        """Block until a token is available, or return False on timeout."""
        deadline = time.monotonic() + timeout
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
                self._last = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True
                wait = (1.0 - self._tokens) / self.rate
            if time.monotonic() + wait > deadline:
                return False
            time.sleep(min(wait, 0.1))


class RateLimiter:
    """Per-host token buckets + backoff + circuit breaker."""

    def __init__(self, rate: float = 5.0):
        self.rate = rate
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = threading.Lock()
        self._backoff_until: dict[str, float] = {}  # host -> timestamp
        self._error_streak: dict[str, int] = {}
        self._circuit_open: dict[str, float] = {}  # host -> until
        self._hits: dict[str, int] = {}
        self._limited: dict[str, int] = {}
        self._skipped: dict[str, int] = {}

    def _bucket(self, host: str) -> TokenBucket:
        with self._lock:
            if host not in self._buckets:
                self._buckets[host] = TokenBucket(self.rate)
            return self._buckets[host]

    def before_request(self, url: str, timeout: float = 30.0) -> tuple[bool, str]:
        """Called before sending a request. Returns (allowed, reason)."""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return True, ""
        now = time.monotonic()

        # circuit breaker: host on timeout after N consecutive errors
        if host in self._circuit_open and self._circuit_open[host] > now:
            self._skipped[host] = self._skipped.get(host, 0) + 1
            return False, "circuit-breaker (host erroring)"

        # backoff window from 429/403
        if host in self._backoff_until and self._backoff_until[host] > now:
            self._limited[host] = self._limited.get(host, 0) + 1
            return False, "rate-limited (backoff)"

        self._hits[host] = self._hits.get(host, 0) + 1
        if not self._bucket(host).acquire(timeout):
            self._limited[host] = self._limited.get(host, 0) + 1
            return False, "rate-limit exceeded (bucket empty)"
        return True, ""

    def after_response(self, url: str, status_code: int, retry_after: str = ""):
        """Called after a response. Updates backoff/circuit state."""
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return
        now = time.monotonic()
        if status_code in (429, 403):
            # honor Retry-After, else exponential backoff
            delay = _parse_retry_after(retry_after)
            if delay is None:
                streak = self._error_streak.get(host, 0) + 1
                self._error_streak[host] = streak
                delay = min(60.0, 2.0 * (2 ** min(streak, 5))) * (0.5 + random.random())
            self._backoff_until[host] = now + delay
        elif status_code >= 500:
            streak = self._error_streak.get(host, 0) + 1
            self._error_streak[host] = streak
            if streak >= 5:
                self._circuit_open[host] = now + 60.0
                self._error_streak[host] = 0
        else:
            self._error_streak[host] = 0

    def stats(self) -> dict:
        return {
            "hosts": len(self._buckets),
            "requests": dict(self._hits),
            "rate_limited": dict(self._limited),
            "circuit_skipped": dict(self._skipped),
        }


def _parse_retry_after(value: str) -> float | None:
    """Retry-After can be seconds (int) or an HTTP-date."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def retry_with_jitter(fn, *, attempts: int = 2, base_delay: float = 0.5, retry_statuses=(429, 500, 502, 503, 504)):
    """Retry a callable on transient status codes / network errors with jitter."""
    last_exc = None
    for i in range(attempts):
        try:
            resp = fn()
            if resp.status_code in retry_statuses and i < attempts - 1:
                time.sleep(base_delay * (2 ** i) * (0.5 + random.random()))
                continue
            return resp
        except Exception as e:  # network errors
            last_exc = e
            if i < attempts - 1:
                time.sleep(base_delay * (2 ** i) * (0.5 + random.random()))
    if last_exc is not None:
        raise last_exc
    return None
