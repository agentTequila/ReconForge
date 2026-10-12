"""Token-bucket rate limiting and retry-with-backoff helpers."""

from __future__ import annotations

import random
import time


class TokenBucket:
    """Simple thread-safe-ish token bucket (best effort under GIL)."""

    def __init__(self, rate: float = 5.0, burst: int = 10) -> None:
        self.rate = rate
        self.capacity = float(burst)
        self.tokens = self.capacity
        self.updated = time.monotonic()

    def acquire(self, tokens: float = 1.0) -> None:
        while True:
            now = time.monotonic()
            self.tokens = min(
                self.capacity, self.tokens + (now - self.updated) * self.rate
            )
            self.updated = now
            if self.tokens >= tokens:
                self.tokens -= tokens
                return
            wait = (tokens - self.tokens) / self.rate
            time.sleep(min(wait, 1.0))


def retry_call(func, attempts: int = 3, base_delay: float = 1.0, exceptions=(Exception,)):
    """Call func with exponential backoff + jitter."""
    last_exc: Exception | None = None
    for attempt in range(attempts):
        try:
            return func()
        except exceptions as exc:  # noqa: PERF203
            last_exc = exc
            if attempt == attempts - 1:
                break
            time.sleep(base_delay * (2**attempt) + random.uniform(0, 0.5))
    raise last_exc
