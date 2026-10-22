"""Size limits and in-memory rate limiting for the ingest endpoint."""

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Limits:
    max_body_bytes: int = 1 << 20
    max_line_bytes: int = 128 << 10
    max_lines: int = 5_000
    # Requests per second (sustained) and burst, per sensor.
    sensor_rate: float = 10.0
    sensor_burst: int = 20
    # Failed authentications per minute (sustained) and burst, per client address.
    auth_failure_rate: float = 10 / 60
    auth_failure_burst: int = 10
    max_reported_errors: int = 20


@dataclass
class _Bucket:
    tokens: float
    updated: float


@dataclass
class RateLimiter:
    """Token bucket per key. Keys are sensor ids or client addresses."""

    rate: float
    burst: int
    clock: Callable[[], float] = time.monotonic
    max_keys: int = 10_000
    _buckets: dict[str, _Bucket] = field(default_factory=dict)

    def _bucket(self, key: str) -> _Bucket:
        now = self.clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            if len(self._buckets) >= self.max_keys:
                # Bounded memory: forget buckets that have fully refilled.
                full = [k for k, b in self._buckets.items() if self._level(b, now) >= self.burst]
                for k in full:
                    del self._buckets[k]
                if len(self._buckets) >= self.max_keys:
                    del self._buckets[min(self._buckets, key=lambda k: self._buckets[k].updated)]
            bucket = self._buckets[key] = _Bucket(float(self.burst), now)
        bucket.tokens = self._level(bucket, now)
        bucket.updated = now
        return bucket

    def _level(self, bucket: _Bucket, now: float) -> float:
        return min(float(self.burst), bucket.tokens + (now - bucket.updated) * self.rate)

    def allowed(self, key: str) -> bool:
        """True if ``key`` still has budget, without spending it."""
        return self._bucket(key).tokens >= 1

    def hit(self, key: str) -> bool:
        """Spend one unit of budget; False if there was none left."""
        bucket = self._bucket(key)
        if bucket.tokens < 1:
            return False
        bucket.tokens -= 1
        return True

    def retry_after(self, key: str) -> int:
        missing = 1 - self._bucket(key).tokens
        return max(1, math.ceil(missing / self.rate)) if missing > 0 else 0
