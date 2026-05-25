"""Bounded runtime state for long-running daemon stability."""

from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from datetime import datetime
import time


class TTLSet:
    """Small TTL set used for duplicate suppression cooldowns."""

    def __init__(self, max_size: int = 4096) -> None:
        self._items: OrderedDict[str, float] = OrderedDict()
        self._max_size = max_size

    def seen_recently(self, key: str, ttl_seconds: int) -> bool:
        """Return true when key exists inside TTL, otherwise record it."""

        now = time.monotonic()
        self.prune(now, ttl_seconds)
        if key in self._items:
            self._items.move_to_end(key)
            return True
        self._items[key] = now
        if len(self._items) > self._max_size:
            self._items.popitem(last=False)
        return False

    def prune(self, now: float, ttl_seconds: int) -> None:
        """Remove expired items."""

        while self._items:
            _, created = next(iter(self._items.items()))
            if now - created <= ttl_seconds:
                break
            self._items.popitem(last=False)

    def __len__(self) -> int:
        return len(self._items)


class RestartTracker:
    """Track PID reuse/restarts by stable fingerprint."""

    def __init__(self, max_fingerprints: int = 4096) -> None:
        self._starts: dict[str, deque[datetime]] = defaultdict(deque)
        self._max_fingerprints = max_fingerprints

    def observe(self, fingerprint: str | None, start_time: datetime | None, window_seconds: int) -> int:
        """Record a process start and return restart count in the window."""

        if not fingerprint or start_time is None:
            return 0
        if len(self._starts) > self._max_fingerprints:
            self._starts.clear()
        bucket = self._starts[fingerprint]
        if start_time not in bucket:
            bucket.append(start_time)
        cutoff = start_time.timestamp() - window_seconds
        while bucket and bucket[0].timestamp() < cutoff:
            bucket.popleft()
        return len(bucket)

    def size(self) -> int:
        """Return tracked fingerprint count."""

        return len(self._starts)

