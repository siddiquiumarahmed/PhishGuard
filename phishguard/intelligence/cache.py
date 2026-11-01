"""Small thread-safe in-memory TTL cache for reputation lookups.

Keys are SHA-256 digests, so cached entries never contain the URL itself.
Only *completed* lookups are cached; failures are retried on the next scan.
The cache lives in process memory and is cleared on restart.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from typing import Generic, TypeVar

V = TypeVar("V")


def cache_key(provider_id: str, url: str) -> str:
    return hashlib.sha256(f"{provider_id}\x00{url}".encode()).hexdigest()


class TTLCache(Generic[V]):
    def __init__(self, ttl_seconds: float = 1800.0, max_entries: int = 2048) -> None:
        self.ttl = ttl_seconds
        self.max_entries = max_entries
        self._data: OrderedDict[str, tuple[float, V]] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: str) -> V | None:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            expires, value = item
            if time.monotonic() >= expires:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value: V, ttl: float | None = None) -> None:
        if self.ttl <= 0:
            return
        with self._lock:
            self._data[key] = (time.monotonic() + (self.ttl if ttl is None else ttl), value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
