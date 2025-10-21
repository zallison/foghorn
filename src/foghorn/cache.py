from __future__ import annotations
import time
from typing import Any, Dict, Tuple

class TTLCache:
    def __init__(self) -> None:
        self._store: Dict[Tuple[str, int], Tuple[float, bytes]] = {}

    def get(self, key: Tuple[str, int]) -> bytes | None:
        now = time.time()
        entry = self._store.get(key)
        if not entry:
            return None
        expiry, data = entry
        if now >= expiry:
            self._store.pop(key, None)
            return None
        return data

    def set(self, key: Tuple[str, int], ttl: int, data: bytes) -> None:
        expiry = time.time() + max(0, int(ttl))
        self._store[key] = (expiry, data)
