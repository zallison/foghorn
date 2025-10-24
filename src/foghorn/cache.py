from __future__ import annotations
import time
from typing import Any, Dict, Tuple

class TTLCache:
    """
    An in-memory cache with Time-To-Live (TTL) support.

    Example use:
        >>> import time
        >>> from foghorn.cache import TTLCache
        >>> cache = TTLCache()
        >>> key = ("example.com", 1) # QNAME, QTYPE
        >>> cache.set(key, 60, b"dns-response-data")
        >>> cache.get(key)
        b'dns-response-data'
        >>> # Wait for expiry
        >>> # time.sleep(61)
        >>> # cache.get(key) is None
    """
    def __init__(self) -> None:
        """
        Initializes the TTLCache.

        Example use:
            >>> cache = TTLCache()
            >>> cache._store
            {}
        """
        self._store: Dict[Tuple[str, int], Tuple[float, bytes]] = {}

    def get(self, key: Tuple[str, int]) -> bytes | None:
        """
        Retrieves an item from the cache.
        Returns the item if it exists and has not expired.

        Args:
            key: The key to retrieve.

        Returns:
            The cached data, or None if the key is not found or has expired.

        Example use:
            >>> cache = TTLCache()
            >>> cache.set(("example.com", 1), 60, b"data")
            >>> cache.get(("example.com", 1))
            b'data'
        """
        now = time.time()
        entry = self._store.get(key)
        if not entry:
            return None
        expiry, data = entry
        # Check if the entry has expired.
        if now >= expiry:
            self._store.pop(key, None)
            return None
        return data

    def set(self, key: Tuple[str, int], ttl: int, data: bytes) -> None:
        """
        Adds an item to the cache with a specified TTL.

        Args:
            key: The key to store the data under.
            ttl: The Time-To-Live in seconds.
            data: The data to store.

        Example use:
            >>> cache = TTLCache()
            >>> cache.set(("example.com", 1), 60, b"data")
            >>> cache.get(("example.com", 1))
            b'data'
        """
        expiry = time.time() + max(0, int(ttl))
        self._store[key] = (expiry, data)
