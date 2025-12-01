from __future__ import annotations

import threading
import time
from typing import Dict, Tuple


class FoghornTTLCache:
    """
    Thread-safe in-memory cache with Time-To-Live (TTL) support.

    Inputs:
        None (constructor)
    Outputs:
        FoghornTTLCache instance

    Notes:
        All dictionary operations are synchronized with an RLock.
        Expired entries are purged opportunistically in get() and set().

    Example use:
        >>> import time
        >>> from foghorn.cache import FoghornTTLCache
        >>> cache = FoghornTTLCache()
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
        Initializes the FoghornTTLCache.

        Inputs:
            None
        Outputs:
            None

        Example use:
            >>> cache = FoghornTTLCache()
            >>> cache._store
            {}
        """
        self._store: Dict[Tuple[str, int], Tuple[float, bytes]] = {}
        self._lock = threading.RLock()

    def get(self, key: Tuple[str, int]) -> bytes | None:
        """
        Retrieves an item from the cache.
        Returns the item if it exists and has not expired.

        Inputs:
            key: The key to retrieve.

        Outputs:
            The cached data, or None if the key is not found or has expired.

        Example use:
            >>> cache = FoghornTTLCache()
            >>> cache.set(("example.com", 1), 60, b"data")
            >>> cache.get(("example.com", 1))
            b'data'
        """
        now = time.time()
        with self._lock:
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

        Inputs:
            key: The key to store the data under.
            ttl: The Time-To-Live in seconds.
            data: The data to store.
        Outputs:
            None

        Example use:
            >>> cache = FoghornTTLCache()
            >>> cache.set(("example.com", 1), 60, b"data")
            >>> cache.get(("example.com", 1))
            b'data'
        """
        expiry = time.time() + max(0, int(ttl))
        with self._lock:
            self._store[key] = (expiry, data)
            # Opportunistic cleanup
            self._purge_expired_locked(now=time.time())

    def purge_expired(self) -> int:
        """
        Remove all expired entries.

        Inputs:
            None
        Outputs:
            Number of entries removed.

        Example use:
            >>> cache = FoghornTTLCache()
            >>> removed = cache.purge_expired()
        """
        with self._lock:
            return self._purge_expired_locked(now=time.time())

    def _purge_expired_locked(self, now: float) -> int:
        """
        Remove expired entries while holding the lock.

        Inputs:
            now: Current time as float epoch seconds
        Outputs:
            Number of entries removed
        """
        removed = 0
        # Iterate on a list of items to avoid runtime dict size change issues
        for k, (exp, _) in list(self._store.items()):
            if exp <= now:
                del self._store[k]
                removed += 1
        return removed
