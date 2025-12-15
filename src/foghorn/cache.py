from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple

""" TTLCache where each entry has it's own TTL. """


class FoghornTTLCache:
    """
    Thread-safe in-memory cache with individual Time-To-Live (TTL) support.

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
        self._store: Dict[Tuple[str, int], Tuple[float, Any]] = {}
        # Track original TTLs separately so callers interested in cache
        # prefetch / stale-while-revalidate behaviour can reason about the
        # configured lifetime without changing the existing get()/set() API.
        self._ttls: Dict[Tuple[str, int], int] = {}
        self._lock = threading.RLock()

    def get(self, key: Tuple[str, int]) -> Any | None:
        """
        Retrieves an item from the cache.
        Returns the item if it exists and has not expired.

        Inputs:
            key: The key to retrieve.

        Outputs:
            The cached value, or None if the key is not found or has expired.

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
                self._ttls.pop(key, None)
                return None
            return data

    def set(self, key: Tuple[str, int], ttl: int, data: Any) -> None:
        """
        Adds an item to the cache with a specified TTL.

        Inputs:
            key: The key to store the value under.
            ttl: The Time-To-Live in seconds.
            data: The value to store.
        Outputs:
            None

        Example use:
            >>> cache = FoghornTTLCache()
            >>> cache.set(("example.com", 1), 60, b"data")
            >>> cache.get(("example.com", 1))
            b'data'
        """
        ttl_int = max(0, int(ttl))
        expiry = time.time() + ttl_int
        with self._lock:
            self._store[key] = (expiry, data)
            self._ttls[key] = ttl_int
            # Opportunistic cleanup
            self._purge_expired_locked(now=time.time())

    def purge_expired(self) -> int:
        """Remove all expired entries.

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
        """Remove expired entries while holding the lock.

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
                # Keep TTL metadata in sync with store removals.
                self._ttls.pop(k, None)
                removed += 1
        return removed

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Return cached value plus seconds_remaining and original TTL.

        Inputs:
            key: Cache key tuple (qname, qtype).

        Outputs:
            Tuple of (value_or_None, seconds_remaining_or_None, ttl_or_None).

        Notes:
            - Unlike get(), this helper does not purge expired entries
              aggressively; callers can decide whether slightly stale entries are
              acceptable based on the returned seconds_remaining value.
        """
        now = time.time()
        with self._lock:
            entry = self._store.get(key)
            if not entry:
                return None, None, None
            expiry, data = entry
            seconds_remaining = float(expiry - now)
            ttl = self._ttls.get(key)
            return (
                data,
                seconds_remaining,
                int(ttl) if ttl is not None else None,
            )
