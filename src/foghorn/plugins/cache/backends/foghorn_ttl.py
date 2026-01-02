from __future__ import annotations

import threading
import time
from typing import Any, Dict, Optional, Tuple

""" TTLCache where each entry has it's own TTL. """


class FoghornTTLCache:
    """
    Thread-safe in-memory cache with individual Time-To-Live (TTL) support.

    Brief:
        In addition to basic TTL caching, this cache can optionally be
        namespaced. Namespacing allows multiple subsystems to share a single
        backing store without key collisions.

    Inputs:
        - namespace: Optional string namespace. When set, all keys are stored
          internally under (namespace, key).

    Outputs:
        FoghornTTLCache instance

    Notes:
        All dictionary operations are synchronized with an RLock.
        Expired entries are purged opportunistically in get() and set().

    Example use:
        >>> import time
        >>> from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
        >>> cache = FoghornTTLCache()
        >>> key = ("example.com", 1) # QNAME, QTYPE
        >>> cache.set(key, 60, b"dns-response-data")
        >>> cache.get(key)
        b'dns-response-data'
        >>> # Wait for expiry
        >>> # time.sleep(61)
        >>> # cache.get(key) is None
    """

    def __init__(
        self,
        namespace: str | None = None,
        *,
        _store: Optional[Dict[Tuple[object, object], Tuple[float, Any]]] = None,
        _ttls: Optional[Dict[Tuple[object, object], int]] = None,
        _lock: Optional[threading.RLock] = None,
    ) -> None:
        """Initializes the FoghornTTLCache.

        Inputs:
            namespace: Optional namespace string. When set, all cache operations
                are isolated to this namespace and keys are stored internally as
                (namespace, key).

        Outputs:
            None

        Example use:
            >>> cache = FoghornTTLCache()
            >>> cache._store
            {}
        """
        ns = None
        if namespace is not None:
            s = str(namespace).strip()
            ns = s if s else None
        self.namespace: str | None = ns

        # Backing store is optionally injected so callers can create namespaced
        # views that share the same underlying store and lock.
        self._store: Dict[Tuple[object, object], Tuple[float, Any]] = (
            {} if _store is None else _store
        )
        # Track original TTLs separately so callers interested in cache
        # prefetch / stale-while-revalidate behaviour can reason about the
        # configured lifetime without changing the existing get()/set() API.
        self._ttls: Dict[Tuple[object, object], int] = {} if _ttls is None else _ttls
        self._lock = threading.RLock() if _lock is None else _lock

        # Per-cache access counters used by admin snapshots. These are best-effort
        # only and do not affect core cache semantics.
        self.calls_total: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

    def _ns_key(self, key: Tuple[str, int]) -> Tuple[object, object]:
        """Brief: Build an internal namespaced key.

        Inputs:
            key: External cache key.

        Outputs:
            Tuple used as the internal key in backing dictionaries.
        """

        if self.namespace is None:
            return key  # type: ignore[return-value]
        return (self.namespace, key)

    def with_namespace(self, namespace: str) -> "FoghornTTLCache":
        """Brief: Return a namespaced view sharing the same backing store.

        Inputs:
            namespace: Namespace identifier.

        Outputs:
            FoghornTTLCache view that shares backing store and lock.
        """

        return FoghornTTLCache(
            namespace=namespace,
            _store=self._store,
            _ttls=self._ttls,
            _lock=self._lock,
        )

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
        ns_key = self._ns_key(key)
        with self._lock:
            self.calls_total += 1

            entry = self._store.get(ns_key)
            if not entry:
                self.cache_misses += 1
                return None

            expiry, data = entry
            # Check if the entry has expired.
            if now >= expiry:
                self._store.pop(ns_key, None)
                self._ttls.pop(ns_key, None)
                self.cache_misses += 1
                return None

            try:
                self.cache_hits += 1
            except Exception:  # pragma: no cover - defensive only
                pass
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
        ns_key = self._ns_key(key)
        with self._lock:
            self._store[ns_key] = (expiry, data)
            self._ttls[ns_key] = ttl_int
            # Opportunistic cleanup (respect namespace isolation when set).
            self._purge_expired_locked(now=time.time(), namespace=self.namespace)

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
            return self._purge_expired_locked(now=time.time(), namespace=self.namespace)

    def _purge_expired_locked(self, now: float, namespace: str | None = None) -> int:
        """Remove expired entries while holding the lock.

        Inputs:
            now: Current time as float epoch seconds
        Outputs:
            Number of entries removed
        """
        removed = 0
        # Iterate on a list of items to avoid runtime dict size change issues
        for k, (exp, _) in list(self._store.items()):
            if namespace is not None:
                # Only purge entries within the requested namespace.
                if not (isinstance(k, tuple) and len(k) == 2 and k[0] == namespace):
                    continue
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
        ns_key = self._ns_key(key)
        with self._lock:
            self.calls_total += 1

            entry = self._store.get(ns_key)
            if not entry:
                try:
                    self.cache_misses += 1
                except Exception:  # pragma: no cover - defensive only
                    pass
                return None, None, None

            expiry, data = entry
            seconds_remaining = float(expiry - now)
            ttl = self._ttls.get(ns_key)

            if seconds_remaining >= 0:
                self.cache_hits += 1
            else:
                self.cache_misses += 1

            return (
                data,
                seconds_remaining,
                int(ttl) if ttl is not None else None,
            )
