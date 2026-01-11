from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Dict, Optional, Tuple

""" TTLCache where each entry has its own TTL.

Brief:
  Thread-safe in-memory cache where each entry has an independent TTL and
  optional capacity bound with pluggable eviction policies.

Notes:
  - Expired entries are removed opportunistically on get()/set() and via
    purge_expired().
  - When maxsize is configured, additional entries beyond that bound are
    evicted according to eviction_policy.
"""


_logger = logging.getLogger(__name__)


class FoghornTTLCache:
    """Thread-safe in-memory cache with per-entry TTL and optional eviction.

    Brief:
        In addition to basic TTL caching, this cache can optionally be
        namespaced. Namespacing allows multiple subsystems to share a single
        backing store without key collisions. When a positive maxsize is
        configured, entries may also be evicted before their TTL expires
        according to the chosen eviction_policy.

    Inputs:
        - namespace: Optional string namespace. When set, all keys are stored
          internally under (namespace, key).

    Outputs:
        FoghornTTLCache instance

    Notes:
        All dictionary operations are synchronized with an RLock.
        Expired entries are purged opportunistically in get() and set().

    Example use:
        >>> from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
        >>> cache = FoghornTTLCache()
        >>> key = ("example.com", 1)  # QNAME, QTYPE
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
        maxsize: Optional[int] = None,
        eviction_policy: str = "none",
        _store: Optional[Dict[Tuple[object, object], Tuple[float, Any]]] = None,
        _ttls: Optional[Dict[Tuple[object, object], int]] = None,
        _lock: Optional[threading.RLock] = None,
    ) -> None:
        """Initializes the FoghornTTLCache.

        Brief:
            Configure an optional namespace plus capacity and eviction policy.

        Inputs:
            namespace: Optional namespace string. When set, all cache operations
                are isolated to this namespace and keys are stored internally as
                (namespace, key).
            maxsize: Optional positive integer capacity bound. When None or
                non-positive, the cache behaves as unbounded and only TTL-based
                expiry applies.
            eviction_policy: Policy name used when maxsize is enforced. Supported
                values include "none", "lru", "lfu", "fifo", "random", and
                "almost_expired".

        Outputs:
            None
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

        # Eviction counters (best-effort) to support diagnostics and admin UI.
        # evictions_total: total number of entries removed due to TTL or
        # capacity-based eviction since process start.
        # evictions_ttl: entries removed because they expired.
        # evictions_capacity: entries removed because of maxsize/eviction_policy.
        self.evictions_total: int = 0
        self.evictions_ttl: int = 0
        self.evictions_capacity: int = 0

        # Optional capacity and eviction configuration. When _maxsize is None,
        # the cache is unbounded and no eviction beyond TTL occurs.
        try:
            self._maxsize: Optional[int] = int(maxsize) if maxsize is not None else None
        except Exception:
            self._maxsize = None
        if isinstance(self._maxsize, int) and self._maxsize <= 0:
            self._maxsize = None

        self._eviction_policy: str = (eviction_policy or "none").strip().lower()
        if not self._eviction_policy:
            self._eviction_policy = "none"

        # Metadata used by eviction policies when capacity is enforced.
        self._op_counter: int = 0
        self._last_access: Dict[Tuple[object, object], int] = {}
        self._hit_counts: Dict[Tuple[object, object], int] = {}
        self._insert_index: Dict[Tuple[object, object], int] = {}

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

    def _bump_op_counter_locked(self) -> int:
        """Brief: Increment and return the internal operation counter.

        Inputs:
          - None.

        Outputs:
          - int: Monotonically increasing counter value.
        """

        self._op_counter += 1
        return self._op_counter

    def _record_insert_locked(self, ns_key: Tuple[object, object]) -> None:
        """Brief: Record insertion metadata for eviction policies.

        Inputs:
          - ns_key: Internal namespaced key for the entry.

        Outputs:
          - None.
        """

        idx = self._bump_op_counter_locked()
        self._insert_index[ns_key] = idx
        self._last_access[ns_key] = idx
        # Initialize hit-counts lazily so LFU treats new entries as least-used.
        if ns_key not in self._hit_counts:
            self._hit_counts[ns_key] = 0

    def _record_access_locked(self, ns_key: Tuple[object, object]) -> None:
        """Brief: Record access metadata for eviction policies.

        Inputs:
          - ns_key: Internal namespaced key for the entry.

        Outputs:
          - None.
        """

        idx = self._bump_op_counter_locked()
        self._last_access[ns_key] = idx
        self._hit_counts[ns_key] = self._hit_counts.get(ns_key, 0) + 1

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
                # TTL-based eviction on access path.
                self._store.pop(ns_key, None)
                self._ttls.pop(ns_key, None)
                # Keep eviction metadata in sync when dropping entries.
                self._last_access.pop(ns_key, None)
                self._hit_counts.pop(ns_key, None)
                self._insert_index.pop(ns_key, None)
                self.cache_misses += 1
                try:
                    self.evictions_total += 1
                    self.evictions_ttl += 1
                except Exception:  # pragma: no cover - defensive counters
                    pass
                try:
                    _logger.debug(
                        "FoghornTTLCache TTL eviction (get): ns=%r key=%r",
                        self.namespace,
                        ns_key,
                    )
                except Exception:  # pragma: no cover - defensive logging
                    pass
                return None

            try:
                self.cache_hits += 1
            except Exception:  # pragma: no cover - defensive only
                pass

            # Record access for eviction policies that depend on recency/frequency.
            self._record_access_locked(ns_key)
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
            is_new = ns_key not in self._store
            self._store[ns_key] = (expiry, data)
            self._ttls[ns_key] = ttl_int
            if is_new:
                self._record_insert_locked(ns_key)
            else:
                # Treat an update as an access for LRU-ish policies.
                self._record_access_locked(ns_key)
            # Opportunistic cleanup (respect namespace isolation when set).
            self._purge_expired_locked(now=time.time(), namespace=self.namespace)

            # Enforce capacity when configured; this is global to the shared
            # backing store so namespaced views still share one physical limit.
            if isinstance(self._maxsize, int) and self._maxsize > 0:
                over = len(self._store) - self._maxsize
                if over > 0:
                    self._evict_locked(over)

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
                # Keep TTL and eviction metadata in sync with store removals.
                self._ttls.pop(k, None)
                self._last_access.pop(k, None)
                self._hit_counts.pop(k, None)
                self._insert_index.pop(k, None)
                removed += 1
                try:
                    self.evictions_total += 1
                    self.evictions_ttl += 1
                except Exception:  # pragma: no cover - defensive counters
                    pass
                try:
                    _logger.debug(
                        "FoghornTTLCache TTL eviction (purge): ns=%r key=%r",
                        namespace,
                        k,
                    )
                except Exception:  # pragma: no cover - defensive logging
                    pass
        return removed

    def _evict_locked(self, to_evict: int) -> int:
        """Brief: Evict up to ``to_evict`` entries according to eviction_policy.

        Inputs:
          - to_evict: Positive integer number of entries to evict.

        Outputs:
          - int: Number of entries actually evicted.
        """

        if to_evict <= 0:
            return 0
        if not isinstance(self._maxsize, int) or self._maxsize <= 0:
            return 0

        # Fast path: when policy is explicitly disabled, do nothing beyond TTL.
        policy = self._eviction_policy
        if policy in {"none", "", "off"}:
            return 0

        # Clamp requested evictions to current size to keep logic simple.
        available = len(self._store)
        if available <= 0:
            return 0
        need = min(to_evict, available)

        # Build a list of candidate keys and per-key scores depending on policy.
        items = list(self._store.items())
        scores: Dict[Tuple[object, object], float] = {}

        if policy == "lru":
            for k, _ in items:
                scores[k] = float(self._last_access.get(k, 0))
        elif policy == "lfu":
            for k, _ in items:
                scores[k] = float(self._hit_counts.get(k, 0))
        elif policy == "fifo":
            for k, _ in items:
                scores[k] = float(self._insert_index.get(k, 0))
        elif policy == "almost_expired":
            for k, (exp, _) in items:
                scores[k] = float(exp)
        elif policy == "random":
            # Random eviction ignores scores entirely; handled below.
            pass
        else:
            # Unknown policies are treated as disabled to avoid surprising
            # behaviour; callers can rely on TTL-only expiry in this case.
            return 0

        # Choose victim keys based on computed scores.
        victims: list[Tuple[object, object]]
        if policy == "random":
            population = [k for k, _ in items]
            if not population:
                return 0
            if need >= len(population):
                victims = population
            else:
                victims = random.sample(population, need)
        else:
            # For LRU/LFU/FIFO/AlmostExpired the smallest score is the best
            # candidate for eviction.
            victims = sorted(scores.keys(), key=scores.get)[:need]

        removed = 0
        for k in victims:
            if k not in self._store:
                continue
            del self._store[k]
            self._ttls.pop(k, None)
            self._last_access.pop(k, None)
            self._hit_counts.pop(k, None)
            self._insert_index.pop(k, None)
            removed += 1
            try:
                self.evictions_total += 1
                self.evictions_capacity += 1
            except Exception:  # pragma: no cover - defensive counters
                pass
            try:
                _logger.debug(
                    "FoghornTTLCache size eviction: policy=%s ns=%r key=%r",
                    policy,
                    self.namespace,
                    k,
                )
            except Exception:  # pragma: no cover - defensive logging
                pass

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
