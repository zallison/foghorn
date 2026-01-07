from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional, Tuple

from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
from foghorn.plugins.cache.backends.sqlite_ttl import SQLite3TTLCache


class TTLCacheAdapter:
    """Adapter that normalizes TTL cache methods across backends.

    Brief:
      Some parts of the codebase use `FoghornTTLCache` directly (purge via
      purge_expired), while others use cache plugins or `SQLite3TTLCache`
      (purge via purge). This adapter provides a tiny common surface.

    Inputs:
      - backend: Cache-like object that supports get/set and optionally
        get_with_meta and purge/purge_expired.

    Outputs:
      - TTLCacheAdapter instance.
    """

    def __init__(self, backend: Any) -> None:
        self._backend = backend

    def get(self, key: Any) -> Any | None:
        """Brief: Lookup a cached entry enforcing expiry.

        Inputs:
          - key: Cache key.

        Outputs:
          - Any | None: Cached value or None.
        """

        return self._backend.get(key)

    def get_with_meta(
        self, key: Any
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata when available.

        Inputs:
          - key: Cache key.

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        fn = getattr(self._backend, "get_with_meta", None)
        if callable(fn):
            return fn(key)
        return self.get(key), None, None

    def set(self, key: Any, ttl: int, value: Any) -> None:
        """Brief: Store a value under key with a TTL.

        Inputs:
          - key: Cache key.
          - ttl: int time-to-live seconds.
          - value: Cache value.

        Outputs:
          - None.
        """

        return self._backend.set(key, ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed.
        """

        fn = getattr(self._backend, "purge", None)
        if callable(fn):
            return int(fn())
        fn2 = getattr(self._backend, "purge_expired", None)
        if callable(fn2):
            return int(fn2())
        return 0


def module_namespace(module_file: str) -> str:
    """Brief: Compute a namespace name from a module filename.

    Inputs:
      - module_file: __file__ string.

    Outputs:
      - str: Filename stem, sans extension.

    Example:
      >>> module_namespace('/a/b/filter.py')
      'filter'
    """

    return Path(str(module_file)).stem


def get_current_namespaced_cache(
    *,
    namespace: str,
    cache_plugin: Optional[object] = None,
) -> TTLCacheAdapter:
    """Brief: Return a TTL cache backed by the configured DNS cache when possible.

    Inputs:
      - namespace: Namespace/table name to isolate data.
      - cache_plugin: Optional CachePlugin-like object. When omitted, this uses
        `foghorn.plugins.resolve.base.DNS_CACHE`.

    Outputs:
      - TTLCacheAdapter wrapping either:
          - SQLite3TTLCache pointing at the DNS cache's sqlite DB (when the
            current DNS cache is SQLite3Cache), or
          - A per-call in-memory FoghornTTLCache fallback.
    """

    # Import lazily to avoid circular imports during module import.
    if cache_plugin is None:
        try:
            from foghorn.plugins.resolve import base as plugin_base

            cache_plugin = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache_plugin = None

    # SQLite-backed DNS cache: create a dedicated sqlite TTL table per namespace.
    try:
        from foghorn.plugins.cache.sqlite_cache import SQLite3Cache

        if isinstance(cache_plugin, SQLite3Cache):
            journal_mode = "WAL"
            try:
                journal_mode = str(getattr(cache_plugin._cache, "journal_mode", "WAL"))
            except Exception:
                journal_mode = "WAL"

            db_path = str(getattr(cache_plugin, "db_path", ""))
            if not db_path:
                # Defensive: should not happen, but avoid creating :memory: caches.
                return TTLCacheAdapter(FoghornTTLCache())

            # Ensure directory exists, mirroring other sqlite users.
            dir_path = os.path.dirname(db_path)
            if dir_path:
                try:
                    os.makedirs(dir_path, exist_ok=True)
                except Exception:
                    pass

            return TTLCacheAdapter(
                SQLite3TTLCache(
                    db_path,
                    namespace=str(namespace),
                    journal_mode=journal_mode,
                    create_dir=True,
                )
            )
    except Exception:
        # SQLite cache plugin not available; fall back.
        pass

    # In-memory DNS cache: when available, derive a namespaced view that shares
    # the same backing store so multiple subsystems still reuse "the current
    # cache".
    try:
        from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache

        if isinstance(cache_plugin, InMemoryTTLCache):
            base = getattr(cache_plugin, "_cache", None)
            if isinstance(base, FoghornTTLCache):
                return TTLCacheAdapter(base.with_namespace(namespace))
    except Exception:
        pass

    # Other cache plugins (e.g., NullCache): return the plugin itself as a TTL
    # backend. This allows per-plugin cache overrides like `cache: none`.
    try:
        from foghorn.plugins.cache.base import CachePlugin

        if isinstance(cache_plugin, CachePlugin):
            return TTLCacheAdapter(cache_plugin)
    except Exception:
        pass

    return TTLCacheAdapter(FoghornTTLCache(namespace=namespace))
