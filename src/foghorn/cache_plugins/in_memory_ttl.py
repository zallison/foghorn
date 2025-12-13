from __future__ import annotations

from typing import Any, Optional, Tuple

from foghorn.cache import FoghornTTLCache

from .base import CachePlugin, cache_aliases


@cache_aliases("in_memory_ttl", "memory", "ttl")
class InMemoryTTLCachePlugin(CachePlugin):
    """In-memory TTL cache plugin.

    Brief:
      Default CachePlugin implementation backed by `foghorn.cache.FoghornTTLCache`.

    Inputs:
      - **config: Optional implementation-specific config.
          - min_cache_ttl: Non-negative int seconds. This is the cache expiry
            floor applied by the resolver when caching responses.

    Outputs:
      - InMemoryTTLCachePlugin instance.
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize an in-memory TTL cache.

        Inputs:
          - **config:
              - min_cache_ttl: Non-negative int seconds cache TTL floor.

        Outputs:
          - None.
        """

        self.min_cache_ttl = max(0, int(config.get("min_cache_ttl", 0) or 0))
        self._cache = FoghornTTLCache()

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Return cached value when present.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - Any | None: Cached value, or None.
        """

        return self._cache.get(key)

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Return cached value plus seconds_remaining and original TTL.

        Inputs:
          - key: Tuple[str, int] cache key.

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        return self._cache.get_with_meta(key)

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a cached value.

        Inputs:
          - key: Tuple[str, int] cache key.
          - ttl: int time-to-live seconds.
          - value: cached payload.

        Outputs:
          - None.
        """

        self._cache.set(key, ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired items from the cache.

        Inputs:
          - None.

        Outputs:
          - int: Number of removed entries.
        """

        return int(self._cache.purge_expired())
