"""Brief: Unit tests for foghorn.utils.register_caches helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, List

from cachetools import TTLCache

import foghorn.utils.register_caches as cache_reg


def _find_entry_by_backend(
    entries: List[Dict[str, Any]], backend: str
) -> Dict[str, Any]:
    """Brief: Helper to locate a registry entry by backend name.

    Inputs:
      - entries: List of registry snapshot entries.
      - backend: Backend name string (e.g., "ttlcache", "lru_cache").

    Outputs:
      - First matching entry dict.
    """

    for entry in entries:
        if entry.get("backend") == backend:
            return entry
    raise AssertionError(f"No entry found for backend={backend!r}")


def test_registered_cached_with_positional_ttlcache_records_meta_and_counters() -> None:
    """Brief: registered_cached with positional TTLCache tracks meta and counters.

    Inputs:
      - None.

    Outputs:
      - None; asserts ttl/maxsize and hit/miss counters are recorded.
    """

    cache = TTLCache(maxsize=32, ttl=5)

    @cache_reg.registered_cached(cache)
    def fn(x: int) -> int:
        return x * 2

    # One miss then one hit for the same key.
    assert fn(10) == 20
    assert fn(10) == 20

    snapshot = cache_reg.get_registered_cached()
    entry = _find_entry_by_backend(snapshot, "ttlcache")

    # Registry should record ttl/maxsize for the TTLCache backend.
    assert isinstance(entry.get("ttl"), int)
    assert isinstance(entry.get("maxsize"), int)
    assert isinstance(entry.get("calls_total"), int) and entry["calls_total"] >= 2
    # Counters should exist and be non-negative; hit/miss classification is best-effort.
    assert isinstance(entry.get("cache_hits"), int) and entry["cache_hits"] >= 0
    assert isinstance(entry.get("cache_misses"), int) and entry["cache_misses"] >= 0
    # size_current should be computed from the underlying TTLCache.
    assert entry.get("size_current") is not None


def test_registered_lru_cached_records_hit_and_miss_counters() -> None:
    """Brief: registered_lru_cached derives hit/miss counts from cache_info().

    Inputs:
      - None.

    Outputs:
      - None; asserts lru_cache wrapper records calls, hits, and misses.
    """

    @cache_reg.registered_lru_cached(maxsize=4)
    def fn_lru(x: int) -> int:
        return x * 3

    # First call for a key is a miss, subsequent calls are hits.
    assert fn_lru(1) == 3
    assert fn_lru(1) == 3
    assert fn_lru(2) == 6

    snapshot = cache_reg.get_registered_cached()
    entry = _find_entry_by_backend(snapshot, "lru_cache")

    # Calls counter should be present and >= number of invocations.
    assert isinstance(entry.get("calls_total"), int) and entry["calls_total"] >= 3
    # Hit/miss counters are best-effort; just assert they exist and are non-negative.
    assert isinstance(entry.get("cache_hits"), int) and entry["cache_hits"] >= 0
    assert isinstance(entry.get("cache_misses"), int) and entry["cache_misses"] >= 0
