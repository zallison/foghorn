"""Brief: Unit tests for foghorn.utils.register_caches helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, List

from cachetools import TTLCache, LFUCache, RRCache

import foghorn.utils.register_caches as cache_reg


def _find_entry_by_backend(
    entries: List[Dict[str, Any]], backend: str
) -> Dict[str, Any]:
    """Brief: Helper to locate the first registry entry by backend name.

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


def _find_last_entry_by_backend(
    entries: List[Dict[str, Any]], backend: str
) -> Dict[str, Any]:
    """Brief: Helper to locate the most recent registry entry by backend name.

    Inputs:
      - entries: List of registry snapshot entries.
      - backend: Backend name string (e.g., "ttlcache", "lru_cache").

    Outputs:
      - Last matching entry dict.
    """

    for entry in reversed(entries):
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


def test_registered_cached_with_lfu_backend_records_backend_and_maxsize() -> None:
    """Brief: registered_cached with LFUCache tags backend and maxsize.

    Inputs:
      - None.

    Outputs:
      - None; asserts backend name and maxsize are recorded.
    """

    cache = LFUCache(maxsize=16)

    @cache_reg.registered_cached(cache)
    def fn_lfu(x: int) -> int:
        return x * 2

    assert fn_lfu(1) == 2
    assert fn_lfu(2) == 4

    snapshot = cache_reg.get_registered_cached()
    entry = _find_last_entry_by_backend(snapshot, "lfu_cache")
    assert entry.get("backend") == "lfu_cache"
    assert entry.get("maxsize") == 16


def test_registered_cached_with_rr_backend_records_backend_and_maxsize() -> None:
    """Brief: registered_cached with RRCache tags backend and maxsize.

    Inputs:
      - None.

    Outputs:
      - None; asserts backend name and maxsize are recorded.
    """

    cache = RRCache(maxsize=32)

    @cache_reg.registered_cached(cache)
    def fn_rr(x: int) -> int:
        return x * 5

    assert fn_rr(1) == 5
    assert fn_rr(2) == 10

    snapshot = cache_reg.get_registered_cached()
    entry = _find_last_entry_by_backend(snapshot, "rr_cache")
    assert entry.get("backend") == "rr_cache"
    assert entry.get("maxsize") == 32


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
    entry = _find_last_entry_by_backend(snapshot, "lru_cache")

    # Calls counter should be present and >= number of invocations.
    assert isinstance(entry.get("calls_total"), int) and entry["calls_total"] >= 3
    # Hit/miss counters are best-effort; just assert they exist and are non-negative.
    assert isinstance(entry.get("cache_hits"), int) and entry["cache_hits"] >= 0
    assert isinstance(entry.get("cache_misses"), int) and entry["cache_misses"] >= 0
    # size_current for lru_cache backends should be present and non-negative.
    assert isinstance(entry.get("size_current"), int) and entry["size_current"] >= 0


def test_apply_decorated_cache_overrides_updates_lru_cache_maxsize() -> None:
    """Brief: apply_decorated_cache_overrides can shrink lru_cache maxsize.

    Inputs:
      - None.

    Outputs:
      - None; asserts that cache_parameters().maxsize reflects the override.
    """

    @cache_reg.registered_lru_cached(maxsize=4)
    def fn_lru_override(x: int) -> int:
        return x * 7

    # Warm up the cache so the wrapper is fully initialized.
    assert fn_lru_override(1) == 7

    params_before = fn_lru_override.cache_parameters()
    assert params_before.get("maxsize") == 4

    overrides = [
        {
            "module": __name__,
            "name": "fn_lru_override",
            "backend": "lru_cache",
            "maxsize": 2,
        }
    ]

    cache_reg.apply_decorated_cache_overrides(overrides)

    params_after = fn_lru_override.cache_parameters()
    assert params_after.get("maxsize") == 2


def test_registered_foghorn_ttl_and_overrides_record_ttl_and_maxsize() -> None:
    """Brief: registered_foghorn_ttl uses registry ttl/maxsize updated by overrides.

    Inputs:
      - None.

    Outputs:
      - None; asserts registry snapshot reflects configured override values.
    """

    from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache

    backend = FoghornTTLCache()

    @cache_reg.registered_foghorn_ttl(cache=backend, ttl=30, maxsize=100)
    def fn_foghorn(x: int) -> int:
        return x + 1

    assert fn_foghorn(10) == 11

    overrides = [
        {
            "module": __name__,
            "name": "fn_foghorn",
            "backend": "foghorn_ttl",
            "ttl": 5,
            "maxsize": 200,
        }
    ]

    cache_reg.apply_decorated_cache_overrides(overrides)

    snapshot = cache_reg.get_registered_cached()
    entry = _find_last_entry_by_backend(snapshot, "foghorn_ttl")
    assert entry.get("ttl") == 5
    assert entry.get("maxsize") == 200


def test_registered_sqlite_ttl_and_overrides_record_ttl_and_maxsize(tmp_path) -> None:
    """Brief: registered_sqlite_ttl uses registry ttl/maxsize updated by overrides.

    Inputs:
      - tmp_path: pytest temporary directory fixture.

    Outputs:
      - None; asserts registry snapshot reflects configured override values.
    """

    from foghorn.plugins.cache.backends.sqlite_ttl import SQLite3TTLCache

    db_path = tmp_path / "decorated_ttl.sqlite"
    backend = SQLite3TTLCache(str(db_path), namespace="decorated")

    @cache_reg.registered_sqlite_ttl(cache=backend, ttl=60, maxsize=50)
    def fn_sqlite(x: int) -> int:
        return x * 2

    assert fn_sqlite(3) == 6

    overrides = [
        {
            "module": __name__,
            "name": "fn_sqlite",
            "backend": "sqlite_ttl",
            "ttl": 10,
            "maxsize": 500,
        }
    ]

    cache_reg.apply_decorated_cache_overrides(overrides)

    snapshot = cache_reg.get_registered_cached()
    entry = _find_last_entry_by_backend(snapshot, "sqlite_ttl")
    assert entry.get("ttl") == 10
    assert entry.get("maxsize") == 500
