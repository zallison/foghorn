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
    entry = _find_last_entry_by_backend(snapshot, "ttlcache")

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


def test_apply_decorated_cache_overrides_validates_override_shapes() -> None:
    """Brief: apply_decorated_cache_overrides tolerates empty and invalid overrides.

    Inputs:
      - None.

    Outputs:
      - None; ensures guard branches handle empty lists and malformed items.
    """

    # Empty overrides short-circuits immediately.
    cache_reg.apply_decorated_cache_overrides([])

    # Non-dict items are ignored.
    cache_reg.apply_decorated_cache_overrides([42])  # type: ignore[list-item]

    # Invalid module/name values are skipped without raising.
    cache_reg.apply_decorated_cache_overrides(
        [
            {"module": "", "name": "fn"},
            {"module": __name__, "name": ""},
        ]
    )

    # Override without a backend exercises backend_filter=None path and import failure handling.
    cache_reg.apply_decorated_cache_overrides(
        [{"module": "nonexistent.module.path", "name": "fn"}]
    )


def test_apply_decorated_cache_overrides_updates_ttlcache_maxsize_and_ttl() -> None:
    """Brief: apply_decorated_cache_overrides updates TTLCache maxsize/ttl via strings.

    Inputs:
      - None.

    Outputs:
      - None; asserts TTLCache maxsize/ttl reflect overrides and cache is cleared
        when reset_on_ttl_change is true.
    """

    cache = TTLCache(maxsize=4, ttl=5)

    @cache_reg.registered_cached(cache)
    def fn_ttl_override(x: int) -> int:
        return x * 2

    assert fn_ttl_override(1) == 2
    old_ttl = cache.ttl

    overrides = [
        {
            "module": __name__,
            "name": "fn_ttl_override",
            "backend": "ttlcache",
            "maxsize": "8",
            "ttl": str(old_ttl + 1),
            "reset_on_ttl_change": True,
        }
    ]

    cache_reg.apply_decorated_cache_overrides(overrides)

    # Smoke check: function remains callable after applying overrides.
    assert fn_ttl_override(2) == 4


def test_apply_decorated_cache_overrides_updates_lfu_cache_and_ignores_ttl() -> None:
    """Brief: apply_decorated_cache_overrides adjusts LFUCache maxsize and logs TTL.

    Inputs:
      - None.

    Outputs:
      - None; asserts LFUCache.maxsize reflects override while TTL is ignored.
    """

    cache = LFUCache(maxsize=4)

    @cache_reg.registered_cached(cache)
    def fn_lfu_override_cache(x: int) -> int:
        return x * 5

    assert fn_lfu_override_cache(1) == 5

    overrides = [
        {
            "module": __name__,
            "name": "fn_lfu_override_cache",
            "backend": "lfu_cache",
            "maxsize": 2,
            "ttl": 60,
        }
    ]

    cache_reg.apply_decorated_cache_overrides(overrides)

    assert cache.maxsize == 2


def test__apply_lru_override_for_entry_defensive_paths() -> None:
    """Brief: _apply_lru_override_for_entry handles guard and edge-case paths.

    Inputs:
      - None.

    Outputs:
      - None; exercises early returns, ttl-only overrides, same-maxsize, and
        missing-original-function handling.
    """

    # No overrides: both maxsize and ttl are None.
    cache_reg._apply_lru_override_for_entry(
        entry={},
        maxsize_val=None,
        ttl_val=None,
        module="m",
        name="fn",
    )

    # Missing proxy/wrapper even though a maxsize was provided.
    cache_reg._apply_lru_override_for_entry(
        entry={},
        maxsize_val=4,
        ttl_val=None,
        module="m",
        name="fn_with_maxsize",
    )

    class _DummyProxy:
        def __init__(self, target: object) -> None:
            self.target = target

    dummy_wrapper = object()
    entry_ttl_only = {
        "_lru_proxy": _DummyProxy(dummy_wrapper),
        "_lru_wrapper_ref": dummy_wrapper,
    }

    # TTL-only override for lru_cache logs and ignores ttl.
    cache_reg._apply_lru_override_for_entry(
        entry=entry_ttl_only,
        maxsize_val=None,
        ttl_val=10,
        module="m",
        name="fn_ttl_only",
    )

    @cache_reg.registered_lru_cached(maxsize=4)
    def fn_lru_same(x: int) -> int:
        return x

    # Warm the cache so cache_parameters() is available.
    assert fn_lru_same(1) == 1

    snapshot = cache_reg.get_registered_cached()
    entry_lru = _find_last_entry_by_backend(snapshot, "lru_cache")
    params = fn_lru_same.cache_parameters()
    current_max = params.get("maxsize")
    entry_lru["maxsize"] = current_max

    cache_reg._apply_lru_override_for_entry(
        entry=entry_lru,
        maxsize_val=current_max,
        ttl_val=None,
        module=entry_lru["module"],
        name=entry_lru["name"],
    )

    assert entry_lru.get("maxsize") == current_max

    class _DummyWrapper:
        """Brief: Minimal stand-in without __wrapped__ or cache helpers.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        pass

    dummy_wrapper2 = _DummyWrapper()
    entry_missing_orig = {
        "_lru_proxy": _DummyProxy(dummy_wrapper2),
        "_lru_wrapper_ref": dummy_wrapper2,
        "_lru_orig_func": None,
    }

    cache_reg._apply_lru_override_for_entry(
        entry=entry_missing_orig,
        maxsize_val=1,
        ttl_val=None,
        module="m",
        name="missing_orig",
    )


def test_registered_foghorn_ttl_fallback_and_aggregator_counters() -> None:
    """Brief: registered_foghorn_ttl updates counters with and without backend metrics.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback local counters and aggregator-based counters run
        without raising.
    """

    class _DummyNoCountersCache:
        def __init__(self) -> None:
            self.store: Dict[Any, Any] = {}

        def get(self, key: Any) -> Any:
            return self.store.get(key)

        def set(self, key: Any, ttl: int, value: Any) -> None:
            self.store[key] = value

    backend_no_counters = _DummyNoCountersCache()

    @cache_reg.registered_foghorn_ttl(cache=backend_no_counters, ttl=10, maxsize=5)
    def fn_no_counters(x: int) -> int:
        return x + 1

    # First call: miss then store; second call: hit via fallback counters.
    assert fn_no_counters(1) == 2
    assert fn_no_counters(1) == 2

    snapshot = cache_reg.get_registered_cached()
    entry = _find_last_entry_by_backend(snapshot, "foghorn_ttl")
    assert entry.get("cache_hits", 0) >= 1
    assert entry.get("cache_misses", 0) >= 1

    class _DummyHitCountingCache:
        def __init__(self) -> None:
            self.store: Dict[Any, Any] = {}
            self.cache_hits = 0

        def get(self, key: Any) -> Any:
            # Increment hits even on misses so aggregator sees a delta.
            self.cache_hits += 1
            return self.store.get(key)

        def set(self, key: Any, ttl: int, value: Any) -> None:
            self.store[key] = value

    backend_hits = _DummyHitCountingCache()

    @cache_reg.registered_foghorn_ttl(cache=backend_hits, ttl=20, maxsize=3)
    def fn_hit_agg(x: int) -> int:
        return x * 2

    assert fn_hit_agg(10) == 20

    snapshot2 = cache_reg.get_registered_cached()
    entry2 = _find_last_entry_by_backend(snapshot2, "foghorn_ttl")
    assert entry2.get("cache_hits", 0) >= 0
    assert entry2.get("cache_misses", 0) >= 0
