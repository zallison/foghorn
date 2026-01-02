"""Brief: Unit tests for src.foghorn.utils.current_cache helpers.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import sys
import types
from typing import Any, Optional, Tuple

import pytest

import foghorn.utils.current_cache as current_cache_module
from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache
from foghorn.utils.current_cache import (
    TTLCacheAdapter,
    get_current_namespaced_cache,
    module_namespace,
)
from foghorn.plugins.cache.base import CachePlugin
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache


class _FakeBackendWithMeta:
    """Brief: Simple backend exposing get/get_with_meta/set/purge.

    Inputs:
      - None.

    Outputs:
      - _FakeBackendWithMeta instance.
    """

    def __init__(self) -> None:
        self.get_calls: list[Tuple[Any]] = []
        self.set_calls: list[Tuple[Any, int, Any]] = []
        self.purge_calls = 0

    def get(self, key: Any) -> Any | None:
        """Brief: Record and return a fixed value for tests.

        Inputs:
          - key: Cache key.

        Outputs:
          - Any | None: Fixed value to assert against.
        """

        self.get_calls.append((key,))
        return "value-for-" + repr(key)

    def get_with_meta(
        self, key: Any
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Return a tuple that includes the key for easy assertions.

        Inputs:
          - key: Cache key.

        Outputs:
          - (value, remaining, ttl): Synthetic metadata for testing.
        """

        return ("meta-" + repr(key), 123.0, 60)

    def set(self, key: Any, ttl: int, value: Any) -> None:
        """Brief: Record set calls for verification.

        Inputs:
          - key: Cache key.
          - ttl: Time-to-live seconds.
          - value: Stored value.

        Outputs:
          - None.
        """

        self.set_calls.append((key, ttl, value))

    def purge(self) -> int:
        """Brief: Increment a counter and return it.

        Inputs:
          - None.

        Outputs:
          - int: Number of purge calls recorded.
        """

        self.purge_calls += 1
        return self.purge_calls


class _FakeBackendPurgeExpiredOnly:
    """Brief: Backend that exposes purge_expired but not purge.

    Inputs:
      - None.

    Outputs:
      - _FakeBackendPurgeExpiredOnly instance.
    """

    def __init__(self) -> None:
        self.purged = 0

    def purge_expired(self) -> int:
        """Brief: Simulate purging a fixed number of entries.

        Inputs:
          - None.

        Outputs:
          - int: Synthetic number of removed entries.
        """

        self.purged += 3
        return self.purged


class _DummyCachePlugin(CachePlugin):
    """Brief: Minimal CachePlugin implementation for adapter tests.

    Inputs:
      - None.

    Outputs:
      - _DummyCachePlugin instance.
    """

    def __init__(self) -> None:
        self._store: dict[Any, Any] = {}

    def get(self, key: Tuple[str, int]) -> Any | None:  # type: ignore[override]
        """Brief: Simple dict-backed get.

        Inputs:
          - key: Cache key.

        Outputs:
          - Any | None: Cached value.
        """

        return self._store.get(key)

    def get_with_meta(  # type: ignore[override]
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Return value with dummy metadata for tests.

        Inputs:
          - key: Cache key.

        Outputs:
          - (value, remaining, ttl): Value with placeholder metadata.
        """

        value = self._store.get(key)
        return value, None, None

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:  # type: ignore[override]
        """Brief: Store a value ignoring TTL for unit tests.

        Inputs:
          - key: Cache key.
          - ttl: Time-to-live seconds (ignored).
          - value: Cached value.

        Outputs:
          - None.
        """

        self._store[key] = value

    def purge(self) -> int:  # type: ignore[override]
        """Brief: Clear the store and report removed count.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed.
        """

        removed = len(self._store)
        self._store.clear()
        return removed


def test_ttl_cache_adapter_delegates_basic_methods() -> None:
    """Brief: TTLCacheAdapter forwards get/set calls to the backend.

    Inputs:
      - None.

    Outputs:
      - None; asserts delegation and value propagation.
    """

    backend = _FakeBackendWithMeta()
    adapter = TTLCacheAdapter(backend)

    adapter.set("k", 5, "v")
    assert backend.set_calls == [("k", 5, "v")]

    value = adapter.get("k")
    assert value == "value-for-'k'"
    assert backend.get_calls == [("k",)]


def test_ttl_cache_adapter_get_with_meta_prefers_backend_impl() -> None:
    """Brief: get_with_meta uses backend implementation when available.

    Inputs:
      - None.

    Outputs:
      - None; asserts adapter returns backend tuple unchanged.
    """

    backend = _FakeBackendWithMeta()
    adapter = TTLCacheAdapter(backend)

    value, remaining, ttl = adapter.get_with_meta("key")
    assert value == "meta-'key'"
    assert remaining == pytest.approx(123.0)
    assert ttl == 60


def test_ttl_cache_adapter_get_with_meta_falls_back_to_get() -> None:
    """Brief: get_with_meta falls back to get() when backend lacks helper.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback tuple when get_with_meta is absent.
    """

    class _BackendNoMeta:
        def get(self, key: Any) -> Any | None:  # pragma: no cover - trivial
            return "value-" + repr(key)

    adapter = TTLCacheAdapter(_BackendNoMeta())

    value, remaining, ttl = adapter.get_with_meta("k")
    assert value == "value-'k'"
    assert remaining is None
    assert ttl is None


def test_ttl_cache_adapter_purge_prefers_purge_over_purge_expired() -> None:
    """Brief: purge() prefers backend.purge() when present.

    Inputs:
      - None.

    Outputs:
      - None; asserts backend purge() is used.
    """

    backend = _FakeBackendWithMeta()
    adapter = TTLCacheAdapter(backend)

    assert adapter.purge() == 1
    assert adapter.purge() == 2


def test_ttl_cache_adapter_purge_uses_purge_expired_when_needed() -> None:
    """Brief: purge() falls back to purge_expired() when purge is missing.

    Inputs:
      - None.

    Outputs:
      - None; asserts purge_expired() return value is propagated.
    """

    backend = _FakeBackendPurgeExpiredOnly()
    adapter = TTLCacheAdapter(backend)

    assert adapter.purge() == 3
    assert adapter.purge() == 6


def test_ttl_cache_adapter_purge_returns_zero_when_backend_has_no_helpers() -> None:
    """Brief: purge() returns 0 when backend is missing purge helpers.

    Inputs:
      - None.

    Outputs:
      - None; asserts defensive 0 return value.
    """

    class _BackendNoPurge:
        def get(self, key: Any) -> Any | None:  # pragma: no cover - trivial
            return None

    adapter = TTLCacheAdapter(_BackendNoPurge())
    assert adapter.purge() == 0


@pytest.mark.parametrize(
    "path, expected",
    [
        ("/a/b/filter.py", "filter"),
        ("module.py", "module"),
        ("no_suffix", "no_suffix"),
    ],
)
def test_module_namespace_returns_stem(path: str, expected: str) -> None:
    """Brief: module_namespace returns the filename stem without extension.

    Inputs:
      - path: Arbitrary path-like string.
      - expected: Expected namespace string.

    Outputs:
      - None; asserts conversion matches expectation.
    """

    assert module_namespace(path) == expected


def test_get_current_namespaced_cache_with_in_memory_plugin_shares_store() -> None:
    """Brief: InMemoryTTLCache yields a namespaced FoghornTTLCache view.

    Inputs:
      - None.

    Outputs:
      - None; asserts namespaced views share backing store but isolate keys.
    """

    plugin = InMemoryTTLCache()

    adapter_a = get_current_namespaced_cache(namespace="ns-a", cache_plugin=plugin)
    adapter_b = get_current_namespaced_cache(namespace="ns-b", cache_plugin=plugin)

    assert isinstance(adapter_a, TTLCacheAdapter)
    assert isinstance(adapter_b, TTLCacheAdapter)

    backend_a = adapter_a._backend  # type: ignore[attr-defined]
    backend_b = adapter_b._backend  # type: ignore[attr-defined]

    assert isinstance(backend_a, FoghornTTLCache)
    assert isinstance(backend_b, FoghornTTLCache)
    assert backend_a.namespace == "ns-a"
    assert backend_b.namespace == "ns-b"

    key = ("example.com", 1)
    adapter_a.set(key, 60, b"A")
    adapter_b.set(key, 60, b"B")

    assert adapter_a.get(key) == b"A"
    assert adapter_b.get(key) == b"B"


def test_get_current_namespaced_cache_with_cache_plugin_wraps_plugin() -> None:
    """Brief: Generic CachePlugin instances are wrapped directly.

    Inputs:
      - None.

    Outputs:
      - None; asserts adapter backend is the plugin instance.
    """

    plugin = _DummyCachePlugin()
    adapter = get_current_namespaced_cache(namespace="ignored", cache_plugin=plugin)

    assert isinstance(adapter, TTLCacheAdapter)
    assert adapter._backend is plugin  # type: ignore[attr-defined]

    key = ("example.org", 1)
    adapter.set(key, 30, b"payload")
    assert adapter.get(key) == b"payload"


def test_get_current_namespaced_cache_falls_back_to_in_memory_when_unknown_backend() -> (
    None
):
    """Brief: Unknown backends yield a new FoghornTTLCache per namespace.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback creates a namespaced FoghornTTLCache.
    """

    adapter = get_current_namespaced_cache(
        namespace="ns-fallback", cache_plugin=object()
    )

    assert isinstance(adapter, TTLCacheAdapter)
    backend = adapter._backend  # type: ignore[attr-defined]
    assert isinstance(backend, FoghornTTLCache)
    assert backend.namespace == "ns-fallback"

    key = ("example.net", 1)
    adapter.set(key, 10, b"v")
    assert adapter.get(key) == b"v"


def test_get_current_namespaced_cache_with_sqlite_plugin_uses_sqlite_backend(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """Brief: SQLite3Cache yields a SQLite3TTLCache-backed adapter.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture used to inject test doubles.
      - tmp_path: Pytest temporary path fixture used to build a DB path.

    Outputs:
      - None; asserts that get_current_namespaced_cache constructs a
        SQLite3TTLCache with the expected arguments when a sqlite plugin is
        active.
    """

    # Ensure the module import used inside get_current_namespaced_cache
    # succeeds by registering a synthetic foghorn.plugins.cache.sqlite_cache
    # module exporting SQLite3Cache.
    sqlite3_cache_mod = types.ModuleType("foghorn.plugins.cache.sqlite_cache")

    class _StubInnerCache:
        """Brief: Minimal inner cache exposing journal_mode for tests.

        Inputs:
          - journal_mode: Journal mode string to expose.

        Outputs:
          - _StubInnerCache instance.
        """

        def __init__(self, journal_mode: str = "TRUNCATE") -> None:
            self.journal_mode = journal_mode

    class _StubSQLite3Cache:
        """Brief: Lightweight SQLite plugin stand-in used by tests.

        Inputs:
          - db_path: Database path string.

        Outputs:
          - _StubSQLite3Cache instance.
        """

        def __init__(self, db_path: str) -> None:
            self.db_path = db_path
            self._cache = _StubInnerCache()

    sqlite3_cache_mod.SQLite3Cache = _StubSQLite3Cache
    monkeypatch.setitem(
        sys.modules, "foghorn.plugins.cache.sqlite_cache", sqlite3_cache_mod
    )

    recorded: dict[str, object] = {}

    class _RecordingSQLite3TTLCache:
        """Brief: Test double that records constructor arguments.

        Inputs:
          - db_path: Database path passed to the TTL cache.
          - namespace: Logical namespace/table name.
          - journal_mode: Journal mode string.
          - create_dir: Whether directory creation was requested.

        Outputs:
          - _RecordingSQLite3TTLCache instance.
        """

        def __init__(
            self,
            db_path: str,
            *,
            namespace: str,
            journal_mode: str,
            create_dir: bool,
        ) -> None:
            recorded["db_path"] = db_path
            recorded["namespace"] = namespace
            recorded["journal_mode"] = journal_mode
            recorded["create_dir"] = create_dir

    monkeypatch.setattr(
        current_cache_module,
        "SQLite3TTLCache",
        _RecordingSQLite3TTLCache,
    )

    db_path = str(tmp_path / "subdir" / "dns_cache.sqlite3")
    plugin = _StubSQLite3Cache(db_path=db_path)

    adapter = get_current_namespaced_cache(
        namespace="my_namespace", cache_plugin=plugin
    )

    assert isinstance(adapter, TTLCacheAdapter)
    assert recorded["db_path"] == db_path
    assert recorded["namespace"] == "my_namespace"
    assert recorded["journal_mode"] == "TRUNCATE"
    assert recorded["create_dir"] is True


def test_get_current_namespaced_cache_with_sqlite_plugin_missing_db_path_uses_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: sqlite plugin with empty db_path falls back to in-memory cache.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture used to inject test doubles.

    Outputs:
      - None; asserts the defensive FoghornTTLCache fallback is used when the
        sqlite plugin has no usable db_path.
    """

    sqlite3_cache_mod = types.ModuleType("foghorn.plugins.cache.sqlite_cache")

    class _StubInnerCacheNoJournal:
        """Brief: Inner cache without journal_mode, forcing default handling.

        Inputs:
          - None.

        Outputs:
          - _StubInnerCacheNoJournal instance.
        """

        def __init__(self) -> None:
            self.calls = 0

    class _StubSQLite3CacheEmptyDb:
        """Brief: sqlite plugin stand-in that exposes an empty db_path.

        Inputs:
          - None.

        Outputs:
          - _StubSQLite3CacheEmptyDb instance.
        """

        def __init__(self) -> None:
            self.db_path = ""
            self._cache = _StubInnerCacheNoJournal()

    sqlite3_cache_mod.SQLite3Cache = _StubSQLite3CacheEmptyDb
    monkeypatch.setitem(
        sys.modules, "foghorn.plugins.cache.sqlite_cache", sqlite3_cache_mod
    )

    def _fail_if_called(*_args: object, **_kwargs: object) -> None:
        """Brief: Helper that raises if the sqlite TTL cache is constructed.

        Inputs:
          - *_args: Positional arguments.
          - **_kwargs: Keyword arguments.

        Outputs:
          - None; always raises AssertionError to detect incorrect code paths.
        """

        raise AssertionError("SQLite3TTLCache should not be constructed")

    monkeypatch.setattr(current_cache_module, "SQLite3TTLCache", _fail_if_called)

    plugin = _StubSQLite3CacheEmptyDb()

    adapter = get_current_namespaced_cache(namespace="ns-empty", cache_plugin=plugin)

    assert isinstance(adapter, TTLCacheAdapter)
    backend = adapter._backend  # type: ignore[attr-defined]
    assert isinstance(backend, FoghornTTLCache)
