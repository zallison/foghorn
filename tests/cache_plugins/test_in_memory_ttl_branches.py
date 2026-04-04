"""Brief: Branch-focused tests for InMemoryTTLCache edge and defensive paths.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import builtins
import time
from typing import Any

import pytest

from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache


class _ExplodingLock:
    """Brief: Context manager that raises on enter for defensive branch tests.

    Inputs:
      - None.

    Outputs:
      - _ExplodingLock instance.
    """

    def __enter__(self) -> None:
        raise RuntimeError("lock-enter-failed")

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        tb: object,
    ) -> bool:
        return False


class _DeleteCacheAttrFail:
    """Brief: Cache double that raises when _ns_key is introspected.

    Inputs:
      - None.

    Outputs:
      - _DeleteCacheAttrFail instance.
    """

    @property
    def _ns_key(self) -> Any:
        raise RuntimeError("ns-key-introspection-failed")


class _DeleteCacheNonDictStore:
    """Brief: Cache double with non-dict _store for early-return branch.

    Inputs:
      - None.

    Outputs:
      - _DeleteCacheNonDictStore instance.
    """

    _lock = None
    _store: list[object] = []

    @staticmethod
    def _ns_key(key: tuple[str, int]) -> tuple[str, int]:
        return key


class _DeleteCacheNoLock:
    """Brief: Cache double that exercises no-lock metadata removal path.

    Inputs:
      - key: Cache key pre-populated in all metadata maps.

    Outputs:
      - _DeleteCacheNoLock instance.
    """

    def __init__(self, key: tuple[str, int]) -> None:
        self._lock = None
        self._store = {key: (time.time() + 10.0, b"v")}
        self._ttls = {key: 10}
        self._last_access = {key: 1}
        self._hit_counts = {key: 1}
        self._insert_index = {key: 1}

    @staticmethod
    def _ns_key(key: tuple[str, int]) -> tuple[str, int]:
        return key


class _DeleteCacheBadLock(_DeleteCacheNoLock):
    """Brief: Cache double that raises while entering lock context."""

    def __init__(self, key: tuple[str, int]) -> None:
        super().__init__(key)
        self._lock = _ExplodingLock()


class _DeleteCacheNoLockPopFail(_DeleteCacheNoLock):
    """Brief: Cache double that raises on store.pop in the no-lock path."""

    def __init__(self, key: tuple[str, int]) -> None:
        super().__init__(key)

        class _RaisePopDict(dict):
            def pop(self, __key: object, __default: object = None) -> object:  # type: ignore[override]
                raise RuntimeError("store-pop-failed")

        self._store = _RaisePopDict(self._store)


class _SnapshotStoreAttrFailCache:
    """Brief: Cache double that raises when reading _store."""

    namespace = "default"
    calls_total = 0
    cache_hits = 0
    cache_misses = 0
    _lock = None

    @property
    def _store(self) -> object:
        raise RuntimeError("store-introspection-failed")


class _SnapshotBadLockCache:
    """Brief: Cache double that raises while lock-protected counting runs."""

    namespace = "default"
    calls_total = 0
    cache_hits = 0
    cache_misses = 0

    def __init__(self) -> None:
        self._store = {("live.example", 1): (time.time() + 30.0, b"data")}
        self._lock = _ExplodingLock()


class _SnapshotNonDictStoreCache:
    """Brief: Cache double with non-dict _store and no lock."""

    namespace = "default"
    calls_total = 0
    cache_hits = 0
    cache_misses = 0
    _lock = None

    def __init__(self) -> None:
        self._store = [("bad", "shape")]


class _BadAddInt(int):
    """Brief: int subclass that raises on addition for defensive math branches."""

    def __add__(self, other: object) -> int:
        raise RuntimeError("addition-failed")


class _SummarizeAttrFailCache:
    """Brief: Cache row source that raises during _store/_lock introspection."""

    calls_total = 1
    cache_hits = 0
    cache_misses = 1

    @property
    def _store(self) -> object:
        raise RuntimeError("target-store-introspection-failed")

    @property
    def _lock(self) -> object:
        raise RuntimeError("target-lock-introspection-failed")


class _SummarizeBadLockCache:
    """Brief: Cache row source with dict store but failing lock context."""

    calls_total = 3
    cache_hits = 1
    cache_misses = 2

    def __init__(self) -> None:
        self._store = {("a.example", 1): (time.time() + 20.0, b"wire")}
        self._lock = _ExplodingLock()


class _SummarizeDictNoLockCache:
    """Brief: Cache row source with dict store and no lock."""

    calls_total = 2
    cache_hits = 1
    cache_misses = 1
    _lock = None

    def __init__(self) -> None:
        self._store = {("nolock.example", 1): (time.time() + 15.0, b"wire")}


class _LenOnlyCache:
    """Brief: Non-TTL mapping-style cache source for len()-fallback branches."""

    def __init__(self, length: int, *, hits: int, misses: int) -> None:
        self._length = int(length)
        self.calls_total = 0
        self.cache_hits = hits
        self.cache_misses = misses

    def __len__(self) -> int:
        return self._length


class _PluginWithTargets:
    """Brief: Runtime plugin double exposing _targets_cache and name."""

    def __init__(self, name: str, cache: object) -> None:
        self.name = name
        self._targets_cache = cache


class _PluginTargetsAttrError:
    """Brief: Runtime plugin double that raises when _targets_cache is read."""

    name = "targets_attr_error"

    @property
    def _targets_cache(self) -> object:
        raise RuntimeError("targets-attr-failed")


class _PluginWithoutTargets:
    """Brief: Runtime plugin double with no _targets_cache payload."""

    name = "no_targets"
    _targets_cache = None


class _PluginNameAttrError:
    """Brief: Runtime plugin double that raises when name is read."""

    def __init__(self, cache: object) -> None:
        self._targets_cache = cache

    @property
    def name(self) -> str:
        raise RuntimeError("name-attr-failed")


class _BadDecoratedEntry:
    """Brief: Decorated-cache row source that raises when get() is used."""

    def get(self, *_args: object, **_kwargs: object) -> object:
        raise RuntimeError("decorated-entry-get-failed")


def test_init_and_wire_type_guard_edge_cases() -> None:
    """Brief: Invalid numeric config values and non-bytes wire payload are safe.

    Inputs:
      - None.

    Outputs:
      - None; asserts defaults/fallbacks for coercion and wire type guard.
    """

    plugin = InMemoryTTLCache(
        min_cache_ttl=object(),
        max_size=object(),
        pct_nxdomain=object(),
    )

    assert plugin.min_cache_ttl == 0
    assert plugin.max_size == 65536
    assert plugin.pct_nxdomain == pytest.approx(0.10)
    assert InMemoryTTLCache._is_nxdomain_wire("not-wire-bytes") is False


def test_delete_helper_defensive_and_no_lock_paths() -> None:
    """Brief: Delete helper handles defensive failures and metadata cleanup.

    Inputs:
      - None.

    Outputs:
      - None; asserts no-lock deletion cleans all maps and defensive paths do not crash.
    """

    key = ("example.com", 1)

    InMemoryTTLCache._delete_from_foghorn_ttl(_DeleteCacheAttrFail(), key)
    InMemoryTTLCache._delete_from_foghorn_ttl(_DeleteCacheNonDictStore(), key)

    no_lock_cache = _DeleteCacheNoLock(key)
    InMemoryTTLCache._delete_from_foghorn_ttl(no_lock_cache, key)
    assert key not in no_lock_cache._store
    assert key not in no_lock_cache._ttls
    assert key not in no_lock_cache._last_access
    assert key not in no_lock_cache._hit_counts
    assert key not in no_lock_cache._insert_index

    bad_lock_cache = _DeleteCacheBadLock(key)
    InMemoryTTLCache._delete_from_foghorn_ttl(bad_lock_cache, key)

    pop_fail_cache = _DeleteCacheNoLockPopFail(key)
    InMemoryTTLCache._delete_from_foghorn_ttl(pop_fail_cache, key)


def test_get_and_get_with_meta_no_nxdomain_partition() -> None:
    """Brief: Missing-key lookups return None tuple when NXDOMAIN cache is absent.

    Inputs:
      - None.

    Outputs:
      - None; asserts fallback-to-None behavior for get() and get_with_meta().
    """

    plugin = InMemoryTTLCache(max_size=4, pct_nxdomain=0.0)

    assert plugin._cache_nxdomain is None
    assert plugin.get(("missing.example", 1)) is None
    assert plugin.get_with_meta(("missing.example", 1)) == (None, None, None)


def test_get_with_meta_primary_and_nxdomain_hits() -> None:
    """Brief: get_with_meta returns hits from primary and NXDOMAIN partitions.

    Inputs:
      - None.

    Outputs:
      - None; asserts primary-hit and NXDOMAIN-partition fallback paths.
    """

    from dnslib import RCODE, DNSRecord

    plugin = InMemoryTTLCache(max_size=10, pct_nxdomain=0.5)

    primary_key = ("primary.example", 1)
    plugin.set(primary_key, 60, b"primary-wire")
    value_primary, _remaining_primary, ttl_primary = plugin.get_with_meta(primary_key)
    assert value_primary == b"primary-wire"
    assert ttl_primary == 60

    q = DNSRecord.question("nxmeta.example")
    nx_reply = q.reply()
    nx_reply.header.rcode = RCODE.NXDOMAIN

    nxdomain_key = ("nxmeta.example", 1)
    plugin.set(nxdomain_key, 60, nx_reply.pack())
    value_nx, _remaining_nx, ttl_nx = plugin.get_with_meta(nxdomain_key)
    assert isinstance(value_nx, (bytes, bytearray))
    assert ttl_nx == 60


def test_snapshot_primary_cache_attr_and_lock_defensive_paths() -> None:
    """Brief: Snapshot tolerates primary cache introspection and lock failures.

    Inputs:
      - None.

    Outputs:
      - None; asserts snapshot remains available with zeroed counts.
    """

    plugin = InMemoryTTLCache()

    plugin._cache = _SnapshotStoreAttrFailCache()  # type: ignore[assignment]
    snap_attr_fail = plugin.get_http_snapshot()
    assert snap_attr_fail["summary"]["total_entries"] == 0

    plugin._cache = _SnapshotBadLockCache()  # type: ignore[assignment]
    snap_lock_fail = plugin.get_http_snapshot()
    assert snap_lock_fail["summary"]["total_entries"] == 0

    plugin._cache = _SnapshotNonDictStoreCache()  # type: ignore[assignment]
    snap_non_dict = plugin.get_http_snapshot()
    assert snap_non_dict["summary"]["total_entries"] == 0


def test_snapshot_counts_malformed_entry_shapes_as_expired() -> None:
    """Brief: Snapshot treats malformed store value shapes as expired entries.

    Inputs:
      - None.

    Outputs:
      - None; asserts malformed tuple/list payloads are counted as expired, not fatal.
    """

    plugin = InMemoryTTLCache()
    store = getattr(plugin._cache, "_store")
    now = time.time()

    store[("good.example", 1)] = (now + 20.0, b"good")
    store[("bad-str.example", 1)] = "not-a-tuple"
    store[("bad-empty.example", 1)] = ()

    snapshot = plugin.get_http_snapshot()
    summary = snapshot["summary"]

    assert summary["total_entries"] == 3
    assert summary["live_entries"] == 1
    assert summary["expired_entries"] == 2


def test_snapshot_nxdomain_cache_attr_and_lock_defensive_paths() -> None:
    """Brief: Snapshot tolerates NXDOMAIN partition introspection/lock failures.

    Inputs:
      - None.

    Outputs:
      - None; asserts snapshot still renders summary/caches payloads.
    """

    plugin = InMemoryTTLCache(max_size=10, pct_nxdomain=0.5)
    assert plugin._cache_nxdomain is not None

    plugin._cache_nxdomain = _SnapshotStoreAttrFailCache()  # type: ignore[assignment]
    snap_attr_fail = plugin.get_http_snapshot()
    assert isinstance(snap_attr_fail["caches"], list)

    plugin._cache_nxdomain = _SnapshotBadLockCache()  # type: ignore[assignment]
    snap_lock_fail = plugin.get_http_snapshot()
    assert isinstance(snap_lock_fail["caches"], list)


def test_snapshot_plugin_targets_and_decorated_defensive_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Snapshot covers plugin target/decorated defensive branches.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts defensive plugin/decorated rows are tolerated and filtered.
    """

    plugin = InMemoryTTLCache()

    from foghorn.servers import dns_runtime_state as runtime_state_mod

    monkeypatch.setattr(
        runtime_state_mod.DNSRuntimeState,
        "plugins",
        [
            _PluginTargetsAttrError(),
            _PluginWithoutTargets(),
            _PluginWithTargets("attr_fail_cache", _SummarizeAttrFailCache()),
            _PluginWithTargets("bad_lock_cache", _SummarizeBadLockCache()),
            _PluginWithTargets("dict_nolock_cache", _SummarizeDictNoLockCache()),
            _PluginWithTargets(
                "len_cache",
                _LenOnlyCache(length=3, hits=_BadAddInt(2), misses=1),
            ),
            _PluginNameAttrError(_LenOnlyCache(length=1, hits=0, misses=0)),
        ],
    )

    import foghorn.utils.register_caches as register_caches_mod

    monkeypatch.setattr(
        register_caches_mod,
        "get_registered_cached",
        lambda: [
            _BadDecoratedEntry(),
            {
                "module": "foghorn.example",
                "name": "decorated_fn",
                "backend": "ttlcache",
                "cache_hits": _BadAddInt(3),
                "cache_misses": 1,
            },
        ],
    )

    snapshot = plugin.get_http_snapshot()

    labels = {str(row["label"]) for row in snapshot["caches"]}
    assert "plugin_targets:attr_fail_cache" in labels
    assert "plugin_targets:bad_lock_cache" in labels
    assert "plugin_targets:dict_nolock_cache" in labels
    assert "plugin_targets:len_cache" in labels
    assert "plugin_targets:_PluginNameAttrError" in labels
    assert "plugin_targets:no_targets" not in labels

    decorated = snapshot["decorated"]
    assert len(decorated) == 1
    assert decorated[0]["module"] == "foghorn.example"
    assert decorated[0]["name"] == "decorated_fn"
    assert decorated[0]["hit_pct"] is None


def test_snapshot_import_fallbacks_for_runtime_plugins_and_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Brief: Snapshot import failures degrade gracefully to empty plugin/decorated data.

    Inputs:
      - monkeypatch: Pytest monkeypatch fixture.

    Outputs:
      - None; asserts import exceptions do not break snapshot response.
    """

    plugin = InMemoryTTLCache()
    real_import = builtins.__import__

    def _fake_import(
        name: str,
        globals: dict[str, object] | None = None,
        locals: dict[str, object] | None = None,
        fromlist: tuple[object, ...] = (),
        level: int = 0,
    ) -> Any:
        if name in {
            "foghorn.servers.dns_runtime_state",
            "foghorn.utils.register_caches",
        }:
            raise RuntimeError("simulated-import-failure")
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr(builtins, "__import__", _fake_import)
    snapshot = plugin.get_http_snapshot()

    assert isinstance(snapshot["caches"], list)
    assert snapshot["decorated"] == []
