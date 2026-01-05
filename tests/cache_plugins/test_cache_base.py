"""Brief: Unit tests for foghorn.plugins.cache.base.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import time

import pytest

from foghorn.plugins.cache.base import CachePlugin, cache_aliases
from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache


def test_cache_aliases_decorator_sets_aliases_and_returns_class() -> None:
    """Brief: cache_aliases decorator attaches tuple aliases and returns the class.

    Inputs:
      - None.

    Outputs:
      - None; asserts the aliases attribute is set and decorator returns the class.
    """

    @cache_aliases("none", "off")
    class C(CachePlugin):
        def get(self, key):  # type: ignore[no-untyped-def]
            return None

        def get_with_meta(self, key):  # type: ignore[no-untyped-def]
            return (None, None, None)

        def set(self, key, ttl, value):  # type: ignore[no-untyped-def]
            return None

        def purge(self) -> int:
            return 0

    assert C.aliases == ("none", "off")


def test_cache_aliases_decorator_empty_produces_empty_tuple() -> None:
    """Brief: cache_aliases() with no args produces an empty tuple.

    Inputs:
      - None.

    Outputs:
      - None; asserts aliases becomes ().
    """

    @cache_aliases()
    class C(CachePlugin):
        def get(self, key):  # type: ignore[no-untyped-def]
            return None

        def get_with_meta(self, key):  # type: ignore[no-untyped-def]
            return (None, None, None)

        def set(self, key, ttl, value):  # type: ignore[no-untyped-def]
            return None

        def purge(self) -> int:
            return 0

    assert C.aliases == ()


def test_cache_plugin_default_aliases_empty() -> None:
    """Brief: CachePlugin base class defaults aliases to empty tuple.

    Inputs:
      - None.

    Outputs:
      - None; asserts default is ().
    """

    assert CachePlugin.aliases == ()


def test_cache_plugin_methods_raise_not_implemented() -> None:
    """Brief: CachePlugin abstract methods raise NotImplementedError.

    Inputs:
      - None.

    Outputs:
      - None; asserts NotImplementedError is raised for base methods.
    """

    c = CachePlugin()

    with pytest.raises(NotImplementedError, match=r"CachePlugin\.get\(\)"):
        c.get(("example.com", 1))

    with pytest.raises(NotImplementedError, match=r"CachePlugin\.get_with_meta\(\)"):
        c.get_with_meta(("example.com", 1))

    with pytest.raises(NotImplementedError, match=r"CachePlugin\.set\(\)"):
        c.set(("example.com", 1), 60, b"wire")

    with pytest.raises(NotImplementedError, match=r"CachePlugin\.purge\(\)"):
        c.purge()


def test_in_memory_ttl_cache_snapshot_includes_counters() -> None:
    """Brief: InMemoryTTLCache snapshot exposes per-cache counters.

    Inputs:
      - None.

    Outputs:
      - None; asserts get_http_snapshot() returns counter fields for primary cache.
    """

    plugin = InMemoryTTLCache()

    # Exercise the cache to ensure counters are non-zero.
    key = ("example.com", 1)
    plugin.set(key, 60, b"wire-bytes")
    assert plugin.get(key) == b"wire-bytes"
    assert plugin.get(("other.com", 1)) is None

    snap = plugin.get_http_snapshot()
    assert "summary" in snap
    assert "caches" in snap

    summary = snap["summary"]
    assert isinstance(summary, dict)
    # Counter keys should be present when the backend exposes them.
    assert "calls_total" in summary
    assert "cache_hits" in summary
    assert "cache_misses" in summary

    caches = snap["caches"]
    assert isinstance(caches, list) and caches
    primary = caches[0]
    assert "label" in primary and "dns_cache" in primary["label"]
    assert "calls_total" in primary


def test_in_memory_ttl_cache_counts_expired_and_malformed_entries(monkeypatch) -> None:
    """Brief: get_http_snapshot counts expired and malformed entries correctly.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts malformed expiry is treated as expired and past entries counted.
    """

    plugin = InMemoryTTLCache()

    # Directly mutate the underlying store to inject various expiry shapes.
    store = getattr(plugin._cache, "_store")
    now = time.time()
    # Live entry (expiry in future), expired entry (expiry in past), malformed expiry.
    store[("live.com", 1)] = (now + 10.0, b"live")
    store[("expired.com", 1)] = (now - 10.0, b"expired")
    store[("bad.com", 1)] = ("not-a-float", b"bad")

    snap = plugin.get_http_snapshot()
    summary = snap["summary"]
    assert summary["total_entries"] == 3
    assert summary["live_entries"] == 1
    assert summary["expired_entries"] == 2


def test_in_memory_ttl_cache_snapshot_includes_plugin_targets_and_decorated(
    monkeypatch,
) -> None:
    """Brief: Snapshot includes per-plugin targets and decorated registry entries.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts caches include plugin_targets rows and decorated rows honor registry.
    """

    plugin = InMemoryTTLCache()

    # Fake a plugin with a FoghornTTLCache-style _targets_cache.
    from foghorn.plugins.cache.backends.foghorn_ttl import FoghornTTLCache

    targets_cache = FoghornTTLCache()
    targets_cache.set(("targets.com", 1), 60, b"wire")

    class FakePlugin:
        name = "fake_plugin"
        _targets_cache = targets_cache

    from foghorn.servers import udp_server as udp_mod

    monkeypatch.setattr(udp_mod.DNSUDPHandler, "plugins", [FakePlugin()])

    # Fake decorated registry entries.
    import foghorn.utils.register_caches as reg_mod

    good_entry = {
        "module": "foghorn.example",
        "name": "fn",
        "ttl": 30,
        "backend": "ttlcache",
        "maxsize": 128,
        "size_current": 10,
        "calls_total": 5,
        "cache_hits": 3,
        "cache_misses": 2,
    }
    bad_entry = {"module": "", "name": ""}

    def _fake_get_registered_cached():
        return [good_entry, bad_entry]

    monkeypatch.setattr(reg_mod, "get_registered_cached", _fake_get_registered_cached)

    snap = plugin.get_http_snapshot()

    caches = snap["caches"]
    assert any(row["label"] == "plugin_targets:fake_plugin" for row in caches)

    decorated = snap["decorated"]
    assert any(row["module"] == "foghorn.example" for row in decorated)
    # Hit percentage should be computed from hits/misses for the decorated row.
    decorated_row = next(r for r in decorated if r["module"] == "foghorn.example")
    assert decorated_row["hit_pct"] == 60.0


def test_in_memory_ttl_cache_purge_and_admin_descriptor() -> None:
    """Brief: purge() returns an int and admin descriptor has expected shape.

    Inputs:
      - None.

    Outputs:
      - None; asserts purge() succeeds and admin UI descriptor has sections.
    """

    plugin = InMemoryTTLCache()

    # purge() delegates to backing cache and returns an int.
    assert isinstance(plugin.purge(), int)

    desc = plugin.get_admin_ui_descriptor()
    assert desc["kind"] == "cache_memory"
    assert "layout" in desc and isinstance(desc["layout"], dict)
    sections = desc["layout"].get("sections")
    assert isinstance(sections, list) and sections
