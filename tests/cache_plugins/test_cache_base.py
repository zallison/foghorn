"""Brief: Unit tests for foghorn.cache_plugins.base.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import pytest

from foghorn.cache_plugins.base import CachePlugin, cache_aliases
from foghorn.cache_plugins.in_memory_ttl import InMemoryTTLCachePlugin


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
    """Brief: InMemoryTTLCachePlugin snapshot exposes per-cache counters.

    Inputs:
      - None.

    Outputs:
      - None; asserts get_http_snapshot() returns counter fields for primary cache.
    """

    plugin = InMemoryTTLCachePlugin()

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
