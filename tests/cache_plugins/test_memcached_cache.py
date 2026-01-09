"""Brief: Unit tests for the Memcached-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict
import sys
import time as _time_mod

import pytest

from foghorn.plugins.cache import memcached_cache as memcached_cache_mod
from foghorn.plugins.cache.registry import get_cache_plugin_class, load_cache_plugin


class FakeMemcachedClient:
    """Brief: Minimal in-memory Memcached client substitute for tests.

    Inputs:
      - server: (host, port) pair.
      - connect_timeout: Optional connect timeout seconds.
      - timeout: Optional operation timeout seconds.

    Outputs:
      - FakeMemcachedClient instance that tracks key/value blobs in memory.
    """

    def __init__(
        self,
        server: tuple[str, int],
        *,
        connect_timeout: float | None = None,
        timeout: float | None = None,
    ) -> None:
        self.server = server
        self.connect_timeout = connect_timeout
        self.timeout = timeout
        self.store: Dict[str, bytes] = {}

    def get(self, key: str) -> bytes | None:
        """Brief: Return a stored value for key.

        Inputs:
          - key: Memcached key string.

        Outputs:
          - bytes | None: Stored blob when present; otherwise None.
        """

        return self.store.get(key)

    def set(self, key: str, value: bytes, expire: int | None = None) -> None:
        """Brief: Store a value for key.

        Inputs:
          - key: Memcached key string.
          - value: Blob to store.
          - expire: Expiry in seconds (ignored; plugin enforces TTL itself).

        Outputs:
          - None.
        """

        self.store[key] = value

    def delete(self, key: str) -> None:
        """Brief: Remove a key from the store.

        Inputs:
          - key: Memcached key string.

        Outputs:
          - None.
        """

        self.store.pop(key, None)


def _fake_pymemcache_module() -> object:
    """Brief: Build a minimal module-like object exposing FakeMemcachedClient.

    Inputs:
      - None.

    Outputs:
      - Object with a Client attribute pointing to FakeMemcachedClient.
    """

    return type("FakeMemcacheModule", (), {"Client": FakeMemcachedClient})()


def test_registry_resolves_memcached_aliases_to_plugin_class() -> None:
    """Brief: Cache plugin registry exposes memcached/memcache aliases.

    Inputs:
      - None.

    Outputs:
      - None; asserts alias resolution returns the expected class.
    """

    cls = get_cache_plugin_class("memcached")
    assert cls.__name__ == "MemcachedCache"

    cls2 = get_cache_plugin_class("memcache")
    assert cls2 is cls


def test_load_cache_plugin_memcached_raises_helpful_error_when_dependency_missing(
    monkeypatch,
) -> None:
    """Brief: Instantiating the memcached cache plugin errors clearly when pymemcache is missing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ImportError message contains install hint.
    """

    # Simulate that `pymemcache.client.base` is not installed.
    monkeypatch.delitem(sys.modules, "pymemcache.client.base", raising=False)

    import importlib

    real_import = importlib.import_module

    def _fake_import(name: str, package=None):  # type: ignore[no-untyped-def]
        if name == "pymemcache.client.base":
            raise ModuleNotFoundError("No module named pymemcache.client.base")
        return real_import(name, package=package)

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    with pytest.raises(ImportError) as excinfo:
        _ = load_cache_plugin(
            {
                "module": "memcached",
                "config": {"host": "127.0.0.1", "port": 11211},
            }
        )

    msg = str(excinfo.value).lower()
    assert "pip install pymemcache" in msg


def test_encode_decode_roundtrip_bytes_and_pickled() -> None:
    """Brief: Helper encode/decode functions support bytes and arbitrary objects.

    Inputs:
      - None.

    Outputs:
      - None; asserts flags and round-trips for bytes and dict objects.
    """

    raw = b"wire-bytes"
    payload, is_pickle = memcached_cache_mod._encode_value(raw)
    assert payload == raw
    assert is_pickle == 0
    assert memcached_cache_mod._decode_value(payload, is_pickle) == raw

    obj = {"name": "example.com", "qtype": 1}
    payload2, is_pickle2 = memcached_cache_mod._encode_value(obj)
    assert is_pickle2 == 1
    assert memcached_cache_mod._decode_value(payload2, is_pickle2) == obj


def test_memcached_cache_roundtrip_bytes_and_metadata_with_fake_client(monkeypatch) -> None:
    """Brief: MemcachedCache set/get round-trip bytes and expose TTL metadata.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts set(), get(), and get_with_meta() cooperate with fake client.
    """

    # Use the fake client in place of pymemcache.client.base.Client.
    monkeypatch.setattr(
        memcached_cache_mod,
        "_import_pymemcache",
        lambda: _fake_pymemcache_module(),
    )

    # Freeze time for deterministic TTL behavior.
    t = {"now": 1000.0}

    def _now() -> float:
        return float(t["now"])

    monkeypatch.setattr(memcached_cache_mod.time, "time", _now)

    plugin = memcached_cache_mod.MemcachedCache(
        host="example-cache",
        port=12345,
        namespace="foghorn:test:",
        min_cache_ttl=-5,
    )

    # min_cache_ttl should be clamped to a non-negative integer.
    assert plugin.min_cache_ttl == 0

    key = ("example.com", 1)
    plugin.set(key, 2, b"wire-bytes")

    client = plugin._client
    assert isinstance(client, FakeMemcachedClient)

    mem_key = plugin._mem_key(key)
    assert mem_key in client.store

    # get() should return the stored bytes.
    assert plugin.get(key) == b"wire-bytes"

    # get_with_meta() should return the value, remaining seconds, and original TTL.
    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value == b"wire-bytes"
    assert ttl_original == 2
    assert remaining is not None and remaining == pytest.approx(2.0)

    # After expiry, get_with_meta() should treat the entry as a miss and delete it.
    t["now"] = 1003.0
    value2, remaining2, ttl2 = plugin.get_with_meta(key)
    assert value2 is None
    assert remaining2 is None
    assert ttl2 is None
    assert mem_key not in client.store


@pytest.mark.parametrize(
    "value",
    [
        {"a": 1, "b": [1, 2, 3]},
        ("tuple", 123),
    ],
)
def test_memcached_cache_roundtrip_pickled_objects(monkeypatch, value: Any) -> None:
    """Brief: Non-bytes values are stored via pickle and returned on get().

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - value: Arbitrary non-bytes object.

    Outputs:
      - None; asserts value equality after a set/get.
    """

    monkeypatch.setattr(
        memcached_cache_mod,
        "_import_pymemcache",
        lambda: _fake_pymemcache_module(),
    )

    # Use real time here; TTL values are large enough to avoid expiry during test.
    plugin = memcached_cache_mod.MemcachedCache(
        host="127.0.0.1",
        port=11211,
        namespace="foghorn:test:",
    )

    key = ("example.com", 28)
    plugin.set(key, 60, value)
    assert plugin.get(key) == value


def test_registry_loads_memcached_cache_from_mapping(monkeypatch) -> None:
    """Brief: load_cache_plugin supports mapping config for memcached cache.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts returned instance type.
    """

    monkeypatch.setattr(
        memcached_cache_mod,
        "_import_pymemcache",
        lambda: _fake_pymemcache_module(),
    )

    inst = load_cache_plugin(
        {
            "module": "memcached",
            "config": {"host": "127.0.0.1", "port": 11211},
        }
    )
    assert inst.__class__.__name__ == "MemcachedCache"


def test_memcached_cache_namespace_and_min_cache_ttl_floor(monkeypatch) -> None:
    """Brief: MemcachedCache normalizes namespace and min_cache_ttl config.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts empty/whitespace namespace falls back to default and TTL is non-negative.
    """

    monkeypatch.setattr(
        memcached_cache_mod,
        "_import_pymemcache",
        lambda: _fake_pymemcache_module(),
    )

    plugin = memcached_cache_mod.MemcachedCache(namespace="   ", min_cache_ttl=-10)
    assert plugin.namespace == "foghorn:dns_cache:"
    assert plugin.min_cache_ttl == 0
