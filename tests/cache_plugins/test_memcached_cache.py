"""Brief: Unit tests for the Memcached-backed cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import sys
from typing import Any, Dict

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


class RaisingGetMemcachedClient(FakeMemcachedClient):
    """Brief: Fake client that raises on get() calls.

    Inputs:
      - Inherits FakeMemcachedClient constructor inputs.

    Outputs:
      - RaisingGetMemcachedClient instance.
    """

    def get(self, key: str) -> bytes | None:
        """Brief: Raise RuntimeError for every read attempt.

        Inputs:
          - key: Memcached key string.

        Outputs:
          - Never returns; raises RuntimeError.
        """

        raise RuntimeError(f"forced get failure for key={key}")


class RaisingSetMemcachedClient(FakeMemcachedClient):
    """Brief: Fake client that raises on set() calls.

    Inputs:
      - Inherits FakeMemcachedClient constructor inputs.

    Outputs:
      - RaisingSetMemcachedClient instance.
    """

    def set(self, key: str, value: bytes, expire: int | None = None) -> None:
        """Brief: Raise RuntimeError for every write attempt.

        Inputs:
          - key: Memcached key string.
          - value: Blob to store.
          - expire: Expiry in seconds.

        Outputs:
          - Never returns; raises RuntimeError.
        """

        raise RuntimeError(f"forced set failure for key={key}, expire={expire}")


def _fake_pymemcache_module(
    client_cls: type[FakeMemcachedClient] = FakeMemcachedClient,
) -> object:
    """Brief: Build a minimal module-like object exposing a fake client class.

    Inputs:
      - client_cls: Class exposed via the module's Client attribute.

    Outputs:
      - Object with a Client attribute pointing to client_cls.
    """

    return type("FakeMemcacheModule", (), {"Client": client_cls})()


def _make_plugin(
    monkeypatch,
    *,
    client_cls: type[FakeMemcachedClient] = FakeMemcachedClient,
    **config: Any,
) -> memcached_cache_mod.MemcachedCache:
    """Brief: Instantiate MemcachedCache with a chosen fake client class.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.
      - client_cls: Fake client class for _import_pymemcache().Client.
      - **config: MemcachedCache kwargs.

    Outputs:
      - MemcachedCache bound to a fake in-memory client.
    """

    monkeypatch.setattr(
        memcached_cache_mod,
        "_import_pymemcache",
        lambda: _fake_pymemcache_module(client_cls),
    )
    return memcached_cache_mod.MemcachedCache(**config)


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


def test_encode_decode_roundtrip_bytes_and_safe_serialized() -> None:
    """Brief: Helper encode/decode functions support bytes and safe serialized objects.

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
    assert is_pickle2 == 2
    assert memcached_cache_mod._decode_value(payload2, is_pickle2) == obj


def test_decode_value_rejects_unknown_encoding_flag() -> None:
    """Brief: _decode_value raises for unsupported encoding flags.

    Inputs:
      - None.

    Outputs:
      - None; asserts ValueError is raised for unknown encoding flags.
    """

    with pytest.raises(ValueError):
        _ = memcached_cache_mod._decode_value(b"payload", 999)


def test_memcached_cache_invalid_port_falls_back_to_default(monkeypatch) -> None:
    """Brief: Constructor falls back to default port when config port is invalid.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts fake client receives default Memcached port.
    """

    plugin = _make_plugin(monkeypatch, port="not-an-int")
    client = plugin._client
    assert isinstance(client, FakeMemcachedClient)
    assert client.server[1] == 11211


def test_memcached_cache_get_with_meta_handles_client_get_failure(monkeypatch) -> None:
    """Brief: get_with_meta() treats backend read exceptions as cache misses.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts read errors map to (None, None, None).
    """

    plugin = _make_plugin(monkeypatch, client_cls=RaisingGetMemcachedClient)
    assert plugin.get_with_meta(("error.example", 1)) == (None, None, None)


def test_memcached_cache_get_with_meta_treats_empty_blob_as_miss(monkeypatch) -> None:
    """Brief: get_with_meta() returns miss tuple for falsey stored blobs.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts empty bytes are treated as cache miss.
    """

    plugin = _make_plugin(monkeypatch)
    key = ("empty.example", 1)
    mem_key = plugin._mem_key(key)
    plugin._client.store[mem_key] = b""
    assert plugin.get_with_meta(key) == (None, None, None)


def test_memcached_cache_get_with_meta_deletes_corrupt_blob(monkeypatch) -> None:
    """Brief: Corrupt envelope blobs are treated as miss and removed.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts corrupt entry is deleted after failed decode.
    """

    plugin = _make_plugin(monkeypatch)
    key = ("corrupt.example", 1)
    mem_key = plugin._mem_key(key)
    plugin._client.store[mem_key] = b"not-json"

    assert plugin.get_with_meta(key) == (None, None, None)
    assert mem_key not in plugin._client.store


def test_memcached_cache_get_with_meta_handles_ttl_parse_errors(monkeypatch) -> None:
    """Brief: Invalid ttl metadata yields unknown ttl/remaining while returning value.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts value survives malformed ttl metadata.
    """

    plugin = _make_plugin(monkeypatch)
    monkeypatch.setattr(memcached_cache_mod.time, "time", lambda: 1000.0)

    key = ("invalid-ttl.example", 1)
    mem_key = plugin._mem_key(key)
    blob = memcached_cache_mod.safe_serialize(
        {
            "v": b"wire-data",
            "p": memcached_cache_mod.RAW_BYTES_FLAG,
            "ttl": "not-an-int",
            "created_at": 998.0,
        }
    )
    plugin._client.store[mem_key] = blob

    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value == b"wire-data"
    assert remaining is None
    assert ttl_original is None


def test_memcached_cache_get_with_meta_handles_missing_ttl_field(monkeypatch) -> None:
    """Brief: Missing ttl metadata still allows value retrieval with unknown meta.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts missing ttl results in remaining=None and ttl=None.
    """

    plugin = _make_plugin(monkeypatch)
    monkeypatch.setattr(memcached_cache_mod.time, "time", lambda: 1000.0)

    key = ("missing-ttl.example", 1)
    mem_key = plugin._mem_key(key)
    blob = memcached_cache_mod.safe_serialize(
        {
            "v": b"wire-data",
            "p": memcached_cache_mod.RAW_BYTES_FLAG,
            "created_at": 999.0,
        }
    )
    plugin._client.store[mem_key] = blob

    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value == b"wire-data"
    assert remaining is None
    assert ttl_original is None


def test_memcached_cache_get_with_meta_handles_created_at_parse_error(
    monkeypatch,
) -> None:
    """Brief: Invalid created_at metadata keeps ttl but clears remaining seconds.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts created_at parse failure returns remaining=None.
    """

    plugin = _make_plugin(monkeypatch)
    key = ("bad-created-at.example", 1)
    mem_key = plugin._mem_key(key)
    blob = memcached_cache_mod.safe_serialize(
        {
            "v": b"wire-data",
            "p": memcached_cache_mod.RAW_BYTES_FLAG,
            "ttl": 9,
            "created_at": "not-a-float",
        }
    )
    plugin._client.store[mem_key] = blob

    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value == b"wire-data"
    assert remaining is None
    assert ttl_original == 9


def test_memcached_cache_get_with_meta_handles_missing_payload(monkeypatch) -> None:
    """Brief: Missing payload returns metadata tuple with None value.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts payload None returns (None, remaining, ttl).
    """

    plugin = _make_plugin(monkeypatch)
    monkeypatch.setattr(memcached_cache_mod.time, "time", lambda: 1000.0)

    key = ("missing-payload.example", 1)
    mem_key = plugin._mem_key(key)
    blob = memcached_cache_mod.safe_serialize(
        {
            "v": None,
            "p": memcached_cache_mod.RAW_BYTES_FLAG,
            "ttl": 5,
            "created_at": 999.0,
        }
    )
    plugin._client.store[mem_key] = blob

    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value is None
    assert remaining is not None and remaining == pytest.approx(4.0)
    assert ttl_original == 5


def test_memcached_cache_get_with_meta_drops_undecodable_payload(monkeypatch) -> None:
    """Brief: Invalid encoding flags are treated as miss and trigger delete.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts undecodable entry is removed and missed.
    """

    plugin = _make_plugin(monkeypatch)
    monkeypatch.setattr(memcached_cache_mod.time, "time", lambda: 1000.0)

    key = ("bad-payload.example", 1)
    mem_key = plugin._mem_key(key)
    blob = memcached_cache_mod.safe_serialize(
        {
            "v": b"wire-data",
            "p": 777,
            "ttl": 5,
            "created_at": 999.0,
        }
    )
    plugin._client.store[mem_key] = blob

    assert plugin.get_with_meta(key) == (None, None, None)
    assert mem_key not in plugin._client.store


def test_memcached_cache_set_ttl_noop_and_backend_failure_paths(monkeypatch) -> None:
    """Brief: set() no-ops for ttl<=0 and suppresses backend write failures.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts no exception and no writes on guarded paths.
    """

    plugin = _make_plugin(monkeypatch)
    key = ("no-store.example", 1)
    plugin.set(key, 0, b"wire-data")
    assert plugin._client.store == {}

    plugin_with_set_error = _make_plugin(
        monkeypatch,
        client_cls=RaisingSetMemcachedClient,
    )
    plugin_with_set_error.set(("set-error.example", 1), 60, b"wire-data")


def test_memcached_cache_purge_returns_zero(monkeypatch) -> None:
    """Brief: purge() reports zero because Memcached handles expiry itself.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts purge() return value is 0.
    """

    plugin = _make_plugin(monkeypatch)
    assert plugin.purge() == 0


def test_memcached_cache_roundtrip_bytes_and_metadata_with_fake_client(
    monkeypatch,
) -> None:
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
def test_memcached_cache_roundtrip_safe_serialized_objects(
    monkeypatch, value: Any
) -> None:
    """Brief: Non-bytes values are safely serialized and returned on get().

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
