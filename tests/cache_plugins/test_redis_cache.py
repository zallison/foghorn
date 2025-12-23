"""Brief: Unit tests for the Redis/Valkey cache plugin.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

from typing import Any, Dict, List

import sys

import pytest

from foghorn.cache_plugins import redis_cache as redis_cache_mod
from foghorn.cache_plugins.registry import get_cache_plugin_class, load_cache_plugin


class FakeRedisClient:
    """Brief: Minimal in-memory Redis client substitute for tests.

    Inputs:
      - host: Redis host string.
      - port: Redis port number.
      - db: Redis database index.
      - username: Optional username.
      - password: Optional password.
      - socket_timeout: Optional socket timeout seconds.
      - decode_responses: Flag indicating response decoding mode (ignored).

    Outputs:
      - FakeRedisClient instance that tracks hash fields, TTLs, and deletes
        entries in a simple in-memory dictionary.
    """

    def __init__(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 6379,
        db: int = 0,
        username: str | None = None,
        password: str | None = None,
        socket_timeout: float | None = None,
        decode_responses: bool | None = None,
    ) -> None:
        self.host = host
        self.port = int(port)
        self.db = int(db)
        self.username = username
        self.password = password
        self.socket_timeout = socket_timeout
        self.decode_responses = decode_responses
        self.store: Dict[str, Dict[str, Any]] = {}
        self.ttls: Dict[str, int] = {}
        self.from_url_calls: List[str] = []

    @classmethod
    def from_url(
        cls,
        url: str,
        *,
        decode_responses: bool | None = None,
        socket_timeout: float | None = None,
    ) -> "FakeRedisClient":
        """Brief: Construct a fake client via the from_url path.

        Inputs:
          - url: Redis connection URL.
          - decode_responses: Decode flag (ignored).
          - socket_timeout: Optional timeout seconds.

        Outputs:
          - FakeRedisClient instance with url recorded in from_url_calls.
        """

        client = cls(
            host="from_url",
            port=0,
            db=0,
            username=None,
            password=None,
            socket_timeout=socket_timeout,
            decode_responses=decode_responses,
        )
        client.from_url_calls.append(url)
        return client

    def hmget(self, key: str, *fields: str) -> list[Any | None]:
        """Brief: Return stored hash fields for key.

        Inputs:
          - key: Redis key string.
          - *fields: Hash field names.

        Outputs:
          - list[Any | None]: Values for each requested field or None.
        """

        mapping = self.store.get(key)
        if mapping is None:
            return [None for _ in fields]
        return [mapping.get(field) for field in fields]

    def hset(self, key: str, mapping: Dict[str, Any]) -> None:
        """Brief: Set hash fields for a key.

        Inputs:
          - key: Redis key string.
          - mapping: Field-to-value mapping.

        Outputs:
          - None.
        """

        current = self.store.setdefault(key, {})
        current.update(mapping)

    def expire(self, key: str, ttl: int) -> None:
        """Brief: Record a TTL in seconds for a key.

        Inputs:
          - key: Redis key string.
          - ttl: Expiry in seconds.

        Outputs:
          - None.
        """

        self.ttls[key] = int(ttl)

    def pttl(self, key: str) -> int:
        """Brief: Return the remaining TTL in milliseconds.

        Inputs:
          - key: Redis key string.

        Outputs:
          - int: TTL in milliseconds or -2/-1 for missing/no TTL.
        """

        ttl = self.ttls.get(key)
        if ttl is None:
            return -2
        return int(ttl * 1000)

    def delete(self, key: str) -> None:
        """Brief: Remove a key and its TTL metadata.

        Inputs:
          - key: Redis key string.

        Outputs:
          - None.
        """

        self.store.pop(key, None)
        self.ttls.pop(key, None)


def _fake_redis_module() -> object:
    """Brief: Build a minimal module-like object exposing FakeRedisClient.

    Inputs:
      - None.

    Outputs:
      - Object with a Redis attribute pointing to FakeRedisClient.
    """

    return type("FakeRedisModule", (), {"Redis": FakeRedisClient})()


def test_registry_resolves_redis_alias_to_plugin_class() -> None:
    """Brief: Cache plugin registry exposes the redis/valkey cache plugin aliases.

    Inputs:
      - None

    Outputs:
      - None; asserts alias resolution returns the expected class.
    """

    cls = get_cache_plugin_class("redis")
    assert cls.__name__ == "RedisCachePlugin"

    cls2 = get_cache_plugin_class("valkey")
    assert cls2 is cls


def test_load_cache_plugin_redis_raises_helpful_error_when_dependency_missing(
    monkeypatch,
) -> None:
    """Brief: Instantiating the redis cache plugin errors clearly when redis is missing.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts ImportError message contains install hint.
    """

    # Simulate that `redis` is not installed.
    monkeypatch.delitem(sys.modules, "redis", raising=False)

    # Force importlib.import_module('redis') to fail.
    import importlib

    real_import = importlib.import_module

    def _fake_import(name: str, package=None):  # type: ignore[no-untyped-def]
        if name == "redis":
            raise ModuleNotFoundError("No module named redis")
        return real_import(name, package=package)

    monkeypatch.setattr(importlib, "import_module", _fake_import)

    with pytest.raises(ImportError) as excinfo:
        _ = load_cache_plugin(
            {"module": "redis", "config": {"url": "redis://localhost:6379/0"}}
        )

    msg = str(excinfo.value).lower()
    assert "pip install redis" in msg


def test_encode_decode_roundtrip_bytes_and_pickled() -> None:
    """Brief: Helper encode/decode functions support bytes and arbitrary objects.

    Inputs:
      - None.

    Outputs:
      - None; asserts flags and round-trips for bytes and dict objects.
    """

    raw = b"wire-bytes"
    payload, is_pickle = redis_cache_mod._encode_value(raw)
    assert payload == raw
    assert is_pickle == 0
    assert redis_cache_mod._decode_value(payload, is_pickle) == raw

    obj = {"name": "example.com", "qtype": 1}
    payload2, is_pickle2 = redis_cache_mod._encode_value(obj)
    assert is_pickle2 == 1
    assert redis_cache_mod._decode_value(payload2, is_pickle2) == obj


def test_redis_cache_uses_fake_redis_from_url_for_url_config(monkeypatch) -> None:
    """Brief: RedisCachePlugin initializes client via Redis.from_url when url is provided.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts FakeRedisClient.from_url was used with the configured URL.
    """

    monkeypatch.setattr(redis_cache_mod, "_import_redis", lambda: _fake_redis_module())

    url = "redis://localhost:6379/0"
    plugin = redis_cache_mod.RedisCachePlugin(url=url, namespace="foghorn:test:")
    client = plugin._client
    assert isinstance(client, FakeRedisClient)
    assert client.from_url_calls == [url]

    key = ("example.com", 1)
    expected_key = f"{plugin.namespace}{redis_cache_mod._stable_digest_for_key(key)}"
    assert plugin._redis_key(key) == expected_key


def test_redis_cache_roundtrip_bytes_and_metadata_with_fake_client(monkeypatch) -> None:
    """Brief: RedisCachePlugin set/get round-trip bytes and expose TTL metadata.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts set(), get(), and get_with_meta() cooperate with fake client.
    """

    monkeypatch.setattr(redis_cache_mod, "_import_redis", lambda: _fake_redis_module())

    plugin = redis_cache_mod.RedisCachePlugin(
        host="example-cache",
        port=1234,
        db="1",
        username="user",
        password="secret",
        namespace="foghorn:test:",
        min_cache_ttl=-5,
    )

    # min_cache_ttl should be clamped to a non-negative integer.
    assert plugin.min_cache_ttl == 0

    key = ("example.com", 1)
    plugin.set(key, 2, b"wire-bytes")

    client = plugin._client
    assert isinstance(client, FakeRedisClient)

    redis_key = plugin._redis_key(key)
    assert client.store[redis_key]["v"] == b"wire-bytes"
    assert client.store[redis_key]["ttl"] == 2
    assert client.ttls[redis_key] == 2

    # get() should return the stored bytes.
    assert plugin.get(key) == b"wire-bytes"

    # get_with_meta() should return the value, remaining seconds, and original TTL.
    value, remaining, ttl_original = plugin.get_with_meta(key)
    assert value == b"wire-bytes"
    assert ttl_original == 2
    assert remaining is not None and remaining == pytest.approx(2.0)


def test_redis_cache_uses_default_namespace_and_min_cache_ttl_floor(
    monkeypatch,
) -> None:
    """Brief: RedisCachePlugin normalizes namespace and min_cache_ttl config.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - None; asserts empty/whitespace namespace falls back to default and TTL is non-negative.
    """

    monkeypatch.setattr(redis_cache_mod, "_import_redis", lambda: _fake_redis_module())

    plugin = redis_cache_mod.RedisCachePlugin(namespace="   ", min_cache_ttl=-10)
    assert plugin.namespace == "foghorn:dns_cache:"
    assert plugin.min_cache_ttl == 0
