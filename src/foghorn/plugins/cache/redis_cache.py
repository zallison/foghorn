from __future__ import annotations

import hashlib
import importlib
import pickle
from typing import Any, Optional, Tuple

from .base import CachePlugin, cache_aliases


def _import_redis() -> Any:
    """Brief: Import the optional `redis` dependency.

    Inputs:
      - None.

    Outputs:
      - redis module.

    Notes:
      - This is intentionally lazy so that importing foghorn.cache_plugins works
        even when `redis` is not installed.
    """

    try:
        return importlib.import_module("redis")
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "RedisCache requires the optional 'redis' dependency. "
            "Install it with: pip install redis"
        ) from exc


def _stable_digest_for_key(key: Tuple[str, int]) -> str:
    """Brief: Create a stable digest for a CachePlugin key.

    Inputs:
      - key: Tuple[str, int] cache key (qname, qtype).

    Outputs:
      - str: Hex digest suitable for embedding in a Redis key.

    Notes:
      - We hash a pickle of the key to avoid ambiguities with string joining.
    """

    payload = pickle.dumps(key, protocol=pickle.HIGHEST_PROTOCOL)
    return hashlib.sha256(payload).hexdigest()


def _encode_value(value: Any) -> Tuple[bytes, int]:
    """Brief: Encode a cache value for Redis storage.

    Inputs:
      - value: Any Python object.

    Outputs:
      - (payload, is_pickle):
          - payload: bytes to store.
          - is_pickle: 1 when payload is pickle-encoded, 0 otherwise.
    """

    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value), 0
    return pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL), 1


def _decode_value(payload: bytes, is_pickle: int) -> Any:
    """Brief: Decode a stored Redis payload.

    Inputs:
      - payload: Stored bytes.
      - is_pickle: 1 if payload is a pickle.

    Outputs:
      - Any: Decoded object.
    """

    if int(is_pickle) == 1:
        return pickle.loads(payload)
    return payload


@cache_aliases("redis", "valkey")
class RedisCache(CachePlugin):
    """Redis/Valkey-backed DNS cache plugin.

    Brief:
      CachePlugin implementation backed by Redis-compatible servers (including
      Valkey). Values are stored in a Redis hash per key, along with the
      original TTL so get_with_meta() can report seconds_remaining and TTL.

    Inputs:
      - **config:
          - url (str): Redis URL (e.g. redis://localhost:6379/0). When provided,
            it takes precedence over host/port/db.
          - host (str): Redis host (default '127.0.0.1').
          - port (int): Redis port (default 6379).
          - db (int): Redis DB index (default 0).
          - username (str|None): Optional Redis username.
          - password (str|None): Optional Redis password.
          - socket_timeout (float|None): Optional socket timeout seconds.
          - namespace (str): Namespace prefix for Redis keys (default 'foghorn:dns_cache:').
          - min_cache_ttl (int): Optional cache TTL floor used by resolver.

    Outputs:
      - RedisCache instance.

    Example:
      cache:
        module: redis
        config:
          url: redis://localhost:6379/0
          namespace: foghorn:dns_cache:
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the Redis/Valkey cache plugin.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        self.min_cache_ttl: int = max(0, int(config.get("min_cache_ttl", 0) or 0))

        namespace = config.get("namespace", "foghorn:dns_cache:")
        if not isinstance(namespace, str) or not namespace.strip():
            namespace = "foghorn:dns_cache:"
        self.namespace: str = str(namespace)

        redis = _import_redis()

        url = config.get("url")
        if isinstance(url, str) and url.strip():
            self._client = redis.Redis.from_url(
                url.strip(),
                decode_responses=False,
                socket_timeout=config.get("socket_timeout"),
            )
            return

        host = str(config.get("host", "127.0.0.1") or "127.0.0.1")
        try:
            port = int(config.get("port", 6379) or 6379)
        except Exception:
            port = 6379
        try:
            db = int(config.get("db", 0) or 0)
        except Exception:
            db = 0

        username = config.get("username")
        password = config.get("password")

        self._client = redis.Redis(
            host=host,
            port=port,
            db=db,
            username=str(username) if isinstance(username, str) and username else None,
            password=str(password) if isinstance(password, str) and password else None,
            socket_timeout=config.get("socket_timeout"),
            decode_responses=False,
        )

    def _redis_key(self, key: Tuple[str, int]) -> str:
        """Brief: Map a CachePlugin key to a Redis key.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - str: Redis key.
        """

        return f"{self.namespace}{_stable_digest_for_key(key)}"

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Lookup a cached entry.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - Any | None: Cached value if present; otherwise None.
        """

        redis_key = self._redis_key(key)
        value_blob, is_pickle = self._client.hmget(redis_key, "v", "p")
        if value_blob is None or is_pickle is None:
            return None
        try:
            return _decode_value(bytes(value_blob), int(is_pickle))
        except Exception:
            # Corrupted entry: treat as miss and best-effort delete.
            try:
                self._client.delete(redis_key)
            except Exception:
                pass
            return None

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)

        Notes:
          - seconds_remaining is derived from Redis PTTL (millisecond precision).
          - original_ttl is stored alongside the value at set() time.
        """

        redis_key = self._redis_key(key)
        value_blob, is_pickle, ttl_blob = self._client.hmget(redis_key, "v", "p", "ttl")
        if value_blob is None or is_pickle is None:
            return None, None, None

        ttl_original: Optional[int] = None
        if ttl_blob is not None:
            try:
                ttl_original = int(ttl_blob)
            except Exception:
                ttl_original = None

        seconds_remaining: Optional[float] = None
        try:
            ms = int(self._client.pttl(redis_key))
            # -2: key does not exist, -1: no expiry.
            if ms >= 0:
                seconds_remaining = float(ms) / 1000.0
        except Exception:
            seconds_remaining = None

        try:
            value = _decode_value(bytes(value_blob), int(is_pickle))
        except Exception:
            return None, None, None

        return value, seconds_remaining, ttl_original

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a value under key with a TTL.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).
          - ttl: int time-to-live in seconds.
          - value: Cached value.

        Outputs:
          - None.
        """

        ttl_int = max(0, int(ttl))
        if ttl_int <= 0:
            return

        redis_key = self._redis_key(key)
        payload, is_pickle = _encode_value(value)

        # Store value and metadata as a hash, and apply expiry to the hash key.
        self._client.hset(
            redis_key,
            mapping={
                "v": payload,
                "p": int(is_pickle),
                "ttl": int(ttl_int),
            },
        )
        self._client.expire(redis_key, int(ttl_int))

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).

        Notes:
          - Redis/Valkey automatically remove expired keys.
          - This method returns 0 and does not scan the keyspace.
        """

        return 0
