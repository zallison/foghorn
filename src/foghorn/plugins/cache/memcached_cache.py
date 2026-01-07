from __future__ import annotations

import hashlib
import importlib
import pickle
import time
from typing import Any, Optional, Tuple

from .base import CachePlugin, cache_aliases


def _import_pymemcache() -> Any:
    """Brief: Import the optional `pymemcache` dependency.

    Inputs:
      - None.

    Outputs:
      - pymemcache.client.base module.

    Notes:
      - This is intentionally lazy so that importing foghorn.cache_plugins works
        even when `pymemcache` is not installed.
    """

    try:
        return importlib.import_module("pymemcache.client.base")
    except Exception as exc:  # pragma: no cover
        raise ImportError(
            "MemcachedCache requires the optional 'pymemcache' dependency. "
            "Install it with: pip install pymemcache"
        ) from exc


def _stable_digest_for_key(key: Tuple[str, int]) -> str:
    """Brief: Create a stable digest for a CachePlugin key.

    Inputs:
      - key: Tuple[str, int] cache key (qname, qtype).

    Outputs:
      - str: Hex digest suitable for embedding in a Memcached key.

    Notes:
      - We hash a pickle of the key to avoid ambiguities with string joining.
    """

    payload = pickle.dumps(key, protocol=pickle.HIGHEST_PROTOCOL)
    return hashlib.sha256(payload).hexdigest()


def _encode_value(value: Any) -> Tuple[bytes, int]:
    """Brief: Encode a cache value for Memcached storage.

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
    """Brief: Decode a stored Memcached payload.

    Inputs:
      - payload: Stored bytes.
      - is_pickle: 1 if payload is a pickle.

    Outputs:
      - Any: Decoded object.
    """

    if int(is_pickle) == 1:
        return pickle.loads(payload)
    return payload


@cache_aliases("memcached", "memcache")
class MemcachedCache(CachePlugin):
    """Memcached-backed DNS cache plugin.

    Brief:
      CachePlugin implementation backed by Memcached using `pymemcache`. Values
      are stored as a small envelope that includes the original TTL and
      creation time so get_with_meta() can report seconds_remaining.

    Inputs:
      - **config:
          - host (str): Memcached host (default '127.0.0.1').
          - port (int): Memcached port (default 11211).
          - namespace (str): Namespace prefix for keys (default 'foghorn:dns_cache:').
          - connect_timeout (float|None): Optional connect timeout seconds.
          - timeout (float|None): Optional operation timeout seconds.
          - min_cache_ttl (int): Optional cache TTL floor used by the resolver.

    Outputs:
      - MemcachedCache instance.

    Example:
      cache:
        module: memcached
        config:
          host: 127.0.0.1
          port: 11211
          namespace: foghorn:dns_cache:
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the Memcached cache plugin.

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

        host = str(config.get("host", "127.0.0.1") or "127.0.0.1")
        try:
            port = int(config.get("port", 11211) or 11211)
        except Exception:
            port = 11211

        connect_timeout = config.get("connect_timeout")
        timeout = config.get("timeout")

        mem_mod = _import_pymemcache()
        self._client = mem_mod.Client(
            (host, port),
            connect_timeout=connect_timeout,
            timeout=timeout,
        )

    def _mem_key(self, key: Tuple[str, int]) -> str:
        """Brief: Map a CachePlugin key to a Memcached key.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - str: Memcached key.
        """

        return f"{self.namespace}{_stable_digest_for_key(key)}"

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Lookup a cached entry.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - Any | None: Cached value if present; otherwise None.
        """

        value, _seconds_remaining, _ttl = self.get_with_meta(key)
        return value

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)

        Notes:
          - seconds_remaining is derived from creation time plus TTL, not from a
            server-side TTL query, because Memcached does not expose that.
        """

        mem_key = self._mem_key(key)
        try:
            blob = self._client.get(mem_key)
        except Exception:
            return None, None, None

        if not blob:
            return None, None, None

        try:
            envelope = pickle.loads(blob)
        except Exception:
            # Corrupted entry: treat as miss and best-effort delete.
            try:
                self._client.delete(mem_key)
            except Exception:
                pass
            return None, None, None

        payload = envelope.get("v")
        is_pickle = envelope.get("p", 1)
        ttl_original_raw = envelope.get("ttl")
        created_at_raw = envelope.get("created_at")

        ttl_original: Optional[int] = None
        try:
            if ttl_original_raw is not None:
                ttl_original = int(ttl_original_raw)
        except Exception:
            ttl_original = None

        seconds_remaining: Optional[float] = None
        try:
            if ttl_original is not None and created_at_raw is not None:
                created_at = float(created_at_raw)
                now = time.time()
                delta = (created_at + float(ttl_original)) - now
                if delta <= 0:
                    # Treat as expired and best-effort delete.
                    try:
                        self._client.delete(mem_key)
                    except Exception:
                        pass
                    return None, None, None
                seconds_remaining = float(delta)
        except Exception:
            seconds_remaining = None

        if payload is None:
            return None, seconds_remaining, ttl_original

        try:
            value = _decode_value(bytes(payload), int(is_pickle))
        except Exception:
            try:
                self._client.delete(mem_key)
            except Exception:
                pass
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

        mem_key = self._mem_key(key)
        payload, is_pickle = _encode_value(value)

        envelope = {
            "v": payload,
            "p": int(is_pickle),
            "ttl": int(ttl_int),
            "created_at": float(time.time()),
        }

        try:
            blob = pickle.dumps(envelope, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception:
            return

        try:
            self._client.set(mem_key, blob, expire=ttl_int)
        except Exception:
            # Best-effort only; failures are treated as cache miss.
            return

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).

        Notes:
          - Memcached automatically evicts expired keys. This method returns 0
            and does not scan the keyspace.
        """

        return 0
