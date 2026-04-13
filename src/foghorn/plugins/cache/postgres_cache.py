"""PostgreSQL-backed cache plugin for Foghorn DNS.

Inputs:
  - Configuration mapping passed via the cache plugin loader with fields:
    host, port, user, password, database, namespace, connect_kwargs, min_cache_ttl.

Outputs:
  - CachePlugin instance that delegates to PostgresTTLCache backend.
"""

from __future__ import annotations

from typing import Any, Optional, Tuple

from .backends.postgres_ttl import PostgresTTLCache
from .base import CachePlugin, cache_aliases

__all__ = ["PostgresCache"]


@cache_aliases("postgres", "postgresql", "pg")
class PostgresCache(CachePlugin):
    """PostgreSQL-backed DNS cache plugin.

    Brief:
      Persistent CachePlugin implementation for DNS caching backed by PostgreSQL.
      Internally this delegates storage and TTL behavior to
      `foghorn.plugins.cache.backends.postgres_ttl.PostgresTTLCache`.

    Inputs:
      - **config:
          - host (str): Database host (default "127.0.0.1").
          - port (int): Database port (default 5432).
          - user (str|None): Database username.
          - password (str|None): Database password.
          - database (str): Database name (default "foghorn_cache").
          - namespace (str): Table prefix (default "cache").
          - connect_kwargs (dict|None): Additional connection kwargs.
          - min_cache_ttl (int): Optional cache TTL floor.

    Outputs:
      - PostgresCache instance.
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the PostgreSQL cache plugin.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        self.min_cache_ttl: int = max(0, int(config.get("min_cache_ttl", 0) or 0))

        host = str(config.get("host", "127.0.0.1") or "127.0.0.1")
        try:
            port = int(config.get("port", 5432) or 5432)
        except Exception:
            port = 5432

        user = config.get("user")
        password = config.get("password")

        database = config.get("database", "foghorn_cache")
        if not isinstance(database, str) or not database.strip():
            database = "foghorn_cache"

        namespace = config.get("namespace", "cache")
        if not isinstance(namespace, str) or not namespace.strip():
            namespace = "cache"

        connect_kwargs = config.get("connect_kwargs")
        if not isinstance(connect_kwargs, dict):
            connect_kwargs = None

        try:
            self._cache = PostgresTTLCache(
                namespace=str(namespace),
                host=host,
                port=port,
                user=str(user) if isinstance(user, str) else None,
                password=str(password) if isinstance(password, str) else None,
                database=str(database),
                connect_kwargs=connect_kwargs,
            )
        except RuntimeError as exc:
            raise RuntimeError(
                f"Failed to initialize PostgreSQL cache backend: {exc}"
            ) from exc

    def get(self, key: Tuple[str, int]) -> Any | None:
        """Brief: Lookup a cached entry enforcing expiry.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - Any | None: Cached value if present and not expired; otherwise None.
        """

        return self._cache.get(key)

    def get_with_meta(
        self, key: Tuple[str, int]
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        return self._cache.get_with_meta(key)

    def set(self, key: Tuple[str, int], ttl: int, value: Any) -> None:
        """Brief: Store a value under key with a TTL.

        Inputs:
          - key: Tuple[str, int] cache key (qname, qtype).
          - ttl: int time-to-live in seconds.
          - value: Cached value.

        Outputs:
          - None.
        """

        effective_ttl = max(self.min_cache_ttl, max(0, int(ttl)))
        self._cache.set(key, effective_ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).
        """

        return int(self._cache.purge())

    def close(self) -> None:
        """Brief: Close underlying PostgreSQL resources.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        try:
            self._cache.close()
        except Exception:  # pragma: nocover - defensive cleanup
            pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # pragma: nocover - defensive cleanup
            pass
