from __future__ import annotations

from typing import Any, Optional, Tuple

from foghorn.plugins.cache.backends.mysql_ttl import MySQLTTLCache

from .base import CachePlugin, cache_aliases


@cache_aliases("mysql", "mariadb", "mysql_cache", "mariadb_cache")
class MySqlCache(CachePlugin):
    """MySQL/MariaDB-backed DNS cache plugin.

    Brief:
      Persistent CachePlugin implementation for DNS caching backed by
      MySQL/MariaDB. Internally this delegates storage and TTL behavior to
      `foghorn.plugins.cache.backends.mysql_ttl.MySQLTTLCache` so other
      subsystems can reuse the same MySQL-backed TTL cache.

    Inputs:
      - **config:
          - host (str): Database host (default "127.0.0.1").
          - port (int): Database port (default 3306).
          - user (str): Database username.
          - password (str): Database password.
          - database (str): Database name (default "foghorn_cache").
          - namespace (str): Namespace/table name (default "dns_cache").
          - table (str): Backward-compatible alias for namespace.
          - connect_kwargs (dict): Additional connection kwargs.
          - min_cache_ttl (int): Optional cache TTL floor.

    Outputs:
      - MySqlCache instance.

    Example:
      cache:
        module: mysql
        config:
          host: 127.0.0.1
          port: 3306
          user: foghorn
          password: secret
          database: foghorn_cache
          min_cache_ttl: 60
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the MySQL cache plugin.

        Inputs:
          - **config: See class docstring.

        Outputs:
          - None.
        """

        self.min_cache_ttl: int = max(0, int(config.get("min_cache_ttl", 0) or 0))

        host = str(config.get("host", "127.0.0.1") or "127.0.0.1")
        try:
            port = int(config.get("port", 3306) or 3306)
        except Exception:
            port = 3306

        user = config.get("user")
        password = config.get("password")

        database = config.get("database", "foghorn_cache")
        if not isinstance(database, str) or not database.strip():
            database = "foghorn_cache"

        namespace = config.get("namespace")
        if not isinstance(namespace, str) or not namespace.strip():
            namespace = config.get("table")
        if not isinstance(namespace, str) or not namespace.strip():
            namespace = "dns_cache"

        connect_kwargs = config.get("connect_kwargs")
        if not isinstance(connect_kwargs, dict):
            connect_kwargs = None

        self._cache = MySQLTTLCache(
            host=host,
            port=port,
            user=str(user) if isinstance(user, str) else None,
            password=str(password) if isinstance(password, str) else None,
            database=str(database),
            namespace=str(namespace),
            connect_kwargs=connect_kwargs,
        )

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

        self._cache.set(key, ttl, value)

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).
        """

        return int(self._cache.purge())

    def close(self) -> None:
        """Brief: Close underlying MySQL resources.

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
