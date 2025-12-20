from __future__ import annotations

import os
from typing import Any, Optional, Tuple

from foghorn.cache_backends.sqlite_ttl import SQLite3TTLCache

from .base import CachePlugin, cache_aliases


@cache_aliases("sqlite3", "sqlite", "sqlite_cache", "sqlite3_cache")
class SQLite3CachePlugin(CachePlugin):
    """SQLite3-backed DNS cache plugin.

    Brief:
      Persistent CachePlugin implementation for DNS caching. Internally this
      delegates storage and TTL behavior to `foghorn.cache_backends.sqlite_ttl.SQLite3TTLCache`
      so other subsystems (plugins, recursive resolver helpers) can reuse the
      same sqlite-backed TTL cache.

    Inputs:
      - **config:
          - db_path (str): Path to sqlite3 DB file.
          - path (str): Alias for db_path.
          - namespace (str): Namespace/table name (default 'dns_cache').
          - table (str): Backward-compatible alias for namespace.
          - min_cache_ttl (int): Optional cache TTL floor used by the resolver.
          - journal_mode (str): SQLite journal mode; defaults to 'WAL'.

    Outputs:
      - SQLite3CachePlugin instance.

    Example:
      cache:
        module: sqlite3
        config:
          db_path: ./config/var/dns_cache.db
          min_cache_ttl: 60
    """

    def __init__(self, **config: object) -> None:
        """Brief: Initialize the sqlite3 cache plugin.

        Inputs:
          - **config:
              - db_path/path: sqlite3 database file path.
              - namespace: Optional namespace/table name.
              - table: Backward-compatible alias for namespace.
              - min_cache_ttl: Optional cache TTL floor used by resolver.
              - journal_mode: SQLite journal mode (e.g., 'WAL').

        Outputs:
          - None.
        """

        cfg_db_path = config.get("db_path")
        if not isinstance(cfg_db_path, str) or not cfg_db_path.strip():
            cfg_db_path = config.get("path")
        if isinstance(cfg_db_path, str) and cfg_db_path.strip():
            db_path = cfg_db_path.strip()
        else:
            db_path = "./config/var/dns_cache.db"

        self.db_path: str = os.path.abspath(os.path.expanduser(str(db_path)))
        self.min_cache_ttl: int = max(0, int(config.get("min_cache_ttl", 0) or 0))

        namespace = config.get("namespace", "dns_cache")
        if not isinstance(namespace, str) or not namespace.strip():
            raise ValueError(
                "sqlite cache config requires a non-empty 'namespace' field"
            )
        journal_mode = config.get("journal_mode", "WAL")

        self._cache = SQLite3TTLCache(
            self.db_path,
            namespace=str(namespace or "dns_cache"),
            journal_mode=str(journal_mode or "WAL"),
            create_dir=True,
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
        """Brief: Close underlying sqlite resources.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        try:
            self._cache.close()
        except Exception:
            pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
