"""PostgreSQL-backed cache plugin for Foghorn DNS.

Inputs:
  - Configuration dictionary passed via cache plugin loader with fields:
    host, port, user, password, database, namespace, connect_kwargs, min_cache_ttl.

Outputs:
  - CachePlugin instance that delegates to PostgresTTLCache backend.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from . import CachePlugin
from .backends.postgres_ttl import PostgresTTLCache

__all__ = ["PostgresCache"]


class PostgresCache(CachePlugin):
    """PostgreSQL-backed DNS cache plugin.

    Aliases: postgres, postgresql, pg.

    This plugin delegates all cache operations to a PostgresTTLCache backend
    that stores DNS responses in a PostgreSQL database using SHA-256 key digests.

    Inputs (constructor):
        config: Configuration dictionary with optional keys:
            - host: Database host (default "127.0.0.1")
            - port: Database port (default 5432)
            - user: Database username
            - password: Database password
            - database: Database name (default "foghorn_cache")
            - namespace: Table prefix (default "cache")
            - connect_kwargs: Extra driver connection kwargs
            - min_cache_ttl: Minimum TTL in seconds (default 0)

    Outputs:
        Initialized PostgresCache instance ready for cache operations.
    """

    aliases = ("postgres", "postgresql", "pg")

    def __init__(self, config: Optional[Dict[str, Any]] = None, **_: Any) -> None:
        config = config or {}

        self.min_cache_ttl = max(0, int(config.get("min_cache_ttl", 0)))

        backend_config = {
            "namespace": config.get("namespace", "cache"),
            "host": config.get("host", "127.0.0.1"),
            "port": config.get("port", 5432),
            "user": config.get("user"),
            "password": config.get("password"),
            "database": config.get("database", "foghorn_cache"),
            "connect_kwargs": config.get("connect_kwargs"),
        }

        try:
            self.backend = PostgresTTLCache(**backend_config)
        except RuntimeError as exc:
            raise RuntimeError(
                f"Failed to initialize PostgreSQL cache backend: {exc}"
            ) from exc

    def set(self, key: bytes, value: bytes, ttl: int) -> None:
        """Cache a DNS response.

        Inputs:
            key: Cache key (bytes).
            value: DNS response value (bytes).
            ttl: Time-to-live in seconds; enforced with min_cache_ttl.

        Outputs:
            None.
        """

        effective_ttl = max(self.min_cache_ttl, ttl)
        self.backend.set(key, value, effective_ttl)

    def get(self, key: bytes) -> Optional[bytes]:
        """Retrieve a cached DNS response if not expired.

        Inputs:
            key: Cache key (bytes).

        Outputs:
            Cached DNS response or None if expired/missing.
        """

        result = self.backend.get(key)
        if result is not None and isinstance(result, bytes):
            return result
        return None

    def close(self) -> None:
        """Close the backend connection.

        Inputs:
            None.

        Outputs:
            None.
        """

        try:
            backend = getattr(self, "backend", None)
            if backend is not None:
                backend.close()
        except Exception:  # pragma: nocover - defensive cleanup
            pass

    def __del__(self) -> None:
        """Cleanup when garbage collected."""

        self.close()
