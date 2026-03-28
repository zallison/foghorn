"""PostgreSQL-backed TTL cache backend.

Inputs:
  - Constructed via a configuration mapping passed through CacheConfig with
    backend-specific fields such as host, port, user, password, and database.

Outputs:
  - Concrete backend instance that can be passed to CachePlugin for persistent
    DNS response caching using a PostgreSQL database.

Notes:
  - This backend mirrors the MySQLTTLCache implementation but targets PostgreSQL.
  - The underlying DB driver (psycopg or psycopg2) is imported lazily.
  - Key digests are stored as SHA-256 hashes for stable, unique row identification.
  - Expiry enforcement happens on read (get/get_with_meta) and optional purge.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
from typing import Any, Dict, Optional, Tuple
from foghorn.plugins.cache.safe_codec import (
    RAW_BYTES_FLAG,
    SAFE_SERIALIZED_FLAG,
    safe_deserialize,
    safe_serialize,
)

logger = logging.getLogger(__name__)


def _import_postgres_driver():
    """Import and return a DB-API compatible PostgreSQL driver module.

    Inputs:
        None.

    Outputs:
        DB-API like module exposing a ``connect`` callable.

    Raises:
        RuntimeError: When no supported PostgreSQL driver is available.
    """

    # Prefer modern psycopg (v3) when available, then fall back to psycopg2.
    try:  # pragma: no cover - import-path dependent
        import psycopg as driver  # type: ignore[import]

        return driver
    except Exception:  # pragma: no cover - environment specific
        try:
            import psycopg2 as driver  # type: ignore[import]

            return driver
        except Exception as exc:  # pragma: no cover - environment specific
            raise RuntimeError(
                "No supported PostgreSQL driver found; install either "
                "'psycopg' or 'psycopg2' to use the PostgresTTLCache"
            ) from exc


def _stable_digest_for_key(key: Any) -> bytes:
    """Brief: Create a stable SHA-256 digest for a cache key.

    Inputs:
      - key: Any Python object used as a cache key.

    Outputs:
      - bytes: 32-byte SHA-256 digest.

    Notes:
      - Bytes-like keys are hashed directly.
      - Other keys are safely serialized then hashed.
    """

    if isinstance(key, (bytes, bytearray, memoryview)):
        payload = bytes(key)
    else:
        payload = safe_serialize(key)

    return hashlib.sha256(payload).digest()


def _encode_key_blob(key: Any) -> bytes:
    """Brief: Encode a key for storage in the key_blob column.

    Inputs:
      - key: Any Python object used as a cache key.

    Outputs:
      - bytes: Bytes to store in key_blob.

    Notes:
      - This is used only for diagnostic/introspection purposes (key lookups are
        driven by key_digest).
      - We store bytes-like keys directly; other keys are safely serialized.
    """

    if isinstance(key, (bytes, bytearray, memoryview)):
        return bytes(key)
    return safe_serialize(key)


class PostgresTTLCache:
    """PostgreSQL-backed TTL cache with lazy driver import and key digest storage.

    Aliases used by the cache plugin registry: postgres, postgresql, pg.

    Inputs (constructor):
        namespace: Table name prefix (a-z, 0-9, underscore only).
        host: Database host (default "127.0.0.1").
        port: Database port (default 5432).
        user: Database username.
        password: Database password.
        database: Database name.
        connect_kwargs: Optional mapping of additional keyword arguments passed
            through to the underlying driver's ``connect`` function.

    Outputs:
        Initialized PostgresTTLCache instance with ensured schema.
    """

    # Namespace pattern: alphanumeric + underscore only
    _NAMESPACE_PATTERN = re.compile(r"^[a-z0-9_]+$", re.IGNORECASE)

    def __init__(
        self,
        namespace: str = "cache",
        host: str = "127.0.0.1",
        port: int = 5432,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "foghorn_cache",
        connect_kwargs: Optional[Dict[str, Any]] = None,
        **_: Any,
    ) -> None:
        # Validate namespace first, before any driver import
        if not self._NAMESPACE_PATTERN.match(namespace):
            raise ValueError(f"namespace must match [a-z0-9_]+; got: {namespace}")

        self.namespace = namespace
        self._lock = threading.RLock()

        driver = _import_postgres_driver()

        kwargs: Dict[str, Any] = {
            "host": host,
            "port": int(port),
            "database": database,
        }
        if user is not None:
            kwargs["user"] = user
        if password is not None:
            kwargs["password"] = password
        if connect_kwargs:
            kwargs.update(dict(connect_kwargs))

        self._conn = driver.connect(**kwargs)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        """Ensure cache table and indexes exist.

        Inputs:
            None.

        Outputs:
            None; creates table/indexes if they do not already exist.
        """

        table_name = f"{self.namespace}_ttl"
        cur = self._conn.cursor()

        # Key digest (SHA-256), key blob, value blob, TTL, expiry timestamp.
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                key_digest BYTEA PRIMARY KEY,
                key_blob BYTEA NOT NULL,
                value_blob BYTEA NOT NULL,
                is_pickle SMALLINT NOT NULL DEFAULT 0,
                ttl_secs BIGINT NOT NULL,
                expiry_ts DOUBLE PRECISION NOT NULL,
                created_ts DOUBLE PRECISION NOT NULL
            )
            """
        )
        cur.execute(
            f"""
            CREATE INDEX IF NOT EXISTS {table_name}_expiry_idx
            ON {table_name}(expiry_ts)
            """
        )
        self._conn.commit()

    @staticmethod
    def _encode(value: Any) -> Tuple[bytes, int]:
        """Encode a value as bytes with a pickle flag.

        Inputs:
            value: Raw bytes or arbitrary object to cache.

        Outputs:
            Tuple of (encoded bytes, is_pickle flag: 0 for bytes, 1 for pickled).
        """

        if isinstance(value, (bytes, bytearray, memoryview)):
            return bytes(value), RAW_BYTES_FLAG
        return safe_serialize(value), SAFE_SERIALIZED_FLAG

    @staticmethod
    def _decode(payload: Any, is_pickle: int) -> Any:
        """Decode bytes back to original value.

        Inputs:
            payload: Encoded bytes-like object.
            is_pickle: Flag indicating whether payload is pickled (1) or raw (0).

        Outputs:
            Decoded value.
        """

        if int(is_pickle) == RAW_BYTES_FLAG:
            # psycopg2 returns BYTEA as memoryview.
            return bytes(payload)
        if int(is_pickle) == SAFE_SERIALIZED_FLAG:
            return safe_deserialize(bytes(payload))
        raise ValueError("Unsupported cache payload encoding flag")

    def set(self, key: Any, ttl: int, value: Any) -> None:
        """Cache a value with TTL.

        Inputs:
            key: Cache key (any Python object).
            ttl: Time-to-live in seconds.
            value: Value to cache (bytes or arbitrary object).

        Outputs:
            None.
        """

        ttl_int = max(0, int(ttl))

        with self._lock:
            payload, is_pickle = self._encode(value)
            digest = _stable_digest_for_key(key)
            key_blob = _encode_key_blob(key)
            now = time.time()
            expiry = now + float(ttl_int)

            table_name = f"{self.namespace}_ttl"
            cur = self._conn.cursor()
            cur.execute(
                f"""
                INSERT INTO {table_name}
                (key_digest, key_blob, value_blob, is_pickle, ttl_secs, expiry_ts, created_ts)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (key_digest) DO UPDATE SET
                    key_blob = EXCLUDED.key_blob,
                    value_blob = EXCLUDED.value_blob,
                    is_pickle = EXCLUDED.is_pickle,
                    ttl_secs = EXCLUDED.ttl_secs,
                    expiry_ts = EXCLUDED.expiry_ts,
                    created_ts = EXCLUDED.created_ts
                """,
                (
                    digest,
                    key_blob,
                    payload,
                    int(is_pickle),
                    int(ttl_int),
                    float(expiry),
                    float(now),
                ),
            )
            self._conn.commit()

    def get(self, key: Any) -> Optional[Any]:
        """Retrieve a cached value if not expired.

        Inputs:
            key: Cache key (any Python object).

        Outputs:
            Cached value or None if expired/missing.
        """

        with self._lock:
            digest = _stable_digest_for_key(key)
            table_name = f"{self.namespace}_ttl"
            cur = self._conn.cursor()

            cur.execute(
                f"""
                SELECT value_blob, is_pickle, expiry_ts FROM {table_name}
                WHERE key_digest = %s
                """,
                (digest,),
            )
            row = cur.fetchone()
            if row is None:
                return None

            value_blob, is_pickle, expiry_ts = row
            now = time.time()
            try:
                expiry_f = float(expiry_ts)
            except Exception:
                expiry_f = 0.0

            if now >= expiry_f:
                # Expired; clean up and return None
                cur.execute(
                    f"DELETE FROM {table_name} WHERE key_digest = %s",
                    (digest,),
                )
                self._conn.commit()
                return None

            return self._decode(value_blob, int(is_pickle))

    def get_with_meta(
        self, key: Any
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Retrieve a cached value with metadata if not expired.

        Inputs:
            key: Cache key (any Python object).

        Outputs:
            (value_or_None, seconds_remaining_or_None, original_ttl_or_None)
        """

        with self._lock:
            digest = _stable_digest_for_key(key)
            table_name = f"{self.namespace}_ttl"
            cur = self._conn.cursor()

            cur.execute(
                f"""
                SELECT value_blob, is_pickle, ttl_secs, expiry_ts
                FROM {table_name}
                WHERE key_digest = %s
                """,
                (digest,),
            )
            row = cur.fetchone()
            if row is None:
                return None, None, None

            value_blob, is_pickle, ttl_secs, expiry_ts = row
            now = time.time()

            try:
                ttl_i = int(ttl_secs)
            except Exception:
                ttl_i = 0

            try:
                expiry_f = float(expiry_ts)
            except Exception:
                expiry_f = 0.0

            remaining = float(expiry_f - now)
            if remaining <= 0:
                # Expired; clean up and return miss.
                cur.execute(
                    f"DELETE FROM {table_name} WHERE key_digest = %s",
                    (digest,),
                )
                self._conn.commit()
                return None, None, None

            return self._decode(value_blob, int(is_pickle)), remaining, ttl_i

    def purge(self) -> int:
        """Remove all expired entries from the cache.

        Inputs:
            None.

        Outputs:
            Number of rows deleted.
        """

        with self._lock:
            table_name = f"{self.namespace}_ttl"
            cur = self._conn.cursor()
            now = time.time()

            cur.execute(
                f"DELETE FROM {table_name} WHERE expiry_ts <= %s",
                (now,),
            )
            self._conn.commit()
            return cur.rowcount

    def close(self) -> None:
        """Close the underlying database connection.

        Inputs:
            None.

        Outputs:
            None.
        """

        try:
            if hasattr(self, "_conn") and self._conn:
                self._conn.close()
        except Exception:
            logger.exception("Error closing PostgreSQL connection")

    def __del__(self) -> None:
        """Cleanup when garbage collected."""

        self.close()
