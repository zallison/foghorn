from __future__ import annotations

import hashlib
import logging
import threading
import time
from typing import Any, Optional, Tuple
from foghorn.plugins.cache.safe_codec import (
    RAW_BYTES_FLAG,
    SAFE_SERIALIZED_FLAG,
    safe_deserialize,
    safe_serialize,
)
from foghorn.plugins.db_drivers import (
    import_mysql_driver,
)
from foghorn.plugins.sql_safety import validate_sql_identifier, validate_sql_placeholder

_logger = logging.getLogger(__name__)
_MYSQL_NAMESPACE_MAX_LENGTH = 53


def _stable_digest_for_key(key: Any) -> str:
    """Brief: Create a stable digest for a cache key.

    Inputs:
      - key: Any Python object.

    Outputs:
      - str: Hex digest suitable for use as a database primary key.

    Notes:
      - We hash a pickle of the key to avoid ambiguities.
    """

    payload = safe_serialize(key)
    return hashlib.sha256(payload).hexdigest()


class MySQLTTLCache:
    """MySQL/MariaDB-backed TTL cache for arbitrary Python keys and values.

    Brief:
      A thread-safe key/value store with per-entry TTL semantics backed by
      MySQL/MariaDB. This is intended to be reusable by multiple parts of
      Foghorn without each subsystem re-implementing connection management,
      directory creation, TTL bookkeeping, and serialization.

    Inputs (constructor):
      - db_path: Not used (for interface compatibility).
      - host: Database host (default "127.0.0.1").
      - port: Database port (default 3306).
      - user: Database username.
      - password: Database password.
      - database: Database name (default "foghorn_cache").
      - namespace: Table name to store entries (default "ttl_cache").
      - connect_kwargs: Optional mapping of additional keyword arguments passed
        through to the underlying driver's ``connect`` function.
      - driver: Preferred DB driver (auto|mariadb|mysql-connector-python or mysql).
      - driver_fallback: Fallback policy for driver import:
          - auto (default): try the other driver as a fallback.
          - none: do not fall back.
          - <driver> or [<driver>, ...]: explicit fallback list.

    Outputs:
      - MySQLTTLCache instance.

    Notes:
      - Keys and values are stored as BLOBs. Bytes-like objects are stored
        directly; other objects are stored as pickles.
      - get() enforces expiry (expired entries are treated as misses and are
        removed).
      - get_with_meta() returns the value even when expired (with a negative
        seconds_remaining) so callers can implement stale-while-revalidate.
      - All DB operations are synchronized with an RLock.
    """

    def __init__(
        self,
        db_path: Optional[str] = None,
        *,
        host: str = "127.0.0.1",
        port: int = 3306,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "foghorn_cache",
        namespace: str = "ttl_cache",
        connect_kwargs: Optional[dict[str, Any]] = None,
        driver: Optional[str] = None,
        driver_fallback: object = None,
    ) -> None:
        """Brief: Initialize the MySQL TTL cache and ensure schema exists.

        Inputs:
          - db_path: Ignored (for interface compatibility with SQLite backend).
          - host: MySQL host.
          - port: MySQL port.
          - user: Username.
          - password: Password.
          - database: Database name.
          - namespace: Table name.
          - connect_kwargs: Additional connection kwargs.
          - driver: Preferred DB driver import choice.
          - driver_fallback: Driver fallback policy.

        Outputs:
          - None.
        """

        driver, param_style = import_mysql_driver(
            driver=driver,
            driver_fallback=driver_fallback,
            consumer_name="MySQLTTLCache",
        )
        self._param_style = param_style
        self._placeholder = validate_sql_placeholder(
            "%s" if param_style == "format" else "?",
            allowed_placeholders={"%s", "?"},
        )

        # namespace is later interpolated into SQL text and cannot be bound as a
        # value parameter; enforce strict identifier validation up front.
        self.namespace = validate_sql_identifier(
            namespace,
            field_name="namespace",
            max_length=_MYSQL_NAMESPACE_MAX_LENGTH,
        )

        # Per-cache access counters used by admin snapshots.
        self.calls_total: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

        # Eviction counters (best-effort) for diagnostics.
        self.evictions_total: int = 0
        self.evictions_ttl: int = 0

        self._lock = threading.RLock()

        kwargs: dict[str, Any] = {
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
        """Brief: Create the TTL cache table and indexes.

        Inputs:
            None.

        Outputs:
            None; creates the table if it does not already exist.
        """

        conn = self._conn
        cur = conn.cursor()

        table = self.namespace
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {table} (
                key_digest BINARY(32) PRIMARY KEY,
                key_blob LONGBLOB NOT NULL,
                key_is_pickle INTEGER NOT NULL DEFAULT 0,
                expiry DOUBLE NOT NULL,
                ttl INTEGER NOT NULL,
                value_blob LONGBLOB NOT NULL,
                value_is_pickle INTEGER NOT NULL DEFAULT 0
            ) ENGINE=InnoDB
            """
        )

        # Create index if it doesn't exist (best-effort; ignore if unsupported)
        try:
            cur.execute(
                f"CREATE INDEX IF NOT EXISTS {table}_expiry_idx ON {table} (expiry)"
            )
        except (
            Exception
        ):  # pragma: nocover - Some older MySQL versions may not support this
            try:
                cur.execute(f"CREATE INDEX {table}_expiry_idx ON {table} (expiry)")
            except Exception:  # pragma: nocover - Index may already exist
                pass

        conn.commit()

    @staticmethod
    def _encode(obj: Any) -> Tuple[bytes, int]:
        """Brief: Encode an arbitrary Python object for MySQL storage.

        Inputs:
          - obj: Any Python object.

        Outputs:
          - (payload, is_pickle):
              - payload: bytes to store.
              - is_pickle: 1 when payload is pickle-encoded, 0 otherwise.
        """

        if isinstance(obj, (bytes, bytearray, memoryview)):
            return bytes(obj), RAW_BYTES_FLAG
        return safe_serialize(obj), SAFE_SERIALIZED_FLAG

    @staticmethod
    def _decode(payload: bytes, is_pickle: int) -> Any:
        """Brief: Decode a stored MySQL payload.

        Inputs:
          - payload: Stored bytes.
          - is_pickle: 1 if payload is a pickle.

        Outputs:
          - Any: Decoded object.
        """

        if int(is_pickle) == RAW_BYTES_FLAG:
            return bytes(payload)
        if int(is_pickle) == SAFE_SERIALIZED_FLAG:
            return safe_deserialize(payload)
        raise ValueError("Unsupported cache payload encoding flag")

    def get(self, key: Any) -> Any | None:
        """Brief: Lookup a cached entry enforcing expiry.

        Inputs:
          - key: Any key object.

        Outputs:
          - Any | None: Cached value if present and not expired; otherwise None.
        """

        key_digest = bytes.fromhex(_stable_digest_for_key(key))
        now = time.time()

        table = self.namespace
        with self._lock:
            self.calls_total += 1

            cur = self._conn.cursor()
            cur.execute(
                f"SELECT value_blob, value_is_pickle, expiry FROM {table} WHERE key_digest={self._placeholder}",  # noqa: S608 - table/placeholder validated in __init__
                (key_digest,),
            )
            row = cur.fetchone()

        if not row:
            self.cache_misses += 1
            return None

        value_blob, value_is_pickle, expiry = row
        try:
            expiry_f = float(expiry)
        except Exception:  # pragma: nocover - defensive
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_digest={self._placeholder}",  # noqa: S608 - table/placeholder validated in __init__
                (key_digest,),
            )
            self._conn.commit()
            self.cache_misses += 1
            return None

        if now >= expiry_f:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_digest={self._placeholder}",  # noqa: S608 - table/placeholder validated in __init__
                (key_digest,),
            )
            self._conn.commit()
            self.cache_misses += 1
            try:
                self.evictions_total += 1
                self.evictions_ttl += 1
            except Exception:  # pragma: nocover - defensive
                pass
            return None

        try:
            value = self._decode(bytes(value_blob), int(value_is_pickle))
        except Exception:  # pragma: nocover - defensive
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_digest={self._placeholder}",  # noqa: S608 - table/placeholder validated in __init__
                (key_digest,),
            )
            self._conn.commit()
            self.cache_misses += 1
            return None

        self.cache_hits += 1
        return value

    def get_with_meta(
        self, key: Any
    ) -> Tuple[Any | None, Optional[float], Optional[int]]:
        """Brief: Lookup a cached entry and return metadata.

        Inputs:
          - key: Any key object.

        Outputs:
          - (value_or_None, seconds_remaining_or_None, original_ttl_or_None)

        Notes:
          - This method intentionally does not purge expired entries.
        """

        key_digest = bytes.fromhex(_stable_digest_for_key(key))
        now = time.time()

        table = self.namespace
        with self._lock:
            self.calls_total += 1
            cur = self._conn.cursor()
            cur.execute(
                f"SELECT value_blob, value_is_pickle, expiry, ttl FROM {table} WHERE key_digest={self._placeholder}",  # noqa: S608 - table/placeholder validated in __init__
                (key_digest,),
            )
            row = cur.fetchone()

        if not row:
            self.cache_misses += 1
            return None, None, None

        value_blob, value_is_pickle, expiry, ttl = row

        try:
            expiry_f = float(expiry)
            ttl_i = int(ttl)
            remaining = float(expiry_f - now)
        except Exception:  # pragma: nocover - defensive
            self.cache_misses += 1
            return None, None, None

        try:
            value = self._decode(bytes(value_blob), int(value_is_pickle))
        except Exception:  # pragma: nocover - defensive
            try:
                self.cache_misses += 1
            except Exception:  # pragma: nocover - defensive
                pass
            return None, None, None

        if remaining >= 0:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

        return value, remaining, ttl_i

    def set(self, key: Any, ttl: int, value: Any) -> None:
        """Brief: Store a value under a key with TTL.

        Inputs:
          - key: Any key object.
          - ttl: Time-to-live in seconds.
          - value: Any value.

        Outputs:
          - None.
        """

        ttl_int = max(0, int(ttl))
        expiry = time.time() + ttl_int

        key_digest = bytes.fromhex(_stable_digest_for_key(key))
        key_blob, key_is_pickle = self._encode(key)
        value_blob, value_is_pickle = self._encode(value)

        table = self.namespace
        placeholder = self._placeholder
        with self._lock:
            cur = self._conn.cursor()
            upsert_sql = (
                f"INSERT INTO {table} "  # noqa: S608 - table/placeholder validated in __init__
                "(key_digest, key_blob, key_is_pickle, expiry, ttl, value_blob, value_is_pickle) "
                f"VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}, {placeholder}) "
                "ON DUPLICATE KEY UPDATE "
                "key_blob=VALUES(key_blob), "
                "key_is_pickle=VALUES(key_is_pickle), "
                "expiry=VALUES(expiry), "
                "ttl=VALUES(ttl), "
                "value_blob=VALUES(value_blob), "
                "value_is_pickle=VALUES(value_is_pickle)"
            )  # noqa: S608 - table/placeholder validated in __init__
            cur.execute(
                upsert_sql,
                (
                    key_digest,
                    key_blob,
                    int(key_is_pickle),
                    float(expiry),
                    int(ttl_int),
                    value_blob,
                    int(value_is_pickle),
                ),
            )
            self._conn.commit()

    def purge(self) -> int:
        """Brief: Purge expired entries.

        Inputs:
          - None.

        Outputs:
          - int: Number of entries removed (best-effort).
        """

        now = time.time()
        table = self.namespace
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE expiry <= {self._placeholder}",  # noqa: S608 - table/placeholder validated in __init__
                (float(now),),
            )
            removed = int(cur.rowcount or 0)
            self._conn.commit()
        if removed > 0:
            try:
                self.evictions_total += removed
                self.evictions_ttl += removed
            except Exception:  # pragma: nocover - defensive
                pass
        return removed

    def close(self) -> None:
        """Brief: Close the underlying connection.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        with self._lock:
            try:
                self._conn.close()
            except Exception:  # pragma: nocover - defensive cleanup
                pass

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:  # pragma: nocover - defensive cleanup
            pass
