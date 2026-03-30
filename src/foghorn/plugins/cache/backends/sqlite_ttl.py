from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from typing import Any, Optional, Tuple
from foghorn.plugins.cache.safe_codec import (
    RAW_BYTES_FLAG,
    SAFE_SERIALIZED_FLAG,
    safe_deserialize,
    safe_serialize,
)
from foghorn.plugins.sql_safety import validate_sql_identifier

_logger = logging.getLogger(__name__)
_SQLITE_NAMESPACE_MAX_LENGTH = 63


class SQLite3TTLCache:
    """SQLite-backed TTL cache for arbitrary Python keys and values.

    Brief:
      A small, thread-safe key/value store with per-entry TTL semantics backed by
      sqlite3. This is intended to be reusable by multiple parts of Foghorn
      (cache plugins, plugins that want persistence, recursive resolver helpers,
      etc.) without each subsystem re-implementing connection management,
      directory creation, TTL bookkeeping, and serialization.

    Inputs (constructor):
      - db_path: Path to sqlite3 DB file. Use ':memory:' for in-memory.
      - table: Table name to store entries.
      - journal_mode: SQLite journal mode string (default 'WAL'). Best-effort.
      - create_dir: When True, create parent directory for db_path if needed.

    Outputs:
      - SQLite3TTLCache instance.

    Notes:
      - Keys and values are stored as BLOBs. Bytes-like objects are stored
        directly; other objects are stored as pickles.
      - get() enforces expiry (expired entries are treated as misses and are
        removed).
      - get_with_meta() returns the value even when expired (with a negative
        seconds_remaining) so callers can implement stale-while-revalidate.
      - All DB operations are synchronized with an RLock.

    Example:
      >>> cache = SQLite3TTLCache(":memory:")
      >>> cache.set(("example.com", 1), 60, b"wire")
      >>> cache.get(("example.com", 1))
      b'wire'
    """

    def __init__(
        self,
        db_path: str,
        *,
        namespace: str = "ttl_cache",
        table: Optional[str] = None,
        journal_mode: str = "WAL",
        create_dir: bool = True,
        maxsize: int | None = None,
    ) -> None:
        """Brief: Initialize the sqlite TTL cache and ensure schema exists.

        Inputs:
          - db_path: sqlite file path or ':memory:'.
          - table: table name.
          - journal_mode: sqlite journal mode.
          - create_dir: create parent directory for on-disk db_path.
          - maxsize: Optional positive integer capacity bound. When set, the
            cache performs best-effort eviction by deleting rows with the
            earliest expiry after inserts.

        Outputs:
          - None.
        """

        self.db_path = str(db_path)
        # namespace/table is interpolated into SQL text and therefore must be a
        # validated identifier token instead of user-controlled raw text.
        table_name = table if table is not None else namespace
        self.namespace = validate_sql_identifier(
            str(table_name or "ttl_cache"),
            field_name="namespace",
            max_length=_SQLITE_NAMESPACE_MAX_LENGTH,
        )
        self.journal_mode = str(journal_mode or "WAL")
        self.create_dir = bool(create_dir)

        try:
            max_i = int(maxsize) if maxsize is not None else None
        except Exception:
            max_i = None
        if isinstance(max_i, int) and max_i <= 0:
            max_i = None
        self.maxsize: int | None = max_i

        # Per-cache access counters used by admin snapshots. These are best-effort
        # only and do not affect core cache semantics.
        self.calls_total: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

        # Eviction counters (best-effort) for diagnostics.
        # evictions_total: total rows removed due to TTL expiry or maxsize.
        # evictions_ttl: TTL-based purges.
        # evictions_capacity: best-effort size-based evictions.
        self.evictions_total: int = 0
        self.evictions_ttl: int = 0
        self.evictions_capacity: int = 0

        self._lock = threading.RLock()
        self._conn = self._init_connection()

    def _init_connection(self) -> sqlite3.Connection:
        """Brief: Create sqlite connection and initialize schema.

        Inputs:
          - None.

        Outputs:
          - sqlite3.Connection: Open sqlite connection with schema ensured.
        """

        db_path = self.db_path
        if db_path != ":memory:":
            # Normalize paths for on-disk DBs.
            db_path = os.path.abspath(os.path.expanduser(db_path))
            self.db_path = db_path

            if self.create_dir:
                dir_path = os.path.dirname(db_path)
                if dir_path:
                    os.makedirs(dir_path, exist_ok=True)

        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        try:
            conn.execute(f"PRAGMA journal_mode={self.journal_mode}")
        except Exception:
            # Best-effort: some environments restrict PRAGMAs.
            pass

        table = self.namespace
        conn.execute(
            f"CREATE TABLE IF NOT EXISTS {table} ("
            "key_blob BLOB PRIMARY KEY, "
            "key_is_pickle INTEGER NOT NULL DEFAULT 0, "
            "expiry REAL NOT NULL, "
            "ttl INTEGER NOT NULL, "
            "value_blob BLOB NOT NULL, "
            "value_is_pickle INTEGER NOT NULL DEFAULT 0"
            ")"
        )
        conn.execute(
            f"CREATE INDEX IF NOT EXISTS {table}_expiry_idx ON {table}(expiry)"
        )
        conn.commit()
        return conn

    @staticmethod
    def _encode(obj: Any) -> Tuple[bytes, int]:
        """Brief: Encode an arbitrary Python object for sqlite storage.

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
        """Brief: Decode a stored sqlite payload.

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

        key_blob, key_is_pickle = self._encode(key)
        now = time.time()

        table = self.namespace
        with self._lock:
            self.calls_total += 1

            cur = self._conn.cursor()
            cur.execute(
                f"SELECT value_blob, value_is_pickle, expiry FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                (key_blob, int(key_is_pickle)),
            )
            row = cur.fetchone()

        if not row:
            self.cache_misses += 1
            return None

        value_blob, value_is_pickle, expiry = row
        try:
            expiry_f = float(expiry)
        except Exception:
            # Malformed row: drop it and treat as a miss for diagnostics.
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                (key_blob, int(key_is_pickle)),
            )
            self._conn.commit()
            self.cache_misses += 1
            return None

        if now >= expiry_f:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                (key_blob, int(key_is_pickle)),
            )
            self._conn.commit()
            self.cache_misses += 1
            try:
                self.evictions_total += 1
                self.evictions_ttl += 1
            except Exception:  # pragma: no cover - defensive counters
                pass
            try:
                _logger.debug(
                    "SQLite3TTLCache TTL eviction (get): ns=%r key_blob_len=%d",
                    self.namespace,
                    len(key_blob),
                )
            except Exception:  # pragma: no cover - defensive logging
                pass
            return None

        try:
            value = self._decode(bytes(value_blob), int(value_is_pickle))
        except Exception:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                (key_blob, int(key_is_pickle)),
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

        key_blob, key_is_pickle = self._encode(key)
        now = time.time()

        table = self.namespace
        with self._lock:
            self.calls_total += 1
            cur = self._conn.cursor()
            cur.execute(
                f"SELECT value_blob, value_is_pickle, expiry, ttl FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                (key_blob, int(key_is_pickle)),
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
        except Exception:
            self.cache_misses += 1
            return None, None, None

        try:
            value = self._decode(bytes(value_blob), int(value_is_pickle))
        except Exception:
            try:
                self.cache_misses += 1
            except Exception:  # pragma: no cover - defensive only
                pass
            return None, None, None

        # get_with_meta intentionally does not purge expired rows, but we still
        # classify them as misses for diagnostics when remaining < 0.
        if remaining >= 0:
            self.cache_hits += 1
        else:
            self.cache_misses += 1

        return value, remaining, ttl_i

    def _enforce_maxsize_locked(self) -> int:
        """Brief: Best-effort size enforcement by deleting rows with oldest expiry.

        Inputs:
          - None (uses self.maxsize and the current sqlite table).

        Outputs:
          - int: Number of rows removed.

        Notes:
          - This is intentionally best-effort; failures should not affect normal
            caching behaviour.
          - Eviction policy is "almost_expired" (oldest expiry first).
        """

        if not isinstance(self.maxsize, int) or self.maxsize <= 0:
            return 0

        table = self.namespace
        try:
            cur = self._conn.cursor()
            cur.execute(  # noqa: S608 - table identifier validated in __init__
                f"SELECT COUNT(*) FROM {table}",  # noqa: S608 - table identifier validated in __init__
            )
            row = cur.fetchone()
            count = int(row[0]) if row and row[0] is not None else 0
        except Exception:
            return 0

        over = int(count - int(self.maxsize))
        if over <= 0:
            return 0

        try:
            cur2 = self._conn.cursor()
            cur2.execute(
                f"SELECT key_blob, key_is_pickle FROM {table} ORDER BY expiry ASC LIMIT ?",  # noqa: S608 - table identifier validated in __init__
                (int(over),),
            )
            victims = list(cur2.fetchall() or [])
        except Exception:
            return 0

        if not victims:
            return 0

        removed = 0
        try:
            cur3 = self._conn.cursor()
            cur3.executemany(
                f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                [(v[0], int(v[1])) for v in victims],
            )
            removed = int(cur3.rowcount or 0)
        except Exception:
            removed = 0

        if removed > 0:
            try:
                self.evictions_total += removed
                self.evictions_capacity += removed
            except Exception:  # pragma: no cover
                pass
        return int(removed)

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

        key_blob, key_is_pickle = self._encode(key)
        value_blob, value_is_pickle = self._encode(value)

        table = self.namespace
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO {table} (key_blob, key_is_pickle, expiry, ttl, value_blob, value_is_pickle) "  # noqa: S608 - table identifier validated in __init__
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    key_blob,
                    int(key_is_pickle),
                    float(expiry),
                    int(ttl_int),
                    value_blob,
                    int(value_is_pickle),
                ),
            )

            # Best-effort size enforcement.
            try:
                self._enforce_maxsize_locked()
            except Exception:
                pass

            self._conn.commit()

    def delete(self, key: Any) -> int:
        """Brief: Remove a cached entry.

        Inputs:
          - key: Any key object.

        Outputs:
          - int: Number of removed rows (0 or 1).
        """

        key_blob, key_is_pickle = self._encode(key)
        table = self.namespace
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(
                f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",  # noqa: S608 - table identifier validated in __init__
                (key_blob, int(key_is_pickle)),
            )
            removed = int(cur.rowcount or 0)
            self._conn.commit()
        return removed

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
            cur.execute(  # noqa: S608 - table identifier validated in __init__
                f"DELETE FROM {table} WHERE expiry <= ?",  # noqa: S608 - table identifier validated in __init__
                (float(now),),
            )
            removed = int(cur.rowcount or 0)
            self._conn.commit()
        if removed > 0:
            try:
                self.evictions_total += removed
                self.evictions_ttl += removed
            except Exception:  # pragma: no cover - defensive counters
                pass
            try:
                _logger.debug(
                    "SQLite3TTLCache TTL purge: ns=%r removed=%d",
                    self.namespace,
                    removed,
                )
            except Exception:  # pragma: no cover - defensive logging
                pass
        return removed

    def close(self) -> None:
        """Brief: Close the underlying sqlite connection.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        with self._lock:
            try:
                self._conn.close()
            except Exception:
                pass

    def __enter__(self) -> "SQLite3TTLCache":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
