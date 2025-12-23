from __future__ import annotations

import os
import pickle
import sqlite3
import threading
import time
from typing import Any, Optional, Tuple


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
    ) -> None:
        """Brief: Initialize the sqlite TTL cache and ensure schema exists.

        Inputs:
          - db_path: sqlite file path or ':memory:'.
          - table: table name.
          - journal_mode: sqlite journal mode.
          - create_dir: create parent directory for on-disk db_path.

        Outputs:
          - None.
        """

        self.db_path = str(db_path)

        self.namespace = str(namespace or "ttl_cache")
        self.journal_mode = str(journal_mode or "WAL")
        self.create_dir = bool(create_dir)

        # Per-cache access counters used by admin snapshots. These are best-effort
        # only and do not affect core cache semantics.
        self.calls_total: int = 0
        self.cache_hits: int = 0
        self.cache_misses: int = 0

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
            return bytes(obj), 0
        return pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL), 1

    @staticmethod
    def _decode(payload: bytes, is_pickle: int) -> Any:
        """Brief: Decode a stored sqlite payload.

        Inputs:
          - payload: Stored bytes.
          - is_pickle: 1 if payload is a pickle.

        Outputs:
          - Any: Decoded object.
        """

        if int(is_pickle) == 1:
            return pickle.loads(payload)
        return payload

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
                f"SELECT value_blob, value_is_pickle, expiry FROM {table} WHERE key_blob=? AND key_is_pickle=?",
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
                cur.execute(
                    f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",
                    (key_blob, int(key_is_pickle)),
                )
                self._conn.commit()
                self.cache_misses += 1
                return None

            if now >= expiry_f:
                cur.execute(
                    f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",
                    (key_blob, int(key_is_pickle)),
                )
                self._conn.commit()
                self.cache_misses += 1
                return None

            try:
                value = self._decode(bytes(value_blob), int(value_is_pickle))
            except Exception:
                cur.execute(
                    f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",
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
                f"SELECT value_blob, value_is_pickle, expiry, ttl FROM {table} WHERE key_blob=? AND key_is_pickle=?",
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
                f"INSERT OR REPLACE INTO {table} (key_blob, key_is_pickle, expiry, ttl, value_blob, value_is_pickle) "
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
                f"DELETE FROM {table} WHERE key_blob=? AND key_is_pickle=?",
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
            cur.execute(f"DELETE FROM {table} WHERE expiry <= ?", (float(now),))
            removed = int(cur.rowcount or 0)
            self._conn.commit()
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
