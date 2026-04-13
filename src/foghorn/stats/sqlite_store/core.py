from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("foghorn.stats")


class _StatsSQLiteStoreCore:
    """Core helpers for StatsSQLiteStore.

    Inputs:
        None (this class is intended to be used via multiple inheritance).

    Outputs:
        Provides connection, batching, and basic counter/query-log write helpers.
    """

    def __init__(
        self,
        db_path: str,
        batch_writes: bool = False,
        batch_time_sec: float = 15.0,
        batch_max_size: int = 1000,
    ) -> None:
        """Initialize SQLite store and ensure schema exists.

        Inputs:
            db_path: Path to SQLite database file.
            batch_writes: If True, queue writes and flush periodically.
            batch_time_sec: Max age of a batch before flush when batching.
            batch_max_size: Max queued operations before forced flush.

        Outputs:
            None
        """
        self._db_path = db_path
        self._conn = self._init_connection()

        # Batching configuration
        self._batch_writes = bool(batch_writes)
        self._batch_time_sec = float(batch_time_sec)
        self._batch_max_size = int(batch_max_size)

        # Internal state for batching and thread-safety
        self._lock = threading.RLock()
        self._pending_ops: List[Tuple[str, Tuple[Any, ...]]] = []
        self._last_flush: float = time.time()

    def _init_connection(self) -> sqlite3.Connection:
        """Create SQLite connection and ensure schema exists.

        Inputs:
            None

        Outputs:
            sqlite3.Connection instance with schema initialized.
        """
        dir_path = os.path.dirname(self._db_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        try:
            # Best-effort journaling tweaks; errors are non-fatal.
            conn.execute("PRAGMA journal_mode=WAL")
        except Exception:  # pragma: no cover - environment specific
            pass

        # Aggregate counters table
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS counts (
                scope TEXT NOT NULL,
                key   TEXT NOT NULL,
                value INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (scope, key)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_counts_scope_key_value
            ON counts(scope, key, value)
            """
        )

        # Raw DNS query log (append-only at the code level)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS query_log (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                ts           REAL NOT NULL,
                client_ip    TEXT NOT NULL,
                name         TEXT NOT NULL,
                qtype        TEXT NOT NULL,
                upstream_id  TEXT,
                rcode        TEXT,
                status       TEXT,
                error        TEXT,
                first        TEXT,
                result_json  TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_ts
            ON query_log(ts)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_name_ts
            ON query_log(name, ts)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_client_ts
            ON query_log(client_ip, ts)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_upstream_ts
            ON query_log(upstream_id, ts)
            """
        )

        conn.commit()
        return conn

    def health_check(self) -> bool:
        """Brief: Return True when the underlying SQLite store is usable.

        Inputs: none

        Outputs:
            bool: True when a trivial query succeeds, else False.

        Notes:
            - This is intended for readiness probes (e.g., /ready) and should be
              very lightweight.
            - The method uses the store lock to avoid racing with batched writes.

        Example:
            >>> store = StatsSQLiteStore(':memory:')
            >>> store.health_check()
            True
        """

        try:
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Low-level execution helpers
    # ------------------------------------------------------------------
    def _execute(self, sql: str, params: Tuple[Any, ...]) -> None:
        """Execute a single SQL statement, with optional batching.

        Inputs:
            sql: SQL statement with positional placeholders.
            params: Tuple of parameters for the placeholders.

        Outputs:
            None
        """
        if not self._batch_writes:
            try:
                with self._conn:
                    self._conn.execute(sql, params)
            except Exception as exc:  # pragma: no cover
                logger.error("StatsSQLiteStore execute error: %s", exc, exc_info=True)
            return

        # Batched mode
        with self._lock:
            self._pending_ops.append((sql, params))
            self._maybe_flush_locked()

    def _maybe_flush_locked(self) -> None:
        """Flush pending batched operations if thresholds are exceeded.

        Inputs:
            None (must be called with _lock held when batching).

        Outputs:
            None
        """
        if not self._batch_writes:
            return

        now = time.time()
        ops_len = len(self._pending_ops)
        if ops_len == 0:
            return  # pragma: no cover - trivial early-exit guard

        age = now - self._last_flush
        if ops_len >= self._batch_max_size or age >= self._batch_time_sec:
            self._flush_locked()

    def _flush_locked(self) -> None:
        """Flush all pending operations in a single transaction.

        Inputs:
            None (must be called with _lock held).

        Outputs:
            None
        """
        if not self._pending_ops:
            return
        try:
            with self._conn:  # type: ignore[attr-defined]
                cur = self._conn.cursor()  # type: ignore[attr-defined]
                for sql, params in self._pending_ops:
                    cur.execute(sql, params)
            self._pending_ops.clear()
            self._last_flush = time.time()
        except Exception as exc:  # pragma: no cover
            logger.error("StatsSQLiteStore flush error: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Public API: counters and query log
    # ------------------------------------------------------------------
    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Increment an aggregate counter in the counts table.

        Inputs:
            scope: Logical scope name (e.g., 'totals', 'domains').
            key: Counter key within the scope.
            delta: Increment value (may be negative for decrements).

        Outputs:
            None
        """
        try:
            sql = (
                "INSERT INTO counts (scope, key, value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(scope, key) DO UPDATE SET value = counts.value + excluded.value"
            )
            self._execute(sql, (scope, key, int(delta)))
        except Exception as exc:  # pragma: no cover
            logger.error(
                "StatsSQLiteStore increment_count error: %s", exc, exc_info=True
            )

    def set_count(self, scope: str, key: str, value: int) -> None:
        """Set an aggregate counter in the counts table.

        Inputs:
            scope: Logical scope name.
            key: Counter key within the scope.
            value: New integer value to assign.

        Outputs:
            None
        """
        try:
            sql = (
                "INSERT INTO counts (scope, key, value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value"
            )
            self._execute(sql, (scope, key, int(value)))
        except Exception as exc:  # pragma: no cover
            logger.error("StatsSQLiteStore set_count error: %s", exc, exc_info=True)

    def insert_query_log(
        self,
        ts: float,
        client_ip: str,
        name: str,
        qtype: str,
        upstream_id: Optional[str],
        rcode: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
        result_json: str,
    ) -> None:
        """Append a DNS query entry to the query_log table.

        Inputs:
            ts: Unix timestamp with millisecond precision.
            client_ip: Client IP address.
            name: Normalized query name.
            qtype: Query type string (e.g., 'A').
            upstream_id: Optional upstream identifier (e.g., '8.8.8.8:53').
            rcode: Optional DNS response code ('NOERROR', 'NXDOMAIN', etc.).
            status: Optional high-level status ('ok', 'timeout', 'cache_hit', ...).
            error: Optional error message summary.
            first: Optional first answer record representation.
            result_json: Structured result payload as JSON text.

        Outputs:
            None
        """
        try:
            sql = (
                "INSERT INTO query_log (ts, client_ip, name, qtype, upstream_id, rcode, "
                "status, error, first, result_json) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
            params: Tuple[Any, ...] = (
                float(ts),
                client_ip,
                name,
                qtype,
                upstream_id,
                rcode,
                status,
                error,
                first,
                result_json,
            )
            self._execute(sql, params)
        except Exception as exc:  # pragma: no cover
            logger.error(
                "StatsSQLiteStore insert_query_log error: %s", exc, exc_info=True
            )

    def has_counts(self) -> bool:
        """Return True if the counts table contains at least one row.

        Inputs:
            None

        Outputs:
            bool: True when counts has rows, False otherwise.
        """
        try:
            cur = self._conn.execute("SELECT 1 FROM counts LIMIT 1")  # type: ignore[attr-defined]
            return cur.fetchone() is not None
        except Exception as exc:  # pragma: no cover
            logger.error("StatsSQLiteStore has_counts error: %s", exc, exc_info=True)
            return False

    def export_counts(self) -> Dict[str, Dict[str, int]]:
        """Export all aggregate counters from the counts table.

        Inputs:
            None

        Outputs:
            Dict[str, Dict[str, int]] mapping scope -> {key -> value}.

        Example:
            >>> store = StatsSQLiteStore('/tmp/stats.db')  # doctest: +SKIP
            >>> store.increment_count('totals', 'total_queries')  # doctest: +SKIP
            >>> counts = store.export_counts()  # doctest: +SKIP
            >>> counts['totals']['total_queries'] >= 1  # doctest: +SKIP
            True
        """
        result: Dict[str, Dict[str, int]] = {}
        try:
            cur = self._conn.cursor()  # type: ignore[attr-defined]
            cur.execute("SELECT scope, key, value FROM counts")
            for scope, key, value in cur:
                scope_map = result.setdefault(str(scope), {})
                try:
                    scope_map[str(key)] = int(value)
                except (TypeError, ValueError):
                    # Skip rows with non-integer values defensively.
                    continue
        except Exception as exc:  # pragma: no cover
            logger.error("StatsSQLiteStore export_counts error: %s", exc, exc_info=True)
        return result

    def has_query_log(self) -> bool:
        """Return True if the query_log table contains at least one row.

        Inputs:
            None

        Outputs:
            bool: True when query_log has rows, False otherwise.
        """
        try:
            cur = self._conn.execute("SELECT 1 FROM query_log LIMIT 1")  # type: ignore[attr-defined]
            return cur.fetchone() is not None
        except Exception as exc:  # pragma: no cover
            logger.error("StatsSQLiteStore has_query_log error: %s", exc, exc_info=True)
            return False

    def close(self) -> None:
        """Close the underlying SQLite connection, flushing any pending writes.

        Inputs:
            None

        Outputs:
            None
        """
        try:
            if self._batch_writes:
                with self._lock:
                    self._flush_locked()
            conn = getattr(self, "_conn", None)
            if conn is not None:
                conn.close()
        except Exception:  # pragma: no cover
            logger.exception("Error while closing StatsSQLiteStore connection")
