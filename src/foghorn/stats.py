"""
Thread-safe statistics collection for Foghorn DNS server.

This module provides a statistics subsystem that tracks queries, cache performance,
plugin decisions, upstream results, and response codes with minimal overhead and
guaranteed thread-safety for concurrent request handling.
"""

from __future__ import annotations

import importlib.metadata as importlib_metadata
import ipaddress
import json
import logging
import os
import socket
import sqlite3
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from foghorn.plugins.querylog import BaseStatsStore
from foghorn.utils.register_caches import registered_lru_cached

logger = logging.getLogger(__name__)

try:
    FOGHORN_VERSION = importlib_metadata.version("foghorn")
except Exception:  # pragma: no cover - defensive fallback when metadata is missing
    FOGHORN_VERSION = "unknown"


_PROCESS_START_TIME = time.time()


def get_process_uptime_seconds() -> float:
    """Return process uptime in seconds since this module was imported.

    Inputs:
      - None.

    Outputs:
      - float seconds representing elapsed wall-clock time since
        ``_PROCESS_START_TIME``; always >= 0.0.

    Example:
      >>> uptime = get_process_uptime_seconds()
      >>> uptime >= 0.0
      True
    """

    return max(0.0, time.time() - _PROCESS_START_TIME)


@registered_lru_cached(maxsize=(16 * 1024))
def _normalize_domain(domain: str) -> str:
    """
    Normalize domain name for statistics tracking.

    Inputs:
        domain: Raw domain name string (may have trailing dot, mixed case)

    Outputs:
        Normalized lowercase domain without trailing dot

    Example:
        >>> _normalize_domain("Example.COM.")
        'example.com'
    """
    return domain.rstrip(".").lower()


@registered_lru_cached(maxsize=(16 * 1024))
def _is_subdomain(domain: str) -> bool:
    """Return True if the name should be treated as a subdomain.

    Inputs:
        domain: Raw or normalized domain name string.

    Outputs:
        Boolean indicating whether the normalized name should be counted as a
        subdomain for statistics:

        - For most domains, at least three labels (e.g., "www.example.com").
        - For domains under "*.co.uk", at least four labels (e.g.,
          "www.example.co.uk"), so that "example.co.uk" itself is treated as a
          base domain, not a subdomain.

    Example:
        >>> _is_subdomain("www.example.com")
        True
        >>> _is_subdomain("example.com")
        False
        >>> _is_subdomain("www.example.co.uk")
        True
        >>> _is_subdomain("example.co.uk")
        False
    """
    norm = _normalize_domain(domain or "")
    if not norm:
        return False

    parts = norm.split(".")
    if len(parts) < 3:
        return False

    # Special-case public suffix style domains ending in "co.uk": treat the
    # registrable "example.co.uk" as the base, and only count queries with at
    # least one additional label as subdomains.
    if len(parts) >= 3 and parts[-2:] == ["co", "uk"]:
        return len(parts) >= 4

    # Default: any name with at least three labels is a subdomain.
    return True


class LatencyHistogram:
    """
    Thread-safe histogram for tracking request latencies with logarithmic bins.

    Inputs (constructor):
        None

    Outputs:
        LatencyHistogram instance for adding samples and computing percentiles

    The histogram uses fixed millisecond bins for O(1) insertion and fast
    percentile computation. Bins: [0.1, 0.2, 0.5, 1, 2, 5, 10, 20, 50, 100,
    200, 500, 1000, 2000, 5000, 10000+].

    Example:
        >>> hist = LatencyHistogram()
        >>> hist.add(0.0035)  # 3.5ms
        >>> hist.add(0.015)   # 15ms
        >>> stats = hist.summarize()
        >>> stats['count']
        2
    """

    _BINS = [0.1, 0.2, 0.5, 1, 2, 5, 10, 15, 20, 25, 30, 40,
             50, 75, 100, 150, 200, 500, 750, 1000, 1500, 2000,
             3000, 5000, 10000]

    def __init__(self) -> None:
        """Initialize empty histogram with zero counts for all bins."""
        self.bins: List[int] = [0] * (len(self._BINS) + 1)
        self.count = 0
        self.sum_ms = 0.0
        self.min_ms: Optional[float] = None
        self.max_ms: Optional[float] = None

    def add(self, seconds: float) -> None:
        """
        Add a latency sample to the histogram.

        Inputs:
            seconds: Latency in seconds (float)

        Outputs:
            None

        Example:
            >>> hist = LatencyHistogram()
            >>> hist.add(0.004)  # 4 milliseconds
        """
        ms = seconds * 1000.0
        self.count += 1
        self.sum_ms += ms

        if self.min_ms is None or ms < self.min_ms:
            self.min_ms = ms
        if self.max_ms is None or ms > self.max_ms:
            self.max_ms = ms

        # Find appropriate bin
        for i, threshold in enumerate(self._BINS):
            if ms < threshold:
                self.bins[i] += 1
                return
        # Overflow bin (>= 10000ms)
        self.bins[-1] += 1

    def summarize(self) -> Dict[str, float]:
        """
        Compute summary statistics from the histogram.

        Inputs:
            None

        Outputs:
            Dictionary with keys: count, min_ms, max_ms, avg_ms, p50_ms, p90_ms, p99_ms

        Example:
            >>> hist = LatencyHistogram()
            >>> hist.add(0.001)
            >>> summary = hist.summarize()
            >>> summary['count']
            1
        """
        if self.count == 0:
            return {
                "count": 0,
                "min_ms": 0.0,
                "max_ms": 0.0,
                "avg_ms": 0.0,
                "p50_ms": 0.0,
                "p90_ms": 0.0,
                "p99_ms": 0.0,
            }

        avg_ms = self.sum_ms / self.count
        p50_ms = self._percentile(0.50)
        p90_ms = self._percentile(0.90)
        p99_ms = self._percentile(0.99)

        return {
            "count": self.count,
            "min_ms": round(self.min_ms or 0.0, 2),
            "max_ms": round(self.max_ms or 0.0, 2),
            "avg_ms": round(avg_ms, 2),
            "p50_ms": round(p50_ms, 2),
            "p90_ms": round(p90_ms, 2),
            "p99_ms": round(p99_ms, 2),
        }

    def _percentile(self, p: float) -> float:
        """
        Compute percentile from histogram bins.

        Inputs:
            p: Percentile as fraction (0.0 to 1.0)

        Outputs:
            Estimated latency in milliseconds at percentile p
        """
        if self.count == 0:
            return 0.0

        target = int(self.count * p)
        cumulative = 0

        for i, count in enumerate(self.bins):
            cumulative += count
            if cumulative >= target:
                # Return midpoint of bin
                if i == 0:
                    return self._BINS[0] / 2
                elif i < len(self._BINS):
                    return (self._BINS[i - 1] + self._BINS[i]) / 2
                else:
                    return 10000.0  # overflow bin

        # Defensive fallback: percentile iteration should always exhaust the
        # histogram bins; if it does not, fall back to the observed max.
        return self.max_ms or 0.0  # pragma: no cover - defensive fallback


TOPK_CAPACITY_FACTOR = 100
TOPK_MIN_CAPACITY = 1024


class TopK:
    """
    Approximate top-K heavy hitters tracker with bounded memory.

    Inputs (constructor):
        capacity: Target number of top items to track (K)
        prune_factor: Multiplier for pruning threshold (default 4)

    Outputs:
        TopK instance for adding keys and exporting top N

    Uses a counter dict that is pruned when size exceeds prune_factor * capacity.
    Provides O(1) amortized insertion and bounded memory.

    Example:
        >>> tracker = TopK(capacity=3, prune_factor=2)
        >>> for _ in range(10):
        ...     tracker.add("example.com")
        >>> for _ in range(5):
        ...     tracker.add("google.com")
        >>> top = tracker.export(2)
        >>> top[0][0]
        'example.com'
    """

    def __init__(self, capacity: int = 10, prune_factor: int = 4) -> None:
        """
        Initialize TopK tracker.

        Inputs:
            capacity: Target top-K size
            prune_factor: Pruning multiplier (prune when size > capacity * prune_factor)

        Outputs:
            None
        """
        self.capacity = max(1, capacity)
        self.prune_factor = max(2, prune_factor)
        self.counts: Dict[str, int] = {}

    def add(self, key: str) -> None:
        """
        Increment count for a key.

        Inputs:
            key: String key to track

        Outputs:
            None

        Example:
            >>> tracker = TopK(capacity=5)
            >>> tracker.add("example.com")
            >>> tracker.add("example.com")
        """
        self.counts[key] = self.counts.get(key, 0) + 1

        # Occasional pruning to bound memory
        if len(self.counts) > self.capacity * self.prune_factor:
            self._prune()

    def export(self, n: int) -> List[Tuple[str, int]]:
        """
        Export top N items sorted by count descending.

        Inputs:
            n: Number of top items to return

        Outputs:
            List of (key, count) tuples sorted by count descending

        Example:
            >>> tracker = TopK(capacity=5)
            >>> tracker.add("a")
            >>> tracker.add("a")
            >>> tracker.add("b")
            >>> tracker.export(2)
            [('a', 2), ('b', 1)]
        """
        items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
        return items[:n]

    def _prune(self) -> None:
        """
        Prune to top capacity items by count.

        Inputs:
            None

        Outputs:
            None
        """
        if len(self.counts) <= self.capacity:
            return  # pragma: no cover - trivial early-exit guard

        items = sorted(self.counts.items(), key=lambda x: x[1], reverse=True)
        self.counts = dict(items[: self.capacity])


@dataclass
class StatsSnapshot:
    """
    Immutable point-in-time snapshot of statistics for logging.

    Inputs (constructor):
        All fields provided by StatsCollector.snapshot().

    Outputs:
        Snapshot instance with read-only view of statistics.

    This dataclass is created under lock but logged outside the lock to
    minimize contention. All collections are copied to prevent mutation.
    """

    created_at: float
    totals: Dict[str, int]
    rcodes: Dict[str, int]
    qtypes: Dict[str, int]
    decisions: Dict[str, Dict[str, int]]
    upstreams: Dict[str, Dict[str, int]]
    uniques: Optional[Dict[str, int]]
    top_clients: Optional[List[Tuple[str, int]]]
    top_subdomains: Optional[List[Tuple[str, int]]]
    top_domains: Optional[List[Tuple[str, int]]]
    latency_stats: Optional[Dict[str, float]]
    latency_recent_stats: Optional[Dict[str, float]] = None
    upstream_rcodes: Optional[Dict[str, Dict[str, int]]] = None
    upstream_qtypes: Optional[Dict[str, Dict[str, int]]] = None
    qtype_qnames: Optional[Dict[str, List[Tuple[str, int]]]] = None
    # Mapping of rcode -> list of (base_domain, count) tuples representing the
    # most frequently seen base domains per response code.
    rcode_domains: Optional[Dict[str, List[Tuple[str, int]]]] = None
    # Mapping of rcode -> list of (subdomain, count) tuples representing
    # subdomain names (full qnames) where subdomain queries (qname != base)
    # produced the response code.
    rcode_subdomains: Optional[Dict[str, List[Tuple[str, int]]]] = None
    # Top base domains by cache outcome, derived from cache hit/miss tracking.
    cache_hit_domains: Optional[List[Tuple[str, int]]] = None
    cache_miss_domains: Optional[List[Tuple[str, int]]] = None
    # Top subdomain names (full qnames) where cache hits/misses were produced
    # by subdomain queries only (qname != base).
    cache_hit_subdomains: Optional[List[Tuple[str, int]]] = None
    cache_miss_subdomains: Optional[List[Tuple[str, int]]] = None
    # Optional aggregated view of rate limiting derived from totals and/or
    # persistent counters (for example, cache_stat_rate_limit).
    rate_limit: Optional[Dict[str, Any]] = None
    # Optional DNSSEC status counters (subset of totals where keys start with
    # "dnssec_"). This is derived from ``totals`` for convenience in APIs and
    # UI rendering; the same keys remain present under ``totals`` for
    # backwards-compatibility.
    dnssec_totals: Optional[Dict[str, int]] = None


class StatsSQLiteStore:
    """SQLite-backed persistent statistics store.

    Inputs (constructor):
        db_path: Filesystem path to the SQLite database file.
        batch_writes: Enable batched writes instead of per-call commits (default False).
        batch_time_sec: Maximum age (in seconds) of a batch before it is flushed.
        batch_max_size: Maximum number of queued operations before forced flush.

    Outputs:
        StatsSQLiteStore instance used to maintain aggregate counters (``counts``
        table) and an append-only DNS query log (``query_log`` table).

    The previous implementation stored :class:`StatsSnapshot` objects as JSON
    blobs in a ``stats_snapshots`` table. That approach has been replaced with
    a more normalized schema that is suitable for analytics and reconstruction
    of statistics across restarts.

    Example:
        >>> store = StatsSQLiteStore("./config/var/stats.db")
        >>> store.increment_count("totals", "total_queries")
        >>> store.increment_count("domains", "example.com")
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
            >>> store = StatsSQLiteStore(":memory:")
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
            except (
                Exception
            ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.error("StatsSQLiteStore flush error: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Public API: counters and query log
    # ------------------------------------------------------------------
    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Increment an aggregate counter in the counts table.

        Inputs:
            scope: Logical scope name (e.g., "totals", "domains").
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
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
            qtype: Query type string (e.g., "A").
            upstream_id: Optional upstream identifier (e.g., "8.8.8.8:53").
            rcode: Optional DNS response code ("NOERROR", "NXDOMAIN", etc.).
            status: Optional high-level status ("ok", "timeout", "cache_hit", ...).
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.error(
                "StatsSQLiteStore insert_query_log error: %s", exc, exc_info=True
            )

    def select_query_log(
        self,
        client_ip: Optional[str] = None,
        qtype: Optional[str] = None,
        qname: Optional[str] = None,
        rcode: Optional[str] = None,
        start_ts: Optional[float] = None,
        end_ts: Optional[float] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        """Select query_log rows with basic filtering and pagination.

        Brief:
            Returns rows from the SQLite-backed query_log table, filtered by
            client_ip, qtype, qname, and rcode, and paginated by (page, page_size).

        Inputs:
            client_ip: Optional client IP filter (exact match).
            qtype: Optional qtype filter (case-insensitive; stored values are typically uppercase).
            qname: Optional qname filter (case-insensitive; compared against normalized stored name).
            rcode: Optional rcode filter (case-insensitive; stored values are typically uppercase).
            start_ts: Optional inclusive start timestamp (Unix seconds).
            end_ts: Optional exclusive end timestamp (Unix seconds).
            page: 1-based page number (defaults to 1).
            page_size: Max rows per page (defaults to 100).

        Outputs:
            Dict with keys:
              - total: total matching row count
              - page: current page (1-based)
              - page_size: page size
              - total_pages: total pages
              - items: list[dict] of query_log rows

        Notes:
            - Results are ordered newest-first by (ts DESC, id DESC).
            - result_json is decoded into a dict under the "result" key.
        """

        # Defensive normalization
        try:
            page_i = int(page)
        except (TypeError, ValueError):
            page_i = 1
        if page_i < 1:
            page_i = 1

        try:
            page_size_i = int(page_size)
        except (TypeError, ValueError):
            page_size_i = 100
        if page_size_i < 1:
            page_size_i = 1

        client_ip_s = str(client_ip).strip() if client_ip is not None else None
        qtype_s = str(qtype).strip().upper() if qtype is not None else None
        rcode_s = str(rcode).strip().upper() if rcode is not None else None
        qname_s = None
        if qname is not None:
            qname_s = str(qname).strip().rstrip(".").lower()

        where: List[str] = []
        params: List[Any] = []

        if client_ip_s:
            where.append("client_ip = ?")
            params.append(client_ip_s)
        if qtype_s:
            where.append("qtype = ?")
            params.append(qtype_s)
        if qname_s:
            where.append("name = ?")
            params.append(qname_s)
        if rcode_s:
            where.append("rcode = ?")
            params.append(rcode_s)
        if isinstance(start_ts, (int, float)):
            where.append("ts >= ?")
            params.append(float(start_ts))
        if isinstance(end_ts, (int, float)):
            where.append("ts < ?")
            params.append(float(end_ts))

        where_sql = (" WHERE " + " AND ".join(where)) if where else ""

        # Reads should include any queued batched ops.
        if self._batch_writes:
            with self._lock:
                self._flush_locked()

        total = 0
        try:
            cur = self._conn.execute(
                f"SELECT COUNT(1) FROM query_log{where_sql}", tuple(params)
            )  # type: ignore[attr-defined]
            row = cur.fetchone()
            total = int(row[0]) if row else 0
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "StatsSQLiteStore select_query_log count error: %s", exc, exc_info=True
            )
            total = 0

        offset = (page_i - 1) * page_size_i
        items: List[Dict[str, Any]] = []
        try:
            sql = (
                "SELECT id, ts, client_ip, name, qtype, upstream_id, rcode, status, error, first, result_json "
                f"FROM query_log{where_sql} "
                "ORDER BY ts DESC, id DESC "
                "LIMIT ? OFFSET ?"
            )
            cur2 = self._conn.execute(
                sql, tuple(params + [page_size_i, offset])
            )  # type: ignore[attr-defined]
            for (
                row_id,
                ts,
                client_ip_row,
                name,
                qtype_row,
                upstream_id,
                rcode_row,
                status_row,
                error_row,
                first_row,
                result_json,
            ) in cur2:
                try:
                    result_obj = json.loads(result_json or "{}")
                    if not isinstance(result_obj, dict):
                        result_obj = {"value": result_obj}
                except Exception:
                    result_obj = {}

                items.append(
                    {
                        "id": int(row_id),
                        "ts": float(ts),
                        "client_ip": str(client_ip_row),
                        "qname": str(name),
                        "qtype": str(qtype_row),
                        "upstream_id": (
                            str(upstream_id) if upstream_id is not None else None
                        ),
                        "rcode": str(rcode_row) if rcode_row is not None else None,
                        "status": str(status_row) if status_row is not None else None,
                        "error": str(error_row) if error_row is not None else None,
                        "first": str(first_row) if first_row is not None else None,
                        "result": result_obj,
                    }
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "StatsSQLiteStore select_query_log rows error: %s", exc, exc_info=True
            )

        total_pages = 0
        if page_size_i > 0:
            total_pages = (total + page_size_i - 1) // page_size_i

        return {
            "total": total,
            "page": page_i,
            "page_size": page_size_i,
            "total_pages": total_pages,
            "items": items,
        }

    def aggregate_query_log_counts(
        self,
        start_ts: float,
        end_ts: float,
        interval_seconds: int,
        client_ip: Optional[str] = None,
        qtype: Optional[str] = None,
        qname: Optional[str] = None,
        rcode: Optional[str] = None,
        group_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Aggregate query_log counts into fixed time buckets.

        Brief:
            Produces counts over the query_log table grouped by a fixed interval
            (bucket width) between start_ts and end_ts.

        Inputs:
            start_ts: Inclusive start timestamp (Unix seconds).
            end_ts: Exclusive end timestamp (Unix seconds).
            interval_seconds: Bucket size in seconds (must be > 0).
            client_ip: Optional client IP filter (exact match).
            qtype: Optional qtype filter (case-insensitive).
            qname: Optional qname filter (case-insensitive).
            rcode: Optional rcode filter (case-insensitive).
            group_by: Optional grouping dimension; one of
                {"client_ip", "qtype", "qname", "rcode"}. When provided, results
                are returned as sparse rows keyed by (bucket_start_ts, group).

        Outputs:
            Dict with keys:
              - start_ts: float
              - end_ts: float
              - interval_seconds: int
              - items: list of bucket results

        Notes:
            - When group_by is None, this returns a dense list that includes zero
              counts for buckets with no matching rows.
            - When group_by is set, this returns sparse rows (no zero-fill).
        """

        try:
            start_f = float(start_ts)
            end_f = float(end_ts)
        except (TypeError, ValueError):
            start_f = 0.0
            end_f = 0.0

        try:
            interval_i = int(interval_seconds)
        except (TypeError, ValueError):
            interval_i = 0

        if interval_i <= 0 or end_f <= start_f:
            return {
                "start_ts": start_f,
                "end_ts": end_f,
                "interval_seconds": interval_i,
                "items": [],
            }

        client_ip_s = str(client_ip).strip() if client_ip is not None else None
        qtype_s = str(qtype).strip().upper() if qtype is not None else None
        rcode_s = str(rcode).strip().upper() if rcode is not None else None
        qname_s = None
        if qname is not None:
            qname_s = str(qname).strip().rstrip(".").lower()

        where: List[str] = ["ts >= ?", "ts < ?"]
        params: List[Any] = [start_f, end_f]

        if client_ip_s:
            where.append("client_ip = ?")
            params.append(client_ip_s)
        if qtype_s:
            where.append("qtype = ?")
            params.append(qtype_s)
        if qname_s:
            where.append("name = ?")
            params.append(qname_s)
        if rcode_s:
            where.append("rcode = ?")
            params.append(rcode_s)

        where_sql = " WHERE " + " AND ".join(where)

        group_col = None
        group_label = None
        if group_by:
            gb = str(group_by).strip().lower()
            mapping = {
                "client_ip": "client_ip",
                "qtype": "qtype",
                "qname": "name",
                "rcode": "rcode",
            }
            if gb in mapping:
                group_col = mapping[gb]
                group_label = gb

        # Reads should include any queued batched ops.
        if self._batch_writes:
            with self._lock:
                self._flush_locked()

        rows: List[Tuple[int, Optional[str], int]] = []
        try:
            if group_col:
                sql = (
                    "SELECT CAST(((ts - ?) / ?) AS INTEGER) AS bucket, "
                    f"{group_col} AS group_value, "
                    "COUNT(1) AS c "
                    f"FROM query_log{where_sql} "
                    "GROUP BY bucket, group_value "
                    "ORDER BY bucket ASC"
                )
                cur = self._conn.execute(
                    sql, tuple([start_f, interval_i] + params)
                )  # type: ignore[attr-defined]
                for bucket, group_value, c in cur:
                    try:
                        b_i = int(bucket)
                    except Exception:
                        continue
                    try:
                        c_i = int(c)
                    except Exception:
                        c_i = 0
                    rows.append(
                        (
                            b_i,
                            str(group_value) if group_value is not None else None,
                            c_i,
                        )
                    )
            else:
                sql = (
                    "SELECT CAST(((ts - ?) / ?) AS INTEGER) AS bucket, COUNT(1) AS c "
                    f"FROM query_log{where_sql} "
                    "GROUP BY bucket "
                    "ORDER BY bucket ASC"
                )
                cur = self._conn.execute(
                    sql, tuple([start_f, interval_i] + params)
                )  # type: ignore[attr-defined]
                for bucket, c in cur:
                    try:
                        b_i = int(bucket)
                    except Exception:
                        continue
                    try:
                        c_i = int(c)
                    except Exception:
                        c_i = 0
                    rows.append((b_i, None, c_i))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "StatsSQLiteStore aggregate_query_log_counts error: %s",
                exc,
                exc_info=True,
            )
            rows = []

        # Dense fill for the common single-series case.
        if not group_col:
            import math

            num = int(math.ceil((end_f - start_f) / float(interval_i)))
            if num < 0:
                num = 0

            by_bucket = {b: c for (b, _g, c) in rows}
            items: List[Dict[str, Any]] = []
            for b in range(num):
                b_start = start_f + (b * interval_i)
                b_end = min(end_f, b_start + interval_i)
                items.append(
                    {
                        "bucket": b,
                        "bucket_start_ts": b_start,
                        "bucket_end_ts": b_end,
                        "count": int(by_bucket.get(b, 0)),
                    }
                )
            return {
                "start_ts": start_f,
                "end_ts": end_f,
                "interval_seconds": interval_i,
                "items": items,
            }

        # Sparse grouped results.
        items2: List[Dict[str, Any]] = []
        for b, g, c in rows:
            b_start = start_f + (b * interval_i)
            b_end = min(end_f, b_start + interval_i)
            items2.append(
                {
                    "bucket": int(b),
                    "bucket_start_ts": b_start,
                    "bucket_end_ts": b_end,
                    "group_by": group_label,
                    "group": g,
                    "count": int(c),
                }
            )

        return {
            "start_ts": start_f,
            "end_ts": end_f,
            "interval_seconds": interval_i,
            "items": items2,
        }

    # ------------------------------------------------------------------
    # Rebuild and inspection helpers
    # ------------------------------------------------------------------
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.error("StatsSQLiteStore has_counts error: %s", exc, exc_info=True)
            return False

    def export_counts(self) -> Dict[str, Dict[str, int]]:
        """Export all aggregate counters from the counts table.

        Inputs:
            None

        Outputs:
            Dict[str, Dict[str, int]] mapping scope -> {key -> value}.

        Example:
            >>> store = StatsSQLiteStore("/tmp/stats.db")  # doctest: +SKIP
            >>> store.increment_count("totals", "total_queries")  # doctest: +SKIP
            >>> counts = store.export_counts()  # doctest: +SKIP
            >>> counts["totals"]["total_queries"] >= 1  # doctest: +SKIP
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
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
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.error("StatsSQLiteStore has_query_log error: %s", exc, exc_info=True)
            return False

    def rebuild_counts_from_query_log(
        self, logger_obj: Optional[logging.Logger] = None
    ) -> None:
        """Rebuild counts table by aggregating over all rows in query_log.

        Inputs:
            logger_obj: Optional logger to use for warnings/errors.

        Outputs:
            Noneh

        Notes:
            - Existing counts are cleared before recomputation.
            - Aggregation approximates the live StatsCollector behavior by
              incrementing totals, qtypes, clients, domains/subdomains,
              rcodes, upstreams, and upstream_qtypes based on each
              query_log row.
            - Cache-domain aggregates include both base-domain views
              (cache_*_domains) and subdomain views (cache_*_subdomains)
              where subdomain names are full qnames.
            - Per-rcode aggregates include both base-domain views
              (rcode_domains) and subdomain views (rcode_subdomains).
            - Upstream aggregates include both outcome and rcode in the stored
              key so that rcodes can be associated with upstream outcomes when
              warm-loading from the persistent store.
            - Upstream_qtypes aggregates store "upstream_id|qtype" keys for
              per-upstream query type breakdowns.
        """
        log = logger_obj or logger
        log.warning(
            "Rebuilding statistics counts from query_log; this may take a while"
        )

        # When batch_writes is enabled, there may be pending INSERTs into
        # query_log that have not yet been flushed to the database. Flush them
        # up front so the rebuild sees a complete view of the log.
        if self._batch_writes:
            with (
                self._lock
            ):  # pragma: no cover - batching lock path exercised indirectly
                self._flush_locked()

        # Clear existing counts so we always rebuild from a clean slate.
        try:
            with self._conn:  # type: ignore[attr-defined]
                self._conn.execute("DELETE FROM counts")  # type: ignore[attr-defined]
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            log.error(
                "Failed to clear counts table before rebuild: %s", exc, exc_info=True
            )
            return

        try:
            cur = self._conn.cursor()  # type: ignore[attr-defined]
            cur.execute(
                "SELECT client_ip, name, qtype, upstream_id, rcode, status, error, result_json FROM query_log"
            )
            for (
                client_ip,
                name,
                qtype,
                upstream_id,
                rcode,
                status,
                error,
                result_json,
            ) in cur:
                domain = _normalize_domain(name or "")
                parts = domain.split(".") if domain else []
                base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

                # Total queries
                self.increment_count("totals", "total_queries", 1)

                # Cache hits/misses/cache_null (best-effort approximation).
                # These semantics mirror the live StatsCollector behavior:
                # - "cache_hit" rows are treated as cache hits.
                # - Pre-plugin deny/override rows ("deny_pre"/"override_pre")
                #   are treated as "cache_null" since no cache lookup occurs.
                # - All other statuses are treated as cache misses.
                if status == "cache_hit":
                    self.increment_count("totals", "cache_hits", 1)
                elif status in ("deny_pre", "override_pre"):
                    self.increment_count("totals", "cache_" + status, 1)
                    self.increment_count("totals", "cache_null", 1)
                else:
                    self.increment_count("totals", "cache_misses", 1)

                # Per-outcome cache-domain aggregates using base domains when
                # available so that warm-loaded top lists align with the
                # in-process StatsCollector tracking. Subdomain-oriented views
                # retain the full qname for *_subdomains scopes.
                if base:
                    if status == "cache_hit":
                        self.increment_count("cache_hit_domains", base, 1)
                    elif status not in ("deny_pre", "override_pre"):
                        # Treat all non-cache_hit, non-cache_null rows as
                        # cache misses for domain-level aggregates.
                        self.increment_count("cache_miss_domains", base, 1)

                # Subdomain-only cache aggregates keyed by full qname.
                if domain and base and _is_subdomain(domain):
                    if status == "cache_hit":
                        self.increment_count("cache_hit_subdomains", domain, 1)
                    elif status not in ("deny_pre", "override_pre"):
                        self.increment_count("cache_miss_subdomains", domain, 1)

                # Qtype breakdown
                if qtype:
                    self.increment_count("qtypes", str(qtype), 1)

                # Clients
                if client_ip:
                    self.increment_count("clients", str(client_ip), 1)

                # Domains and subdomains: only treat names with at least three
                # labels as subdomains for aggregation purposes.
                if domain:
                    if _is_subdomain(domain):
                        self.increment_count("sub_domains", domain, 1)
                    if base:
                        self.increment_count("domains", base, 1)

                # Per-qtype domain counters for all qtypes.
                if domain and qtype:
                    qkey = f"{qtype}|{domain}"
                    self.increment_count("qtype_qnames", qkey, 1)

                # Rcodes
                if rcode:
                    self.increment_count("rcodes", str(rcode), 1)
                    if base:
                        rkey = f"{rcode}|{base}"
                        self.increment_count("rcode_domains", rkey, 1)
                    if domain and base and _is_subdomain(domain):
                        sub_rkey = f"{rcode}|{domain}"
                        self.increment_count("rcode_subdomains", sub_rkey, 1)

                # Upstreams
                if upstream_id:
                    # Approximate outcome classification using status/rcode.
                    outcome = "success"
                    if rcode != "NOERROR" or (
                        status and status not in ("ok", "cache_hit")
                    ):
                        outcome = str(status or "error")

                    # Include rcode in the upstream key so that we can
                    # reconstruct both outcome and rcode aggregates when
                    # warm-loading from the persistent store.
                    rcode_key = str(rcode or "UNKNOWN")
                    key = f"{upstream_id}|{outcome}|{rcode_key}"
                    self.increment_count("upstreams", key, 1)

                    # Track per-upstream qtype breakdowns as "upstream_id|qtype".
                    if qtype:
                        qt_key = f"{upstream_id}|{qtype}"
                        self.increment_count("upstream_qtypes", qt_key, 1)

                # DNSSEC outcome (when present in result_json)
                if result_json:
                    try:
                        payload = json.loads(result_json)
                        dnssec_status = payload.get("dnssec_status")
                    except Exception:
                        dnssec_status = None

                    if dnssec_status in {
                        "dnssec_secure",
                        "dnssec_zone_secure",
                        "dnssec_unsigned",
                        "dnssec_bogus",
                        "dnssec_indeterminate",
                    }:
                        # dnssec_status values are already fully-qualified
                        # keys in the new scheme (for example, 'dnssec_secure').
                        self.increment_count("totals", dnssec_status, 1)

            # Ensure any batched operations are flushed so that export_counts()
            # immediately observes the recomputed aggregates when this method
            # returns.
            if self._batch_writes:
                with (
                    self._lock
                ):  # pragma: no cover - batching lock path exercised indirectly
                    self._flush_locked()
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            log.error(
                "Error while rebuilding counts from query_log: %s", exc, exc_info=True
            )

    def rebuild_counts_if_needed(
        self, force_rebuild: bool = False, logger_obj: Optional[logging.Logger] = None
    ) -> None:
        """Conditionally rebuild counts table based on current DB state and flags.

        Inputs:
            force_rebuild: If True, always rebuild counts when query_log has rows.
            logger_obj: Optional logger to use for warnings/errors.

        Outputs:
            None

        Behavior:
            - If query_log is empty, no rebuild is performed.
            - If counts is empty and query_log is not, a rebuild is performed.
            - If force_rebuild is True and query_log is not empty, a rebuild is
              performed even when counts already has data.
        """
        log = logger_obj or logger
        has_counts = self.has_counts()
        has_log = self.has_query_log()

        if not has_log:
            if force_rebuild:
                log.warning(
                    "Force rebuild requested but query_log is empty; skipping rebuild",
                )
            return

        if has_counts and not force_rebuild:
            # Normal case: counts already present and no override requested.
            return

        if has_counts and force_rebuild:
            log.warning(
                "Force rebuild requested: discarding existing counts and rebuilding from query_log",
            )
        elif not has_counts:
            log.warning(
                "Counts table is empty but query_log has rows; rebuilding counts from query_log",
            )

        self.rebuild_counts_from_query_log(logger_obj=log)

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
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.exception("Error while closing StatsSQLiteStore connection")


class StatsCollector:
    """
    Thread-safe statistics aggregator for DNS server metrics.

    Inputs (constructor):
        track_uniques: Enable unique client/domain tracking (default True)
        include_qtype_breakdown: Track query type distribution (default True)
        include_top_clients: Track top clients by request count (default False)
        include_top_domains: Track top domains by request count (default False)
        top_n: Number of top items to track (default 10)
        track_latency: Enable latency histogram (default False)
        ignore_top_clients: Optional list of client IPs/CIDRs to hide from top_clients
        ignore_top_domains: Optional list of base domains to hide from top_domains
        ignore_top_subdomains: Optional list of full qnames to hide from top_subdomains

    Outputs:
        StatsCollector instance for recording events and taking snapshots

    All public methods are thread-safe via a single RLock. Critical sections
    are kept minimal (O(1) operations only). The snapshot() method creates a
    deep copy for safe logging without holding the lock.

    Example:
        >>> collector = StatsCollector(track_uniques=True, track_latency=True)
        >>> collector.record_query("192.0.2.1", "example.com", "A")
        >>> collector.record_cache_hit("example.com")
        >>> collector.record_response_rcode("NOERROR")
        >>> snapshot = collector.snapshot(reset=False)
        >>> snapshot.totals['total_queries']
        1
    """

    def __init__(
        self,
        track_uniques: bool = True,
        include_qtype_breakdown: bool = True,
        include_top_clients: bool = False,
        include_top_domains: bool = False,
        top_n: int = 10,
        track_latency: bool = False,
        stats_store: Optional[BaseStatsStore] = None,
        ignore_top_clients: Optional[List[str]] = None,
        ignore_top_domains: Optional[List[str]] = None,
        ignore_top_subdomains: Optional[List[str]] = None,
        ignore_domains_as_suffix: bool = False,
        ignore_subdomains_as_suffix: bool = False,
        ignore_single_host: bool = False,
        include_ignored_in_stats: bool = True,
        logging_only: bool = False,
        query_log_only: bool = False,
    ) -> None:
        """Initialize statistics collector with configuration flags.

        Inputs:
            track_uniques: Enable unique client/domain tracking
            include_qtype_breakdown: Track qtype distribution
            include_top_clients: Enable top-N client tracking
            include_top_domains: Enable top-N domain tracking
            top_n: Size of top-N lists
            track_latency: Enable latency histogram
            stats_store: Optional SQLite-backed persistence store
            ignore_top_clients: Optional list of client IPs/CIDRs to hide from top_clients
            ignore_top_domains: Optional list of base domains to hide from top_domains
            ignore_top_subdomains: Optional list of full qnames to hide from top_subdomains
            ignore_domains_as_suffix: When True, treat ignore_top_domains entries
                as suffixes for matching both top_domains and (when used as
                fallback) top_subdomains.
            ignore_subdomains_as_suffix: When True, treat ignore_top_subdomains
                entries (or the fallback domain set) as suffixes when matching
                top_subdomains.
            include_ignored_in_stats: When True (default), ignore filters only
                affect display/exported top lists. When False, entries matching
                ignore filters are excluded from aggregation (totals/uniques/topk)
                but are still written to the persistent query_log.
            logging_only: When True, skip background warm-load operations from
                the persistent store so that only insert-style operations
                (query_log appends and counter increments) are performed against
                the attached stats_store.
            query_log_only: When True, only the raw query_log is written to the
                persistent store; aggregate counters are kept in-memory only and
                are not mirrored into the counts table.

        Outputs:
            None
        """
        self._lock = threading.RLock()

        # Config flags
        self.track_uniques = track_uniques
        self.include_qtype_breakdown = include_qtype_breakdown
        self.include_top_clients = include_top_clients
        self.include_top_domains = include_top_domains
        self.top_n = max(1, top_n)
        self.track_latency = track_latency
        # Display-only flag for hiding single-label hosts from top lists
        self.ignore_single_host = bool(ignore_single_host)

        # Control whether ignore filters exclude entries from aggregation.
        self.include_ignored_in_stats = bool(include_ignored_in_stats)
        # Logging-only mode controls whether background warm-loads use the
        # attached persistent store. Insert-style operations remain enabled.
        self.logging_only = bool(logging_only)
        # When query_log_only is true, only query_log appends are written to
        # the persistent store; aggregate counters remain in-memory only.
        self.query_log_only = bool(query_log_only)

        # Optional persistent store for long-lived aggregates and query logs.
        # This can be any BaseStatsStore implementation, including
        # MultiStatsStore, which fans writes out to multiple concrete
        # backends (for example, SQLite plus an MQTT logging sink).
        self._store: Optional[BaseStatsStore] = stats_store

        # Core counters
        self._totals: Dict[str, int] = defaultdict(int)
        self._rcodes: Dict[str, int] = defaultdict(int)
        self._qtypes: Dict[str, int] = defaultdict(int)

        # Plugin decisions: plugin_name -> {action -> count}
        self._plugin_decisions: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Reasons: plugin_name -> {reason -> count}
        self._allowed_by: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        self._blocked_by: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Upstream results: upstream_id -> {outcome -> count}
        self._upstreams: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Upstream response codes: upstream_id -> {rcode -> count}
        self._upstream_rcodes: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Upstream query types: upstream_id -> {qtype -> count}
        self._upstream_qtypes: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

        # Optional: unique tracking
        self._unique_clients: Optional[Set[str]] = set() if track_uniques else None
        self._unique_domains: Optional[Set[str]] = set() if track_uniques else None

        # Optional: top-K trackers. Use a larger internal capacity so that
        # display-only filters and downstream consumers (such as prefetching
        # logic) can work with deeper top lists than the default display size.
        # By default we keep up to max(top_n * TOPK_CAPACITY_FACTOR, TOPK_MIN_CAPACITY)
        # entries in memory.
        internal_capacity = max(TOPK_MIN_CAPACITY, self.top_n * TOPK_CAPACITY_FACTOR)
        self._top_capacity: int = internal_capacity

        self._top_clients: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_clients else None
        )
        # Track both subdomains (full qname) and base domains (last two labels)
        self._top_subdomains: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        self._top_domains: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )

        # Per-qtype top domains (full qnames). Keys are qtype strings such as
        # "A", "AAAA", "PTR"; values are TopK trackers of normalized domains.
        self._top_qtype_qnames: Dict[str, TopK] = {}

        # Top base domains split by cache outcome.
        self._top_cache_hit_domains: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        self._top_cache_miss_domains: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        # Top base domains where cache hits/misses were produced by
        # subdomain queries only (qname != base).
        self._top_cache_hit_subdomains: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )
        self._top_cache_miss_subdomains: Optional[TopK] = (
            TopK(capacity=internal_capacity) if include_top_domains else None
        )

        # Per-rcode top base domains; trackers are created lazily when rcodes
        # are observed with associated query names.
        self._top_rcode_domains: Dict[str, TopK] = {}
        # Per-rcode top base domains where only subdomain queries (qname !=
        # base) are counted.
        self._top_rcode_subdomains: Dict[str, TopK] = {}

        # Optional: latency histogram
        self._latency: Optional[LatencyHistogram] = (
            LatencyHistogram() if track_latency else None
        )
        self._latency_recent: Optional[LatencyHistogram] = (
            LatencyHistogram() if track_latency else None
        )

        # Ignore filters.
        #
        # Brief:
        #   By default (include_ignored_in_stats=True), these filters are
        #   display-only (they hide entries from exported top lists but do not
        #   affect totals/uniques).
        #   When include_ignored_in_stats=False, matching entries are excluded
        #   from aggregation (totals/uniques/topk) while leaving the persistent
        #   query log untouched.
        self._ignore_top_client_networks: List[ipaddress._BaseNetwork] = []
        self._ignore_top_domains: Set[str] = set()
        self._ignore_top_subdomains: Set[str] = set()
        self._ignore_domains_as_suffix: bool = bool(ignore_domains_as_suffix)
        self._ignore_subdomains_as_suffix: bool = bool(ignore_subdomains_as_suffix)

        self.set_ignore_filters(
            ignore_top_clients or [],
            ignore_top_domains or [],
            ignore_top_subdomains or [],
        )

    def _client_is_ignored_locked(self, client_ip: str) -> bool:
        """Brief: Return True if the client IP matches ignore_top_clients.

        Inputs:
          - client_ip: Client IP string.

        Outputs:
          - bool
        """

        if not client_ip or not self._ignore_top_client_networks:
            return False
        try:
            addr = ipaddress.ip_address(str(client_ip))
        except Exception:
            return False
        return any(addr in net for net in self._ignore_top_client_networks)

    def _base_domain_is_ignored_locked(self, base_domain: str) -> bool:
        """Brief: Return True if base domain matches ignore_top_domains.

        Inputs:
          - base_domain: Normalized base domain (typically last two labels).

        Outputs:
          - bool
        """

        norm = _normalize_domain(str(base_domain or ""))
        if not norm or not self._ignore_top_domains:
            return False
        if self._ignore_domains_as_suffix:
            return any(
                norm == ig or norm.endswith("." + ig) for ig in self._ignore_top_domains
            )
        return norm in self._ignore_top_domains

    def _qname_is_ignored_locked(self, qname: str) -> bool:
        """Brief: Return True if full qname matches ignore_top_subdomains.

        Inputs:
          - qname: Normalized qname.

        Outputs:
          - bool
        """

        norm = _normalize_domain(str(qname or ""))
        if not norm:
            return False

        active: Set[str]
        if self._ignore_top_subdomains:
            active = self._ignore_top_subdomains
        else:
            # Fallback to domain ignore set when subdomain ignore set is empty.
            active = self._ignore_top_domains

        if not active:
            return False

        if self._ignore_subdomains_as_suffix:
            return any(norm == ig or norm.endswith("." + ig) for ig in active)
        return norm in active

    def _should_ignore_query_locked(
        self, client_ip: str, domain: str, base: str
    ) -> bool:
        """Brief: Return True if a query should be excluded from aggregation.

        Inputs:
          - client_ip: Client IP string.
          - domain: Normalized qname.
          - base: Normalized base domain.

        Outputs:
          - bool
        """

        if self._client_is_ignored_locked(client_ip):
            return True
        if base and self._base_domain_is_ignored_locked(base):
            return True
        if domain and self._qname_is_ignored_locked(domain):
            return True
        return False

    def record_query(self, client_ip: str, qname: str, qtype: str) -> None:
        """Record an incoming DNS query.

        Inputs:
            client_ip: Client IP address
            qname: Query domain name
            qtype: Query type (e.g., "A", "AAAA", "CNAME")

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_query("192.0.2.1", "example.com", "A")
        """
        domain = _normalize_domain(qname)

        # Compute base domain once so it can be reused for top_domains and persistence.
        parts = domain.split(".") if domain else []
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        with self._lock:
            # When include_ignored_in_stats is False, ignore filters exclude
            # entries from aggregation but do not affect persistent query logging
            # (record_query_result).
            if not self.include_ignored_in_stats and self._should_ignore_query_locked(
                client_ip, domain, base
            ):
                return

            self._totals["total_queries"] += 1

            if self.include_qtype_breakdown:
                self._qtypes[qtype] += 1

            if self._unique_clients is not None:
                self._unique_clients.add(client_ip)

            if self._unique_domains is not None:
                self._unique_domains.add(domain)

            if self._top_clients is not None:
                self._top_clients.add(client_ip)

            if self._top_subdomains is not None and _is_subdomain(domain):
                self._top_subdomains.add(domain)

            if self._top_domains is not None:
                # Aggregate by base domain (last two labels)
                self._top_domains.add(base)

            # Per-qtype top domains (full qnames) for all observed qtypes.
            if self.include_top_domains and qtype:
                tracker = self._top_qtype_qnames.get(qtype)
                if tracker is None:
                    tracker = TopK(capacity=self._top_capacity)
                    self._top_qtype_qnames[qtype] = tracker
                tracker.add(domain)

            # Mirror core counters into the persistent store when available.
            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("totals", "total_queries")
                    if self.include_qtype_breakdown:
                        self._store.increment_count("qtypes", qtype)
                    self._store.increment_count("clients", client_ip)
                    if _is_subdomain(domain):
                        self._store.increment_count("sub_domains", domain)
                    if base:
                        self._store.increment_count("domains", base)
                    if qtype and domain:
                        qkey = f"{qtype}|{domain}"
                        self._store.increment_count("qtype_qnames", qkey)
                except Exception:  # pragma: no cover
                    logger.debug(
                        "StatsCollector: failed to persist query counters",
                        exc_info=True,
                    )

    def record_cache_hit(self, qname: str) -> None:
        """Record a cache hit.

        Inputs:
            qname: Query domain name

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_cache_hit("example.com")
        """
        # Normalize to base domain so cache statistics align with other
        # domain-oriented top lists. Subdomain-oriented views retain the full
        # qname while still using the derived base for grouping where needed.
        domain = _normalize_domain(qname)
        parts = domain.split(".") if domain else []
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._totals["cache_hits"] += 1

            if self._top_cache_hit_domains is not None and base:
                self._top_cache_hit_domains.add(base)
            # Track cache hits attributed specifically to subdomain queries
            # (qname != base) at the subdomain (full qname) level.
            if (
                self._top_cache_hit_subdomains is not None
                and domain
                and base
                and domain != base
            ):
                self._top_cache_hit_subdomains.add(domain)

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("totals", "cache_hits")
                    if base:
                        self._store.increment_count("cache_hit_domains", base)
                        if domain and domain != base:
                            self._store.increment_count("cache_hit_subdomains", domain)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist cache_hit", exc_info=True
                    )

    def record_cache_miss(self, qname: str) -> None:
        """Record a cache miss.

        Inputs:
            qname: Query domain name

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_cache_miss("example.com")
        """
        domain = _normalize_domain(qname)
        parts = domain.split(".") if domain else []
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._totals["cache_misses"] += 1

            if self._top_cache_miss_domains is not None and base:
                self._top_cache_miss_domains.add(base)
            # Track cache misses attributed specifically to subdomain queries
            # (qname != base) at the subdomain (full qname) level.
            if (
                self._top_cache_miss_subdomains is not None
                and domain
                and base
                and domain != base
            ):
                self._top_cache_miss_subdomains.add(domain)

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("totals", "cache_misses")
                    if base:
                        self._store.increment_count("cache_miss_domains", base)
                        if domain and domain != base:
                            self._store.increment_count("cache_miss_subdomains", domain)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist cache_miss", exc_info=True
                    )

    def record_cache_null(self, qname: str, status: Optional[str] = None) -> None:
        """Record a response served directly by plugins without cache usage.

        Inputs:
            qname: Query domain name associated with the plugin-handled response.
            status: Optional high-level status classification for the cache-null
                event (for example, "deny_pre" or "override_pre"). When
                provided and recognized, additional per-status counters are
                incremented alongside the generic ``cache_null`` total.

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_cache_null("example.com")
        """
        domain = _normalize_domain(qname)
        parts = domain.split(".") if domain else []
        base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._totals["cache_null"] += 1

            # When the cache-null event is caused by a pre-plugin deny/override
            # decision, also track per-status totals so live in-memory counters
            # mirror the aggregates produced by rebuild_counts_from_query_log.
            if status in ("deny_pre", "override_pre"):
                key = f"cache_{status}"
                self._totals[key] += 1

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("totals", "cache_null")
                    if status in ("deny_pre", "override_pre"):
                        self._store.increment_count("totals", f"cache_{status}")
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist cache_null", exc_info=True
                    )

    def record_dnssec_status(self, status: str) -> None:
        """Record a DNSSEC validation outcome.

        Inputs:
            status: One of "dnssec_secure", "dnssec_unsigned", "dnssec_bogus",
                "dnssec_indeterminate".

        Outputs:
            None; updates totals.dnssec_* counters in memory and, when a
            StatsSQLiteStore is attached, mirrors them into the persistent
            "totals" scope so that warm-load and rebuild semantics stay
            aligned.
        """
        if not status:
            return

        # In the new scheme we expect fully-qualified dnssec_* keys rather
        # than short status labels.
        totals_key = status if status.startswith("dnssec_") else None
        if not totals_key:
            return

        with self._lock:
            self._totals[totals_key] += 1

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count(
                        "totals", totals_key
                    )  # pragma: no cover - mirrors in-memory counter
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist dnssec_status", exc_info=True
                    )

    def record_cache_stat(self, label: str) -> None:
        """Record a cache-related classification label derived from PluginDecision.stat.

        Inputs:
            label: Non-empty string identifying the decision source or reason
                (for example, "filter", "skip", or plugin-specific tags).

        Outputs:
            None; updates in-memory totals (under a ``cache_stat_<label>`` key)
            and, when a StatsSQLiteStore is attached, increments the persistent
            ``counts`` row for scope ``"cache"`` and key equal to ``label``.
        """
        if not label:
            return

        key = f"cache_stat_{label}"
        with self._lock:
            try:
                self._totals[key] += 1
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                return

            if self._store is not None and not self.query_log_only:
                try:
                    # Use a dedicated "cache" scope so per-label aggregates can
                    # be inspected or warm-loaded separately from core totals.
                    self._store.increment_count("cache", label)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist cache_stat", exc_info=True
                    )

    def record_cache_pre_plugin(self, label: str) -> None:
        """Record per-plugin pre_resolve deny/override cache classifications.

        Inputs:
            label: Non-empty string key to store under ``totals`` (for example,
                ``"pre_deny_filter"`` or ``"pre_override_greylist"``).

        Outputs:
            None; increments ``totals[label]`` in-memory and, when a
            StatsSQLiteStore is attached, mirrors the counter into the
            persistent ``totals`` scope so that snapshot.totals reflects the
            same values as warm-loaded aggregates.
        """
        if not label:
            return

        with self._lock:
            self._totals[label] += 1

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("totals", label)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist cache_pre_plugin",
                        exc_info=True,
                    )

    def set_ignore_filters(
        self,
        clients: Optional[List[str]] = None,
        domains: Optional[List[str]] = None,
        subdomains: Optional[List[str]] = None,
        domains_as_suffix: Optional[bool] = None,
        subdomains_as_suffix: Optional[bool] = None,
    ) -> None:
        """Update ignore filters for statistics aggregation.

        Inputs:
            clients: Optional list of client IPs or CIDR strings to hide from
                ``top_clients`` (IPv4 and IPv6 supported). When None, the
                client ignore list is cleared.
            domains: Optional list of base domains to hide from
                ``top_domains`` (exact or suffix match after normalization,
                depending on domains_as_suffix). When None, the domain ignore
                list is cleared.
            subdomains: Optional list of full qnames to hide from
                ``top_subdomains`` (exact or suffix match after
                normalization, depending on subdomains_as_suffix). When
                None, the subdomain ignore list is cleared. When the
                resulting ignore set is empty, the domain ignore set is used
                as a fallback for subdomain filtering.
            domains_as_suffix: Optional flag controlling whether domain
                ignores use suffix semantics. When True, a top_domains entry
                is suppressed if its normalized name equals an ignore entry
                or ends with "." + ignore entry. When None, the existing
                setting is preserved.
            subdomains_as_suffix: Optional flag controlling whether
                subdomain ignores use suffix semantics. When True, a
                top_subdomains entry is suppressed if its normalized name
                equals an ignore entry or ends with "." + ignore entry.
                When None, the existing setting is preserved.

        Outputs:
            None (updates internal ignore sets used during aggregation in
            record_query/record_cache_* and when exporting snapshots).

        Example:
            >>> collector = StatsCollector(include_top_clients=True)
            >>> collector.set_ignore_filters(
            ...     ["10.0.0.0/8"],
            ...     ["example.com"],
            ...     ["www.example.com"],
            ...     domains_as_suffix=True,
            ... )
            >>> snap = collector.snapshot(reset=False)
            >>> # Matching entries will not be counted in totals/top lists,
            >>> # but queries are still written to the persistent query_log.
        """
        clients = clients or []
        domains = domains or []
        subdomains = subdomains or []

        client_networks: List[ipaddress._BaseNetwork] = []
        for raw in clients:
            if not raw:
                continue
            try:
                net = ipaddress.ip_network(str(raw), strict=False)
            except (
                Exception
            ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.debug("StatsCollector: invalid ignore client %r", raw)
                continue
            client_networks.append(net)

        domain_set: Set[str] = set()
        for raw in domains:
            if not raw:
                continue
            domain_set.add(_normalize_domain(str(raw)))

        subdomain_set: Set[str] = set()
        for raw in subdomains:
            if not raw:
                continue
            subdomain_set.add(_normalize_domain(str(raw)))

        with self._lock:
            self._ignore_top_client_networks = client_networks
            self._ignore_top_domains = domain_set
            self._ignore_top_subdomains = subdomain_set
            if domains_as_suffix is not None:
                self._ignore_domains_as_suffix = bool(
                    domains_as_suffix
                )  # pragma: no cover - simple flag assignment
            if subdomains_as_suffix is not None:
                self._ignore_subdomains_as_suffix = bool(
                    subdomains_as_suffix
                )  # pragma: no cover - simple flag assignment

    def record_plugin_decision(
        self,
        plugin_name: str,
        action: str,
        reason: Optional[str] = None,
        domain: Optional[str] = None,
        client_ip: Optional[str] = None,
    ) -> None:
        """
        Record a plugin decision (allow, block, modify, skip).

        Inputs:
            plugin_name: Name of the plugin making the decision
            action: Decision action ("allow", "block", "modify", "skip")
            reason: Optional reason code or description
            domain: Optional domain name affected
            client_ip: Optional client IP

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_plugin_decision(
            ...     "Filter", "block", reason="blocklist_match", domain="bad.com"
            ... )
        """
        with self._lock:
            self._plugin_decisions[plugin_name][action] += 1

            if action == "allow":
                self._totals["allowed"] += 1
                if reason:
                    self._allowed_by[plugin_name][reason] += 1
            elif action == "block":
                self._totals["blocked"] += 1
                if reason:
                    self._blocked_by[plugin_name][reason] += 1
            elif action == "modify":
                self._totals["modified"] += 1

            if self._store is not None and not self.query_log_only:
                try:
                    if action == "allow":
                        self._store.increment_count("totals", "allowed")
                    elif action == "block":
                        self._store.increment_count("totals", "blocked")
                    elif action == "modify":
                        self._store.increment_count("totals", "modified")
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist plugin decision",
                        exc_info=True,
                    )

    def record_upstream_result(
        self,
        upstream_id: str,
        outcome: str,
        bytes_out: Optional[int] = None,
        bytes_in: Optional[int] = None,
        qtype: Optional[str] = None,
    ) -> None:
        """
        Record upstream resolution outcome.

        Inputs:
            upstream_id: Upstream identifier (e.g., "8.8.8.8:53")
            outcome: Outcome classification ("success", "timeout", "error")
            bytes_out: Optional bytes sent to upstream
            bytes_in: Optional bytes received from upstream

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_upstream_result("8.8.8.8:53", "success")
            >>> collector.record_upstream_result("1.1.1.1:53", "timeout", qtype="A")
        """
        with self._lock:
            self._upstreams[upstream_id][outcome] += 1
            if qtype:
                self._upstream_qtypes[upstream_id][qtype] += 1
            if self._store is not None and not self.query_log_only:
                try:
                    key = f"{upstream_id}|{outcome}"
                    self._store.increment_count("upstreams", key)
                    if qtype:
                        qt_key = f"{upstream_id}|{qtype}"
                        self._store.increment_count("upstream_qtypes", qt_key)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist upstream result",
                        exc_info=True,
                    )

    def record_upstream_rcode(self, upstream_id: str, rcode: str) -> None:
        """Record DNS response code grouped by upstream identifier.

        Inputs:
            upstream_id: Upstream identifier (e.g., "8.8.8.8:53").
            rcode: Response code ("NOERROR", "NXDOMAIN", "SERVFAIL", etc.).

        Outputs:
            None; updates in-memory per-upstream rcode aggregates and, when a
            StatsSQLiteStore is attached, mirrors them into the persistent
            "upstream_rcodes" scope so that warm-load and rebuild semantics stay
            aligned with the HTML dashboard's upstream breakdown view.

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_upstream_rcode("8.8.8.8:53", "NOERROR")
        """

        if not upstream_id or not rcode:
            return

        with self._lock:
            self._upstream_rcodes[upstream_id][rcode] += 1

            if self._store is not None and not self.query_log_only:
                try:
                    key = f"{upstream_id}|{rcode}"
                    # Use a dedicated scope for per-upstream rcodes so that
                    # warm_load_from_store can hydrate them directly without
                    # relying solely on composite "upstreams" keys.
                    self._store.increment_count("upstream_rcodes", key)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist upstream rcode",
                        exc_info=True,
                    )

    def record_response_rcode(self, rcode: str, qname: Optional[str] = None) -> None:
        """Record DNS response code.

        Inputs:
            rcode: Response code ("NOERROR", "NXDOMAIN", "SERVFAIL", etc.)
            qname: Optional query name used to attribute rcodes to domains and
                subdomains for per-rcode top-domain statistics.

        Outputs:
            None

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_response_rcode("NOERROR", qname="example.com")
            >>> collector.record_response_rcode("NXDOMAIN")
        """
        base: Optional[str] = None
        domain: Optional[str] = None
        if qname:
            domain = _normalize_domain(qname)
            parts = domain.split(".") if domain else []
            base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        with self._lock:
            if not self.include_ignored_in_stats:
                if base and self._base_domain_is_ignored_locked(base):
                    return
                if domain and self._qname_is_ignored_locked(domain):
                    return

            self._rcodes[rcode] += 1

            # Track per-rcode top base domains when domain information is
            # available and domain tracking is enabled.
            if base and self.include_top_domains:
                tracker = self._top_rcode_domains.get(rcode)
                if tracker is None:
                    tracker = TopK(capacity=self.top_n * TOPK_CAPACITY_FACTOR)
                    self._top_rcode_domains[rcode] = tracker
                tracker.add(base)

                # Additionally track per-rcode subdomain names where only
                # subdomain queries (qname != base) are counted.
                if domain and domain != base:
                    sub_tracker = self._top_rcode_subdomains.get(rcode)
                    if sub_tracker is None:
                        sub_tracker = TopK(capacity=self._top_capacity)
                        self._top_rcode_subdomains[rcode] = sub_tracker
                    sub_tracker.add(domain)

            if self._store is not None and not self.query_log_only:
                try:
                    self._store.increment_count("rcodes", rcode)
                    if base:
                        key = f"{rcode}|{base}"
                        self._store.increment_count("rcode_domains", key)
                        if domain and domain != base:
                            sub_key = f"{rcode}|{domain}"
                            self._store.increment_count("rcode_subdomains", sub_key)
                except (
                    Exception
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    logger.debug(
                        "StatsCollector: failed to persist rcode", exc_info=True
                    )

    def record_latency(self, seconds: float) -> None:
        """Record request latency.

        Inputs:
            seconds: Latency duration in seconds

        Outputs:
            None

        Example:
            >>> collector = StatsCollector(track_latency=True)
            >>> collector.record_latency(0.0042)  # 4.2ms
        """
        if self._latency is not None:
            with self._lock:
                self._latency.add(seconds)
                if self._latency_recent is not None:
                    self._latency_recent.add(seconds)

    def record_query_result(
        self,
        client_ip: str,
        qname: str,
        qtype: str,
        rcode: Optional[str],
        upstream_id: Optional[str],
        status: Optional[str],
        error: Optional[str],
        first: Optional[str],
        result: Optional[Dict[str, Any]],
        ts: Optional[float] = None,
    ) -> None:
        """Record a completed DNS query into the persistent query log.

        Inputs:
            client_ip: Client IP address.
            qname: Query name (will be normalized for storage).
            qtype: Query type string (e.g., "A", "AAAA").
            rcode: Optional DNS response code ("NOERROR", "NXDOMAIN", etc.).
            upstream_id: Optional upstream identifier (e.g., "8.8.8.8:53").
            status: Optional high-level status ("ok", "timeout", "cache_hit", ...).
            error: Optional error message summary.
            first: Optional first answer record representation.
            result: Optional structured result mapping to be JSON-encoded.
            ts: Optional Unix timestamp; if omitted, current time is used with
                millisecond precision.

        Outputs:
            None

        Notes:
            This method does not modify in-memory counters; callers should
            continue to use the existing record_* APIs for live aggregation.
        """
        if self._store is None:
            return

        # Normalize timestamp to milliseconds precision as a float.
        if ts is None:
            ts = round(time.time(), 3)

        name = _normalize_domain(qname)
        try:
            payload = json.dumps(result or {}, separators=(",", ":"))
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            payload = "{}"

        try:
            self._store.insert_query_log(
                ts=ts,
                client_ip=client_ip,
                name=name,
                qtype=qtype,
                upstream_id=upstream_id,
                rcode=rcode,
                status=status,
                error=error,
                first=first,
                result_json=payload,
            )
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.debug(
                "StatsCollector: failed to append query_log row", exc_info=True
            )

    def snapshot(self, reset: bool = False) -> StatsSnapshot:
        """Create immutable snapshot of current statistics.

        Inputs:
            reset: If True, reset all counters after snapshot (default False)

        Outputs:
            StatsSnapshot with deep copies of all statistics

        When reset=True, all counters are zeroed for interval-based reporting.
        The snapshot is created under lock but can be formatted outside the lock.

        Notes:
            - The ``totals`` mapping in the returned snapshot always contains
              ``cache_deny_pre`` and ``cache_override_pre`` keys. These may be
              zero when no pre-plugin deny/override events have occurred, or
              populated from a warm-loaded SQLite store / rebuild pipeline.

        Example:
            >>> collector = StatsCollector()
            >>> collector.record_query("1.2.3.4", "example.com", "A")
            >>> snap = collector.snapshot(reset=False)
            >>> snap.totals['total_queries']
            1
        """
        with self._lock:
            # Copy all data structures
            totals = dict(self._totals)
            # Ensure cache_deny_pre and cache_override_pre are always present
            # in snapshots so that callers can rely on these counters even
            # when they are zero or only present in persistent aggregates.
            totals.setdefault("cache_deny_pre", 0)
            totals.setdefault("cache_override_pre", 0)

            rcodes = dict(self._rcodes)
            qtypes = dict(self._qtypes)

            # Deep copy nested plugin decisions
            decisions = {}
            for plugin, actions in self._plugin_decisions.items():
                decisions[plugin] = dict(actions)
                if plugin in self._allowed_by:
                    decisions[plugin]["allowed_by"] = dict(self._allowed_by[plugin])
                if plugin in self._blocked_by:
                    decisions[plugin]["blocked_by"] = dict(self._blocked_by[plugin])

            # Deep copy upstream results
            upstreams = {}
            for upstream_id, outcomes in self._upstreams.items():
                upstreams[upstream_id] = dict(outcomes)

            # Deep copy upstream response codes
            upstream_rcodes: Dict[str, Dict[str, int]] = {}
            for upstream_id, rcodes_map in self._upstream_rcodes.items():
                upstream_rcodes[upstream_id] = dict(rcodes_map)

            # Deep copy upstream query types
            upstream_qtypes: Dict[str, Dict[str, int]] = {}
            for upstream_id, qtypes_map in self._upstream_qtypes.items():
                upstream_qtypes[upstream_id] = dict(qtypes_map)

            # Unique counts
            uniques = None
            # When track_uniques is disabled, do not expose uniques even if
            # internal sets happen to be non-None (e.g., after a config reload).
            if (
                self.track_uniques
                and self._unique_clients is not None
                and self._unique_domains is not None
            ):
                uniques = {
                    "clients": len(self._unique_clients),
                    "domains": len(self._unique_domains),
                }

            # Top lists
            top_clients = None
            if self._top_clients is not None:
                # Export up to internal capacity so ignore filters can still
                # produce a full top_n list when possible.
                top_clients = self._top_clients.export(self._top_clients.capacity)

            top_subdomains = None
            if self._top_subdomains is not None:
                top_subdomains = self._top_subdomains.export(
                    self._top_subdomains.capacity
                )

            top_domains = None
            if self._top_domains is not None:
                top_domains = self._top_domains.export(self._top_domains.capacity)

            # Apply display-only ignore filters to top lists. These filters do
            # not affect counters or underlying TopK state; they only hide
            # entries from exported snapshots and downstream JSON formatting.
            if top_clients is not None and self._ignore_top_client_networks:
                import ipaddress

                filtered_clients: List[Tuple[str, int]] = []
                for client, count in top_clients:
                    try:
                        addr = ipaddress.ip_address(str(client))
                    except (
                        Exception
                    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                        filtered_clients.append((client, count))
                        continue
                    if any(addr in net for net in self._ignore_top_client_networks):
                        continue
                    filtered_clients.append((client, count))
                top_clients = filtered_clients

            # Do not truncate here; export the full internal capacity so callers
            # (including HTTP APIs and prefetch logic) can decide how many items
            # to display or consume.

            if top_domains is not None:
                filtered_domains: List[Tuple[str, int]] = []
                for domain, count in top_domains:
                    norm = _normalize_domain(str(domain))
                    # Optionally hide single-label hosts (no dots) from display.
                    if self.ignore_single_host and "." not in norm:
                        continue
                    if self._ignore_top_domains:
                        if self._ignore_domains_as_suffix:
                            if any(
                                norm == ig or norm.endswith("." + ig)
                                for ig in self._ignore_top_domains
                            ):
                                continue
                        else:
                            if norm in self._ignore_top_domains:
                                continue
                    filtered_domains.append((domain, count))
                top_domains = filtered_domains

            # Leave top_domains at full internal capacity; downstream code can
            # apply its own view-specific limits.

            if top_subdomains is not None:
                # Fallback: if no explicit subdomain ignore list is configured,
                # reuse the domain ignore set for top_subdomains.
                active_subdomain_ignores: Set[str]
                if self._ignore_top_subdomains:
                    active_subdomain_ignores = self._ignore_top_subdomains
                else:
                    active_subdomain_ignores = self._ignore_top_domains

                filtered_subdomains: List[Tuple[str, int]] = []
                for name, count in top_subdomains:
                    norm = _normalize_domain(str(name))
                    # Only include true subdomains: names with at least three
                    # labels (e.g., "www.example.com").
                    if not _is_subdomain(norm):
                        continue  # pragma: no cover - defensive subdomain filter
                    # Optionally hide single-label hosts (no dots) from display.
                    # This check is largely redundant given the subdomain
                    # requirement but kept for consistency with other lists.
                    if self.ignore_single_host and "." not in norm:
                        continue  # pragma: no cover - display-only single-host filter
                    if active_subdomain_ignores:
                        if self._ignore_subdomains_as_suffix:
                            if any(
                                norm == ig or norm.endswith("." + ig)
                                for ig in active_subdomain_ignores
                            ):
                                continue
                        else:
                            if norm in active_subdomain_ignores:
                                continue
                    filtered_subdomains.append((name, count))
                top_subdomains = filtered_subdomains

            # Leave top_subdomains at full internal capacity; downstream code
            # (e.g. HTTP APIs) is responsible for applying any display limits.

            # Per-qtype top domains (full qnames) for configured qtypes.
            qtype_qnames: Optional[Dict[str, List[Tuple[str, int]]]] = None
            if self._top_qtype_qnames:
                qtype_qnames = {}
                for qtype_name, tracker in self._top_qtype_qnames.items():
                    entries = tracker.export(tracker.capacity)
                    if not entries:
                        continue

                    # Apply the same ignore filters used for top_subdomains so
                    # that statistics.ignore.top_domains / statistics.ignore.subdomains
                    # affect all "Top X Domains" style lists.
                    active_subdomain_ignores: Set[str]
                    if self._ignore_top_subdomains:
                        active_subdomain_ignores = self._ignore_top_subdomains
                    else:
                        active_subdomain_ignores = self._ignore_top_domains

                    if active_subdomain_ignores or self.ignore_single_host:
                        filtered_entries: List[Tuple[str, int]] = []
                        for name, count in entries:
                            norm = _normalize_domain(str(name))
                            # Optionally hide single-label hosts (no dots).
                            if self.ignore_single_host and "." not in norm:
                                continue
                            if active_subdomain_ignores:
                                # For per-qtype top domains, use the same
                                # suffix/exact semantics as top_domains,
                                # controlled via statistics.ignore.top_domains_mode.
                                if self._ignore_domains_as_suffix:
                                    if any(
                                        norm == ig or norm.endswith("." + ig)
                                        for ig in active_subdomain_ignores
                                    ):
                                        continue
                                else:
                                    if norm in active_subdomain_ignores:
                                        continue
                            filtered_entries.append((name, count))
                        entries = filtered_entries

                    if entries:
                        qtype_qnames[qtype_name] = entries

                if not qtype_qnames:
                    qtype_qnames = None

            # Per-rcode top base domains with domain ignore filters applied.
            rcode_domains: Optional[Dict[str, List[Tuple[str, int]]]] = None
            if self._top_rcode_domains:
                rcode_domains = {}
                for rcode_name, tracker in self._top_rcode_domains.items():
                    entries = tracker.export(tracker.capacity)
                    if not entries:
                        continue  # pragma: no cover - empty per-qtype bucket

                    filtered_entries: List[Tuple[str, int]] = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        # Optionally hide single-label hosts (no dots).
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover - display-only single-host filter
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover - ignore filter branch
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover - ignore filter branch
                        filtered_entries.append((domain, count))

                    if not filtered_entries:
                        continue  # pragma: no cover - no visible entries after filtering

                    rcode_domains[rcode_name] = filtered_entries

                if not rcode_domains:
                    rcode_domains = (
                        None  # pragma: no cover - normalization of empty mapping
                    )

            # Per-rcode top subdomain names (full qnames) restricted to
            # subdomain queries only (qname != base), with the same domain
            # ignore filters applied. Only true subdomains (as defined by
            # _is_subdomain) are included to keep these lists consistent with
            # other subdomain-oriented views.
            rcode_subdomains: Optional[Dict[str, List[Tuple[str, int]]]] = None
            if self._top_rcode_subdomains:
                rcode_subdomains = {}
                for rcode_name, tracker in self._top_rcode_subdomains.items():
                    entries = tracker.export(tracker.capacity)
                    if not entries:
                        continue  # pragma: no cover - empty per-rcode bucket

                    filtered_entries: List[Tuple[str, int]] = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        # Only include true subdomains: names with at least
                        # three labels (e.g., "www.example.com") or the
                        # equivalent under public-suffix-style bases such as
                        # "co.uk".
                        if not _is_subdomain(norm):
                            continue  # pragma: no cover - defensive subdomain filter
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover - display-only single-host filter
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover - ignore filter branch
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover - ignore filter branch
                        filtered_entries.append((domain, count))

                    if not filtered_entries:
                        continue

                    rcode_subdomains[rcode_name] = filtered_entries

                if not rcode_subdomains:
                    rcode_subdomains = None

            # Top base domains split by cache outcome, sharing domain ignore filters.
            cache_hit_domains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_hit_domains is not None:
                entries = self._top_cache_hit_domains.export(
                    self._top_cache_hit_domains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        # Optionally hide single-label hosts (no dots).
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover - display-only single-host filter
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover - ignore filter branch
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover - ignore filter branch
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_hit_domains = filtered_entries

            cache_miss_domains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_miss_domains is not None:
                entries = self._top_cache_miss_domains.export(
                    self._top_cache_miss_domains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        # Optionally hide single-label hosts (no dots).
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover - display-only single-host filter
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover - ignore filter branch
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover - ignore filter branch
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_miss_domains = filtered_entries

            # Top subdomain names (full qnames) for cache outcome restricted to
            # subdomain queries only (qname != base). Only true subdomains are
            # included to keep naming aligned with the "Top Subdomains" list.
            cache_hit_subdomains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_hit_subdomains is not None:
                entries = self._top_cache_hit_subdomains.export(
                    self._top_cache_hit_subdomains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        # Enforce subdomain semantics consistently with
                        # _is_subdomain so that base domains are not exposed
                        # under subdomain-oriented views.
                        if not _is_subdomain(norm):
                            continue  # pragma: no cover - defensive subdomain filter
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover - display-only single-host filter
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover - ignore filter branch
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover - ignore filter branch
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_hit_subdomains = filtered_entries

            cache_miss_subdomains: Optional[List[Tuple[str, int]]] = None
            if self._top_cache_miss_subdomains is not None:
                entries = self._top_cache_miss_subdomains.export(
                    self._top_cache_miss_subdomains.capacity
                )
                if entries:
                    filtered_entries = []
                    for domain, count in entries:
                        norm = _normalize_domain(str(domain))
                        if not _is_subdomain(norm):
                            continue  # pragma: no cover - defensive subdomain filter
                        if self.ignore_single_host and "." not in norm:
                            continue  # pragma: no cover - display-only single-host filter
                        if self._ignore_top_domains:
                            if self._ignore_domains_as_suffix:
                                if any(
                                    norm == ig or norm.endswith("." + ig)
                                    for ig in self._ignore_top_domains
                                ):
                                    continue  # pragma: no cover - ignore filter branch
                            else:
                                if norm in self._ignore_top_domains:
                                    continue  # pragma: no cover - ignore filter branch
                        filtered_entries.append((domain, count))
                    if filtered_entries:
                        cache_miss_subdomains = filtered_entries

            # Latency
            latency_stats = None
            if self._latency is not None:
                latency_stats = self._latency.summarize()

            latency_recent_stats = None
            if self._latency_recent is not None:
                latency_recent_stats = self._latency_recent.summarize()

            # Derive a simple rate-limit summary from cache_stat_* counters
            # when present. This keeps RateLimit statistics visible in
            # snapshots and downstream APIs without coupling StatsCollector to
            # plugin internals.
            rate_limit: Optional[Dict[str, Any]] = None
            rl_key = "cache_stat_rate_limit"
            if rl_key in totals:
                try:
                    denied = int(totals.get(rl_key, 0))
                except (
                    TypeError,
                    ValueError,
                ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                    denied = 0
                rate_limit = {"denied": denied}

            # Extract DNSSEC-related counters (keys beginning with "dnssec_")
            # into a dedicated mapping while leaving them under ``totals`` for
            # backwards-compatibility.
            dnssec_totals: Optional[Dict[str, int]] = None
            try:
                dnssec_subset = {
                    k: int(v)
                    for k, v in totals.items()
                    if isinstance(v, (int, float)) and str(k).startswith("dnssec_")
                }
            except Exception:
                dnssec_subset = {}
            if dnssec_subset:
                dnssec_totals = dnssec_subset

            snapshot = StatsSnapshot(
                created_at=time.time(),
                totals=totals,
                rcodes=rcodes,
                qtypes=qtypes,
                decisions=decisions,
                upstreams=upstreams,
                uniques=uniques,
                top_clients=top_clients,
                top_subdomains=top_subdomains,
                top_domains=top_domains,
                latency_stats=latency_stats,
                latency_recent_stats=latency_recent_stats,
                upstream_rcodes=upstream_rcodes,
                upstream_qtypes=upstream_qtypes,
                qtype_qnames=qtype_qnames,
                rcode_domains=rcode_domains,
                rcode_subdomains=rcode_subdomains,
                cache_hit_domains=cache_hit_domains,
                cache_miss_domains=cache_miss_domains,
                cache_hit_subdomains=cache_hit_subdomains,
                cache_miss_subdomains=cache_miss_subdomains,
                rate_limit=rate_limit,
                dnssec_totals=dnssec_totals,
            )

            # Reset if requested
            if reset:
                self._totals.clear()
                self._rcodes.clear()
                self._qtypes.clear()
                self._plugin_decisions.clear()
                self._allowed_by.clear()
                self._blocked_by.clear()
                self._upstreams.clear()
                self._upstream_rcodes.clear()
                self._upstream_qtypes.clear()
                self._top_qtype_qnames.clear()

                if self._unique_clients is not None:
                    self._unique_clients.clear()
                if self._unique_domains is not None:
                    self._unique_domains.clear()

                if self._top_clients is not None:
                    self._top_clients.counts.clear()
                if self._top_subdomains is not None:
                    self._top_subdomains.counts.clear()
                if self._top_domains is not None:
                    self._top_domains.counts.clear()
                if self._top_cache_hit_domains is not None:
                    self._top_cache_hit_domains.counts.clear()
                if self._top_cache_miss_domains is not None:
                    self._top_cache_miss_domains.counts.clear()
                if self._top_cache_hit_subdomains is not None:
                    self._top_cache_hit_subdomains.counts.clear()
                if self._top_cache_miss_subdomains is not None:
                    self._top_cache_miss_subdomains.counts.clear()
                self._top_rcode_domains.clear()
                self._top_rcode_subdomains.clear()

                if self._latency is not None:
                    self._latency = LatencyHistogram()
                if self._latency_recent is not None:
                    self._latency_recent = LatencyHistogram()

            return snapshot

    def load_from_snapshot(self, snapshot: StatsSnapshot) -> None:
        """Initialize in-memory counters from a prior snapshot.

        Inputs:
            snapshot: StatsSnapshot previously produced by this collector.

        Outputs:
            None

        Notes:
            - Restores core aggregates (totals, rcodes, qtypes, decisions, upstreams).
            - Does not attempt to recreate uniqueness sets, top-K trackers, or
              latency histograms; those remain process-local for the current run.
        """
        with self._lock:
            # Core counters
            self._totals.clear()
            self._totals.update(snapshot.totals or {})

            self._rcodes.clear()
            self._rcodes.update(snapshot.rcodes or {})

            self._qtypes.clear()
            self._qtypes.update(snapshot.qtypes or {})

            # Plugin decisions and reasons
            self._plugin_decisions.clear()
            self._allowed_by.clear()
            self._blocked_by.clear()

            for plugin, actions in (snapshot.decisions or {}).items():
                # Separate action counters from allowed_by/blocked_by mappings
                action_counts: Dict[str, int] = {}
                allowed_by = (
                    actions.get("allowed_by") if isinstance(actions, dict) else None
                )
                blocked_by = (
                    actions.get("blocked_by") if isinstance(actions, dict) else None
                )

                if isinstance(actions, dict):
                    for key, value in actions.items():
                        if key in {"allowed_by", "blocked_by"}:
                            continue
                        try:
                            action_counts[key] = int(value)
                        except (TypeError, ValueError):
                            continue

                self._plugin_decisions[plugin] = defaultdict(int, action_counts)

                if isinstance(allowed_by, dict):
                    self._allowed_by[plugin] = defaultdict(int, allowed_by)
                if isinstance(blocked_by, dict):
                    self._blocked_by[plugin] = defaultdict(int, blocked_by)

            # Upstreams
            self._upstreams.clear()
            for upstream_id, outcomes in (snapshot.upstreams or {}).items():
                if isinstance(outcomes, dict):
                    self._upstreams[upstream_id] = defaultdict(int, outcomes)

            # Upstream response codes
            self._upstream_rcodes.clear()
            for upstream_id, rcodes_map in (snapshot.upstream_rcodes or {}).items():
                if isinstance(rcodes_map, dict):
                    try:
                        self._upstream_rcodes[upstream_id] = defaultdict(
                            int,
                            {str(k): int(v) for k, v in rcodes_map.items()},
                        )
                    except Exception:
                        continue

            # Upstream query types
            self._upstream_qtypes.clear()
            for upstream_id, qtypes_map in (snapshot.upstream_qtypes or {}).items():
                if isinstance(qtypes_map, dict):
                    try:
                        self._upstream_qtypes[upstream_id] = defaultdict(
                            int,
                            {str(k): int(v) for k, v in qtypes_map.items()},
                        )
                    except Exception:
                        continue

            # Per-qtype top domains (full qnames)
            self._top_qtype_qnames.clear()
            if snapshot.qtype_qnames:
                for qtype_name, entries in snapshot.qtype_qnames.items():
                    if not entries:
                        continue  # pragma: no cover - empty per-qtype bucket from snapshot
                    tracker = TopK(capacity=self.top_n * TOPK_CAPACITY_FACTOR)
                    for domain, count in entries:
                        try:
                            tracker.counts[str(domain)] = int(count)
                        except (TypeError, ValueError):
                            continue
                    self._top_qtype_qnames[qtype_name] = tracker

    def warm_load_from_store(self) -> None:
        """Warm-load core counters from the attached SQLite stats store.

        Inputs:
            None (uses self._store when configured).

        Outputs:
            None; mutates in-memory aggregate counters in place.

        Example:
            >>> store = StatsSQLiteStore("/tmp/stats.db")  # doctest: +SKIP
            >>> store.increment_count("totals", "total_queries", 5)  # doctest: +SKIP
            >>> collector = StatsCollector(stats_store=store)  # doctest: +SKIP
            >>> collector.warm_load_from_store()  # doctest: +SKIP
            >>> snap = collector.snapshot(reset=False)  # doctest: +SKIP
            >>> snap.totals["total_queries"] >= 5  # doctest: +SKIP
            True

        Notes:
            - This is a best-effort warm load used on process start. If the
              store is not configured or an error occurs, the collector simply
              starts from empty in-memory counters.
            - Only scopes known to StatsCollector (totals, rcodes, qtypes,
              clients, sub_domains, domains, upstreams, upstream_qtypes,
              upstream_rcodes, qtype_qnames, cache_hit_domains,
              cache_miss_domains, rcode_domains, rcode_subdomains) are applied.
            - Top-N client/domain trackers and unique counts are approximated
              from the aggregated counts when enabled.
            - When logging_only or query_log_only is True, this method is a
              no-op so that the attached stats_store is only exercised via
              insert-style operations (query_log appends, and in logging_only
              mode, counter increments).
        """
        if self._store is None or self.logging_only or self.query_log_only:
            return

        try:
            counts = self._store.export_counts()
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.error(
                "StatsCollector warm_load_from_store: failed to export counts",
                exc_info=True,
            )
            return

        with self._lock:
            # Core totals/qtypes/rcodes
            for key, value in counts.get("totals", {}).items():
                try:
                    self._totals[key] = int(value)
                except (TypeError, ValueError):
                    continue

            # Optional per-label cache statistics persisted under "cache" scope.
            # These are exposed in snapshots via totals keys of the form
            # "cache_stat_<label>" so the HTML dashboard can render them
            # alongside other cache metrics without schema changes.
            for label, value in counts.get("cache", {}).items():
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue
                stat_key = f"cache_stat_{label}"
                self._totals[stat_key] = int_value

            for key, value in counts.get("rcodes", {}).items():
                try:
                    self._rcodes[key] = int(value)
                except (TypeError, ValueError):
                    continue

            for key, value in counts.get("qtypes", {}).items():
                try:
                    self._qtypes[key] = int(value)
                except (TypeError, ValueError):
                    continue

            # Decide whether we have a dedicated upstream_rcodes scope. When
            # present, that scope is treated as authoritative for
            # per-upstream rcode aggregates and we avoid double-counting from
            # composite "upstreams" keys.
            upstream_rcode_counts = counts.get("upstream_rcodes", {}) or {}
            has_upstream_rcode_scope = bool(upstream_rcode_counts)

            # Always start with a clean slate for upstream_rcodes when
            # warm-loading from the persistent store.
            self._upstream_rcodes.clear()

            # Upstreams: keys are stored as "upstream_id|outcome|rcode" in
            # new data, but we also accept legacy "upstream_id|outcome" keys
            # for backward compatibility.
            for key, value in counts.get("upstreams", {}).items():
                parts = str(key).split("|")
                if len(parts) == 3:
                    upstream_id, outcome, rcode_key = parts
                elif len(parts) == 2:
                    # Legacy format without rcode dimension.
                    upstream_id, outcome = parts
                    rcode_key = None
                else:
                    continue

                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue

                # Always restore outcome-based upstream aggregates. Multiple
                # persisted rows may exist for the same upstream/outcome pair
                # when different rcodes are present; accumulate all of them so
                # in-memory outcome counters reflect the total volume across
                # rcodes rather than only the last row seen.
                self._upstreams[upstream_id][outcome] += int_value

                # When no dedicated upstream_rcodes scope is present, fall back
                # to reconstructing per-upstream rcode aggregates from
                # composite "upstreams" keys that include a rcode segment.
                if not has_upstream_rcode_scope and rcode_key:
                    self._upstream_rcodes[upstream_id][rcode_key] += int_value

            # If a dedicated upstream_rcodes scope exists, hydrate from it now,
            # overriding any fallback reconstruction from composite keys.
            if has_upstream_rcode_scope:
                self._upstream_rcodes.clear()
                for key, value in upstream_rcode_counts.items():
                    try:
                        upstream_id, rcode_name = str(key).split("|", 1)
                    except ValueError:
                        continue  # pragma: no cover - malformed key from persistent store
                    try:
                        int_value = int(value)
                    except (TypeError, ValueError):
                        continue  # pragma: no cover - defensive parse failure
                    self._upstream_rcodes[upstream_id][rcode_name] += int_value

            # Upstream qtypes: keys are stored as "upstream_id|qtype".
            for key, value in counts.get("upstream_qtypes", {}).items():
                try:
                    upstream_id, qtype = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover - malformed key from persistent store
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover - defensive parse failure
                self._upstream_qtypes[upstream_id][qtype] = int_value

            # Per-qtype qname counters: keys are stored as "qtype|qname".
            qtype_qname_counts: Dict[str, Dict[str, int]] = {}
            for key, value in counts.get("qtype_qnames", {}).items():
                try:
                    qtype_name, qname = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover - malformed key from persistent store
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover - defensive parse failure
                inner = qtype_qname_counts.setdefault(qtype_name, {})
                inner[str(qname)] = int_value

            # Per-rcode base-domain counters: keys are stored as "rcode|domain".
            rcode_domain_counts: Dict[str, Dict[str, int]] = {}
            for key, value in counts.get("rcode_domains", {}).items():
                try:
                    rcode_name, dname = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover - malformed key from persistent store
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover - defensive parse failure
                inner = rcode_domain_counts.setdefault(rcode_name, {})
                inner[str(dname)] = int_value

            # Per-rcode subdomain counters for subdomain-only traffic: keys
            # are stored as "rcode|subdomain" where subdomain is the full
            # qname (e.g. "www.example.com").
            rcode_subdomain_counts: Dict[str, Dict[str, int]] = {}
            for key, value in counts.get("rcode_subdomains", {}).items():
                try:
                    rcode_name, dname = str(key).split("|", 1)
                except ValueError:
                    continue  # pragma: no cover - malformed key from persistent store
                try:
                    int_value = int(value)
                except (TypeError, ValueError):
                    continue  # pragma: no cover - defensive parse failure
                inner = rcode_subdomain_counts.setdefault(rcode_name, {})
                inner[str(dname)] = int_value

            # Clients/domains: rebuild uniques and top-K trackers when enabled.
            client_counts = counts.get("clients", {})
            subdomain_counts = counts.get("sub_domains", {})
            domain_counts = counts.get("domains", {})
            cache_hit_domain_counts = counts.get("cache_hit_domains", {})
            cache_miss_domain_counts = counts.get("cache_miss_domains", {})
            cache_hit_subdomain_counts = counts.get("cache_hit_subdomains", {})
            cache_miss_subdomain_counts = counts.get("cache_miss_subdomains", {})

            # Unique clients/domains are approximated from available keys.
            if self._unique_clients is not None:
                self._unique_clients = set(str(c) for c in client_counts.keys())
            if self._unique_domains is not None:
                # Prefer sub_domains keys (full qnames) when present; otherwise
                # fall back to base domains.
                src = subdomain_counts or domain_counts
                self._unique_domains = set(str(d) for d in src.keys())

            # Top clients
            if self._top_clients is not None and client_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in client_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_clients.capacity])
                self._top_clients.counts = limited

            # Top subdomains (full qnames)
            if self._top_subdomains is not None and subdomain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in subdomain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_subdomains.capacity])
                self._top_subdomains.counts = limited

            # Per-qtype top domains from qtype_qname_counts
            if qtype_qname_counts and self.include_top_domains:
                for qtype_name, qmap in qtype_qname_counts.items():
                    items = sorted(
                        ((str(k), int(v)) for k, v in qmap.items()),
                        key=lambda kv: kv[1],
                        reverse=True,
                    )
                    tracker = TopK(capacity=self._top_capacity)
                    tracker.counts = dict(items[: tracker.capacity])
                    self._top_qtype_qnames[qtype_name] = tracker

            # Per-rcode top base domains from rcode_domain_counts.
            if rcode_domain_counts and self.include_top_domains:
                self._top_rcode_domains.clear()
                for rcode_name, dmap in rcode_domain_counts.items():
                    items = sorted(
                        ((str(k), int(v)) for k, v in dmap.items()),
                        key=lambda kv: kv[1],
                        reverse=True,
                    )
                    tracker = TopK(capacity=self._top_capacity)
                    tracker.counts = dict(items[: tracker.capacity])
                    self._top_rcode_domains[rcode_name] = tracker

            # Per-rcode top base domains for subdomain-only traffic from
            # rcode_subdomain_counts.
            if rcode_subdomain_counts and self.include_top_domains:
                self._top_rcode_subdomains.clear()
                for rcode_name, dmap in rcode_subdomain_counts.items():
                    items = sorted(
                        ((str(k), int(v)) for k, v in dmap.items()),
                        key=lambda kv: kv[1],
                        reverse=True,
                    )
                    tracker = TopK(capacity=self._top_capacity)
                    tracker.counts = dict(items[: tracker.capacity])
                    self._top_rcode_subdomains[rcode_name] = tracker

            # Top base domains
            if self._top_domains is not None and domain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in domain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_domains.capacity])
                self._top_domains.counts = limited

            # Top cache hit/miss base domains.
            if self._top_cache_hit_domains is not None and cache_hit_domain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_hit_domain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_hit_domains.capacity])
                self._top_cache_hit_domains.counts = limited

            if self._top_cache_miss_domains is not None and cache_miss_domain_counts:
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_miss_domain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_miss_domains.capacity])
                self._top_cache_miss_domains.counts = limited

            # Top cache hit/miss subdomain names for subdomain-only traffic.
            if (
                self._top_cache_hit_subdomains is not None
                and cache_hit_subdomain_counts
            ):
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_hit_subdomain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_hit_subdomains.capacity])
                self._top_cache_hit_subdomains.counts = limited

            if (
                self._top_cache_miss_subdomains is not None
                and cache_miss_subdomain_counts
            ):
                items = sorted(
                    ((str(k), int(v)) for k, v in cache_miss_subdomain_counts.items()),
                    key=lambda kv: kv[1],
                    reverse=True,
                )
                limited = dict(items[: self._top_cache_miss_subdomains.capacity])
                self._top_cache_miss_subdomains.counts = limited

    def reset_latency_recent(self) -> None:
        """
        Reset only the recent latency window.

        Inputs:
            None

        Outputs:
            None

        Example:
            >>> collector = StatsCollector(track_latency=True)
            >>> collector.record_latency(0.005)
            >>> snapshot1 = collector.snapshot()
            >>> collector.reset_latency_recent()
            >>> snapshot2 = collector.snapshot()
            >>> snapshot2.latency_recent_stats['count']
            0
        """
        with self._lock:
            if self._latency_recent is not None:
                self._latency_recent = LatencyHistogram()


def format_snapshot_json(snapshot: StatsSnapshot) -> str:
    """Format statistics snapshot as single-line JSON with meta information.

    Inputs:
        snapshot: StatsSnapshot to serialize.

    Outputs:
        JSON string (single line, no trailing newline).

    The output is a compact JSON object suitable for structured logging.
    Empty sections are omitted to minimize log size. A top-level "meta"
    object includes a timestamp, hostname, version, and process uptime.

    Notes:
      - The ``totals`` object always includes ``cache_deny_pre`` and
        ``cache_override_pre`` fields so downstream dashboards can safely
        rely on their presence even when zero.

    Example:
        >>> collector = StatsCollector()
        >>> collector.record_query("1.2.3.4", "example.com", "A")
        >>> snap = collector.snapshot()
        >>> json_str = format_snapshot_json(snap)
        >>> "total_queries" in json_str
        True
    """
    ts = datetime.fromtimestamp(snapshot.created_at, tz=timezone.utc).isoformat()

    try:
        hostname = socket.gethostname()
    except Exception:  # pragma: no cover - environment specific
        hostname = "unknown-host"

    meta: Dict[str, Any] = {
        "timestamp": ts,
        "hostname": hostname,
        "version": FOGHORN_VERSION,
        "uptime": get_process_uptime_seconds(),
    }

    output: Dict[str, Any] = {
        "ts": ts,
        "totals": snapshot.totals,
        "meta": meta,
    }

    # When available, expose DNSSEC totals as a dedicated top-level object.
    if getattr(snapshot, "dnssec_totals", None):
        output["dnssec"] = snapshot.dnssec_totals

    if snapshot.uniques:
        output["uniques"] = snapshot.uniques

    if snapshot.rcodes:
        output["rcodes"] = snapshot.rcodes

    if snapshot.qtypes:
        output["qtypes"] = snapshot.qtypes

    if snapshot.decisions:
        output["plugins"] = snapshot.decisions

    if snapshot.upstreams:
        output["upstreams"] = snapshot.upstreams

    if snapshot.top_clients:
        output["top_clients"] = [
            {"client": c, "count": n} for c, n in snapshot.top_clients
        ]

    if snapshot.top_subdomains:
        output["top_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.top_subdomains
        ]

    if snapshot.top_domains:
        output["top_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.top_domains
        ]

    if snapshot.upstream_rcodes:
        output["upstream_rcodes"] = snapshot.upstream_rcodes

    if snapshot.upstream_qtypes:
        output["upstream_qtypes"] = snapshot.upstream_qtypes

    if snapshot.qtype_qnames:
        output["qtype_qnames"] = snapshot.qtype_qnames

    if snapshot.rcode_domains:
        output["rcode_domains"] = {
            rcode: [{"domain": d, "count": n} for d, n in entries]
            for rcode, entries in snapshot.rcode_domains.items()
        }

    if snapshot.rcode_subdomains:
        output["rcode_subdomains"] = {
            rcode: [{"domain": d, "count": n} for d, n in entries]
            for rcode, entries in snapshot.rcode_subdomains.items()
        }

    if snapshot.cache_hit_domains:
        output["cache_hit_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_hit_domains
        ]

    if snapshot.cache_miss_domains:
        output["cache_miss_domains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_miss_domains
        ]

    if snapshot.cache_hit_subdomains:
        output["cache_hit_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_hit_subdomains
        ]

    if snapshot.cache_miss_subdomains:
        output["cache_miss_subdomains"] = [
            {"domain": d, "count": n} for d, n in snapshot.cache_miss_subdomains
        ]

    if snapshot.latency_stats:
        output["latency"] = snapshot.latency_stats

    if snapshot.latency_recent_stats:
        output["latency_recent"] = snapshot.latency_recent_stats

    if snapshot.rate_limit:
        output["rate_limit"] = snapshot.rate_limit

    return json.dumps(output, separators=(",", ":"))


class StatsReporter(threading.Thread):
    """
    Background daemon thread for periodic statistics logging.

    Inputs (constructor):
        collector: StatsCollector instance to snapshot
        interval_seconds: Seconds between log emissions (default 10)
        reset_on_log: Reset counters after each log (default False)
        log_level: Logging level name ("debug", "info", "warning", "error")
        logger_name: Logger name to use (default "foghorn.stats")

    Outputs:
        StatsReporter thread instance (call start() to begin)

    The reporter sleeps for interval_seconds, takes a snapshot, formats to JSON,
    and logs. The lock is only held during snapshot creation, not during
    formatting or logging.

    Example:
        >>> collector = StatsCollector()
        >>> reporter = StatsReporter(collector, interval_seconds=10, reset_on_log=True)
        >>> reporter.daemon = True
        >>> reporter.start()
        >>> # reporter logs every 10 seconds until stop() is called
    """

    def __init__(
        self,
        collector: StatsCollector,
        interval_seconds: int = 10,
        reset_on_log: bool = False,
        log_level: str = "info",
        logger_name: str = "foghorn.stats",
        persistence_store: Any | None = None,
    ) -> None:
        """
        Initialize statistics reporter thread.

        Inputs:
            collector: StatsCollector to snapshot
            interval_seconds: Log interval in seconds
            reset_on_log: Reset counters after each log
            log_level: Log level name
            logger_name: Logger name
            persistence_store: Optional StatsSQLiteStore for persistence.

        Outputs:
            None
        """
        super().__init__(daemon=True, name="StatsReporter")
        self.collector = collector
        self.interval_seconds = max(1, interval_seconds)
        self.reset_on_log = reset_on_log
        self.logger = logging.getLogger(logger_name)
        self.persistence_store = persistence_store

        # Map log level string to logging constant
        level_map = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
        }
        self.log_level = level_map.get(log_level.lower(), logging.INFO)

        self._stop_event = threading.Event()

    def run(self) -> None:
        """
        Reporter main loop (called by start()).

        Inputs:
            None

        Outputs:
            None

        Sleeps interval_seconds, snapshots stats, formats JSON, and logs.
        Exits when stop() is called.
        """
        while not self._stop_event.wait(self.interval_seconds):
            try:
                snapshot = self.collector.snapshot(reset=self.reset_on_log)
                json_line = format_snapshot_json(snapshot)
                self.logger.debug(json_line)

                # Always reset recent latency window after emission
                self.collector.reset_latency_recent()
            except (
                Exception
            ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                self.logger.error("StatsReporter error: %s", e, exc_info=True)

    def stop(self, timeout: float = 5.0) -> None:
        """
        Signal reporter to stop and wait for thread to exit.

        Inputs:
            timeout: Maximum seconds to wait for thread join (default 5.0)

        Outputs:
            None

        Example:
            >>> reporter.stop()
        """
        self._stop_event.set()
        self.join(timeout=timeout)
