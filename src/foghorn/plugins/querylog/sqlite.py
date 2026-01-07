"""SQLite-backed implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via the same configuration fields historically used for the
    legacy StatsSQLiteStore (db_path, batch_writes, batch_time_sec,
    batch_max_size), typically through load_stats_store_backend().

Outputs:
  - Concrete backend instance that can be passed to StatsCollector and
    StatsReporter for persistent statistics and query-log storage.

Notes:
  - This module ports the prior StatsSQLiteStore implementation into
    SqliteStatsStore so that the SQLite backend can live under
    foghorn.plugins.querylog without changing its runtime behavior.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

from foghorn.plugins.querylog.base import BaseStatsStore

logger = logging.getLogger(__name__)


def _normalize_domain(domain: str) -> str:
    """Normalize domain name for statistics tracking.

    Inputs:
        domain: Raw domain name string (may have trailing dot, mixed case).

    Outputs:
        Normalized lowercase domain without trailing dot.
    """

    return domain.rstrip(".").lower()


def _is_subdomain(domain: str) -> bool:
    """Return True if the name should be treated as a subdomain.

    Inputs:
        domain: Raw or normalized domain name string.

    Outputs:
        Boolean indicating whether the normalized name should be counted as a
        subdomain for statistics. See foghorn.stats._is_subdomain for the
        detailed behavior this mirrors.
    """

    norm = _normalize_domain(domain or "")
    if not norm:
        return False

    parts = norm.split(".")
    if len(parts) < 3:
        return False

    if len(parts) >= 3 and parts[-2:] == ["co", "uk"]:
        return len(parts) >= 4

    return True


class SqliteStatsStore(BaseStatsStore):
    """SQLite-backed persistent statistics and query-log backend.

    This class is a direct port of the legacy StatsSQLiteStore implementation
    so that it satisfies the BaseStatsStore interface while preserving
    existing SQLite behavior.
    """

    # Aliases used by the stats backend registry. The default alias derived from
    # the class name is "sqlite", but we also accept "sqlite3" for convenience.
    aliases = ("sqlite", "sqlite3")

    # Default configuration values used by the generic loader when db_path or
    # batching knobs are omitted from statistics.persistence.
    default_config = {
        "db_path": "./config/var/stats.db",
        "batch_writes": True,
        "batch_time_sec": 15.0,
        "batch_max_size": 1000,
    }

    def __init__(
        self,
        db_path: str,
        batch_writes: bool = False,
        batch_time_sec: float = 15.0,
        batch_max_size: int = 1000,
        async_logging: bool = False,
        **_: Any,
    ) -> None:
        """Initialize SQLite backend and ensure schema exists.

        Inputs:
            db_path: Path to SQLite database file.
            batch_writes: If True, queue writes and flush periodically.
            batch_time_sec: Max age of a batch before flush when batching.
            batch_max_size: Max queued operations before forced flush.

        Outputs:
            None.
        """

        self._db_path = db_path
        self._conn = self._init_connection()

        # Logging/queuing behaviour
        self._async_logging = bool(async_logging)

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
            None; uses self._db_path.

        Outputs:
            sqlite3.Connection: Open connection with schema ensured.
        """

        dir_path = os.path.dirname(self._db_path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        db_path = self._db_path
        try:
            # When using the default on-disk path and the directory is not
            # writable (e.g. created by another user), fall back to an
            # in-memory database so statistics persistence does not prevent
            # the process from starting.
            default_db_path = SqliteStatsStore.default_config.get("db_path")
            if (
                isinstance(default_db_path, str)
                and os.path.abspath(os.path.expanduser(str(db_path)))
                == os.path.abspath(os.path.expanduser(str(default_db_path)))
                and dir_path
                and not os.access(dir_path, os.W_OK | os.X_OK)
            ):
                db_path = ":memory:"
        except Exception:  # pragma: no cover - defensive permission check
            pass

        conn = sqlite3.connect(db_path, check_same_thread=False)
        try:
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
        """Return True when the underlying SQLite store is usable."""

        try:
            with self._lock:
                cur = self._conn.cursor()
                cur.execute("SELECT 1")
                cur.fetchone()
            return True
        except Exception:
            return False

    def _execute(self, sql: str, params: Tuple[Any, ...]) -> None:
        """Execute a single SQL statement, with optional batching."""

        if not self._batch_writes:
            try:
                with self._conn:
                    self._conn.execute(sql, params)
            except Exception as exc:  # pragma: no cover - defensive
                logger.error("SqliteStatsStore execute error: %s", exc, exc_info=True)
            return

        # Batched mode
        with self._lock:
            self._pending_ops.append((sql, params))
            self._maybe_flush_locked()

    def _maybe_flush_locked(self) -> None:
        """Flush pending batched operations if thresholds are exceeded."""

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
        """Flush all pending operations in a single transaction."""

        if not self._pending_ops:
            return
        try:
            with self._conn:  # type: ignore[attr-defined]
                cur = self._conn.cursor()  # type: ignore[attr-defined]
                for sql, params in self._pending_ops:
                    cur.execute(sql, params)
            self._pending_ops.clear()
            self._last_flush = time.time()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("SqliteStatsStore flush error: %s", exc, exc_info=True)

    # ------------------------------------------------------------------
    # Public API: counters and query log
    # ------------------------------------------------------------------
    def _increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Increment an aggregate counter in the counts table."""

        try:
            sql = (
                "INSERT INTO counts (scope, key, value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(scope, key) DO UPDATE SET value = counts.value + excluded.value"
            )
            self._execute(sql, (scope, key, int(delta)))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "SqliteStatsStore increment_count error: %s", exc, exc_info=True
            )

    def set_count(self, scope: str, key: str, value: int) -> None:
        """Set an aggregate counter in the counts table."""

        try:
            sql = (
                "INSERT INTO counts (scope, key, value) "
                "VALUES (?, ?, ?) "
                "ON CONFLICT(scope, key) DO UPDATE SET value = excluded.value"
            )
            self._execute(sql, (scope, key, int(value)))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("SqliteStatsStore set_count error: %s", exc, exc_info=True)

    def _insert_query_log(
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
        """Append a DNS query entry to the query_log table."""

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
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "SqliteStatsStore insert_query_log error: %s", exc, exc_info=True
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
        """Select query_log rows with basic filtering and pagination."""

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
                "SqliteStatsStore select_query_log count error: %s",
                exc,
                exc_info=True,
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
                "SqliteStatsStore select_query_log rows error: %s",
                exc,
                exc_info=True,
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
        """Aggregate query_log counts into fixed time buckets."""

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
                "SqliteStatsStore aggregate_query_log_counts error: %s",
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
        """Return True if the counts table contains at least one row."""

        try:
            cur = self._conn.execute("SELECT 1 FROM counts LIMIT 1")  # type: ignore[attr-defined]
            return cur.fetchone() is not None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("SqliteStatsStore has_counts error: %s", exc, exc_info=True)
            return False

    def export_counts(self) -> Dict[str, Dict[str, int]]:
        """Export all aggregate counters from the counts table."""

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
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("SqliteStatsStore export_counts error: %s", exc, exc_info=True)
        return result

    def has_query_log(self) -> bool:
        """Return True if the query_log table contains at least one row."""

        try:
            cur = self._conn.execute("SELECT 1 FROM query_log LIMIT 1")  # type: ignore[attr-defined]
            return cur.fetchone() is not None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("SqliteStatsStore has_query_log error: %s", exc, exc_info=True)
            return False

    def rebuild_counts_from_query_log(
        self, logger_obj: Optional[logging.Logger] = None
    ) -> None:
        """Rebuild counts table by aggregating over all rows in query_log."""

        log = logger_obj or logger
        log.warning(
            "Rebuilding statistics counts from query_log; this may take a while"
        )

        if self._batch_writes:
            with self._lock:  # pragma: no cover - batching lock path
                self._flush_locked()

        try:
            with self._conn:  # type: ignore[attr-defined]
                self._conn.execute("DELETE FROM counts")  # type: ignore[attr-defined]
        except Exception as exc:  # pragma: no cover - defensive
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
                    outcome = "success"
                    if rcode != "NOERROR" or (
                        status and status not in ("ok", "cache_hit")
                    ):
                        outcome = str(status or "error")

                    rcode_key = str(rcode or "UNKNOWN")
                    key = f"{upstream_id}|{outcome}|{rcode_key}"
                    self.increment_count("upstreams", key, 1)

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
                        self.increment_count("totals", dnssec_status, 1)

            if self._batch_writes:
                with self._lock:  # pragma: no cover - batching lock path
                    self._flush_locked()
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error while rebuilding counts from query_log: %s", exc, exc_info=True
            )

    def rebuild_counts_if_needed(
        self, force_rebuild: bool = False, logger_obj: Optional[logging.Logger] = None
    ) -> None:
        """Conditionally rebuild counts table based on current DB state and flags."""

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
        """Close the underlying SQLite connection, flushing any pending writes."""

        try:
            if self._batch_writes:
                with self._lock:
                    self._flush_locked()
            conn = getattr(self, "_conn", None)
            if conn is not None:
                conn.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while closing SqliteStatsStore connection")
