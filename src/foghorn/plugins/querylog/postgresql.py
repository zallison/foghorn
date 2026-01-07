from __future__ import annotations

"""PostgreSQL-backed implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via a configuration mapping passed through StatsStoreBackendConfig
    with backend-specific fields such as host, port, user, password, and
    database.

Outputs:
  - Concrete backend instance that can be passed to StatsCollector and
    StatsReporter for persistent statistics and query-log storage using a
    PostgreSQL database instead of SQLite.

Notes:
  - This backend intentionally mirrors the logical schema and behaviour of the
    SqliteStatsStore so callers remain backend-agnostic.
  - The underlying DB driver (psycopg or psycopg2) is imported lazily so that
    Foghorn does not require it unless this backend is used.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseStatsStore
from .sqlite import _normalize_domain, _is_subdomain

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
                "'psycopg' or 'psycopg2' to use the PostgresStatsStore"
            ) from exc


class PostgresStatsStore(BaseStatsStore):
    """PostgreSQL-backed persistent statistics and query-log backend.

    # Aliases used by the stats backend registry.
    aliases = ("postgres", "postgresql", "pg")

    This backend stores the same logical ``counts`` and ``query_log`` tables as
    the SQLite implementation, but in a PostgreSQL database.

    Inputs (constructor):
        host: Database host (default "127.0.0.1").
        port: Database port (default 5432).
        user: Database username.
        password: Database password.
        database: Database name.
        connect_kwargs: Optional mapping of additional keyword arguments passed
            through to the underlying driver's ``connect`` function
            (for example, sslmode, options).

    Outputs:
        Initialized PostgresStatsStore instance with ensured schema.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5432,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "foghorn_stats",
        connect_kwargs: Optional[Dict[str, Any]] = None,
        async_logging: bool = False,
        **_: Any,
    ) -> None:
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

        self._driver = driver
        self._conn = driver.connect(**kwargs)

        # Use synchronous logging by default for SQL stats backends.
        self._async_logging = bool(async_logging)

        self._ensure_schema()

    # ------------------------------------------------------------------
    # Schema and connection helpers
    # ------------------------------------------------------------------
    def _ensure_schema(self) -> None:
        """Ensure counts and query_log tables and indexes exist.

        Inputs:
            None.

        Outputs:
            None; creates tables/indexes if they do not already exist.
        """

        conn = self._conn
        cur = conn.cursor()

        # counts table mirrors the SQLite schema: primary key on (scope, key).
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS counts (
                scope TEXT NOT NULL,
                key   TEXT NOT NULL,
                value BIGINT NOT NULL DEFAULT 1,
                PRIMARY KEY (scope, key)
            )
            """
        )

        # query_log table mirrors the SQLite schema closely.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS query_log (
                id           BIGSERIAL PRIMARY KEY,
                ts           DOUBLE PRECISION NOT NULL,
                client_ip    TEXT NOT NULL,
                name         TEXT NOT NULL,
                qtype        TEXT NOT NULL,
                upstream_id  TEXT NULL,
                rcode        TEXT NULL,
                status       TEXT NULL,
                error        TEXT NULL,
                first        TEXT NULL,
                result_json  TEXT NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_ts
            ON query_log(ts)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_name_ts
            ON query_log(name, ts)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_client_ts
            ON query_log(client_ip, ts)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_query_log_upstream_ts
            ON query_log(upstream_id, ts)
            """
        )

        conn.commit()

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:
        """Return True when the underlying PostgreSQL store is usable.

        Inputs:
            None.

        Outputs:
            bool: True when a trivial connectivity probe succeeds, else False.
        """

        try:
            cur = self._conn.cursor()
            cur.execute("SELECT 1")
            cur.fetchone()
            return True
        except Exception:  # pragma: no cover - defensive
            return False

    def close(self) -> None:
        """Close the underlying connection.

        Inputs:
            None.

        Outputs:
            None; connection is closed if open.
        """

        try:
            conn = getattr(self, "_conn", None)
            if conn is not None:
                conn.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while closing PostgresStatsStore connection")

    # ------------------------------------------------------------------
    # Counter API
    # ------------------------------------------------------------------
    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Increment an aggregate counter, synchronously by default.

        Inputs:
            scope: Logical scope (e.g. "totals").
            key: Counter key within the scope.
            delta: Increment value (may be negative).

        Outputs:
            None; increments immediately when async_logging is False, otherwise
            enqueues the operation on the BaseStatsStore worker queue.
        """

        if getattr(self, "_async_logging", False):
            super().increment_count(scope, key, delta)
        else:
            self._increment_count(scope, key, delta)

    def _increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Increment an aggregate counter in the counts table.

        Inputs:
            scope: Logical scope (e.g. "totals").
            key: Counter key within the scope.
            delta: Increment value (may be negative).

        Outputs:
            None.
        """

        sql = (
            "INSERT INTO counts(scope, key, value) VALUES(%s, %s, %s) "
            "ON CONFLICT (scope, key) DO UPDATE SET value = counts.value + EXCLUDED.value"
        )
        cur = self._conn.cursor()
        cur.execute(sql, (scope, key, int(delta)))
        self._conn.commit()

    def set_count(self, scope: str, key: str, value: int) -> None:
        """Set an aggregate counter in the counts table.

        Inputs:
            scope: Logical scope.
            key: Counter key within the scope.
            value: New integer value to set.

        Outputs:
            None.
        """

        sql = (
            "INSERT INTO counts(scope, key, value) VALUES(%s, %s, %s) "
            "ON CONFLICT (scope, key) DO UPDATE SET value = EXCLUDED.value"
        )
        cur = self._conn.cursor()
        cur.execute(sql, (scope, key, int(value)))
        self._conn.commit()

    def has_counts(self) -> bool:
        """Return True if the counts table contains at least one row.

        Inputs:
            None.

        Outputs:
            bool indicating whether counts has rows.
        """

        cur = self._conn.cursor()
        cur.execute("SELECT 1 FROM counts LIMIT 1")
        return cur.fetchone() is not None

    def export_counts(self) -> Dict[str, Dict[str, int]]:
        """Export all aggregate counters from the counts table.

        Inputs:
            None.

        Outputs:
            Mapping of scope -> {key -> value} for all rows in counts.
        """

        result: Dict[str, Dict[str, int]] = {}
        cur = self._conn.cursor()
        cur.execute("SELECT scope, key, value FROM counts")
        for scope, key, value in cur:
            scope_map = result.setdefault(str(scope), {})
            try:
                scope_map[str(key)] = int(value)
            except (TypeError, ValueError):  # pragma: no cover - defensive
                continue
        return result

    # ------------------------------------------------------------------
    # Query-log API
    # ------------------------------------------------------------------
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
        """Dispatch a DNS query entry synchronously or via async worker.

        Inputs:
            ts: Unix timestamp (float seconds).
            client_ip: Client IP address string.
            name: Normalized query name.
            qtype: Query type string.
            upstream_id: Optional upstream identifier.
            rcode: Optional DNS response code.
            status: Optional high-level status string.
            error: Optional error summary.
            first: Optional first answer value.
            result_json: JSON-encoded result payload.

        Outputs:
            None; appends immediately when async_logging is False, otherwise
            enqueues the operation on the BaseStatsStore worker queue.
        """

        if getattr(self, "_async_logging", False):
            super().insert_query_log(
                ts,
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
        else:
            self._insert_query_log(
                ts,
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
        """Append a DNS query entry to the query_log table.

        Inputs:
            ts: Unix timestamp (float seconds).
            client_ip: Client IP address string.
            name: Normalized query name.
            qtype: Query type string.
            upstream_id: Optional upstream identifier.
            rcode: Optional DNS response code.
            status: Optional high-level status string.
            error: Optional error summary.
            first: Optional first answer value.
            result_json: JSON-encoded result payload.

        Outputs:
            None.
        """

        sql = (
            "INSERT INTO query_log (ts, client_ip, name, qtype, upstream_id, rcode, "
            "status, error, first, result_json) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)"
        )
        cur = self._conn.cursor()
        cur.execute(
            sql,
            (
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
            ),
        )
        self._conn.commit()

    def has_query_log(self) -> bool:
        """Return True if the query_log table contains at least one row.

        Inputs:
            None.

        Outputs:
            bool indicating whether query_log has rows.
        """

        cur = self._conn.cursor()
        cur.execute("SELECT 1 FROM query_log LIMIT 1")
        return cur.fetchone() is not None

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

        Inputs:
            client_ip: Optional client IP filter.
            qtype: Optional qtype filter.
            qname: Optional qname filter.
            rcode: Optional rcode filter.
            start_ts: Optional inclusive start timestamp.
            end_ts: Optional exclusive end timestamp.
            page: 1-based page index.
            page_size: Max rows per page.

        Outputs:
            Dictionary with total, page, page_size, total_pages, and items.
        """

        page_i, page_size_i = BaseStatsStore._normalize_page_args(page, page_size)

        where: List[str] = []
        params: List[Any] = []

        if client_ip:
            where.append("client_ip = %s")
            params.append(client_ip.strip())
        if qtype:
            where.append("qtype = %s")
            params.append(qtype.strip().upper())
        if qname:
            where.append("name = %s")
            params.append(qname.strip().rstrip(".").lower())
        if rcode:
            where.append("rcode = %s")
            params.append(rcode.strip().upper())
        if isinstance(start_ts, (int, float)):
            where.append("ts >= %s")
            params.append(float(start_ts))
        if isinstance(end_ts, (int, float)):
            where.append("ts < %s")
            params.append(float(end_ts))

        where_sql = " WHERE " + " AND ".join(where) if where else ""

        cur = self._conn.cursor()
        cur.execute(f"SELECT COUNT(1) FROM query_log{where_sql}", tuple(params))
        row = cur.fetchone()
        total = int(row[0]) if row else 0

        offset = (page_i - 1) * page_size_i
        sql = (
            "SELECT id, ts, client_ip, name, qtype, upstream_id, rcode, status, "
            "error, first, result_json "
            f"FROM query_log{where_sql} "
            "ORDER BY ts DESC, id DESC LIMIT %s OFFSET %s"
        )
        cur2 = self._conn.cursor()
        cur2.execute(sql, tuple(params + [page_size_i, offset]))

        items: List[Dict[str, Any]] = []
        for (
            row_id,
            ts,
            client_ip_row,
            name_row,
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
                    "qname": str(name_row),
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

        total_pages = (total + page_size_i - 1) // page_size_i if page_size_i > 0 else 0
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

        Inputs:
            start_ts: Inclusive start timestamp.
            end_ts: Exclusive end timestamp.
            interval_seconds: Bucket size in seconds.
            client_ip: Optional client IP filter.
            qtype: Optional qtype filter.
            qname: Optional qname filter.
            rcode: Optional rcode filter.
            group_by: Optional grouping dimension (client_ip/qtype/qname/rcode).

        Outputs:
            Mapping with window metadata and aggregated bucket counts.
        """

        start_f, end_f, interval_i = BaseStatsStore._normalize_interval_args(
            start_ts, end_ts, interval_seconds
        )
        if interval_i <= 0 or end_f <= start_f:
            return {
                "start_ts": start_f,
                "end_ts": end_f,
                "interval_seconds": interval_i,
                "items": [],
            }

        where: List[str] = ["ts >= %s", "ts < %s"]
        params: List[Any] = [start_f, end_f]

        if client_ip:
            where.append("client_ip = %s")
            params.append(client_ip.strip())
        if qtype:
            where.append("qtype = %s")
            params.append(qtype.strip().upper())
        if qname:
            where.append("name = %s")
            params.append(qname.strip().rstrip(".").lower())
        if rcode:
            where.append("rcode = %s")
            params.append(rcode.strip().upper())

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

        cur = self._conn.cursor()
        rows: List[Tuple[int, Optional[str], int]] = []
        if group_col:
            sql = (
                "SELECT FLOOR((ts - %s) / %s)::BIGINT AS bucket, "
                f"{group_col} AS group_value, COUNT(1) AS c "
                f"FROM query_log{where_sql} "
                "GROUP BY bucket, group_value ORDER BY bucket ASC"
            )
            cur.execute(sql, tuple([start_f, interval_i] + params))
            for bucket, group_value, c in cur:
                try:
                    b_i = int(bucket)
                    c_i = int(c)
                except Exception:
                    continue
                rows.append(
                    (b_i, str(group_value) if group_value is not None else None, c_i)
                )
        else:
            sql = (
                "SELECT FLOOR((ts - %s) / %s)::BIGINT AS bucket, COUNT(1) AS c "
                f"FROM query_log{where_sql} "
                "GROUP BY bucket ORDER BY bucket ASC"
            )
            cur.execute(sql, tuple([start_f, interval_i] + params))
            for bucket, c in cur:
                try:
                    b_i = int(bucket)
                    c_i = int(c)
                except Exception:
                    continue
                rows.append((b_i, None, c_i))

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
    # Count rebuild helpers
    # ------------------------------------------------------------------
    def rebuild_counts_from_query_log(
        self,
        logger_obj: Optional[logging.Logger] = None,
    ) -> None:
        """Rebuild counts by aggregating over all rows in query_log.

        Inputs:
            logger_obj: Optional logger used for warnings and errors.

        Outputs:
            None; counts table is cleared and recomputed from query_log.
        """

        log = logger_obj or logger
        conn = self._conn
        cur = conn.cursor()

        try:
            cur.execute("DELETE FROM counts")
            conn.commit()
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Failed to clear counts table before rebuild: %s", exc, exc_info=True
            )
            return

        # Re-aggregate from query_log using the same semantics as the SQLite
        # backend so that counts and warm-load behaviour remain consistent.
        try:
            cur.execute(
                "SELECT client_ip, name, qtype, upstream_id, rcode, status, error, result_json "
                "FROM query_log"
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

                # Per-outcome cache-domain aggregates using base domains.
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
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Error while rebuilding counts from query_log: %s", exc, exc_info=True
            )

    def rebuild_counts_if_needed(
        self,
        force_rebuild: bool = False,
        logger_obj: Optional[logging.Logger] = None,
    ) -> None:
        """Conditionally rebuild counts based on current DB state and flags.

        Inputs:
            force_rebuild: When True, always rebuild when query_log has rows.
            logger_obj: Optional logger used for informational messages.

        Outputs:
            None.
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
