from __future__ import annotations

import json
import logging
import math
import time
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseStatsStore
from foghorn.security_limits import enforce_query_log_aggregate_bucket_limit
from foghorn.utils import dns_names
from .sqlite import _is_subdomain, _normalize_domain

"""MySQL/MariaDB-backed implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via a configuration mapping passed through StatsStoreBackendConfig
    with backend-specific fields such as host, port, user, password, and
    database.

Outputs:
  - Concrete backend instance that can be passed to StatsCollector and
    StatsReporter for persistent statistics and query-log storage using a
    MariaDB/MySQL database instead of SQLite.

Notes:
  - This backend intentionally mirrors the logical schema and behaviour of the
    SqliteStatsStore so callers remain backend-agnostic.
  - The underlying DB driver (mariadb or mysql-connector-python) is imported
    lazily so that Foghorn does not require it unless this backend is used.
  - Config may specify:
      - driver: auto|mariadb|mysql-connector-python (or mysql)
      - driver_fallback: auto|none|<driver>|[<driver>, ...]
"""

logger = logging.getLogger(__name__)


def _normalize_mysql_driver_name(raw: object) -> str | None:
    """Brief: Normalize a MySQL driver name from config.

    Inputs:
        raw: Candidate value (string-like) from config.

    Outputs:
        str | None: Canonical driver key:
          - 'mariadb'
          - 'mysql-connector-python'
        Returns None when raw is missing/empty/auto.
    """

    if raw is None:
        return None
    if not isinstance(raw, str):
        return None

    value = raw.strip().lower().replace("_", "-").replace(" ", "")
    if not value or value in {"auto", "default"}:
        return None

    # Accept a few common synonyms.
    if value in {"mariadb", "maria-db"}:
        return "mariadb"
    if value in {
        "mysql",
        "mysql-connector-python",
        "mysql.connector",
        "mysql-connector",
        "mysqlconnector",
        "mysql-connector/py",
        "connector",
    }:
        return "mysql-connector-python"

    raise ValueError(
        "mysql driver must be one of 'auto', 'mariadb', 'mysql', or 'mysql-connector-python'"
    )


def _normalize_driver_fallbacks(raw: object) -> list[str] | None:
    """Brief: Normalize driver fallback configuration.

    Inputs:
        raw: Candidate fallback config from YAML (string or list of strings).

    Outputs:
        list[str] | None:
          - None for default behavior (auto fallback)
          - [] for explicit no-fallback (none)
          - list of canonical driver keys
    """

    if raw is None:
        return None

    if isinstance(raw, str):
        v = raw.strip().lower().replace("_", "-").replace(" ", "")
        if not v or v in {"auto", "default"}:
            return None
        if v in {"none", "no", "false", "off"}:
            return []
        return [_normalize_mysql_driver_name(raw)]  # type: ignore[list-item]

    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if item is None:
                continue
            name = _normalize_mysql_driver_name(item)
            if name is None:
                continue
            out.append(name)
        return out

    return None


def _driver_order_from_config(
    *,
    driver: object = None,
    driver_fallback: object = None,
) -> list[str]:
    """Brief: Compute the driver import order based on config.

    Inputs:
        driver: Preferred driver name ('auto'|'mariadb'|'mysql-connector-python').
        driver_fallback: Fallback policy ('auto'|'none'|<driver>|[<driver>,...]).

    Outputs:
        list[str]: Ordered list of canonical driver keys to try.
    """

    preferred = _normalize_mysql_driver_name(driver)
    fallbacks = _normalize_driver_fallbacks(driver_fallback)

    # Default order: prefer mariadb, then mysql-connector-python.
    default_order = ["mariadb", "mysql-connector-python"]

    if preferred is None:
        # auto/default
        if fallbacks == []:
            return [default_order[0]]
        return default_order

    # Explicit preferred.
    if fallbacks is None:
        # Default fallback for an explicit preference is "the other driver".
        fallbacks = [d for d in default_order if d != preferred]

    # fallbacks may be [] to disable.
    order = [preferred] + list(fallbacks or [])

    # Deduplicate while preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for item in order:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _import_mysql_driver(
    *,
    driver: object = None,
    driver_fallback: object = None,
) -> tuple[object, str]:
    """Import and return a DB-API compatible MySQL/MariaDB driver module.

    Inputs:
        driver: Preferred driver name.
        driver_fallback: Fallback policy.

    Outputs:
        (driver_module, placeholder):
          - driver_module: DB-API like module exposing a ``connect`` callable.
          - placeholder: Parameter placeholder string ('%s' or '?').

    Raises:
        RuntimeError: When no supported MySQL/MariaDB driver is available.
        ValueError: When driver/driver_fallback values are invalid.
    """

    order = _driver_order_from_config(driver=driver, driver_fallback=driver_fallback)

    last_exc: Exception | None = None
    for choice in order:
        try:
            if choice == "mariadb":
                # pragma: disable E402
                import mariadb as driver_mod  # type: ignore[import]

                return driver_mod, "?"  # DB-API qmark style

            if choice == "mysql-connector-python":
                # pragma: disable E402
                import mysql.connector as driver_mod  # type: ignore[import]

                return driver_mod, "%s"  # DB-API format style

        except ImportError as exc:  # pragma: no cover - import-path dependent
            last_exc = exc
            continue

    raise RuntimeError(
        "No supported MySQL/MariaDB driver found; install either 'mariadb' or "
        "'mysql-connector-python' to use the MySqlStatsStore"
    ) from last_exc


class MySqlStatsStore(BaseStatsStore):
    """MySQL/MariaDB-backed persistent statistics and query-log backend.

    # Aliases used by the stats backend registry.
    aliases = ("mysql", "mariadb")

    This backend stores the same logical ``counts`` and ``query_log`` tables as
    the SQLite implementation, but in a MariaDB/MySQL database.

    Inputs (constructor):
        host: Database host (default "127.0.0.1").
        port: Database port (default 3306).
        user: Database username.
        password: Database password.
        database: Database name.
        connect_kwargs: Optional mapping of additional keyword arguments passed
            through to the underlying driver's ``connect`` function
            (for example, ssl, unix_socket).
        driver: Preferred DB driver (auto|mariadb|mysql-connector-python or mysql).
        driver_fallback: Fallback policy for driver import:
            - auto (default): try the other driver as a fallback.
            - none: do not fall back.
            - <driver> or [<driver>, ...]: explicit fallback list.

    Outputs:
        Initialized MySqlStatsStore instance with ensured schema.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 3306,
        user: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "foghorn_stats",
        connect_kwargs: Optional[Dict[str, Any]] = None,
        async_logging: bool = False,
        max_logging_queue: int = 4096,
        retention_max_records: Optional[int] = None,
        retention_days: Optional[float] = None,
        retention_max_bytes: Optional[int] = None,
        retention_prune_interval_seconds: Optional[float] = None,
        retention_prune_every_n_inserts: Optional[int] = None,
        retention_optimize_on_prune: bool = False,
        retention_optimize_interval_seconds: Optional[float] = None,
        driver: Optional[str] = None,
        driver_fallback: object = None,
        **_: Any,
    ) -> None:
        driver_mod, placeholder = _import_mysql_driver(
            driver=driver, driver_fallback=driver_fallback
        )

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

        self._driver = driver_mod
        self._placeholder = str(placeholder)
        self._conn = driver_mod.connect(**kwargs)

        # Use synchronous logging by default for SQL stats backends.
        self._async_logging = bool(async_logging)
        # BaseStatsStore worker queue capacity
        try:
            self._max_logging_queue = int(max_logging_queue)
        except Exception:
            self._max_logging_queue = 4096
        self._query_log_retention_max_records = (
            BaseStatsStore._normalize_retention_max_records(retention_max_records)
        )
        self._query_log_retention_days = BaseStatsStore._normalize_retention_days(
            retention_days
        )
        self._query_log_retention_max_bytes = (
            BaseStatsStore._normalize_retention_max_bytes(retention_max_bytes)
        )
        self._query_log_retention_prune_interval_seconds = (
            BaseStatsStore._normalize_retention_prune_interval_seconds(
                retention_prune_interval_seconds
            )
        )
        self._query_log_retention_prune_every_n_inserts = (
            BaseStatsStore._normalize_retention_prune_every_n_inserts(
                retention_prune_every_n_inserts
            )
        )
        self._query_log_retention_seen_inserts = 0
        self._query_log_retention_last_prune_ts = 0.0
        self._retention_optimize_on_prune = bool(retention_optimize_on_prune)
        self._retention_optimize_interval_seconds = (
            BaseStatsStore._normalize_retention_prune_interval_seconds(
                retention_optimize_interval_seconds
            )
        )
        self._retention_last_optimize_ts = 0.0

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
                scope VARCHAR(255) NOT NULL,
                key   VARCHAR(255) NOT NULL,
                value BIGINT NOT NULL DEFAULT 1,
                PRIMARY KEY (scope, key)
            ) ENGINE=InnoDB
            """
        )

        # query_log table mirrors the SQLite schema closely.
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS query_log (
                id           BIGINT NOT NULL AUTO_INCREMENT,
                ts           DOUBLE NOT NULL,
                client_ip    VARCHAR(64) NOT NULL,
                name         VARCHAR(255) NOT NULL,
                qtype        VARCHAR(16) NOT NULL,
                upstream_id  VARCHAR(255) NULL,
                rcode        VARCHAR(32) NULL,
                status       VARCHAR(32) NULL,
                error        TEXT NULL,
                first        TEXT NULL,
                result_json  MEDIUMTEXT NOT NULL,
                PRIMARY KEY (id),
                INDEX idx_query_log_ts (ts),
                INDEX idx_query_log_name_ts (name, ts),
                INDEX idx_query_log_client_ts (client_ip, ts),
                INDEX idx_query_log_upstream_ts (upstream_id, ts)
            ) ENGINE=InnoDB
            """
        )

        conn.commit()

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:
        """Return True when the underlying MySQL/MariaDB store is usable.

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
            logger.exception("Error while closing MySqlStatsStore connection")

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

        ph = self._placeholder
        sql = (
            f"INSERT INTO counts(scope, key, value) VALUES({ph}, {ph}, {ph}) "
            "ON DUPLICATE KEY UPDATE value = value + VALUES(value)"
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

        ph = self._placeholder
        sql = (
            f"INSERT INTO counts(scope, key, value) VALUES({ph}, {ph}, {ph}) "
            "ON DUPLICATE KEY UPDATE value = VALUES(value)"
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

        ph = self._placeholder
        sql = (
            "INSERT INTO query_log (ts, client_ip, name, qtype, upstream_id, rcode, "
            "status, error, first, result_json) "
            f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})"
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
        self._apply_query_log_retention()

    def _apply_query_log_retention(self) -> None:
        """Brief: Enforce configured query-log retention limits.

        Inputs:
            None.

        Outputs:
            None; deletes rows older than the cutoff and/or rows beyond the
            configured max-record count.
        """

        cutoff_ts = BaseStatsStore._retention_cutoff_ts(
            self._query_log_retention_days,
            now_ts=time.time(),
        )
        max_records = self._query_log_retention_max_records
        max_bytes = self._query_log_retention_max_bytes
        now_ts = time.time()
        if cutoff_ts is None and max_records is None and max_bytes is None:
            return
        if not self._should_run_query_log_retention_prune(now_ts=now_ts):
            return

        ph = self._placeholder
        cur = self._conn.cursor()

        try:
            changed = False
            if cutoff_ts is not None:
                cur.execute(
                    f"DELETE FROM query_log WHERE ts < {ph}",
                    (float(cutoff_ts),),
                )
                changed = changed or bool(getattr(cur, "rowcount", 0))

            if max_records is not None:
                cur.execute(
                    (
                        "DELETE FROM query_log WHERE id NOT IN ("
                        "SELECT id FROM ("
                        f"SELECT id FROM query_log ORDER BY ts DESC, id DESC LIMIT {ph}"
                        ") AS retained"
                        ")"
                    ),
                    (int(max_records),),
                )
                changed = changed or bool(getattr(cur, "rowcount", 0))

            if max_bytes is not None:
                changed = self._prune_query_log_to_max_bytes(int(max_bytes)) or changed

            self._conn.commit()
            if changed:
                self._maybe_optimize_query_log_table(now_ts=now_ts)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MySqlStatsStore retention prune failed: %s", exc, exc_info=True
            )

    def _prune_query_log_to_max_bytes(self, max_bytes: int) -> bool:
        """Brief: Remove oldest rows until estimated query_log bytes fit a cap.

        Inputs:
            max_bytes: Maximum estimated bytes to retain in query_log.

        Outputs:
            bool: True when one or more rows were deleted.
        """

        if max_bytes <= 0:
            return False

        ph = self._placeholder
        changed = False
        max_passes = 32
        for _ in range(max_passes):
            cur = self._conn.cursor()
            cur.execute(
                """
                SELECT
                    COALESCE(
                        SUM(
                            OCTET_LENGTH(client_ip)
                            + OCTET_LENGTH(name)
                            + OCTET_LENGTH(qtype)
                            + OCTET_LENGTH(COALESCE(upstream_id, ''))
                            + OCTET_LENGTH(COALESCE(rcode, ''))
                            + OCTET_LENGTH(COALESCE(status, ''))
                            + OCTET_LENGTH(COALESCE(error, ''))
                            + OCTET_LENGTH(COALESCE(first, ''))
                            + OCTET_LENGTH(result_json)
                            + 64
                        ),
                        0
                    ),
                    COUNT(1)
                FROM query_log
                """
            )
            row = cur.fetchone()
            total_bytes = int(row[0] or 0) if row else 0
            total_rows = int(row[1] or 0) if row else 0
            if total_bytes <= max_bytes or total_rows <= 0:
                break

            over = max(1, total_bytes - int(max_bytes))
            ratio = float(over) / float(max(total_bytes, 1))
            rows_to_delete = max(1, min(total_rows, int(math.ceil(ratio * total_rows))))

            cur_del = self._conn.cursor()
            cur_del.execute(
                (
                    "DELETE FROM query_log WHERE id IN ("
                    "SELECT id FROM ("
                    f"SELECT id FROM query_log ORDER BY ts ASC, id ASC LIMIT {ph}"
                    ") AS doomed"
                    ")"
                ),
                (int(rows_to_delete),),
            )
            if not bool(getattr(cur_del, "rowcount", 0)):
                break
            changed = True

        return changed

    def _maybe_optimize_query_log_table(self, *, now_ts: float) -> None:
        """Brief: Run optional MySQL table optimization after retention pruning.

        Inputs:
            now_ts: Current Unix timestamp used for interval gating.

        Outputs:
            None.
        """

        if not self._retention_optimize_on_prune:
            return

        interval = self._retention_optimize_interval_seconds
        if interval is not None:
            try:
                last = float(getattr(self, "_retention_last_optimize_ts", 0.0) or 0.0)
            except Exception:
                last = 0.0
            if last > 0.0 and (float(now_ts) - last) < float(interval):
                return

        try:
            cur = self._conn.cursor()
            cur.execute("OPTIMIZE TABLE query_log")
            self._conn.commit()
            self._retention_last_optimize_ts = float(now_ts)
        except Exception:  # pragma: no cover - defensive
            logger.exception("MySqlStatsStore optimize table failed")

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
        status: Optional[str] = None,
        source: Optional[str] = None,
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
            status: Optional status filter.
            source: Optional result.source filter.
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
            where.append(f"client_ip = {self._placeholder}")
            params.append(client_ip.strip())
        if qtype:
            where.append(f"qtype = {self._placeholder}")
            params.append(qtype.strip().upper())
        if qname:
            where.append(f"name = {self._placeholder}")
            params.append(dns_names.normalize_name(qname))
        if rcode:
            where.append(f"rcode = {self._placeholder}")
            params.append(rcode.strip().upper())
        if status:
            where.append(f"LOWER(COALESCE(status, '')) = {self._placeholder}")
            params.append(status.strip().lower())
        if source:
            source_s = source.strip().lower()
            where.append(
                f"(LOWER(result_json) LIKE {self._placeholder} OR LOWER(result_json) LIKE {self._placeholder})"
            )
            params.append(f'%"source":"{source_s}"%')
            params.append(f'%"source": "{source_s}"%')
        if isinstance(start_ts, (int, float)):
            where.append(f"ts >= {self._placeholder}")
            params.append(float(start_ts))
        if isinstance(end_ts, (int, float)):
            where.append(f"ts < {self._placeholder}")
            params.append(float(end_ts))

        where_sql = " WHERE " + " AND ".join(where) if where else ""

        cur = self._conn.cursor()
        cur.execute(f"SELECT COUNT(1) FROM query_log{where_sql}", tuple(params))
        row = cur.fetchone()
        total = int(row[0]) if row else 0

        offset = (page_i - 1) * page_size_i
        ph = self._placeholder
        sql = (
            "SELECT id, ts, client_ip, name, qtype, upstream_id, rcode, status, "
            "error, first, result_json "
            f"FROM query_log{where_sql} "
            f"ORDER BY ts DESC, id DESC LIMIT {ph} OFFSET {ph}"
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

        where: List[str] = [
            f"ts >= {self._placeholder}",
            f"ts < {self._placeholder}",
        ]
        params: List[Any] = [start_f, end_f]

        if client_ip:
            where.append(f"client_ip = {self._placeholder}")
            params.append(client_ip.strip())
        if qtype:
            where.append(f"qtype = {self._placeholder}")
            params.append(qtype.strip().upper())
        if qname:
            where.append(f"name = {self._placeholder}")
            params.append(dns_names.normalize_name(qname))
        if rcode:
            where.append(f"rcode = {self._placeholder}")
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
            ph = self._placeholder
            sql = (
                f"SELECT FLOOR((ts - {ph}) / {ph}) AS bucket, "
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
            ph = self._placeholder
            sql = (
                f"SELECT FLOOR((ts - {ph}) / {ph}) AS bucket, COUNT(1) AS c "
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
            try:
                num = enforce_query_log_aggregate_bucket_limit(
                    start_f, end_f, interval_i
                )
            except ValueError as exc:
                logger.warning(
                    "MySqlStatsStore aggregate_query_log_counts rejected: %s", exc
                )
                return {
                    "start_ts": start_f,
                    "end_ts": end_f,
                    "interval_seconds": interval_i,
                    "items": [],
                }
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
