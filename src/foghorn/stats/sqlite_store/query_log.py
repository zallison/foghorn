from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from foghorn.security_limits import enforce_query_log_aggregate_bucket_limit
from foghorn.utils import dns_names

logger = logging.getLogger("foghorn.stats")


class _QueryLogMixin:
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

        Brief:
            Returns rows from the SQLite-backed query_log table, filtered by
            client_ip, qtype, qname, and rcode, and paginated by (page, page_size).

        Inputs:
            client_ip: Optional client IP filter (exact match).
            qtype: Optional qtype filter (case-insensitive; stored values are typically uppercase).
            qname: Optional qname filter (case-insensitive; compared against normalized stored name).
            rcode: Optional rcode filter (case-insensitive; stored values are typically uppercase).
            status: Optional status filter (case-insensitive exact match).
            source: Optional result.source filter (case-insensitive match against result_json).
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
            - result_json is decoded into a dict under the 'result' key.
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
        status_s = str(status).strip().lower() if status is not None else None
        source_s = str(source).strip().lower() if source is not None else None
        qname_s = None
        if qname is not None:
            qname_s = dns_names.normalize_name(qname)

        where: List[str] = []
        params: List[Any] = []

        if client_ip_s:
            where.append("client_ip = ?")
            params.append(client_ip_s)
        if qtype_s:
            where.append("qtype = ?")
            params.append(qtype_s)
        if qname_s:
            where.append("(name = ? OR name LIKE ?)")
            params.append(qname_s)
            params.append(f"%.{qname_s}")
        if rcode_s:
            where.append("rcode = ?")
            params.append(rcode_s)
        if status_s:
            where.append("LOWER(COALESCE(status, '')) = ?")
            params.append(status_s)
        if source_s:
            # result_json is stored as text; avoid JSON extension requirements by
            # matching compact and spaced key/value forms.
            where.append("(LOWER(result_json) LIKE ? OR LOWER(result_json) LIKE ?)")
            params.append(f'%"source":"{source_s}"%')
            params.append(f'%"source": "{source_s}"%')
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
        except Exception as exc:  # pragma: no cover
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
        except Exception as exc:  # pragma: no cover
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
                {'client_ip', 'qtype', 'qname', 'rcode'}. When provided, results
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
            qname_s = dns_names.normalize_name(qname)

        where: List[str] = ["ts >= ?", "ts < ?"]
        params: List[Any] = [start_f, end_f]

        if client_ip_s:
            where.append("client_ip = ?")
            params.append(client_ip_s)
        if qtype_s:
            where.append("qtype = ?")
            params.append(qtype_s)
        if qname_s:
            where.append("(name = ? OR name LIKE ?)")
            params.append(qname_s)
            params.append(f"%.{qname_s}")
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
        except Exception as exc:  # pragma: no cover
            logger.error(
                "StatsSQLiteStore aggregate_query_log_counts error: %s",
                exc,
                exc_info=True,
            )
            rows = []

        # Dense fill for the common single-series case.
        if not group_col:
            try:
                num = enforce_query_log_aggregate_bucket_limit(
                    start_f, end_f, interval_i
                )
            except ValueError as exc:
                logger.warning(
                    "StatsSQLiteStore aggregate_query_log_counts rejected: %s", exc
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
