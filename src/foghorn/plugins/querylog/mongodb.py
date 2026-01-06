from __future__ import annotations

"""MongoDB-backed implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via a configuration mapping passed through StatsStoreBackendConfig
    with backend-specific fields such as uri, host, port, username, password,
    and database.

Outputs:
  - Concrete backend instance that can be passed to StatsCollector and
    StatsReporter for persistent statistics and query-log storage using MongoDB
    instead of SQLite.

Notes:
  - This backend intentionally mirrors the logical schema and behaviour of the
    SqliteStatsStore so callers remain backend-agnostic.
  - The underlying DB driver (pymongo) is imported lazily so that Foghorn does
    not require it unless this backend is used.
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple

from .base import BaseStatsStore
from .sqlite import _normalize_domain, _is_subdomain

logger = logging.getLogger(__name__)


def _import_mongo_driver():
    """Import and return a MongoDB driver module exposing MongoClient.

    Inputs:
        None.

    Outputs:
        pymongo-like module exposing a ``MongoClient`` callable.

    Raises:
        RuntimeError: When no supported MongoDB driver is available.
    """

    try:  # pragma: no cover - import-path dependent
        import pymongo  # type: ignore[import]

        return pymongo
    except Exception as exc:  # pragma: no cover - environment specific
        raise RuntimeError(
            "No supported MongoDB driver found; install 'pymongo' to use the "
            "MongoStatsStore"
        ) from exc


class MongoStatsStore(BaseStatsStore):
    """MongoDB-backed persistent statistics and query-log backend.

    # Aliases used by the stats backend registry.
    aliases = ("mongo", "mongodb")

    This backend stores the same logical ``counts`` and ``query_log`` data as
    the SQLite implementation, but in MongoDB collections.

    Inputs (constructor):
        uri: Optional MongoDB connection URI.
        host: Database host (default "127.0.0.1").
        port: Database port (default 27017).
        username: Optional username for authentication.
        password: Optional password for authentication.
        database: Database name (default "foghorn_stats").
        connect_kwargs: Optional mapping of additional keyword arguments passed
            through to MongoClient (for example, tls, replicaSet).

    Outputs:
        Initialized MongoStatsStore instance with ensured collections/indexes.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        host: str = "127.0.0.1",
        port: int = 27017,
        username: Optional[str] = None,
        password: Optional[str] = None,
        database: str = "foghorn_stats",
        connect_kwargs: Optional[Dict[str, Any]] = None,
        async_logging: bool = False,
        **_: Any,
    ) -> None:
        mongo_mod = _import_mongo_driver()
        connect_kwargs = dict(connect_kwargs or {})

        if uri:
            self._client = mongo_mod.MongoClient(uri, **connect_kwargs)
        else:
            kwargs: Dict[str, Any] = {
                "host": host,
                "port": int(port),
            }
            if username is not None:
                kwargs["username"] = username
            if password is not None:
                kwargs["password"] = password
            kwargs.update(connect_kwargs)
            self._client = mongo_mod.MongoClient(**kwargs)

        # Use synchronous logging by default for Mongo stats backend.
        self._async_logging = bool(async_logging)

        self._db = self._client[database]
        self._counts = self._db["counts"]
        self._query_log = self._db["query_log"]

        self._ensure_indexes()

    # ------------------------------------------------------------------
    # Schema and connection helpers
    # ------------------------------------------------------------------
    def _ensure_indexes(self) -> None:
        """Ensure indexes exist on counts and query_log collections.

        Inputs:
            None.

        Outputs:
            None; creates indexes if they do not already exist.
        """

        try:
            # Unique composite key for counts documents.
            self._counts.create_index([("scope", 1), ("key", 1)], unique=True)

            # Query-log indexes mirroring SQLite/SQL backends.
            self._query_log.create_index([("ts", 1)], name="idx_query_log_ts")
            self._query_log.create_index(
                [("name", 1), ("ts", 1)], name="idx_query_log_name_ts"
            )
            self._query_log.create_index(
                [("client_ip", 1), ("ts", 1)], name="idx_query_log_client_ts"
            )
            self._query_log.create_index(
                [("upstream_id", 1), ("ts", 1)], name="idx_query_log_upstream_ts"
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MongoStatsStore _ensure_indexes error: %s", exc, exc_info=True
            )

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:
        """Return True when the underlying MongoDB store is usable.

        Inputs:
            None.

        Outputs:
            bool: True when a trivial connectivity probe succeeds, else False.
        """

        try:
            # Use a cheap ping command against the admin database.
            self._client.admin.command("ping")
            return True
        except Exception:  # pragma: no cover - defensive
            return False

    def close(self) -> None:
        """Close the underlying MongoDB client.

        Inputs:
            None.

        Outputs:
            None; client is closed if open.
        """

        try:
            client = getattr(self, "_client", None)
            if client is not None:
                client.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while closing MongoStatsStore client")

    # ------------------------------------------------------------------
    # Counter API
    # ------------------------------------------------------------------
    def _increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Increment an aggregate counter in the counts collection.

        Inputs:
            scope: Logical scope (e.g. "totals").
            key: Counter key within the scope.
            delta: Increment value (may be negative).

        Outputs:
            None.
        """

        try:
            self._counts.update_one(
                {"scope": scope, "key": key},
                {"$inc": {"value": int(delta)}},
                upsert=True,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MongoStatsStore increment_count error: %s", exc, exc_info=True
            )

    def set_count(self, scope: str, key: str, value: int) -> None:
        """Set an aggregate counter in the counts collection.

        Inputs:
            scope: Logical scope.
            key: Counter key within the scope.
            value: New integer value to set.

        Outputs:
            None.
        """

        try:
            self._counts.update_one(
                {"scope": scope, "key": key},
                {"$set": {"value": int(value)}},
                upsert=True,
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("MongoStatsStore set_count error: %s", exc, exc_info=True)

    def has_counts(self) -> bool:
        """Return True if the counts collection contains at least one document.

        Inputs:
            None.

        Outputs:
            bool indicating whether counts has documents.
        """

        try:
            return self._counts.find_one({}, {"_id": 1}) is not None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("MongoStatsStore has_counts error: %s", exc, exc_info=True)
            return False

    def export_counts(self) -> Dict[str, Dict[str, int]]:
        """Export all aggregate counters from the counts collection.

        Inputs:
            None.

        Outputs:
            Mapping of scope -> {key -> value} for all documents in counts.
        """

        result: Dict[str, Dict[str, int]] = {}
        try:
            for doc in self._counts.find(
                {}, {"_id": 0, "scope": 1, "key": 1, "value": 1}
            ):
                scope = str(doc.get("scope", ""))
                key = str(doc.get("key", ""))
                scope_map = result.setdefault(scope, {})
                try:
                    scope_map[key] = int(doc.get("value", 0))
                except (TypeError, ValueError):  # pragma: no cover - defensive
                    continue
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("MongoStatsStore export_counts error: %s", exc, exc_info=True)
        return result

    # ------------------------------------------------------------------
    # Query-log API
    # ------------------------------------------------------------------
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
        """Append a DNS query entry to the query_log collection.

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

        try:
            doc = {
                "ts": float(ts),
                "client_ip": client_ip,
                "name": name,
                "qtype": qtype,
                "upstream_id": upstream_id,
                "rcode": rcode,
                "status": status,
                "error": error,
                "first": first,
                "result_json": result_json,
            }
            self._query_log.insert_one(doc)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MongoStatsStore insert_query_log error: %s", exc, exc_info=True
            )

    def has_query_log(self) -> bool:
        """Return True if the query_log collection contains at least one document.

        Inputs:
            None.

        Outputs:
            bool indicating whether query_log has documents.
        """

        try:
            return self._query_log.find_one({}, {"_id": 1}) is not None
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("MongoStatsStore has_query_log error: %s", exc, exc_info=True)
            return False

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
        """Select query_log documents with basic filtering and pagination.

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

        flt: Dict[str, Any] = {}
        if client_ip:
            flt["client_ip"] = client_ip.strip()
        if qtype:
            flt["qtype"] = qtype.strip().upper()
        if qname:
            flt["name"] = qname.strip().rstrip(".").lower()
        if rcode:
            flt["rcode"] = rcode.strip().upper()
        if isinstance(start_ts, (int, float)) or isinstance(end_ts, (int, float)):
            ts_cond: Dict[str, Any] = {}
            if isinstance(start_ts, (int, float)):
                ts_cond["$gte"] = float(start_ts)
            if isinstance(end_ts, (int, float)):
                ts_cond["$lt"] = float(end_ts)
            flt["ts"] = ts_cond

        try:
            total = int(self._query_log.count_documents(flt))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MongoStatsStore select_query_log count error: %s", exc, exc_info=True
            )
            total = 0

        offset = (page_i - 1) * page_size_i
        items: List[Dict[str, Any]] = []
        try:
            cursor = (
                self._query_log.find(flt)
                .sort([("ts", -1), ("_id", -1)])
                .skip(offset)
                .limit(page_size_i)
            )
            for doc in cursor:
                try:
                    raw_json = doc.get("result_json") or "{}"
                    result_obj = json.loads(raw_json)
                    if not isinstance(result_obj, dict):
                        result_obj = {"value": result_obj}
                except Exception:
                    result_obj = {}

                items.append(
                    {
                        "id": str(doc.get("_id")),
                        "ts": float(doc.get("ts", 0.0)),
                        "client_ip": str(doc.get("client_ip", "")),
                        "qname": str(doc.get("name", "")),
                        "qtype": str(doc.get("qtype", "")),
                        "upstream_id": (
                            str(doc.get("upstream_id"))
                            if doc.get("upstream_id") is not None
                            else None
                        ),
                        "rcode": (
                            str(doc.get("rcode"))
                            if doc.get("rcode") is not None
                            else None
                        ),
                        "status": (
                            str(doc.get("status"))
                            if doc.get("status") is not None
                            else None
                        ),
                        "error": (
                            str(doc.get("error"))
                            if doc.get("error") is not None
                            else None
                        ),
                        "first": (
                            str(doc.get("first"))
                            if doc.get("first") is not None
                            else None
                        ),
                        "result": result_obj,
                    }
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MongoStatsStore select_query_log rows error: %s", exc, exc_info=True
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

        flt: Dict[str, Any] = {"ts": {"$gte": start_f, "$lt": end_f}}
        if client_ip:
            flt["client_ip"] = client_ip.strip()
        if qtype:
            flt["qtype"] = qtype.strip().upper()
        if qname:
            flt["name"] = qname.strip().rstrip(".").lower()
        if rcode:
            flt["rcode"] = rcode.strip().upper()

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

        rows: List[Tuple[int, Optional[str], int]] = []
        try:
            if group_col:
                pipeline = [
                    {"$match": flt},
                    {
                        "$project": {
                            "bucket": {
                                "$floor": {
                                    "$divide": [
                                        {"$subtract": ["$ts", float(start_f)]},
                                        float(interval_i),
                                    ]
                                }
                            },
                            "group_value": f"${group_col}",
                        }
                    },
                    {
                        "$group": {
                            "_id": {
                                "bucket": "$bucket",
                                "group_value": "$group_value",
                            },
                            "c": {"$sum": 1},
                        }
                    },
                    {"$sort": {"_id.bucket": 1}},
                ]
                for doc in self._query_log.aggregate(pipeline):
                    try:
                        bucket = int(doc["_id"]["bucket"])
                        c_i = int(doc.get("c", 0))
                    except Exception:
                        continue
                    group_value = doc["_id"].get("group_value")
                    rows.append(
                        (
                            bucket,
                            str(group_value) if group_value is not None else None,
                            c_i,
                        )
                    )
            else:
                pipeline = [
                    {"$match": flt},
                    {
                        "$project": {
                            "bucket": {
                                "$floor": {
                                    "$divide": [
                                        {"$subtract": ["$ts", float(start_f)]},
                                        float(interval_i),
                                    ]
                                }
                            }
                        }
                    },
                    {"$group": {"_id": "$bucket", "c": {"$sum": 1}}},
                    {"$sort": {"_id": 1}},
                ]
                for doc in self._query_log.aggregate(pipeline):
                    try:
                        bucket = int(doc["_id"])
                        c_i = int(doc.get("c", 0))
                    except Exception:
                        continue
                    rows.append((bucket, None, c_i))
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "MongoStatsStore aggregate_query_log_counts error: %s",
                exc,
                exc_info=True,
            )
            rows = []

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
        """Rebuild counts by aggregating over all documents in query_log.

        Inputs:
            logger_obj: Optional logger used for warnings and errors.

        Outputs:
            None; counts collection is cleared and recomputed from query_log.
        """

        log = logger_obj or logger

        try:
            self._counts.delete_many({})
        except Exception as exc:  # pragma: no cover - defensive
            log.error(
                "Failed to clear counts collection before rebuild: %s",
                exc,
                exc_info=True,
            )
            return

        try:
            cursor = self._query_log.find(
                {},
                {
                    "client_ip": 1,
                    "name": 1,
                    "qtype": 1,
                    "upstream_id": 1,
                    "rcode": 1,
                    "status": 1,
                    "error": 1,
                    "result_json": 1,
                },
            )
            for doc in cursor:
                client_ip = doc.get("client_ip")
                name = doc.get("name")
                qtype = doc.get("qtype")
                upstream_id = doc.get("upstream_id")
                rcode = doc.get("rcode")
                status = doc.get("status")
                result_json = doc.get("result_json")

                domain = _normalize_domain(name or "")
                parts = domain.split(".") if domain else []
                base = ".".join(parts[-2:]) if len(parts) >= 2 else domain

                # Total queries
                self.increment_count("totals", "total_queries", 1)

                # Cache hits/misses/cache_null (best-effort approximation).
                if status == "cache_hit":
                    self.increment_count("totals", "cache_hits", 1)
                elif status in ("deny_pre", "override_pre"):
                    self.increment_count("totals", "cache_" + str(status), 1)
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
                "Counts collection is empty but query_log has documents; rebuilding counts from query_log",
            )

        self.rebuild_counts_from_query_log(logger_obj=log)
