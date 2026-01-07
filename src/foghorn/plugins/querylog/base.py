"""Abstract base classes for persistent statistics and query-log backends.

This module defines:

- StatsStoreBackendConfig: Pydantic model describing a single backend
  configuration entry (backend identifier plus backend-specific config).
- BaseStatsStore: Abstract interface mirroring the public API of
  StatsSQLiteStore for use by multiple storage backends (SQLite, MariaDB/MySQL,
  MongoDB, Redis, etc.).

Concrete backends must subclass BaseStatsStore and implement all
methods. The semantics of methods are defined to match the existing
StatsSQLiteStore behavior so callers (StatsCollector, webserver, helper
scripts) can remain backend-agnostic.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Dict, Optional, Tuple

from pydantic import BaseModel, Field


class StatsStoreBackendConfig(BaseModel):
    """Brief: Typed configuration model for a single statistics/query-log backend.

    Inputs (constructor fields):
      - name: Optional logical instance name used to distinguish multiple
        backends of the same type (for example, "primary", "analytics"). When
        omitted, a default name is derived from the backend alias.
      - backend: String identifier for the backend implementation. This may be
        a short alias (for example, "sqlite", "mysql", "redis", "mongo") or a
        fully-qualified dotted import path to a concrete backend class.
      - config: Free-form mapping of backend-specific configuration options.
        Concrete backends are responsible for validating and using these
        values (for example, db_path or batch_writes for SQLite).

    Outputs:
      - StatsStoreBackendConfig instance with normalized types.
    """

    name: Optional[str] = Field(
        default=None,
        description=(
            "Logical instance name used for selection when multiple backends "
            "of the same type are configured."
        ),
    )
    backend: str = Field(..., description="Backend alias or dotted import path")
    config: Dict[str, Any] = Field(
        default_factory=dict,
        description="Backend-specific configuration options",
    )

    class Config:
        extra = "allow"


class BaseStatsStore:
    """Brief: Base class for persistent statistics and query-log backends.

    Implementations are responsible for:
      - Maintaining aggregate counters in a logical "counts" store.
      - Providing an append-only query log with filter and aggregation helpers.
      - Exposing lightweight health checks and lifecycle management.

    Inputs (constructor):
      - **config: Arbitrary configuration mapping specific to the backend.
        Callers typically construct a concrete backend from a
        StatsStoreBackendConfig instance, but this base class does not impose
        a fixed schema.

    Outputs:
      - Initialized backend instance when implemented by a subclass.

    Notes:
      - All public methods intentionally mirror the StatsSQLiteStore API in
        src/foghorn/stats.py so that existing callers remain compatible when
        the concrete backend is swapped.
      - The base class provides a lightweight background worker thread and
        in-memory queue for high-volume write paths (increment_count and
        insert_query_log). Subclasses should implement the private
        ``_increment_count`` and ``_insert_query_log`` helpers; callers keep
        using the public methods and need not be aware of the queue.
    """

    def __init__(self, **config: object) -> None:  # pragma: no cover - interface only
        """Brief: Initialize the backend with a generic configuration mapping.

        Inputs:
          - **config: Backend-specific configuration options.

        Outputs:
          - None in the base class; subclasses should perform any setup
            required to become usable.
        """

        raise NotImplementedError("BaseStatsStore.__init__ must be implemented")

    # ------------------------------------------------------------------
    # Internal async worker for write-heavy operations
    # ------------------------------------------------------------------
    def _ensure_worker(self) -> None:
        """Brief: Start the background worker thread on first use.

        Inputs:
          - None.

        Outputs:
          - None; ensures ``self._op_queue`` and the worker thread exist.
        """

        if getattr(self, "_op_queue", None) is not None:
            return

        q: "queue.Queue[tuple[str, tuple[Any, ...], dict[str, Any]]]" = queue.Queue()
        self._op_queue = q

        worker = threading.Thread(
            target=self._worker_loop,
            name=f"{self.__class__.__name__}Worker",
            daemon=True,
        )
        self._op_worker = worker
        worker.start()

    def _worker_loop(self) -> None:
        """Brief: Background loop that consumes and executes queued operations.

        Inputs:
          - None; runs until a sentinel (empty op_name) is received or an
            unrecoverable queue error occurs.

        Outputs:
          - None; logs and continues on per-operation failures.
        """

        log = logging.getLogger(__name__)
        q = getattr(self, "_op_queue", None)
        if q is None:
            return

        while True:
            try:
                op_name, args, kwargs = q.get()
            except Exception:
                # Unexpected queue error; bail out to avoid a tight error loop.
                break

            try:
                if not op_name:
                    # Sentinel received: stop the worker.
                    break

                handler = getattr(self, f"_{op_name}", None)
                if callable(handler):
                    handler(*args, **kwargs)
                else:
                    log.debug("BaseStatsStore: unknown op_name %r discarded", op_name)
            except Exception:
                # Ensure one failing backend or handler does not kill logging.
                log.exception("BaseStatsStore worker failed while handling %r", op_name)
            finally:
                try:
                    q.task_done()
                except Exception:
                    # Defensive: task_done must not raise.
                    pass

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:  # pragma: no cover - interface only
        """Brief: Return True when the underlying backend is usable.

        Inputs:
          - None.

        Outputs:
          - bool: True when a trivial health probe succeeds, else False.
        """

        raise NotImplementedError("health_check() must be implemented by a subclass")

    def close(self) -> None:  # pragma: no cover - interface only
        """Brief: Close the backend and release any associated resources.

        Inputs:
          - None.

        Outputs:
          - None.
        """

        raise NotImplementedError("close() must be implemented by a subclass")

    # ------------------------------------------------------------------
    # Counter API: aggregate counts table
    # ------------------------------------------------------------------
    def increment_count(self, scope: str, key: str, delta: int = 1) -> None:
        """Brief: Enqueue an aggregate counter increment for async processing.

        Inputs:
          - scope: Logical scope name (for example, "totals", "domains").
          - key: Counter key within the scope.
          - delta: Increment value (may be negative for decrements).

        Outputs:
          - None; returns after queuing the operation. The worker thread will
            later call ``_increment_count`` on this instance. When the queue
            cannot be used, falls back to calling ``_increment_count``
            synchronously when available.
        """

        try:
            self._ensure_worker()
            self._op_queue.put(  # type: ignore[attr-defined]
                ("increment_count", (scope, key, delta), {})
            )
        except Exception:
            handler = getattr(self, "_increment_count", None)
            if callable(handler):
                handler(scope, key, delta)
            else:
                raise NotImplementedError(
                    "_increment_count() must be implemented by a subclass"
                )

    def set_count(
        self, scope: str, key: str, value: int
    ) -> None:  # pragma: no cover - interface only
        """Brief: Set an aggregate counter to an exact value in the counts store.

        Inputs:
          - scope: Logical scope name.
          - key: Counter key within the scope.
          - value: New integer value to assign.

        Outputs:
          - None.
        """

        raise NotImplementedError("set_count() must be implemented by a subclass")

    def has_counts(self) -> bool:  # pragma: no cover - interface only
        """Brief: Return True if the counts store contains at least one row.

        Inputs:
          - None.

        Outputs:
          - bool: True when counts has rows, False otherwise.
        """

        raise NotImplementedError("has_counts() must be implemented by a subclass")

    def export_counts(
        self,
    ) -> Dict[str, Dict[str, int]]:  # pragma: no cover - interface only
        """Brief: Export all aggregate counters from the counts store.

        Inputs:
          - None.

        Outputs:
          - Dict[str, Dict[str, int]] mapping scope -> {key -> value}.
        """

        raise NotImplementedError("export_counts() must be implemented by a subclass")

    def rebuild_counts_from_query_log(
        self,
        logger_obj: Optional[logging.Logger] = None,
    ) -> None:  # pragma: no cover - interface only
        """Brief: Rebuild counts by aggregating over all rows in the query log.

        Inputs:
          - logger_obj: Optional logger to use for warnings/errors.

        Outputs:
          - None.

        Notes:
          - Implementations should clear existing counts before recomputing to
            ensure a consistent view derived solely from the current query log.
        """

        raise NotImplementedError(
            "rebuild_counts_from_query_log() must be implemented by a subclass"
        )

    def rebuild_counts_if_needed(
        self,
        force_rebuild: bool = False,
        logger_obj: Optional[logging.Logger] = None,
    ) -> None:  # pragma: no cover - interface only
        """Brief: Conditionally rebuild counts based on backend state and flags.

        Inputs:
          - force_rebuild: When True, always rebuild counts when the query log
            has rows, even if counts is already populated.
          - logger_obj: Optional logger used for informational and warning
            messages.

        Outputs:
          - None.
        """

        raise NotImplementedError(
            "rebuild_counts_if_needed() must be implemented by a subclass"
        )

    # ------------------------------------------------------------------
    # Query-log API: append-only DNS query log
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
        """Brief: Enqueue a DNS query entry for async logging.

        Inputs:
          - ts: Unix timestamp (float seconds) with at least millisecond
            precision.
          - client_ip: Client IP address.
          - name: Normalized query name.
          - qtype: Query type string (for example, "A").
          - upstream_id: Optional upstream identifier (for example,
            "8.8.8.8:53").
          - rcode: Optional DNS response code ("NOERROR", "NXDOMAIN", etc.).
          - status: Optional high-level status ("ok", "timeout", "cache_hit", ...).
          - error: Optional error message summary.
          - first: Optional first answer record representation.
          - result_json: Structured result payload as JSON text.

        Outputs:
          - None; returns after queuing the operation. The worker thread will
            later call ``_insert_query_log`` on this instance. When the queue
            cannot be used, falls back to calling ``_insert_query_log``
            synchronously when available.
        """

        try:
            self._ensure_worker()
            self._op_queue.put(  # type: ignore[attr-defined]
                (
                    "insert_query_log",
                    (
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
                    ),
                    {},
                )
            )
        except Exception:
            handler = getattr(self, "_insert_query_log", None)
            if callable(handler):
                handler(
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
                raise NotImplementedError(
                    "_insert_query_log() must be implemented by a subclass"
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
    ) -> Dict[str, Any]:  # pragma: no cover - interface only
        """Brief: Select query-log rows with basic filtering and pagination.

        Inputs:
          - client_ip: Optional client IP filter (exact match).
          - qtype: Optional qtype filter (typically case-insensitive).
          - qname: Optional qname filter (typically normalized before storage).
          - rcode: Optional rcode filter (case-insensitive).
          - start_ts: Optional inclusive start timestamp (Unix seconds).
          - end_ts: Optional exclusive end timestamp (Unix seconds).
          - page: 1-based page number.
          - page_size: Max rows per page.

        Outputs:
          - Dict with keys at least:
            - total: total matching row count (int).
            - page: current page (int).
            - page_size: page size (int).
            - total_pages: total pages (int).
            - items: list[dict] of query-log row representations.
        """

        raise NotImplementedError(
            "select_query_log() must be implemented by a subclass"
        )

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
    ) -> Dict[str, Any]:  # pragma: no cover - interface only
        """Brief: Aggregate query-log counts into fixed time buckets.

        Inputs:
          - start_ts: Inclusive start timestamp (Unix seconds).
          - end_ts: Exclusive end timestamp (Unix seconds).
          - interval_seconds: Bucket size in seconds (must be > 0).
          - client_ip: Optional client IP filter (exact match).
          - qtype: Optional qtype filter (case-insensitive).
          - qname: Optional qname filter (case-insensitive).
          - rcode: Optional rcode filter (case-insensitive).
          - group_by: Optional grouping dimension (for example,
            "client_ip", "qtype", "qname", "rcode").

        Outputs:
          - Dict with keys at least:
            - start_ts: float
            - end_ts: float
            - interval_seconds: int
            - items: list of bucket results (dense or sparse depending on
              group_by semantics).
        """

        raise NotImplementedError(
            "aggregate_query_log_counts() must be implemented by a subclass"
        )

    def has_query_log(self) -> bool:  # pragma: no cover - interface only
        """Brief: Return True if the query-log store contains at least one row.

        Inputs:
          - None.

        Outputs:
          - bool: True when query_log has rows, False otherwise.
        """

        raise NotImplementedError("has_query_log() must be implemented by a subclass")

    # ------------------------------------------------------------------
    # Optional shared helpers for backends
    # ------------------------------------------------------------------
    @staticmethod
    def _normalize_page_args(
        page: object,
        page_size: object,
        *,
        default_page: int = 1,
        default_page_size: int = 100,
        max_page_size: int = 1000,
    ) -> Tuple[int, int]:
        """Brief: Normalize pagination arguments to sane integer bounds.

        Inputs:
          - page: Raw page value (int-like or other).
          - page_size: Raw page_size value (int-like or other).
          - default_page: Fallback page when parsing fails.
          - default_page_size: Fallback page_size when parsing fails.
          - max_page_size: Upper bound for page_size.

        Outputs:
          - (page_i, page_size_i): Normalized positive integers.
        """

        try:
            page_i = int(page)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            page_i = default_page
        if page_i < 1:
            page_i = default_page

        try:
            page_size_i = int(page_size)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            page_size_i = default_page_size
        if page_size_i < 1:
            page_size_i = default_page_size
        if page_size_i > max_page_size:
            page_size_i = max_page_size

        return page_i, page_size_i

    @staticmethod
    def _normalize_interval_args(
        start_ts: object,
        end_ts: object,
        interval_seconds: object,
    ) -> Tuple[float, float, int]:
        """Brief: Normalize time-window and interval arguments for aggregations.

        Inputs:
          - start_ts: Inclusive start timestamp (float-like).
          - end_ts: Exclusive end timestamp (float-like).
          - interval_seconds: Bucket size in seconds (int-like).

        Outputs:
          - (start_f, end_f, interval_i): Normalized window and interval.
        """

        try:
            start_f = float(start_ts)  # type: ignore[arg-type]
            end_f = float(end_ts)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            start_f = 0.0
            end_f = 0.0

        try:
            interval_i = int(interval_seconds)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            interval_i = 0

        return start_f, end_f, interval_i
