from __future__ import annotations

"""JSON file logging-only implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via a configuration mapping passed through StatsStoreBackendConfig
    with a backend-specific field ``file_path`` indicating where to append
    JSON-formatted query-log entries.

Outputs:
  - Concrete backend instance that can be used to write query-log entries as
    single-line JSON records to a local file. This backend is intentionally
    *write-only* for query logs and does not implement statistics aggregation or
    read APIs.

Notes:
  - This backend is meant for side-channel logging/archival of DNS query-log
    events (for example, for later offline analysis). It is *not* suitable as
    the primary statistics backend for StatsCollector. Methods other than
    insert_query_log, health_check, and close are left unimplemented so that
    NotImplementedError continues to be raised if they are called.
"""

import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from foghorn.stats import FOGHORN_VERSION

from .base import BaseStatsStore

logger = logging.getLogger(__name__)


class JsonLogging(BaseStatsStore):
    """JSON-backed logging-only backend for DNS query logs.

    Inputs (constructor):
        file_path: Path to the JSON log file. Parent directories are created
            if they do not already exist.
        async_logging: Accepted for API compatibility with other backends.
            insert_query_log dispatch is handled by BaseStatsStore queue logic.
        max_logging_queue: Best-effort queue size hint consumed by the shared
            BaseStatsStore worker implementation.
        retention_max_records: Optional max-record retention limit. When set,
            compaction keeps only the newest N query-log records.
        retention_days: Optional day-window retention limit. When set,
            compaction drops records older than the computed cutoff.
        retention_max_bytes: Optional byte-cap retention limit. When set,
            compaction drops oldest records until retained bytes are within cap.
        retention_prune_interval_seconds: Optional minimum seconds between
            compaction passes.
        retention_prune_every_n_inserts: Optional insertion cadence for
            compaction passes.

    Outputs:
        Initialized JsonLogging instance ready to append JSON lines to the
        configured file.
    """

    # Aliases used by the stats backend registry.
    aliases = ("json", "file")

    def __init__(
        self,
        file_path: str,
        async_logging: bool = False,
        max_logging_queue: int = 4096,
        retention_max_records: Optional[int] = None,
        retention_days: Optional[float] = None,
        retention_max_bytes: Optional[int] = None,
        retention_prune_interval_seconds: Optional[float] = None,
        retention_prune_every_n_inserts: Optional[int] = None,
        **_: Any,
    ) -> None:
        self._healthy = False
        self._io_lock = threading.RLock()

        # Normalize and create the target directory if needed.
        path = os.path.abspath(os.path.expanduser(str(file_path)))
        dir_path = os.path.dirname(path)
        # pragma: nocover - os.path.abspath() yields a parent directory on supported paths.
        if dir_path:  # pragma: no branch
            try:
                os.makedirs(dir_path, exist_ok=True)
            except Exception:  # pragma: no cover - defensive
                logger.exception("Failed to create directory for JsonLogging backend")
                self._file_path = path
                self._fh = None
                return

        self._file_path = path
        try:
            # Open the file in append mode with UTF-8 encoding; callers are
            # expected to treat it as an append-only log.
            self._fh = open(self._file_path, "a", encoding="utf-8")
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to open JSON query_log file for appending")
            self._fh = None
            return

        # Configure logging behaviour for BaseStatsStore insert_query_log.
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

        # Emit a header line that marks the start of a logging session. Downstream
        # tools can treat this as a lightweight metadata record preceding the
        # JSON-lines stream of per-query entries.
        try:
            ts = datetime.now(timezone.utc).isoformat()
            try:
                hostname = socket.gethostname()
            except Exception:  # pragma: no cover - defensive
                hostname = "unknown-host"

            header = {
                "log_start": ts,
                "version": f"v{FOGHORN_VERSION}",
                "hostname": hostname,
            }
            self._fh.write(json.dumps(header, separators=(",", ":")) + "\n")
            self._fh.flush()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to write JsonLogging start header line")

        self._healthy = True

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:  # type: ignore[override]
        """Return True when the JSON logging backend is considered usable.

        Inputs:
            None.

        Outputs:
            bool: True when the file handle was opened successfully and has
            not been closed due to an error or explicit close().
        """

        return bool(self._healthy and getattr(self, "_fh", None) is not None)

    def close(self) -> None:  # type: ignore[override]
        """Close the underlying file handle.

        Inputs:
            None.

        Outputs:
            None; subsequent writes will be dropped and health_check() returns
            False.
        """

        try:
            with self._io_lock:
                fh = getattr(self, "_fh", None)
                if fh is not None:
                    try:
                        fh.flush()
                    except Exception:  # pragma: no cover - defensive
                        logger.exception("Failed to flush JsonLogging file on close")
                    try:
                        fh.close()
                    except Exception:  # pragma: no cover - defensive
                        logger.exception("Failed to close JsonLogging file handle")
                self._fh = None
        finally:
            self._healthy = False

    # ------------------------------------------------------------------
    # Query-log API (write-only)
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
    ) -> None:  # type: ignore[override]
        """Append a DNS query-log entry as a single-line JSON record.

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
            result_json: JSON-encoded result payload from the resolver.

        Outputs:
            None; best-effort append to the configured log file. Append/rewrite
            I/O failures are logged and mark the backend unhealthy.
        """

        if not self.health_check():
            return

        # Base payload mirrors the MQTT logging backend structure so that
        # downstream consumers can reuse the same schema and adds the local
        # hostname for multi-node correlation.
        try:
            hostname = socket.gethostname()
        except Exception:  # pragma: no cover - defensive
            hostname = "unknown-host"

        payload: Dict[str, Any] = {
            "ts": float(ts),
            "client_ip": client_ip,
            "name": name,
            "qtype": qtype,
            "upstream_id": upstream_id,
            "rcode": rcode,
            "status": status,
            "error": error,
            "first": first,
            "hostname": hostname,
        }

        # Include parsed result when it is a JSON object; ignore malformed
        # payloads defensively.
        try:
            parsed = json.loads(result_json) if result_json else None
        except Exception:
            parsed = None
        if isinstance(parsed, dict):
            payload["result"] = parsed

        try:
            line = json.dumps(payload, separators=(",", ":"))
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to encode JsonLogging payload as JSON")
            return

        try:
            with self._io_lock:
                fh = self._fh
                # pragma: nocover - concurrent close() can clear _fh after health_check().
                if fh is None:  # pragma: no cover - defensive race
                    return
                fh.write(line + "\n")
                fh.flush()
                self._apply_query_log_retention_locked()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to append JSON query_log entry to file")
            self._healthy = False

    def _apply_query_log_retention_locked(self) -> None:
        """Brief: Enforce configured retention by compacting the JSON log file.

        Inputs:
            None. Caller must hold ``self._io_lock``.

        Outputs:
            None; rewrites the JSONL file when compaction changes the retained
            record set.
        """

        cutoff_ts = BaseStatsStore._retention_cutoff_ts(
            self._query_log_retention_days,
            now_ts=time.time(),
        )
        max_records = self._query_log_retention_max_records
        max_bytes = self._query_log_retention_max_bytes
        if cutoff_ts is None and max_records is None and max_bytes is None:
            return

        if not self._should_run_query_log_retention_prune(now_ts=time.time()):
            return

        fh = getattr(self, "_fh", None)
        # pragma: nocover - _fh may be cleared if retention runs during/after close().
        if fh is None:  # pragma: no cover - defensive race
            return

        try:
            fh.flush()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to flush JsonLogging file before retention prune")
            return

        try:
            with open(self._file_path, "r", encoding="utf-8") as read_fh:
                raw_lines = read_fh.read().splitlines()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to read JsonLogging file for retention prune")
            return

        if not raw_lines:
            return

        header_line: Optional[str] = None
        record_lines = raw_lines
        try:
            first_obj = json.loads(raw_lines[0])
            if isinstance(first_obj, dict) and "log_start" in first_obj:
                header_line = raw_lines[0]
                record_lines = raw_lines[1:]
        except Exception:
            header_line = None
            record_lines = raw_lines

        filtered_records: list[str] = []
        for raw in record_lines:
            if not raw:
                continue
            if cutoff_ts is not None:
                try:
                    obj = json.loads(raw)
                    ts_val = obj.get("ts") if isinstance(obj, dict) else None
                    if ts_val is not None and float(ts_val) < float(cutoff_ts):
                        continue
                except Exception:
                    # Keep malformed lines so retention compaction does not
                    # silently discard data unexpectedly.
                    pass
            filtered_records.append(raw)

        if max_records is not None and len(filtered_records) > int(max_records):
            filtered_records = filtered_records[-int(max_records) :]

        if max_bytes is not None:
            byte_cap = int(max_bytes)

            def _line_bytes(line: str) -> int:
                return len(line.encode("utf-8")) + 1

            header_bytes = _line_bytes(header_line) if header_line is not None else 0
            retained_bytes = header_bytes + sum(
                _line_bytes(item) for item in filtered_records
            )
            while filtered_records and retained_bytes > byte_cap:
                removed = filtered_records.pop(0)
                retained_bytes -= _line_bytes(removed)

        rewritten_lines: list[str] = []
        if header_line is not None:
            rewritten_lines.append(header_line)
        rewritten_lines.extend(filtered_records)

        if rewritten_lines == raw_lines:
            return

        try:
            fh.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to close JsonLogging file before rewrite")

        try:
            with open(self._file_path, "w", encoding="utf-8") as out_fh:
                for item in rewritten_lines:
                    out_fh.write(item + "\n")
            self._fh = open(self._file_path, "a", encoding="utf-8")
        except Exception:  # pragma: no cover - defensive
            logger.exception(
                "Failed to rewrite JsonLogging file during retention prune"
            )
            self._healthy = False
