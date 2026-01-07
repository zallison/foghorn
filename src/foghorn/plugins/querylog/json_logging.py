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
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .base import BaseStatsStore
from foghorn.stats import FOGHORN_VERSION

logger = logging.getLogger(__name__)


class JsonLogging(BaseStatsStore):
    """JSON-backed logging-only backend for DNS query logs.

    Inputs (constructor):
        file_path: Path to the JSON log file. Parent directories are created
            if they do not already exist.
        async_logging: When True, use the BaseStatsStore background worker
            queue for insert_query_log calls; when False (default), writes are
            performed synchronously in the calling thread.

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
        **_: Any,
    ) -> None:
        self._healthy = False

        # Normalize and create the target directory if needed.
        path = os.path.abspath(os.path.expanduser(str(file_path)))
        dir_path = os.path.dirname(path)
        if dir_path:
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
            None; best-effort append to the configured log file. Failures are
            logged and cause the backend to be marked unhealthy.
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
            fh = self._fh
            fh.write(line + "\n")
            fh.flush()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Failed to append JSON query_log entry to file")
            self._healthy = False
