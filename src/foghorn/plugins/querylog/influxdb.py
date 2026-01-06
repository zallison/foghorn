from __future__ import annotations

"""InfluxDB logging-only implementation of the BaseStatsStore interface.

Inputs:
  - Constructed via a configuration mapping passed through StatsStoreBackendConfig
    with backend-specific fields such as write_url, org, bucket, precision,
    and token.

Outputs:
  - Concrete backend instance that can be used to stream query-log entries to
    an InfluxDB-compatible line-protocol HTTP endpoint. This backend is
    intentionally *write-only* for query logs and does not implement statistics
    aggregation or read APIs.

Notes:
  - This backend is meant for side-channel logging/streaming of DNS query-log
    events (for example, into an external metrics pipeline). It is *not*
    suitable as the primary statistics backend for StatsCollector. Methods
    other than insert_query_log, health_check, and close are left
    unimplemented so that NotImplementedError continues to be raised if they
    are called.
"""

import json
import logging
import time
from typing import Any, Dict, Optional

import requests

from .base import BaseStatsStore

logger = logging.getLogger(__name__)


def _escape_tag(value: str) -> str:
    """Escape a tag value for InfluxDB line protocol.

    Inputs:
        value: Raw tag value string.

    Outputs:
        Escaped tag value with commas, spaces, and equals signs backslash-escaped.
    """

    return (
        value.replace("\\", "\\\\")
        .replace(",", "\\,")
        .replace(" ", "\\ ")
        .replace("=", "\\=")
    )


def _escape_field_string(value: str) -> str:
    """Escape a string field value for InfluxDB line protocol.

    Inputs:
        value: Raw field value string.

    Outputs:
        Value wrapped in double quotes with internal quotes and backslashes escaped.
    """

    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _format_line_protocol(
    measurement: str,
    tags: Dict[str, Optional[str]],
    fields: Dict[str, Any],
    ts: float,
) -> str:
    """Format a single InfluxDB line-protocol entry.

    Inputs:
        measurement: Measurement name.
        tags: Mapping of tag keys to optional values; None values are skipped.
        fields: Mapping of field keys to values (ints, floats, bools, or strings).
        ts: Unix timestamp in seconds.

    Outputs:
        Single line-protocol string including timestamp in nanoseconds.
    """

    tag_parts = []
    for k, v in tags.items():
        if v is None:
            continue
        tag_parts.append(f"{_escape_tag(str(k))}={_escape_tag(str(v))}")
    tag_section = "" if not tag_parts else "," + ",".join(tag_parts)

    field_parts = []
    for k, v in fields.items():
        key = _escape_tag(str(k))
        if isinstance(v, bool):
            field_parts.append(f"{key}={'true' if v else 'false'}")
        elif isinstance(v, int):
            field_parts.append(f"{key}={v}i")
        elif isinstance(v, float):
            field_parts.append(f"{key}={v}")
        elif v is None:
            continue
        else:
            field_parts.append(f"{key}={_escape_field_string(str(v))}")

    if not field_parts:
        field_parts.append("count=1i")

    ns_ts = int(ts * 1_000_000_000)
    line = (
        f"{_escape_tag(measurement)}{tag_section} " f"{','.join(field_parts)} {ns_ts}"
    )
    return line


class InfluxLogging(BaseStatsStore):
    """InfluxDB-backed logging-only backend for DNS query logs.

    # Aliases used by the stats backend registry.
    aliases = ("influx", "influxdb")

    Inputs (constructor):
        write_url: HTTP endpoint for InfluxDB line-protocol writes
            (for example, "http://127.0.0.1:8086/api/v2/write").
        org: Optional organization identifier (v2); appended as a query
            parameter when provided.
        bucket: Optional bucket/database name; appended as a query parameter
            when provided.
        precision: Timestamp precision for writes (default "ns").
        token: Optional authentication token; when provided, an Authorization
            header "Token <token>" is added.
        timeout: Request timeout in seconds (default 2.0).
        session_kwargs: Optional mapping of extra keyword arguments passed to
            requests.Session().

    Outputs:
        Initialized InfluxLogging instance ready to accept query-log entries.
    """

    def __init__(
        self,
        write_url: str,
        org: Optional[str] = None,
        bucket: Optional[str] = None,
        precision: str = "ns",
        token: Optional[str] = None,
        timeout: float = 2.0,
        session_kwargs: Optional[Dict[str, Any]] = None,
        async_logging: bool = True,
        **_: Any,
    ) -> None:
        self._write_url = str(write_url)
        self._org = str(org) if org is not None else None
        self._bucket = str(bucket) if bucket is not None else None
        self._precision = str(precision or "ns")
        self._timeout = float(timeout)

        # Logging behaviour: default to async for remote HTTP logging, but
        # allow callers to disable it via config.
        self._async_logging = bool(async_logging)

        self._session = requests.Session(**(session_kwargs or {}))
        self._params: Dict[str, str] = {"precision": self._precision}
        if self._org is not None:
            self._params["org"] = self._org
        if self._bucket is not None:
            self._params["bucket"] = self._bucket

        headers: Dict[str, str] = {}
        if token is not None:
            headers["Authorization"] = f"Token {token}"
        self._headers = headers

        # Mark backend as healthy; health_check can be refined after writes.
        self._healthy = True

        # Best-effort startup marker using a lightweight point so that external
        # systems can detect when logging begins.
        try:
            line = _format_line_protocol(
                measurement="foghorn_query_log_meta",
                tags={},
                fields={
                    "event": "log_start",
                    "version": 1,
                    "ts": float(time.time()),
                },
                ts=time.time(),
            )
            self._session.post(
                self._write_url,
                params=self._params,
                data=line.encode("utf-8"),
                headers=self._headers,
                timeout=self._timeout,
            )
        except Exception:  # pragma: no cover - environment specific
            logger.exception("Failed to publish InfluxDB query_log start marker")

    # ------------------------------------------------------------------
    # Health and lifecycle
    # ------------------------------------------------------------------
    def health_check(self) -> bool:  # type: ignore[override]
        """Return True when the InfluxDB logging backend is considered usable.

        Inputs:
            None.

        Outputs:
            bool: Current health flag; may be set False after repeated failures.
        """

        return bool(self._healthy)

    def close(self) -> None:  # type: ignore[override]
        """Close the underlying HTTP session.

        Inputs:
            None.

        Outputs:
            None; subsequent writes will fail or be dropped.
        """

        try:
            session = getattr(self, "_session", None)
            if session is not None:
                session.close()
        except Exception:  # pragma: no cover - defensive
            logger.exception("Error while closing InfluxLogging session")
        finally:
            self._healthy = False

    # ------------------------------------------------------------------
    # Query-log API (write-only)
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
    ) -> None:  # type: ignore[override]
        """Enqueue or synchronously write a DNS query-log entry.

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
            None; writes directly via the InfluxDB HTTP session.
        """

        # This backend is write-only and relatively low volume, so use a
        # synchronous implementation here instead of the BaseStatsStore
        # background queue. This keeps behavior simple and deterministic for
        # callers and tests while still allowing other backends to use the
        # shared async worker.
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
    ) -> None:  # type: ignore[override]
        """Write a DNS query-log entry to InfluxDB using line protocol.

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
            None; best-effort HTTP write to the configured InfluxDB endpoint.
        """

        if not self._healthy:
            return

        # Parse result_json to derive lightweight fields when possible.
        result_obj: Optional[Dict[str, Any]]
        try:
            parsed = json.loads(result_json) if result_json else None
            result_obj = parsed if isinstance(parsed, dict) else None
        except Exception:
            result_obj = None

        fields: Dict[str, Any] = {
            "count": 1,
            "ts": float(ts),
            "name": name,
            "error": error,
            "first": first,
        }

        if result_obj is not None:
            dnssec_status = result_obj.get("dnssec_status")
            if dnssec_status:
                fields["dnssec_status"] = str(dnssec_status)

        tags = {
            "client_ip": client_ip,
            "qtype": qtype,
            "upstream_id": upstream_id,
            "rcode": rcode,
            "status": status,
        }

        line = _format_line_protocol(
            measurement="foghorn_query_log",
            tags=tags,
            fields=fields,
            ts=float(ts),
        )

        try:
            resp = self._session.post(
                self._write_url,
                params=self._params,
                data=line.encode("utf-8"),
                headers=self._headers,
                timeout=self._timeout,
            )
            if resp.status_code >= 400:
                logger.warning(
                    "InfluxLogging write failed with status %s: %s",
                    resp.status_code,
                    resp.text,
                )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error(
                "Failed to write query_log to InfluxDB: %s", exc, exc_info=True
            )
            self._healthy = False
