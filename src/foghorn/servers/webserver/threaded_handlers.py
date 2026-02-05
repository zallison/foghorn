"""Threaded HTTP request handler for Foghorn admin webserver fallback.

This module contains the _ThreadedAdminRequestHandler class that implements
the standard library http.server-based fallback HTTP server used when uvicorn
is not available or asyncio is disabled.
"""

from __future__ import annotations

import http.server
import json
import logging
import mimetypes
import os
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import yaml

from ...stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from ..udp_server import DNSUDPHandler
from . import admin_logic as _admin_logic
from . import config_persistence as _config_persistence
from .config_helpers import (
    _get_web_cfg,
    _get_redact_keys,
    _get_config_raw_text,
    _get_config_raw_json,
    _parse_utc_datetime,
    sanitize_config,
    _get_sanitized_config_yaml_cached,
)
from .http_helpers import (
    _json_safe,
    _schedule_sighup_after_config_save,
    resolve_www_root,
)
from .meta_helpers import _get_about_payload, FOGHORN_VERSION
from .rate_limit_helpers import _collect_rate_limit_stats
from .runtime import evaluate_readiness
from .stats_helpers import (
    _build_stats_payload_from_snapshot,
    _build_traffic_payload_from_snapshot,
    _get_stats_snapshot_cached,
    _trim_top_fields,
    _utc_now_iso,
    get_system_info,
)
from .logging_utils import RingBuffer

# Forward declaration - _AdminHTTPServer is defined in server_management
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .server_management import _AdminHTTPServer


logger = logging.getLogger("foghorn.webserver")


class _ThreadedAdminRequestHandler(http.server.BaseHTTPRequestHandler):
    """Brief: Minimal admin HTTP handler using the standard library.

    Inputs:
      - Inherits request/connection attributes from BaseHTTPRequestHandler.

    Outputs:
      - Serves /health, /stats, /stats/reset, /traffic, /config, /logs,
        virtual / and /index.html, and static files from html/ when present.
    """

    def _server(self) -> _AdminHTTPServer:
        """Brief: Return typed reference to the underlying HTTP server.

        Inputs: none
        Outputs: _AdminHTTPServer instance.
        """

        return self.server  # type: ignore[return-value]

    # ---------- Helpers ----------

    def _client_ip(
        self,
    ) -> str:  # pragma: no cover - currently unused helper for threaded admin path
        """Brief: Return best-effort client IP address.

        Inputs: none
        Outputs: str IP address.
        """

        addr = getattr(self, "client_address", None)
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return "0.0.0.0"

    def _web_cfg(
        self,
    ) -> Dict[
        str, Any
    ]:  # pragma: no cover - thin helper mirrored by FastAPI config handling
        """Brief: Return webserver config subsection from global config.

        Inputs: none
        Outputs: dict representing config['webserver'] or {}.
        """

        cfg = getattr(self._server(), "config", {}) or {}
        return _get_web_cfg(cfg)

    def _apply_cors_headers(
        self,
    ) -> None:  # pragma: no cover - threaded CORS behaviour mirrors FastAPI path
        """Brief: Apply CORS headers when webserver.cors.enabled is true.

        Inputs: none
        Outputs: None (mutates response headers).
        """

        web_cfg = self._web_cfg()
        cors_cfg = web_cfg.get("cors") or {}
        if not cors_cfg.get("enabled"):
            return

        origins = cors_cfg.get("allowlist") or ["*"]
        origin_hdr = self.headers.get("Origin") or ""
        if "*" in origins:
            allow_origin = "*"
        elif origin_hdr and origin_hdr in origins:
            allow_origin = origin_hdr
        else:
            allow_origin = origins[0]

        self.send_header("Access-Control-Allow-Origin", allow_origin)
        self.send_header("Access-Control-Allow-Credentials", "false")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")

    def _send_json(
        self,
        status_code: int,
        payload: Dict[str, Any],
        headers: Dict[str, str] | None = None,
    ) -> None:  # pragma: no cover - low-level HTTP I/O helper
        """Brief: Send JSON response with appropriate headers.

        Inputs:
          - status_code: HTTP status code
          - payload: Dict that will be converted to a JSON-safe structure.
          - headers: Optional mapping of extra HTTP headers to include.

        Outputs:
          - None
        """

        safe_payload = _json_safe(payload)
        body = json.dumps(safe_payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        if headers:
            for k, v in headers.items():
                self.send_header(str(k), str(v))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (
            BrokenPipeError
        ):  # pragma: no cover - requires simulating client disconnect
            logger.warning(
                "Client disconnected while sending JSON response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _send_text(
        self, status_code: int, text: str
    ) -> None:  # pragma: no cover - low-level HTTP I/O helper
        """Brief: Send plain-text response.

        Inputs:
          - status_code: HTTP status code
          - text: Response body
        Outputs:
          - None
        """

        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (
            BrokenPipeError
        ):  # pragma: no cover - requires simulating client disconnect
            logger.warning(
                "Client disconnected while sending text response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _send_yaml(
        self, status_code: int, text: str
    ) -> None:  # pragma: no cover - low-level HTTP I/O helper
        """Brief: Send YAML response with application/x-yaml content type.

        Inputs:
          - status_code: HTTP status code
          - text: YAML response body
        Outputs:
          - None
        """

        body = text.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/x-yaml; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (
            BrokenPipeError
        ):  # pragma: no cover - requires simulating client disconnect
            logger.warning(
                "Client disconnected while sending YAML response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _send_html(
        self, status_code: int, html_body: str
    ) -> None:  # pragma: no cover - low-level HTTP I/O helper
        """Brief: Send HTML response.

        Inputs:
          - status_code: HTTP status code
          - html_body: HTML document/string to send.
        Outputs:
          - None
        """

        body = html_body.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except (
            BrokenPipeError
        ):  # pragma: no cover - requires simulating client disconnect
            logger.warning(
                "Client disconnected while sending HTML response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _require_auth(
        self,
    ) -> (
        bool
    ):  # pragma: no cover - behaviour duplicated by FastAPI auth dependency tests
        """Brief: Enforce auth.mode=token semantics for protected endpoints.

        Inputs: none
        Outputs: bool indicating whether the request is authorized.
        """

        web_cfg = self._web_cfg()
        auth_cfg = web_cfg.get("auth") or {}
        mode = str(auth_cfg.get("mode", "none")).lower()
        if mode != "token":
            return True

        token = auth_cfg.get("token")
        if not token:
            self._send_json(
                500,
                {
                    "detail": "webserver.auth.token not configured",
                    "server_time": _utc_now_iso(),
                },
            )
            return False

        hdr = self.headers.get("Authorization") or ""
        api_key = self.headers.get("X-API-Key")
        if hdr.lower().startswith("bearer "):
            provided = hdr[7:].strip()
        else:
            provided = api_key.strip() if api_key else ""
        if not provided or provided != str(token):
            self._send_json(
                401,
                {"detail": "unauthorized", "server_time": _utc_now_iso()},
                headers={"WWW-Authenticate": "Bearer"},
            )
            return False
        return True

    # ---------- Endpoint handlers ----------

    def _handle_health(
        self,
    ) -> None:  # pragma: no cover - threaded /health mirrors FastAPI /health behaviour
        """Brief: Handle GET /health.

        Inputs: none
        Outputs: None (sends JSON response).
        """

        self._send_json(200, {"status": "ok", "server_time": _utc_now_iso()})

    def _handle_about(self) -> None:
        """Brief: Handle GET /about and /api/v1/about.

        Inputs: none

        Outputs:
          - None (sends JSON response with version/build info).
        """

        self._send_json(200, _get_about_payload())

    def _handle_ready(self) -> None:
        """Brief: Handle GET /ready and /api/v1/ready.

        Inputs: none

        Outputs:
          - None (sends JSON response with 200 when ready, else 503).
        """

        server = self._server()
        state = getattr(server, "runtime_state", None)
        ready_ok, not_ready, details = evaluate_readiness(
            stats=getattr(server, "stats", None),
            config=getattr(server, "config", None),
            runtime_state=state,
        )
        payload = {
            "server_time": _utc_now_iso(),
            "ready": ready_ok,
            "not_ready": not_ready,
            "details": details,
        }
        self._send_json(200 if ready_ok else 503, payload)

    def _handle_stats(
        self, params: Dict[str, list[str]]
    ) -> None:  # pragma: no cover - threaded /stats mirrors FastAPI /stats
        """Brief: Handle GET /stats.

        Inputs:
          - params: Query string parameters mapping
        Outputs:
          - None
        """

        if not self._require_auth():
            return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
        if collector is None:
            self._send_json(
                200,
                {"status": "disabled", "server_time": _utc_now_iso()},
            )
            return

        reset_raw = params.get("reset", ["false"])[0]
        reset = str(reset_raw).lower() in {"1", "true", "yes"}
        top_raw = params.get("top", ["10"])[0]
        try:
            top = int(top_raw)
        except (TypeError, ValueError):
            top = 10
        if top <= 0:
            top = 10
        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=reset)

        server = self._server()
        hostname = getattr(server, "hostname", "unknown-host")
        host_ip = getattr(server, "host_ip", "0.0.0.0")

        meta: Dict[str, Any] = {
            "timestamp": snap.created_at,
            "server_time": _utc_now_iso(),
            "hostname": hostname,
            "ip": host_ip,
            "version": FOGHORN_VERSION,
            "uptime": get_process_uptime_seconds(),
        }

        payload = _build_stats_payload_from_snapshot(
            snap,
            meta=meta,
            system_info=get_system_info(),
        )
        payload["created_at"] = snap.created_at

        limit = int(top) if isinstance(top, int) and top > 0 else 10
        _trim_top_fields(
            payload,
            limit,
            [
                "top_clients",
                "top_subdomains",
                "top_domains",
                "cache_hit_domains",
                "cache_miss_domains",
                "cache_hit_subdomains",
                "cache_miss_subdomains",
                "qtype_qnames",
                "rcode_domains",
                "rcode_subdomains",
            ],
        )

        self._send_json(200, payload)

    def _handle_stats_reset(
        self,
    ) -> None:  # pragma: no cover - threaded /stats/reset mirrors FastAPI endpoint
        """Brief: Handle POST /stats/reset.

        Inputs: none
        Outputs: None
        """

        if not self._require_auth():
            return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
        if collector is None:
            self._send_json(
                200,
                {"status": "disabled", "server_time": _utc_now_iso()},
            )
            return
        collector.snapshot(reset=True)
        self._send_json(200, {"status": "ok", "server_time": _utc_now_iso()})

    def _handle_traffic(
        self,
        params: Dict[str, list[str]],
    ) -> None:  # pragma: no cover - threaded /traffic mirrors FastAPI endpoint
        """Brief: Handle GET /traffic.

        Inputs: none
        Outputs: None
        """

        if not self._require_auth():
            return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
        if collector is None:
            self._send_json(
                200,
                {"status": "disabled", "server_time": _utc_now_iso()},
            )
            return

        top_raw = params.get("top", ["10"])[0]
        try:
            top = int(top_raw)
        except (TypeError, ValueError):
            top = 10
        if top <= 0:
            top = 10

        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=False)
        payload = _build_traffic_payload_from_snapshot(snap, meta=None, top=top)
        self._send_json(200, payload)

    #    @cached(cache=TTLCache(maxsize=1, ttl=2))
    def _handle_config(
        self,
    ) -> None:  # pragma: no cover - threaded /config mirrors FastAPI endpoint
        """Brief: Handle GET /config.

        Inputs: none
        Outputs: None (sends YAML body).
        """

        if not self._require_auth():
            return

        cfg = getattr(self._server(), "config", {}) or {}
        redact_keys = _get_redact_keys(cfg)
        cfg_path = getattr(self._server(), "config_path", None)
        body = _get_sanitized_config_yaml_cached(cfg, cfg_path, redact_keys)
        self._send_yaml(200, body)

    #    @cached(cache=TTLCache(maxsize=1, ttl=2))
    def _handle_config_json(
        self,
    ) -> None:  # pragma: no cover - threaded /config.json mirrors FastAPI endpoint
        """Brief: Handle GET /config.json (sanitized JSON config)."""

        if not self._require_auth():
            return

        cfg = getattr(self._server(), "config", {}) or {}
        redact_keys = _get_redact_keys(cfg)
        clean = sanitize_config(cfg, redact_keys=redact_keys)
        self._send_json(
            200,
            {"server_time": _utc_now_iso(), "config": clean},
        )

    #    @cached(cache=TTLCache(maxsize=1, ttl=2))
    def _handle_config_raw(
        self,
    ) -> None:  # pragma: no cover - threaded /config_raw mirrors FastAPI /config/raw
        """Brief: Handle GET /config_raw to return on-disk configuration as raw YAML.

        Inputs:
          - None (uses self.server.config_path to locate YAML file).

        Outputs:
          - YAML body containing the exact on-disk configuration text.
        """

        if not self._require_auth():
            return

        cfg_path = getattr(self._server(), "config_path", None)
        if not cfg_path:
            self._send_json(
                500,
                {"detail": "config_path not configured", "server_time": _utc_now_iso()},
            )
            return
        try:
            raw_text = _get_config_raw_text(cfg_path)
        except Exception as exc:  # pragma: no cover - environment-specific
            self._send_json(
                500,
                {
                    "detail": f"failed to read config from {cfg_path}: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        self._send_yaml(200, raw_text)

    #    @cached(cache=TTLCache(maxsize=1, ttl=2))
    def _handle_config_raw_json(
        self,
    ) -> None:  # pragma: no cover - threaded /config/raw.json mirrors FastAPI endpoint
        """Brief: Handle GET /config/raw.json to return on-disk configuration as JSON.

        Inputs:
          - None (uses self.server.config_path to locate YAML file).

        Outputs:
          - JSON with server_time, raw_yaml (exact file contents), and parsed config mapping.
        """

        if not self._require_auth():
            return

        cfg_path = getattr(self._server(), "config_path", None)
        if not cfg_path:
            self._send_json(
                500,
                {"detail": "config_path not configured", "server_time": _utc_now_iso()},
            )
            return
        try:
            raw = _get_config_raw_json(cfg_path)
        except Exception as exc:  # pragma: no cover - environment-specific
            self._send_json(
                500,
                {
                    "detail": f"failed to read config from {cfg_path}: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "config": raw["config"],
                "raw_yaml": raw["raw_yaml"],
            },
        )

    def _handle_query_log(self, params: Dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/query_log for the threaded fallback server.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response).
        """

        if not self._require_auth():
            return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
        store = getattr(collector, "_store", None) if collector is not None else None
        if store is None:
            self._send_json(
                200,
                {
                    "status": "disabled",
                    "server_time": _utc_now_iso(),
                    "items": [],
                    "total": 0,
                    "page": 1,
                    "page_size": 100,
                    "total_pages": 0,
                },
            )
            return

        client_ip = (params.get("client_ip") or [None])[0]
        qtype = (params.get("qtype") or [None])[0]
        qname = (params.get("qname") or [None])[0]
        rcode = (params.get("rcode") or [None])[0]
        start = (params.get("start") or [None])[0]
        end = (params.get("end") or [None])[0]

        page_raw = (params.get("page") or ["1"])[0]
        page_size_raw = (params.get("page_size") or ["100"])[0]

        try:
            page = int(page_raw)
        except Exception:
            page = 1
        if page < 1:
            page = 1

        try:
            ps = int(page_size_raw)
        except Exception:
            ps = 100
        if ps <= 0:
            ps = 100
        if ps > 1000:
            ps = 1000

        start_ts: float | None = None
        end_ts: float | None = None
        if start:
            try:
                start_ts = _parse_utc_datetime(str(start)).timestamp()
            except Exception:
                self._send_json(
                    400,
                    {"detail": "invalid start datetime", "server_time": _utc_now_iso()},
                )
                return
        if end:
            try:
                end_ts = _parse_utc_datetime(str(end)).timestamp()
            except Exception:
                self._send_json(
                    400,
                    {"detail": "invalid end datetime", "server_time": _utc_now_iso()},
                )
                return

        payload = _admin_logic.build_query_log_payload(
            store,
            client_ip=str(client_ip) if client_ip is not None else None,
            qtype=str(qtype) if qtype is not None else None,
            qname=str(qname) if qname is not None else None,
            rcode=str(rcode) if rcode is not None else None,
            start_ts=start_ts,
            end_ts=end_ts,
            page=page,
            page_size=ps,
        )
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_query_log_aggregate(self, params: Dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/query_log/aggregate for the threaded fallback server.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response).
        """

        if not self._require_auth():
            return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
        store = getattr(collector, "_store", None) if collector is not None else None
        if store is None:
            self._send_json(
                200, {"status": "disabled", "server_time": _utc_now_iso(), "items": []}
            )
            return

        interval_raw = (params.get("interval") or [""])[0]
        units = (params.get("interval_units") or [""])[0]
        start = (params.get("start") or [""])[0]
        end = (params.get("end") or [""])[0]

        if not start or not end:
            self._send_json(
                400,
                {"detail": "start and end are required", "server_time": _utc_now_iso()},
            )
            return

        try:
            start_dt = _parse_utc_datetime(start)
            end_dt = _parse_utc_datetime(end)
        except Exception:
            self._send_json(
                400,
                {"detail": "invalid start/end datetime", "server_time": _utc_now_iso()},
            )
            return

        try:
            interval_i = int(interval_raw)
        except Exception:
            interval_i = 0
        if interval_i <= 0:
            self._send_json(
                400,
                {
                    "detail": "interval must be a positive integer",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        unit_seconds = {
            "seconds": 1,
            "second": 1,
            "minutes": 60,
            "minute": 60,
            "hours": 3600,
            "hour": 3600,
            "days": 86400,
            "day": 86400,
        }.get(str(units or "").strip().lower())
        if not unit_seconds:
            self._send_json(
                400,
                {
                    "detail": "interval_units must be one of seconds, minutes, hours, days",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        interval_seconds = interval_i * int(unit_seconds)

        client_ip = (params.get("client_ip") or [None])[0]
        qtype = (params.get("qtype") or [None])[0]
        qname = (params.get("qname") or [None])[0]
        rcode = (params.get("rcode") or [None])[0]
        group_by = (params.get("group_by") or [None])[0]

        payload = _admin_logic.build_query_log_aggregate_payload(
            store,
            start_dt=start_dt,
            end_dt=end_dt,
            interval_seconds=int(interval_seconds),
            client_ip=str(client_ip) if client_ip is not None else None,
            qtype=str(qtype) if qtype is not None else None,
            qname=str(qname) if qname is not None else None,
            rcode=str(rcode) if rcode is not None else None,
            group_by=str(group_by) if group_by is not None else None,
        )
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_logs(
        self, params: Dict[str, list[str]]
    ) -> None:  # pragma: no cover - threaded /logs mirrors FastAPI endpoint
        """Brief: Handle GET /logs.

        Inputs:
          - params: Query parameters mapping
        Outputs:
          - None
        """

        if not self._require_auth():
            return

        buf: Optional[RingBuffer] = getattr(self._server(), "log_buffer", None)
        if buf is None:
            entries: list[Any] = []
        else:
            raw = params.get("limit", ["100"])[0]
            try:
                limit = max(0, int(raw))
            except ValueError:
                limit = 100
            entries = buf.snapshot(limit=limit)

        self._send_json(
            200,
            {"server_time": _utc_now_iso(), "entries": entries},
        )

    def _handle_upstream_status(
        self,
    ) -> (
        None
    ):  # pragma: no cover - threaded /api/v1/upstream_status mirrors FastAPI endpoint
        """Brief: Handle GET /api/v1/upstream_status.

        Inputs: none
        Outputs: None (sends JSON response with upstream health state).
        """

        if not self._require_auth():
            return

        cfg = getattr(self._server(), "config", {}) or {}
        payload = _admin_logic.build_upstream_status_payload(cfg)
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_config_save(
        self, body: Dict[str, Any]
    ) -> None:  # pragma: no cover - threaded /config/save mirrors FastAPI endpoint
        """Brief: Handle POST /config/save to persist config and schedule SIGHUP.

        Inputs:
          - body: Parsed JSON object representing full configuration mapping.

        Outputs:
          - JSON describing outcome (status, server_time, path, backed_up_to).
        """

        if not self._require_auth():
            return

        if not isinstance(body, dict):
            self._send_json(
                400,
                {
                    "detail": "request body must be a JSON object",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        cfg_path = getattr(self._server(), "config_path", None)
        if not cfg_path:
            self._send_json(
                500,
                {"detail": "config_path not configured", "server_time": _utc_now_iso()},
            )
            return

        cfg_path_abs = os.path.abspath(cfg_path)
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-")
        backup_path = f"{cfg_path_abs}-{ts}"
        upload_path = f"{cfg_path_abs}.new"

        try:
            # Validate request body
            raw_yaml = body.get("raw_yaml")
            if not isinstance(raw_yaml, str):
                self._send_json(
                    400,
                    {
                        "detail": "request body must include 'raw_yaml' string field",
                        "server_time": _utc_now_iso(),
                    },
                )
                return

            # Validate YAML contents
            res = yaml.safe_load(raw_yaml) or None

            if not res or res is None:
                self._send_json(
                    400,
                    {
                        "detail": f"failed to parse YAML for {cfg_path_abs}",
                        "server_time": _utc_now_iso(),
                        "error": "empty or invalid YAML document",
                    },
                )
                return

            _config_persistence.safe_write_raw_yaml(
                dst_path=cfg_path_abs,
                raw_yaml=raw_yaml,
                backup_path=backup_path,
                tmp_path=upload_path,
                strategy="replace",
            )
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            try:
                # Clean up after ourselves.
                if os.path.exists(upload_path):
                    os.remove(upload_path)
            except Exception:
                pass

            self._send_json(
                500,
                {
                    "detail": f" failed to update config: {exc}",
                    "server_time": _utc_now_iso(),
                    "stats": "error",
                    "error": str(exc),
                },
            )
            return

        # Schedule a SIGHUP for the main process after the updated configuration
        # has been safely written to disk. Use synchronous delivery here to
        # avoid delayed signals outliving the caller's context (e.g., tests
        # that monkeypatch os.kill).
        _schedule_sighup_after_config_save(delay_seconds=0.0)

        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "path": cfg_path_abs,
                "backed_up_to": backup_path,
            },
        )

    #    @cached(cache=TTLCache(maxsize=2, ttl=300))
    def _handle_index(
        self,
    ) -> None:  # pragma: no cover - threaded index handler mirrors FastAPI index route
        """Brief: Handle GET / and /index.html by serving html/index.html.

        Inputs: none
        Outputs: None
        """

        web_cfg = self._web_cfg()
        index_enabled = bool(web_cfg.get("index", True))
        if not index_enabled:
            self._send_text(404, "index disabled")
            return

        index_path = os.path.abspath(os.path.join(self._www_root(), "index.html"))
        if not os.path.isfile(index_path):
            self._send_text(404, "index not found")
            return

        try:
            with open(index_path, "rb") as f:
                data = f.read()
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.error("Failed to read static index.html: %s", exc)
            self._send_text(500, "failed to read static index")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            logger.warning(
                "Client disconnected while sending index.html for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    #    @cached(cache=TTLCache(maxsize=1, ttl=300))
    def _www_root(
        self,
    ) -> str:  # pragma: no cover - thin wrapper around resolve_www_root()
        """Brief: Resolve absolute path to the html directory for static assets.

        Inputs: none
        Outputs: str absolute path to html/.
        """

        cfg = getattr(self._server(), "config", None)
        return resolve_www_root(cfg)

    def _try_serve_www(
        self, path: str
    ) -> (
        bool
    ):  # pragma: no cover - threaded static file helper mirrors FastAPI static route
        """Brief: Attempt to serve a static file from html/ for the given path.

        Inputs:
          - path: Request path (e.g., "/logo.png" or "/css/app.css").

        Outputs:
          - bool: True if a response was sent, False if no matching file exists.
        """

        # Normalize and guard against path traversal
        rel = path.lstrip("/")
        root = self._www_root()
        root_abs = os.path.abspath(root)
        candidate = os.path.abspath(os.path.join(root_abs, rel))
        if not candidate.startswith(root_abs + os.sep):
            return False
        if not os.path.isfile(candidate):
            return False

        try:
            with open(candidate, "rb") as f:
                data = f.read()
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.error("Failed to read static file %s: %s", candidate, exc)
            self._send_text(500, "failed to read static file")
            return True

        content_type, _ = mimetypes.guess_type(candidate)
        if not content_type:
            content_type = "application/octet-stream"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            logger.warning(
                "Client disconnected while sending static file %s for %s %s",
                candidate,
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return True
        return True

    # ---------- HTTP verb handlers ----------

    def do_OPTIONS(
        self,
    ) -> (
        None
    ):  # noqa: N802  # pragma: no cover - low-level HTTP verb handler for fallback server
        """Brief: Handle CORS preflight requests.

        Inputs: none
        Outputs: None
        """

        self.send_response(204)
        self._apply_cors_headers()
        self.end_headers()

    def _handle_plugin_pages_list(self) -> None:
        """Brief: Handle GET /api/v1/plugin_pages for the threaded admin server.

        Inputs:
          - None (uses self._server().plugins).

        Outputs:
          - None (sends JSON response with a pages list).
        """

        plugins_list = getattr(self._server(), "plugins", []) or []
        pages = _admin_logic.collect_admin_pages_for_response(plugins_list)

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "pages": _json_safe(pages),
            },
        )

    def _handle_plugins_ui_descriptors(self) -> None:
        """Brief: Handle GET /api/v1/plugins/ui for the threaded admin server.

        Inputs:
          - None (uses self._server().plugins and global DNS cache).

        Outputs:
          - None (sends JSON response with items list).
        """

        if not self._require_auth():
            return
        plugins_list = list(getattr(self._server(), "plugins", []) or [])

        # Also surface the global DNS cache plugin when it exposes admin UI.
        try:
            from ...plugins.resolve import base as plugin_base

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is not None:
            try:
                get_desc = getattr(cache, "get_admin_ui_descriptor", None)
            except Exception:
                get_desc = None
            if callable(get_desc):
                plugins_list.append(cache)

        items = _admin_logic.collect_plugin_ui_descriptors(plugins_list)
        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "items": _json_safe(items),
            },
        )

    def _handle_plugin_page_detail_route(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugin_pages/{plugin_name}/{page_slug}.

        Inputs:
          - path: Request path including plugin_name and page_slug.

        Outputs:
          - None (sends JSON response with page detail or 404).
        """

        # /api/v1/plugin_pages/{plugin_name}/{page_slug}
        if not self._require_auth():
            return
        prefix = "/api/v1/plugin_pages/"
        raw_segment = path[len(prefix) :]
        parts = [p for p in raw_segment.split("/", 1) if p]
        if len(parts) != 2:
            self._send_json(
                404,
                {
                    "detail": "plugin page not found",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        plugin_name, page_slug = parts[0], parts[1]

        plugins_list = getattr(self._server(), "plugins", []) or []
        detail = _admin_logic.find_admin_page_detail(
            plugins_list, plugin_name, page_slug
        )

        if detail is None:
            self._send_json(
                404,
                {
                    "detail": "plugin page not found",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "page": _json_safe(detail),
            },
        )

    def _handle_docker_hosts_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/docker_hosts.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        if not self._require_auth():
            return
        # Extract plugin_name between the fixed prefix and suffix.
        prefix = "/api/v1/plugins/"
        suffix = "/docker_hosts"
        raw_segment = path[len(prefix) : -len(suffix)]
        plugin_name = raw_segment.strip("/")
        plugins_list = getattr(self._server(), "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="DockerHosts"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "plugin": snap["plugin"],
                "data": _json_safe(snap["data"]),
            },
        )

    def _handle_mdns_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/mdns.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        if not self._require_auth():
            return
        prefix = "/api/v1/plugins/"
        suffix = "/mdns"
        raw_segment = path[len(prefix) : -len(suffix)]
        plugin_name = raw_segment.strip("/")
        plugins_list = getattr(self._server(), "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="MdnsBridge"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "plugin": snap["plugin"],
                "data": _json_safe(snap["data"]),
            },
        )

    def _handle_etc_hosts_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/etc_hosts.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        if not self._require_auth():
            return
        prefix = "/api/v1/plugins/"
        suffix = "/etc_hosts"
        raw_segment = path[len(prefix) : -len(suffix)]
        plugin_name = raw_segment.strip("/")
        plugins_list = getattr(self._server(), "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="EtcHosts"
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "plugin": snap["plugin"],
                "data": _json_safe(snap["data"]),
            },
        )

    def do_GET(
        self,
    ) -> (
        None
    ):  # noqa: N802  # pragma: no cover - low-level HTTP verb handler for fallback server
        """Brief: Dispatch GET requests to admin endpoints.

        Inputs: none
        Outputs: None
        """

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path in {"/health", "/api/v1/health"}:
            self._handle_health()
        elif path in {"/about", "/api/v1/about"}:
            self._handle_about()
        elif path in {"/ready", "/api/v1/ready"}:
            self._handle_ready()
        elif path in {"/stats", "/api/v1/stats"}:
            self._handle_stats(params)
        elif path in {"/traffic", "/api/v1/traffic"}:
            self._handle_traffic(params)
        elif path in {"/config", "/api/v1/config"}:
            self._handle_config()
        elif path in {"/config.json", "/api/v1/config.json"}:
            self._handle_config_json()
        elif path in {
            "/config/raw",
            "/config_raw",
            "/api/v1/config/raw",
            "/api/v1/config_raw",
        }:
            self._handle_config_raw()
        elif path in {
            "/config/raw.json",
            "/config_raw.json",
            "/api/v1/config/raw.json",
            "/api/v1/config_raw.json",
        }:
            self._handle_config_raw_json()
        elif path in {"/logs", "/api/v1/logs"}:
            self._handle_logs(params)
        elif path in {"/query_log", "/api/v1/query_log"}:
            self._handle_query_log(params)
        elif path == "/api/v1/query_log/aggregate":
            self._handle_query_log_aggregate(params)
        elif path == "/api/v1/upstream_status":
            self._handle_upstream_status()
        elif path == "/api/v1/ratelimit":
            # Rate-limit statistics are derived from config and sqlite profile DBs.
            cfg = getattr(self._server(), "config", None)
            data = _collect_rate_limit_stats(cfg)
            data["server_time"] = _utc_now_iso()
            self._send_json(200, data)
        elif path == "/api/v1/plugin_pages":
            self._handle_plugin_pages_list()
        elif path == "/api/v1/plugins/ui":
            self._handle_plugins_ui_descriptors()
        elif path.startswith("/api/v1/plugin_pages/"):
            self._handle_plugin_page_detail_route(path)
        elif path.startswith("/api/v1/plugins/") and path.endswith("/docker_hosts"):
            self._handle_docker_hosts_snapshot(path)
        elif path.startswith("/api/v1/plugins/") and path.endswith("/mdns"):
            self._handle_mdns_snapshot(path)
        elif path.startswith("/api/v1/plugins/") and path.endswith("/etc_hosts"):
            self._handle_etc_hosts_snapshot(path)
        elif path in {"/", "/index.html"}:
            self._handle_index()
        else:
            # As a last resort, try to serve from html/ if the file exists.
            if self._try_serve_www(path):
                return
            self._send_text(404, "not found")

    def do_POST(
        self,
    ) -> (
        None
    ):  # noqa: N802  # pragma: no cover - low-level HTTP verb handler for fallback server
        """Brief: Dispatch POST requests to admin endpoints.

        Inputs: none
        Outputs: None
        """

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in {"/stats/reset", "/api/v1/stats/reset"}:
            self._handle_stats_reset()
        elif path in {"/config/save", "/api/v1/config/save"}:
            length = int(self.headers.get("Content-Length", "0") or "0")
            raw_body = self.rfile.read(length) if length > 0 else b""
            try:
                body = json.loads(raw_body.decode("utf-8") or "{}")
            except Exception:
                self._send_json(
                    400,
                    {
                        "detail": "invalid JSON body",
                        "server_time": _utc_now_iso(),
                    },
                )
                return
            if not isinstance(body, dict):
                self._send_json(
                    400,
                    {
                        "detail": "request body must be a JSON object",
                        "server_time": _utc_now_iso(),
                    },
                )
                return
            self._handle_config_save(body)
        else:
            self._send_text(404, "not found")

    def log_message(
        self, format: str, *args: Any
    ) -> None:  # noqa: A003  # pragma: no cover - logging-only fallback path
        """Brief: Route handler logs through the module logger instead of stderr.

        Inputs:
          - format: format string
          - args: format arguments
        Outputs:
          - None
        """

        try:
            msg = format % args
        except Exception:
            msg = format
            logger.debug("webserver HTTP: %s", msg)
