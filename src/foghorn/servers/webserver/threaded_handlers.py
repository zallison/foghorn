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
import shutil
import signal
import time
import urllib.parse
from datetime import UTC, datetime, timezone

# Forward declaration - _AdminHTTPServer is defined in server_management
from typing import TYPE_CHECKING, Any, ClassVar, Dict, Optional

import yaml

from ...security_limits import MAX_ADMIN_JSON_BODY_BYTES, maybe_parse_content_length
from ...stats import StatsCollector, StatsSnapshot
from ..udp_server import DNSUDPHandler
from . import admin_logic as _admin_logic
from . import admin_rate_limit as _admin_rate_limit
from . import config_persistence as _config_persistence
from . import endpoint_services as _endpoint_services
from .api_request_audit import ApiRequestAuditLogger
from .config_helpers import (
    _get_web_cfg,
    _parse_utc_datetime,
)
from .http_helpers import (
    _evaluate_web_auth,
    _json_safe,
    _schedule_process_signal,
    resolve_www_root,
)
from .rate_limit_helpers import _collect_rate_limit_stats
from .stats_helpers import (
    _get_stats_snapshot_cached,
    _utc_now_iso,
    get_system_info,
    resolve_stats_table_rows,
)

if TYPE_CHECKING:
    from .server_management import _AdminHTTPServer


logger = logging.getLogger("foghorn.webserver")


def _is_control_plane_path(path: str) -> bool:
    """Brief: Return True for reload/restart/config-write admin control paths.

    Inputs:
      - path: Request URL path.

    Outputs:
      - bool
    """

    p = str(path or "")
    if p.startswith("/api/v1/admin"):
        return True
    control_exact = {
        "/reload",
        "/api/v1/reload",
        "/reload_reloadable",
        "/api/v1/reload_reloadable",
        "/restart",
        "/api/v1/restart",
        "/config/reload",
        "/api/v1/config/reload",
        "/config/reload_reloadable",
        "/api/v1/config/reload_reloadable",
        "/config/save",
        "/api/v1/config/save",
        "/config/save_and_reload",
        "/api/v1/config/save_and_reload",
        "/config/save_and_restart",
        "/api/v1/config/save_and_restart",
    }
    return p in control_exact


class _ThreadedAdminRequestHandler(http.server.BaseHTTPRequestHandler):
    """Brief: Minimal admin HTTP handler using the standard library.

    Inputs:
      - Inherits request/connection attributes from BaseHTTPRequestHandler.

    Outputs:
      - Serves /health, /stats, /stats/reset, /traffic, /config, /logs,
        virtual / and /index.html, and static files from html/ when present.
    """

    HTTP_GET_MAP_STATIC: ClassVar[dict[str, str]] = {
        "/openapi.json": "_handle_openapi_json",
        "/docs": "_handle_docs",
        "/docs/oauth2-redirect": "_handle_docs_oauth2_redirect",
        "/": "_handle_index",
        "/index.html": "_handle_index",
        "/health": "_handle_health",
        "/api/v1/health": "_handle_health",
        "/about": "_handle_about",
        "/api/v1/about": "_handle_about",
        "/ready": "_handle_ready",
        "/api/v1/ready": "_handle_ready",
        "/api/v1/cache": "_handle_cache_snapshot",
        "/api/v1/plugin_pages": "_handle_plugin_pages_list",
        "/api/v1/plugins/ui": "_handle_plugins_ui_descriptors",
        "/api/v1/admin/status": "_handle_admin_status",
        "/api/v1/admin/capabilities": "_handle_admin_capabilities",
        "/api/v1/admin/restart/status": "_handle_admin_restart_status",
        "/api/v1/admin/version/compat": "_handle_admin_version_compat",
        "/api/v1/admin/diag/runtime-snapshot": "_handle_admin_diag_runtime_snapshot",
        "/api/v1/upstream_status": "_handle_upstream_status",
    }
    HTTP_GET_MAP_PARAM: ClassVar[dict[str, str]] = {
        "/stats": "_handle_stats",
        "/api/v1/stats": "_handle_stats",
        "/api/v1/admin/audit": "_handle_admin_audit",
        "/api/v1/admin/tasks": "_handle_admin_tasks",
        "/api/v1/admin/rate_limit/hot_keys": "_handle_admin_rate_limit_hot_keys",
        "/api/v1/admin/rate_limit/keys": "_handle_admin_rate_limit_keys",
    }
    HTTP_POST_MAP_NO_BODY: ClassVar[dict[str, str]] = {
        "/stats/reset": "_handle_stats_reset",
        "/api/v1/stats/reset": "_handle_stats_reset",
        "/api/v1/admin/audit/clear": "_handle_admin_audit_clear",
        "/config/reload": "_handle_config_reload",
        "/api/v1/config/reload": "_handle_config_reload",
        "/reload": "_handle_config_reload",
        "/api/v1/reload": "_handle_config_reload",
        "/config/reload_reloadable": "_handle_config_reload_reloadable",
        "/api/v1/config/reload_reloadable": "_handle_config_reload_reloadable",
        "/reload_reloadable": "_handle_config_reload_reloadable",
        "/api/v1/reload_reloadable": "_handle_config_reload_reloadable",
    }
    HTTP_POST_MAP_JSON_BODY: ClassVar[dict[str, str]] = {
        "/api/v1/admin/config/verify": "_handle_admin_config_verify",
        "/api/v1/admin/config/diff": "_handle_admin_config_diff",
        "/api/v1/admin/config/lint": "_handle_admin_config_lint",
        "/api/v1/admin/query_log/clear": "_handle_admin_query_log_clear",
        "/api/v1/admin/query_log/export": "_handle_admin_query_log_export",
        "/api/v1/admin/query_log/compact": "_handle_admin_query_log_compact",
        "/api/v1/admin/rate_limit/clear": "_handle_admin_rate_limit_clear",
        "/api/v1/admin/rate_limit/reset_counters": "_handle_admin_rate_limit_reset_counters",
    }

    def _server(self) -> _AdminHTTPServer:
        """Brief: Return typed reference to the underlying HTTP server.

        Inputs: none
        Outputs: _AdminHTTPServer instance.
        """

        return self.server  # type: ignore[return-value]

    # ---------- Helpers ----------
    def send_response(self, code: int, message: str | None = None) -> None:
        """Brief: Capture last response code for API audit logging.

        Inputs:
          - code: HTTP response code.
          - message: Optional reason phrase.

        Outputs:
          - None.
        """

        self._last_status_code = int(code)
        super().send_response(code, message)
        if bool(getattr(self, "_api_audit_logged", False)):
            return
        started_ts_obj = getattr(self, "_api_audit_started_ts", None)
        started_ts = (
            float(started_ts_obj) if isinstance(started_ts_obj, (int, float)) else None
        )
        duration_ms = (
            float((time.time() - started_ts) * 1000.0)
            if started_ts is not None
            else 0.0
        )
        path = str(getattr(self, "_api_audit_path", "") or "")
        params = getattr(self, "_api_audit_params", {})
        if not isinstance(params, dict):
            params = {}
        self._log_api_audit_event(
            method=str(getattr(self, "command", "") or ""),
            path=path,
            params=params,
            duration_ms=duration_ms,
            error_text=None,
        )
        self._api_audit_logged = True

    def _begin_api_audit_context(
        self, *, path: str, params: dict[str, list[str]]
    ) -> None:
        """Brief: Initialize per-request context for send_response audit logging.

        Inputs:
          - path: Request path.
          - params: Parsed query parameter mapping.

        Outputs:
          - None.
        """

        self._api_audit_logged = False
        self._api_audit_started_ts = float(time.time())
        self._api_audit_path = str(path or "")
        self._api_audit_params = dict(params or {})
        self._last_admin_json_body = None

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
    ) -> dict[
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

    def _send_bytes(
        self,
        status_code: int,
        body: bytes,
        *,
        content_type: str,
        headers: dict[str, str] | None = None,
        body_kind: str = "response",
    ) -> None:
        """Brief: Send byte response payload with common HTTP headers.

        Inputs:
          - status_code: HTTP status code.
          - body: Raw response bytes.
          - content_type: Content-Type header value.
          - headers: Optional mapping of extra HTTP headers to include.
          - body_kind: Short label used in disconnect warning logs.

        Outputs:
          - None.
        """

        self.send_response(status_code)
        self.send_header("Content-Type", str(content_type))
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
                "Client disconnected while sending %s for %s %s",
                str(body_kind or "response"),
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _send_json(
        self,
        status_code: int,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
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
        self._send_bytes(
            status_code,
            body,
            content_type="application/json; charset=utf-8",
            headers=headers,
            body_kind="JSON response",
        )

    def _send_text(
        self,
        status_code: int,
        text: str,
        headers: dict[str, str] | None = None,
    ) -> None:  # pragma: no cover - low-level HTTP I/O helper
        """Brief: Send plain-text response.

        Inputs:
          - status_code: HTTP status code.
          - text: Response body
          - headers: Optional mapping of extra HTTP headers to include.

        Outputs:
          - None
        """

        body = text.encode("utf-8")
        self._send_bytes(
            status_code,
            body,
            content_type="text/plain; charset=utf-8",
            headers=headers,
            body_kind="text response",
        )

    def _get_query_param(
        self,
        params: dict[str, list[str]],
        key: str,
        default: str | None = None,
    ) -> str | None:
        """Brief: Fetch a single string query parameter from parse_qs output.

        Inputs:
          - params: Dict from urllib.parse.parse_qs.
          - key: Query parameter key.
          - default: Value to return when the key is missing.

        Outputs:
          - Parameter string value or default.
        """

        values = params.get(key)
        if not values:
            return default
        if not isinstance(values, list):
            return default
        if not values:
            return default
        val = values[0]
        if val is None:
            return default
        return str(val)

    def _get_int_param(
        self,
        params: dict[str, list[str]],
        key: str,
        default: int,
    ) -> int:
        """Brief: Fetch an int query parameter from parse_qs output.

        Inputs:
          - params: Dict from urllib.parse.parse_qs.
          - key: Query parameter key.
          - default: Default int when missing or invalid.

        Outputs:
          - Parsed int value.
        """

        raw = self._get_query_param(params, key)
        if raw is None:
            return int(default)
        try:
            return int(raw)
        except Exception:
            return int(default)

    def _get_bool_param(
        self,
        params: dict[str, list[str]],
        key: str,
        default: bool = False,
    ) -> bool:
        """Brief: Fetch a bool query parameter from parse_qs output.

        Inputs:
          - params: Dict from urllib.parse.parse_qs.
          - key: Query parameter key.
          - default: Default bool when missing or invalid.

        Outputs:
          - Parsed bool value.
        """

        raw = self._get_query_param(params, key)
        if raw is None:
            return bool(default)
        raw = str(raw).strip().lower()
        if raw in {"1", "true", "t", "yes", "y", "on"}:
            return True
        if raw in {"0", "false", "f", "no", "n", "off"}:
            return False
        return bool(default)

    def _send_yaml(
        self, status_code: int, text: str
    ) -> None:  # pragma: nocover - [low-level HTTP I/O helper tested via FastAPI]
        """Brief: Send YAML response with application/x-yaml content type.

        Inputs:
          - status_code: HTTP status code
          - text: YAML response body
        Outputs:
          - None
        """

        body = text.encode("utf-8")
        self._send_bytes(
            status_code,
            body,
            content_type="application/x-yaml; charset=utf-8",
            body_kind="YAML response",
        )

    def _send_html(
        self, status_code: int, html_body: str
    ) -> None:  # pragma: nocover - [low-level HTTP I/O helper tested via FastAPI]
        """Brief: Send HTML response.

        Inputs:
          - status_code: HTTP status code
          - html_body: HTML document/string to send.
        Outputs:
          - None
        """

        body = html_body.encode("utf-8")
        self._send_bytes(
            status_code,
            body,
            content_type="text/html; charset=utf-8",
            body_kind="HTML response",
        )

    def _read_request_body_limited(
        self, *, max_bytes: int, too_large_detail: str
    ) -> bytes | None:
        """Brief: Read request body after enforcing a strict Content-Length cap.

        Inputs:
          - max_bytes: Maximum accepted Content-Length in bytes.
          - too_large_detail: Error detail text for 413 responses.

        Outputs:
          - bytes when body is accepted (possibly empty).
          - None when an error response was sent.
        """

        max_allowed = int(max_bytes)
        length = maybe_parse_content_length(self.headers.get("Content-Length"))
        if length > max_allowed:
            self._send_json(
                413,
                {
                    "detail": str(too_large_detail),
                    "server_time": _utc_now_iso(),
                },
            )
            return None
        if length <= 0:
            return b""
        try:
            return self.rfile.read(length)
        except Exception:
            self._send_json(
                400,
                {
                    "detail": "failed to read request body",
                    "server_time": _utc_now_iso(),
                },
            )
            return None

    def _resolve_config_path_or_send_error(self) -> Any | None:
        """Brief: Return configured config_path or send a standard 500 JSON error.

        Inputs:
          - None.

        Outputs:
          - Config path object when configured.
          - None when missing (after emitting the error response).
        """

        cfg_path = getattr(self._server(), "config_path", None)
        if cfg_path:
            return cfg_path
        self._send_json(
            500,
            {"detail": "config_path not configured", "server_time": _utc_now_iso()},
        )
        return None

    def _diagram_config_signature(self, cfg_path: Any) -> str:
        """Brief: Build best-effort cache signature for config diagram freshness.

        Inputs:
          - cfg_path: Config path-like value.

        Outputs:
          - Stable signature string using mtime/size when available.
        """

        try:
            st = os.stat(str(cfg_path))
            return f"{cfg_path}:{int(st.st_mtime_ns)}:{int(st.st_size)}"
        except Exception:
            return str(cfg_path)

    def _is_meta_only_param(self, params: dict[str, list[str]]) -> bool:
        """Brief: Parse query parameter to detect metadata-only responses.

        Inputs:
          - params: Parsed query parameter mapping.

        Outputs:
          - True when meta parameter requests metadata-only mode.
        """

        try:
            return bool(
                params.get("meta")
                and str(params.get("meta")[0]) not in {"", "0", "false"}
            )
        except Exception:
            return False

    def _send_diagram_png_bytes(self, data: bytes, headers: dict[str, str]) -> None:
        """Brief: Send diagram PNG bytes with standard headers and disconnect logging.

        Inputs:
          - data: PNG file bytes.
          - headers: Extra response headers to include.

        Outputs:
          - None.
        """

        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        for k, v in headers.items():
            self.send_header(str(k), str(v))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:  # pragma: no cover - client disconnect
            logger.warning(
                "Client disconnected while sending diagram for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _get_openapi_schema_cached(self) -> dict[str, Any] | None:
        """Brief: Return OpenAPI schema for the admin API, caching it on the server.

        Inputs: none

        Outputs:
          - OpenAPI schema dict when FastAPI is available.
          - None when schema generation is not possible.

        Notes:
          - The threaded fallback server does not use FastAPI at runtime, but we
            reuse the FastAPI app's OpenAPI generation to keep the schema aligned
            with the uvicorn path.
          - runtime_state is intentionally not passed to create_app() to avoid
            mutating the shared RuntimeState from a docs/schema request.
        """

        server = self._server()
        cached = getattr(server, "_openapi_schema_cache", None)
        if isinstance(cached, dict):
            return cached

        try:
            from .core import create_app as _create_app
        except Exception as exc:  # pragma: no cover - optional dependency
            logger.debug("OpenAPI schema unavailable (FastAPI import failed): %s", exc)
            return None

        app = _create_app(
            stats=getattr(server, "stats", None),
            config=getattr(server, "config", None) or {},
            log_buffer=getattr(server, "log_buffer", None),
            config_path=getattr(server, "config_path", None),
            runtime_state=None,
            plugins=getattr(server, "plugins", None) or [],
        )
        schema = app.openapi()
        server._openapi_schema_cache = schema
        return schema

    def _handle_openapi_json(self) -> None:
        """Brief: Handle GET /openapi.json.

        Inputs: none
        Outputs: None (writes JSON response).
        """

        web_cfg = self._web_cfg()
        if not bool(web_cfg.get("enable_schema", False)):
            self._send_text(404, "openapi schema not available")
            return

        schema = self._get_openapi_schema_cached()
        if schema is None:
            self._send_json(404, {"detail": "openapi schema not available"})
            return
        self._send_json(200, schema)

    def _handle_docs(self) -> None:
        """Brief: Handle GET /docs.

        Inputs: none
        Outputs: None (writes HTML response).
        """

        web_cfg = self._web_cfg()
        if not bool(web_cfg.get("enable_docs", False)) or not bool(
            web_cfg.get("enable_schema", False)
        ):
            self._send_text(404, "docs not available")
            return

        try:
            from fastapi.openapi.docs import get_swagger_ui_html
        except Exception as exc:  # pragma: no cover - optional dependency
            logger.debug("Swagger UI unavailable (FastAPI import failed): %s", exc)
            self._send_text(404, "docs not available")
            return

        # NOTE: We intentionally do not require auth for /docs so that Swagger UI
        # can load the schema. Operators can still enable auth for the actual API
        # endpoints; Swagger UI will prompt for auth when making requests.
        resp = get_swagger_ui_html(
            openapi_url="/openapi.json",
            title="Foghorn Admin HTTP API - Swagger UI",
            swagger_ui_parameters={"persistAuthorization": True},
        )
        body = (
            resp.body.decode("utf-8")
            if isinstance(resp.body, (bytes, bytearray))
            else str(resp.body)
        )
        self._send_html(200, body)

    def _handle_docs_oauth2_redirect(self) -> None:
        """Brief: Handle GET /docs/oauth2-redirect.

        Inputs: none
        Outputs: None (writes HTML response).
        """

        web_cfg = self._web_cfg()
        if not bool(web_cfg.get("enable_docs", False)) or not bool(
            web_cfg.get("enable_schema", False)
        ):
            self._send_text(404, "not found")
            return

        try:
            from fastapi.openapi.docs import get_swagger_ui_oauth2_redirect_html
        except Exception as exc:  # pragma: no cover - optional dependency
            logger.debug(
                "Swagger OAuth2 redirect unavailable (FastAPI import failed): %s", exc
            )
            self._send_text(404, "not found")
            return

        resp = get_swagger_ui_oauth2_redirect_html()
        body = (
            resp.body.decode("utf-8")
            if isinstance(resp.body, (bytes, bytearray))
            else str(resp.body)
        )
        self._send_html(200, body)

    def _require_auth(
        self,
    ) -> bool:  # pragma: nocover - [behaviour tested via FastAPI auth dependency tests]
        """Brief: Enforce auth.mode=token semantics for protected endpoints.

        Inputs: none
        Outputs: bool indicating whether the request is authorized.
        """
        authorized, status_code, detail, headers = _evaluate_web_auth(
            self._web_cfg(),
            authorization_header=self.headers.get("Authorization"),
            api_key_header=self.headers.get("X-API-Key"),
            default_mode="token",
        )
        if authorized:
            return True
        self._send_json(
            int(status_code or 401),
            {"detail": str(detail or "unauthorized"), "server_time": _utc_now_iso()},
            headers=headers,
        )
        return False

    # ---------- Endpoint handlers ----------

    def _handle_health(
        self,
    ) -> (
        None
    ):  # pragma: nocover - [threaded /health mirrors FastAPI /health tested via FastAPI]
        """Brief: Handle GET /health.

        Inputs: none
        Outputs: None (sends JSON response).
        """

        self._send_json(200, _endpoint_services.build_health_payload())

    def _handle_about(self) -> None:
        """Brief: Handle GET /about and /api/v1/about.

        Inputs: none

        Outputs:
          - None (sends JSON response with version/build info).
        """

        self._send_json(200, _endpoint_services.build_about_payload())

    def _handle_ready(self) -> None:
        """Brief: Handle GET /ready and /api/v1/ready.

        Inputs: none

        Outputs:
          - None (sends JSON response with 200 when ready, else 503).
        """

        status_code, payload = _endpoint_services.build_ready_result(
            stats=getattr(self._server(), "stats", None),
            config=getattr(self._server(), "config", None),
            runtime_state=getattr(self._server(), "runtime_state", None),
        )
        self._send_json(int(status_code), payload)

    def _handle_stats(
        self, params: dict[str, list[str]]
    ) -> (
        None
    ):  # pragma: nocover - [threaded /stats mirrors FastAPI /stats tested via FastAPI]
        """Brief: Handle GET /stats.

        Inputs:
          - params: Query string parameters mapping
        Outputs:
          - None
        """

        if not self._require_auth():
            return
        server = self._server()
        status_code, payload = _endpoint_services.build_stats_result(
            collector=getattr(server, "stats", None),
            reset=str(params.get("reset", ["false"])[0]).lower()
            in {"1", "true", "yes"},
            top=params.get("top", ["10"])[0],
            get_system_info=get_system_info,
            hostname=getattr(server, "hostname", None),
            host_ip=getattr(server, "host_ip", None),
        )
        self._send_json(int(status_code), payload)

    def _handle_stats_table(self, path: str, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/stats/table/{table_id}.

        Inputs:
          - path: Request path including the table_id segment.
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response with a paged table payload).
        """

        if not self._require_auth():
            return

        collector: StatsCollector | None = getattr(self._server(), "stats", None)
        if collector is None:
            self._send_json(
                404,
                {"detail": "stats collector disabled", "server_time": _utc_now_iso()},
            )
            return

        prefix = "/api/v1/stats/table/"
        table_id_raw = path[len(prefix) :].strip("/")
        table_id = urllib.parse.unquote(table_id_raw)
        if not table_id:
            self._send_json(
                404,
                {"detail": "unknown stats table", "server_time": _utc_now_iso()},
            )
            return

        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=False)

        group_key = self._get_query_param(params, "group_key")
        tid = str(table_id).strip()
        rows, error_code = resolve_stats_table_rows(
            snap,
            table_id=tid,
            group_key=group_key,
        )
        if error_code == "missing_group_key":
            self._send_json(
                400,
                {
                    "detail": "group_key is required for grouped stats tables",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        if error_code == "unknown_table":
            self._send_json(
                404,
                {"detail": "unknown stats table", "server_time": _utc_now_iso()},
            )
            return

        payload = _admin_logic.build_table_page_payload(
            rows,
            page=self._get_int_param(params, "page", 1),
            page_size=self._get_int_param(params, "page_size", 50),
            sort_key=self._get_query_param(params, "sort_key"),
            sort_dir=self._get_query_param(params, "sort_dir"),
            search=self._get_query_param(params, "search"),
            hide_zero_calls=False,
            hide_zero_hits=False,
            show_down_services=True,
            hide_hash_like=False,
            default_sort_key="count",
            default_sort_dir="desc",
        )
        payload["server_time"] = _utc_now_iso()
        payload["table_id"] = tid
        if group_key is not None:
            payload["group_key"] = str(group_key)
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
        status_code, payload = _endpoint_services.build_stats_reset_result(
            collector=getattr(self._server(), "stats", None)
        )
        self._send_json(int(status_code), payload)

    def _handle_traffic(
        self,
        params: dict[str, list[str]],
    ) -> None:  # pragma: no cover - threaded /traffic mirrors FastAPI endpoint
        """Brief: Handle GET /traffic.

        Inputs:
          - params: Query string parameters mapping

        Outputs:
          - None (sends JSON response).
        """

        if not self._require_auth():
            return
        server = self._server()
        status_code, payload = _endpoint_services.build_traffic_result(
            collector=getattr(server, "stats", None),
            top=params.get("top", ["10"])[0],
            hostname=getattr(server, "hostname", None),
            host_ip=getattr(server, "host_ip", None),
        )
        self._send_json(int(status_code), payload)

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
        _status_code, body = _endpoint_services.build_config_yaml_result(
            config=getattr(self._server(), "config", None),
            config_path=getattr(self._server(), "config_path", None),
        )
        self._send_yaml(200, body)

    #    @cached(cache=TTLCache(maxsize=1, ttl=2))
    def _handle_config_json(
        self,
    ) -> None:  # pragma: no cover - threaded /config.json mirrors FastAPI endpoint
        """Brief: Handle GET /config.json (sanitized JSON config).

        Inputs:
          - None (uses in-memory server config).

        Outputs:
          - JSON payload containing server_time and sanitized config mapping.
        """

        if not self._require_auth():
            return
        status_code, payload = _endpoint_services.build_config_json_result(
            config=getattr(self._server(), "config", None),
        )
        self._send_json(int(status_code), payload)

    #    @cached(cache=TTLCache(maxsize=1, ttl=2))
    def _handle_config_raw(
        self,
    ) -> None:  # pragma: no cover - threaded /config_raw mirrors FastAPI /config/raw
        """Brief: Handle GET /config/raw to return on-disk configuration as raw YAML.

        Inputs:
          - None (uses self.server.config_path to locate YAML file).

        Outputs:
          - YAML body containing the exact on-disk configuration text.
        """

        if not self._require_auth():
            return
        status_code, raw_text, error_detail = (
            _endpoint_services.build_config_raw_yaml_result(
                config_path=getattr(self._server(), "config_path", None),
            )
        )
        if error_detail is not None:
            self._send_json(
                int(status_code),
                {"detail": str(error_detail), "server_time": _utc_now_iso()},
            )
            return
        self._send_yaml(int(status_code), raw_text)

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
        status_code, payload, error_detail = (
            _endpoint_services.build_config_raw_json_result(
                config_path=getattr(self._server(), "config_path", None),
            )
        )
        if error_detail is not None or payload is None:
            self._send_json(
                int(status_code),
                {
                    "detail": str(error_detail or "failed to read config"),
                    "server_time": _utc_now_iso(),
                },
            )
            return
        self._send_json(int(status_code), payload)

    def _handle_config_schema(
        self,
    ) -> None:  # pragma: no cover - threaded /config/schema mirrors FastAPI endpoint
        """Brief: Handle GET /config/schema and return the active JSON schema.

        Inputs:
          - None.

        Outputs:
          - JSON payload with server_time, schema_path, and schema document.
        """

        if not self._require_auth():
            return
        status_code, payload, error_detail = (
            _endpoint_services.build_config_schema_result(include_path_in_error=True)
        )
        if error_detail is not None or payload is None:
            self._send_json(
                int(status_code),
                {
                    "detail": str(error_detail or "failed to read config schema"),
                    "server_time": _utc_now_iso(),
                },
            )
            return
        self._send_json(int(status_code), payload)

    def _handle_config_diagram_png_variant(
        self,
        *,
        params: dict[str, list[str]],
        candidate_paths_fn: Any,
        refresh_stale: bool,
    ) -> None:
        """Brief: Serve a config diagram PNG variant with shared behavior.

        Inputs:
          - params: Query parameters mapping.
          - candidate_paths_fn: Callable returning candidate PNG paths for config.
          - refresh_stale: Whether to attempt stale-file refresh after warning.

        Outputs:
          - None (sends PNG or metadata/status response).
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
        meta_only = self._is_meta_only_param(params)
        status_code, headers, png_path, error_detail, next_attempted_sig = (
            _endpoint_services.build_config_diagram_png_result(
                config_path=cfg_path,
                attempted_signature=getattr(
                    self._server(), "_config_diagram_build_attempt_sig", None
                ),
                candidate_paths_fn=candidate_paths_fn,
                refresh_stale=refresh_stale,
                meta_only=meta_only,
            )
        )
        if next_attempted_sig is not None:
            self._server()._config_diagram_build_attempt_sig = next_attempted_sig
        if meta_only:
            self._send_text(200, "", headers=headers)
            return
        if error_detail is not None:
            self._send_text(int(status_code), str(error_detail))
            return
        if not png_path:
            self._send_text(500, "config diagram path unavailable")
            return

        try:
            with open(str(png_path), "rb") as f:
                data = f.read()
        except Exception as exc:  # pragma: no cover - environment specific
            self._send_text(500, f"failed to read diagram: {exc}")
            return
        self._send_diagram_png_bytes(data, headers)

    def _handle_config_diagram_png(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/config/diagram.png.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends image/png body when present).
          - When meta=1 is provided, sends an empty 200 with:
              - X-Foghorn-Exists: '1' or '0'
              - X-Foghorn-Warning (optional)
        """

        self._handle_config_diagram_png_variant(
            params=params,
            candidate_paths_fn=_endpoint_services.diagram_png_candidate_paths_for_config,
            refresh_stale=True,
        )

    def _handle_config_diagram_png_dark(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/config/diagram-dark.png.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends image/png body when present).
          - When meta=1 is provided, sends an empty 200 with:
              - X-Foghorn-Exists: '1' or '0'
              - X-Foghorn-Warning (optional)
        """

        self._handle_config_diagram_png_variant(
            params=params,
            candidate_paths_fn=(
                _endpoint_services.diagram_dark_png_candidate_paths_for_config
            ),
            refresh_stale=False,
        )

    def _parse_multipart_form_file(
        self, *, body: bytes, content_type: str, field_name: str = "file"
    ) -> tuple[str, bytes] | None:
        """Brief: Extract a single file field from multipart/form-data.

        Inputs:
          - body: Raw HTTP request body bytes.
          - content_type: Content-Type header value.
          - field_name: Form field name to extract (default: 'file').

        Outputs:
          - (filename, data) tuple when found, otherwise None.

        Notes:
          - This is a lightweight parser intended for small uploads.
          - It intentionally ignores non-file fields.
        """

        ct = str(content_type or "")
        if "multipart/form-data" not in ct.lower():
            return None

        boundary = ""
        for part in ct.split(";"):
            part = part.strip()
            if part.lower().startswith("boundary="):
                boundary = part.split("=", 1)[1].strip().strip('"')
                break
        if not boundary:
            return None

        delim = ("--" + boundary).encode("utf-8")
        chunks = body.split(delim)
        for chunk in chunks:
            if not chunk:
                continue
            if chunk.startswith(b"--"):
                continue
            if chunk.startswith(b"\r\n"):
                chunk = chunk[2:]
            header_end = chunk.find(b"\r\n\r\n")
            if header_end < 0:
                continue
            header_blob = chunk[:header_end].decode("utf-8", errors="replace")
            payload = chunk[header_end + 4 :]
            if payload.endswith(b"\r\n"):
                payload = payload[:-2]

            disp = ""
            for line in header_blob.split("\r\n"):
                if line.lower().startswith("content-disposition:"):
                    disp = line.split(":", 1)[1].strip()
                    break
            if not disp:
                continue

            name_val = None
            filename_val = ""
            for item in disp.split(";"):
                item = item.strip()
                if item.startswith("name="):
                    name_val = item.split("=", 1)[1].strip().strip('"')
                elif item.startswith("filename="):
                    filename_val = item.split("=", 1)[1].strip().strip('"')

            if name_val != field_name:
                continue

            return filename_val, bytes(payload)

        return None

    def _handle_config_diagram_png_upload(self, body: bytes) -> None:
        """Brief: Handle POST /api/v1/config/diagram.png.

        Inputs:
          - body: Raw HTTP request body bytes.

        Outputs:
          - None (sends JSON response with status and saved path).
        """

        if not self._require_auth():
            return

        cfg_path = self._resolve_config_path_or_send_error()
        if not cfg_path:
            return

        max_bytes = 1_000_000
        if len(body) > max_bytes + 1024:
            self._send_json(
                413,
                {
                    "detail": "file too large (max 1,000,000 bytes)",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        content_type = self.headers.get("Content-Type") or ""
        parsed = self._parse_multipart_form_file(
            body=body,
            content_type=content_type,
            field_name="file",
        )
        if parsed is None:
            self._send_json(
                400,
                {"detail": "invalid multipart upload", "server_time": _utc_now_iso()},
            )
            return

        filename, payload = parsed
        if filename and not str(filename).lower().endswith(".png"):
            self._send_json(
                400,
                {
                    "detail": "file must have .png extension",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        if len(payload) > max_bytes:
            self._send_json(
                413,
                {
                    "detail": "file too large (max 1,000,000 bytes)",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        if not payload.startswith(b"\x89PNG\r\n\x1a\n"):
            self._send_json(
                400,
                {
                    "detail": "file does not look like a PNG",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        try:
            from pathlib import Path

            cfg_dir = Path(str(cfg_path)).resolve().parent
            dst_path = cfg_dir / "diagram.png"
            tmp_path = cfg_dir / "diagram.png.new"

            dst_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.write_bytes(payload)
            os.replace(str(tmp_path), str(dst_path))
        except Exception as exc:  # pragma: no cover
            try:
                if "tmp_path" in locals() and tmp_path.exists():
                    tmp_path.unlink()
            except Exception:
                pass
            self._send_json(
                500,
                {
                    "detail": f"failed to write diagram png: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "path": str(dst_path),
                "size_bytes": len(payload),
            },
        )

    def _handle_config_diagram_dot(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/config/diagram.dot.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends dot text).
        """

        if not self._require_auth():
            return
        status_code, headers, text, error_detail = (
            _endpoint_services.build_config_diagram_dot_result(
                config_path=getattr(self._server(), "config_path", None),
                meta_only=self._is_meta_only_param(params),
            )
        )
        if error_detail is not None:
            self._send_text(int(status_code), str(error_detail))
            return
        self._send_text(int(status_code), str(text or ""), headers=headers)

    def _handle_query_log(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/query_log for the threaded fallback server.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response).
        """

        if not self._require_auth():
            return

        collector: StatsCollector | None = getattr(self._server(), "stats", None)
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
        status = (params.get("status") or [None])[0]
        source = (params.get("source") or [None])[0]
        ede_code = (params.get("ede_code") or [None])[0]
        start = (params.get("start") or [None])[0]
        end = (params.get("end") or [None])[0]

        page_raw = (params.get("page") or ["1"])[0]
        page_size_raw = (params.get("page_size") or ["100"])[0]

        try:
            page = int(page_raw)
        except Exception:
            page = 1
        page = max(page, 1)

        try:
            ps = int(page_size_raw)
        except Exception:
            ps = 100
        if ps <= 0:
            ps = 100
        ps = min(ps, 1000)

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
            status=str(status) if status is not None else None,
            source=str(source) if source is not None else None,
            ede_code=str(ede_code) if ede_code is not None else None,
            start_ts=start_ts,
            end_ts=end_ts,
            page=page,
            page_size=ps,
        )
        self._send_admin_payload(payload)

    def _handle_admin_restart_status(self) -> None:
        """Brief: Handle GET /api/v1/admin/restart/status."""
        if not self._require_admin_action(action="admin.restart.status"):
            return
        status_code, payload = _endpoint_services.build_admin_restart_status_result(
            runtime_state=self._admin_runtime_state(),
            build_payload=_admin_logic.build_admin_restart_status_payload,
        )
        self._send_json(int(status_code), payload)

    def _handle_admin_tasks(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/admin/tasks."""
        if not self._require_admin_action(action="admin.tasks"):
            return
        limit = max(1, min(self._get_int_param(params, "limit", 50), 500))
        status_code, payload = _endpoint_services.build_admin_tasks_result(
            runtime_state=self._admin_runtime_state(),
            limit=limit,
            task_type=self._get_query_param(params, "task_type"),
            status=self._get_query_param(params, "status"),
            build_payload=_admin_logic.build_admin_tasks_payload,
        )
        self._send_json(int(status_code), payload)

    def _handle_admin_config_diff(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/config/diff."""
        if not self._require_admin_action(action="admin.config.diff"):
            return
        raw_yaml = body.get("raw_yaml")
        if raw_yaml is not None and not isinstance(raw_yaml, str):
            self._send_json(
                400,
                {"detail": "raw_yaml must be a string", "server_time": _utc_now_iso()},
            )
            return
        try:
            payload = _admin_logic.build_config_diff_payload(
                raw_yaml=(str(raw_yaml) if isinstance(raw_yaml, str) else None),
                config_path=getattr(self._server(), "config_path", None),
                current_cfg=getattr(self._server(), "config", {}) or {},
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_admin_logic_error(exc)
            return
        self._send_admin_payload(payload)

    def _handle_admin_config_lint(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/config/lint."""
        if not self._require_admin_action(action="admin.config.lint"):
            return
        raw_yaml = body.get("raw_yaml")
        if raw_yaml is not None and not isinstance(raw_yaml, str):
            self._send_json(
                400,
                {"detail": "raw_yaml must be a string", "server_time": _utc_now_iso()},
            )
            return
        try:
            payload = _admin_logic.build_config_lint_payload(
                raw_yaml=(str(raw_yaml) if isinstance(raw_yaml, str) else None),
                config_path=getattr(self._server(), "config_path", None),
                current_cfg=getattr(self._server(), "config", {}) or {},
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_admin_logic_error(exc)
            return
        self._send_admin_payload(payload)

    def _handle_admin_query_log_export(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/query_log/export."""
        if not self._require_admin_action(action="admin.query_log.export"):
            return
        filters = body.get("filters")
        if filters is None:
            filters = {}
        if not isinstance(filters, dict):
            self._send_json(
                400,
                {"detail": "filters must be an object", "server_time": _utc_now_iso()},
            )
            return
        limit = int(body.get("limit", 5000) or 5000)
        if limit <= 0:
            self._send_json(
                400,
                {"detail": "limit must be > 0", "server_time": _utc_now_iso()},
            )
            return
        export_format = str(body.get("format", "jsonl") or "jsonl")
        collector: StatsCollector | None = getattr(self._server(), "stats", None)
        store = getattr(collector, "_store", None) if collector is not None else None
        try:
            payload = _admin_logic.execute_query_log_export(
                store=store,
                filters=filters,
                export_format=export_format,
                limit=limit,
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_query_log_compact(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/query_log/compact."""
        if not self._require_admin_action(action="admin.query_log.compact"):
            return
        mode = str(body.get("mode", "vacuum") or "vacuum")
        dry_run = bool(body.get("dry_run", True))
        collector: StatsCollector | None = getattr(self._server(), "stats", None)
        store = getattr(collector, "_store", None) if collector is not None else None
        try:
            payload = _admin_logic.execute_query_log_compact(
                store=store, mode=mode, dry_run=dry_run
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_rate_limit_hot_keys(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/admin/rate_limit/hot_keys."""
        if not self._require_admin_action(action="admin.rate_limit.hot_keys"):
            return
        plugin_name = self._get_query_param(params, "plugin")
        limit = max(1, min(self._get_int_param(params, "limit", 20), 200))
        try:
            payload = _admin_logic.execute_rate_limit_hot_keys(
                plugins=list(getattr(self._server(), "plugins", []) or []),
                plugin_name=plugin_name,
                limit=limit,
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_rate_limit_reset_counters(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/rate_limit/reset_counters."""

        if not self._require_admin_action(action="admin.rate_limit.reset_counters"):
            return
        plugin = body.get("plugin")
        if plugin is not None and not isinstance(plugin, str):
            self._send_json(
                400,
                {"detail": "plugin must be a string", "server_time": _utc_now_iso()},
            )
            return
        include_global = bool(body.get("include_global", False))
        try:
            payload = _admin_logic.execute_rate_limit_reset_counters(
                plugins=list(getattr(self._server(), "plugins", []) or []),
                plugin_name=(plugin.strip() if isinstance(plugin, str) else None),
                include_global=include_global,
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_admin_logic_error(exc)
            return
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_version_compat(self) -> None:
        """Brief: Handle GET /api/v1/admin/version/compat."""
        if not self._require_admin_action(action="admin.version.compat"):
            return
        status_code, payload = _endpoint_services.build_admin_version_compat_result(
            plugins=list(getattr(self._server(), "plugins", []) or []),
            stats_collector=getattr(self._server(), "stats", None),
            build_payload=_admin_logic.build_admin_version_compat_payload,
        )
        self._send_json(int(status_code), payload)

    def _handle_admin_diag_runtime_snapshot(self) -> None:
        """Brief: Handle GET /api/v1/admin/diag/runtime-snapshot."""
        if not self._require_admin_action(action="admin.diag.runtime_snapshot"):
            return
        status_code, payload = (
            _endpoint_services.build_admin_diag_runtime_snapshot_result(
                config=getattr(self._server(), "config", None),
                config_path=getattr(self._server(), "config_path", None),
                runtime_state=self._admin_runtime_state(),
                plugins=list(getattr(self._server(), "plugins", []) or []),
                stats_collector=getattr(self._server(), "stats", None),
                build_payload=_admin_logic.build_admin_diag_runtime_snapshot,
            )
        )
        self._send_json(int(status_code), payload)

    def _handle_query_log_aggregate(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/query_log/aggregate for the threaded fallback server.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response).
        """

        if not self._require_auth():
            return

        collector: StatsCollector | None = getattr(self._server(), "stats", None)
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

        try:
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
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _admin_audit(
        self,
        *,
        action: str,
        target: str,
        ok: bool,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Brief: Best-effort append an admin audit event.

        Inputs:
          - action: Action identifier.
          - target: Action target identifier.
          - ok: Success flag.
          - details: Optional event details.

        Outputs:
          - None.
        """

        _admin_logic.add_admin_audit_event(
            self._admin_runtime_state(),
            action=action,
            target=target,
            ok=bool(ok),
            details=details or {},
        )

    def _require_admin_action(self, *, action: str) -> bool:
        """Brief: Enforce admin auth and per-action rate limits.

        Inputs:
          - action: Stable rate-limit action identifier.

        Outputs:
          - True when request may continue; False when a response was already sent.
        """

        if not self._require_auth():
            return False
        return bool(self._enforce_admin_rate_limit(action=action))

    def _send_admin_logic_error(self, exc: _admin_logic.AdminLogicHttpError) -> None:
        """Brief: Serialize AdminLogicHttpError as JSON error response.

        Inputs:
          - exc: AdminLogicHttpError raised by admin_logic helpers.

        Outputs:
          - None (sends JSON response with exc.status_code and exc.detail).
        """

        self._send_json(
            exc.status_code,
            {"detail": exc.detail, "server_time": _utc_now_iso()},
        )

    def _send_admin_payload(
        self, payload: dict[str, Any], *, status_code: int = 200
    ) -> None:
        """Brief: Send admin JSON payload with server_time attached.

        Inputs:
          - payload: JSON-compatible payload mapping.
          - status_code: HTTP status code for the response.

        Outputs:
          - None (sends JSON response).
        """

        payload["server_time"] = _utc_now_iso()
        self._send_json(int(status_code), payload)

    def _handle_admin_status(self) -> None:
        """Brief: Handle GET /api/v1/admin/status."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.status"):
            return
        status_code, payload = _endpoint_services.build_admin_status_result(
            config=getattr(self._server(), "config", None),
            config_path=getattr(self._server(), "config_path", None),
            stats_collector=getattr(self._server(), "stats", None),
            plugins=list(getattr(self._server(), "plugins", []) or []),
            admin_runtime_state=self._admin_runtime_state(),
            build_payload=_admin_logic.build_admin_status_payload,
        )
        self._send_json(int(status_code), payload)

    def _handle_admin_capabilities(self) -> None:
        """Brief: Handle GET /api/v1/admin/capabilities."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.capabilities"):
            return
        status_code, payload = _endpoint_services.build_admin_capabilities_result(
            stats_collector=getattr(self._server(), "stats", None),
            plugins=list(getattr(self._server(), "plugins", []) or []),
            build_payload=_admin_logic.build_admin_capabilities_payload,
        )
        self._send_json(int(status_code), payload)

    def _handle_admin_audit(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/admin/audit."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.audit"):
            return
        runtime_state = self._admin_runtime_state()
        list_fn = getattr(runtime_state, "list_audit_events", None)
        limit = self._get_int_param(params, "limit", 100)
        action = self._get_query_param(params, "action")
        items: list[dict[str, Any]] = []
        if callable(list_fn):
            try:
                raw = list_fn(limit=int(limit), action=action)
                if isinstance(raw, list):
                    items = [dict(it) for it in raw if isinstance(it, dict)]
            except Exception:
                items = []
        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "items": items,
                "count": len(items),
            },
        )

    def _handle_admin_audit_clear(self) -> None:
        """Brief: Handle POST /api/v1/admin/audit/clear."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.audit.clear"):
            return
        runtime_state = self._admin_runtime_state()
        clear_fn = getattr(runtime_state, "clear_audit_events", None)
        removed = 0
        if callable(clear_fn):
            try:
                removed = int(clear_fn() or 0)
            except Exception:
                removed = 0
        self._admin_audit(
            action="audit.clear",
            target="admin",
            ok=True,
            details={"removed": int(removed)},
        )
        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "removed": int(removed),
            },
        )

    def _handle_admin_config_verify(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/config/verify."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.config.verify"):
            return
        raw_yaml = body.get("raw_yaml")
        if raw_yaml is not None and not isinstance(raw_yaml, str):
            self._send_json(
                400,
                {"detail": "raw_yaml must be a string", "server_time": _utc_now_iso()},
            )
            return
        try:
            payload = _admin_logic.build_config_verify_payload(
                raw_yaml=(str(raw_yaml) if isinstance(raw_yaml, str) else None),
                config_path=getattr(self._server(), "config_path", None),
                current_cfg=getattr(self._server(), "config", {}) or {},
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._admin_audit(
                action="config.verify",
                target="config",
                ok=False,
                details={"detail": str(exc.detail)},
            )
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        runtime_state = self._admin_runtime_state()
        set_last = getattr(runtime_state, "set_last_config_verify", None)
        if callable(set_last):
            try:
                set_last(dict(payload))
            except Exception:
                pass
        self._admin_audit(
            action="config.verify",
            target="config",
            ok=True,
            details={"path": payload.get("path")},
        )
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_query_log_clear(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/query_log/clear."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.query_log.clear"):
            return
        filters = body.get("filters")
        if filters is None:
            filters = {}
        if not isinstance(filters, dict):
            self._send_json(
                400,
                {"detail": "filters must be an object", "server_time": _utc_now_iso()},
            )
            return
        dry_run = bool(body.get("dry_run", False))
        collector: StatsCollector | None = getattr(self._server(), "stats", None)
        store = getattr(collector, "_store", None) if collector is not None else None
        try:
            payload = _admin_logic.execute_query_log_clear(
                store=store,
                filters=filters,
                dry_run=dry_run,
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._admin_audit(
                action="query_log.clear",
                target="query_log",
                ok=False,
                details={"detail": str(exc.detail)},
            )
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        self._admin_audit(
            action="query_log.clear",
            target="query_log",
            ok=True,
            details={
                "dry_run": bool(payload.get("dry_run", dry_run)),
                "matched": int(payload.get("matched", 0) or 0),
                "deleted": int(payload.get("deleted", 0) or 0),
            },
        )
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_rate_limit_keys(self, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/admin/rate_limit/keys."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.rate_limit.keys"):
            return
        plugin_name = self._get_query_param(params, "plugin")
        page = max(1, self._get_int_param(params, "page", 1))
        page_size = max(1, min(self._get_int_param(params, "page_size", 100), 1000))
        search = self._get_query_param(params, "search")
        try:
            payload = _admin_logic.execute_rate_limit_keys_list(
                plugins=list(getattr(self._server(), "plugins", []) or []),
                plugin_name=plugin_name,
                page=page,
                page_size=page_size,
                search=search,
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._admin_audit(
                action="rate_limit.keys",
                target=(str(plugin_name) if plugin_name else "all"),
                ok=False,
                details={"detail": str(exc.detail)},
            )
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_rate_limit_clear(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /api/v1/admin/rate_limit/clear."""

        if not self._require_auth():
            return
        if not self._enforce_admin_rate_limit(action="admin.rate_limit.clear"):
            return
        plugin_name = body.get("plugin")
        if plugin_name is not None and not isinstance(plugin_name, str):
            self._send_json(
                400,
                {"detail": "plugin must be a string", "server_time": _utc_now_iso()},
            )
            return
        key = body.get("key")
        if key is not None and not isinstance(key, str):
            self._send_json(
                400,
                {"detail": "key must be a string", "server_time": _utc_now_iso()},
            )
            return
        include_global = bool(body.get("include_global", False))
        try:
            payload = _admin_logic.execute_rate_limit_clear(
                plugins=list(getattr(self._server(), "plugins", []) or []),
                plugin_name=(
                    str(plugin_name) if isinstance(plugin_name, str) else None
                ),
                key=(str(key) if isinstance(key, str) else None),
                include_global=include_global,
            )
        except _admin_logic.AdminLogicHttpError as exc:
            self._admin_audit(
                action="rate_limit.clear",
                target=(str(plugin_name) if isinstance(plugin_name, str) else "all"),
                ok=False,
                details={"detail": str(exc.detail)},
            )
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return
        self._admin_audit(
            action="rate_limit.clear",
            target=(str(plugin_name) if isinstance(plugin_name, str) else "all"),
            ok=True,
            details={
                "key": (str(key) if isinstance(key, str) else None),
                "include_global": include_global,
            },
        )
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_admin_records_action(
        self,
        *,
        target: str,
        action: str,
        body: dict[str, Any],
    ) -> None:
        """Brief: Handle POST record mutation admin endpoints."""

        action_norm = str(action or "").strip().lower()
        if not self._require_admin_action(
            action=f"admin.records.{action_norm or 'unknown'}"
        ):
            return
        plugin_name = body.get("plugin")
        if not isinstance(plugin_name, str) or not plugin_name.strip():
            self._send_json(
                400,
                {"detail": "plugin is required", "server_time": _utc_now_iso()},
            )
            return
        target_norm = str(target or "").strip().lower()
        plugins = list(getattr(self._server(), "plugins", []) or [])
        try:
            if action_norm == "validate":
                payload = _admin_logic.execute_records_validate(
                    plugins=plugins,
                    target=target_norm,
                    plugin_name=plugin_name.strip(),
                    payload=body,
                )
            elif action_norm == "apply":
                payload = _admin_logic.execute_records_apply(
                    plugins=plugins,
                    target=target_norm,
                    plugin_name=plugin_name.strip(),
                    payload=body,
                    runtime_state=self._admin_runtime_state(),
                )
            elif action_norm == "delete":
                payload = _admin_logic.execute_records_delete(
                    plugins=plugins,
                    target=target_norm,
                    plugin_name=plugin_name.strip(),
                    payload=body,
                    runtime_state=self._admin_runtime_state(),
                )
            elif action_norm == "list":
                payload = _admin_logic.execute_records_list(
                    plugins=plugins,
                    runtime_state=self._admin_runtime_state(),
                    target=target_norm,
                    plugin_name=plugin_name.strip(),
                )
            elif action_norm == "purge_expired":
                payload = _admin_logic.execute_records_purge_expired(
                    plugins=plugins,
                    runtime_state=self._admin_runtime_state(),
                    target=target_norm,
                    plugin_name=plugin_name.strip(),
                )
            else:
                self._send_json(
                    404,
                    {"detail": "not found", "server_time": _utc_now_iso()},
                )
                return
        except _admin_logic.AdminLogicHttpError as exc:
            self._admin_audit(
                action=f"records.{target_norm}.{action_norm}",
                target=plugin_name.strip(),
                ok=False,
                details={"detail": str(exc.detail)},
            )
            self._send_admin_logic_error(exc)
            return
        details: dict[str, Any] = {}
        if action_norm in {"apply", "delete"}:
            details["persist"] = bool(body.get("persist", False))
        self._admin_audit(
            action=f"records.{target_norm}.{action_norm}",
            target=plugin_name.strip(),
            ok=True,
            details=details,
        )
        payload["server_time"] = _utc_now_iso()
        self._send_json(200, payload)

    def _handle_logs(
        self, params: dict[str, list[str]]
    ) -> None:  # pragma: no cover - threaded /logs mirrors FastAPI endpoint
        """Brief: Handle GET /logs.

        Inputs:
          - params: Query parameters mapping
        Outputs:
          - None
        """

        if not self._require_auth():
            return
        status_code, payload = _endpoint_services.build_logs_result(
            log_buffer=getattr(self._server(), "log_buffer", None),
            limit=params.get("limit", ["100"])[0],
        )
        self._send_json(int(status_code), payload)

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

        status_code, payload = _endpoint_services.build_upstream_status_result(
            config=getattr(self._server(), "config", None),
            build_payload=_admin_logic.build_upstream_status_payload,
        )
        self._send_json(int(status_code), payload)

    def _schedule_restart(self, *, delay_seconds: float = 1.0) -> None:
        """Brief: Schedule a process restart by delivering SIGHUP.

        Inputs:
          - delay_seconds: Delay before sending SIGHUP so HTTP responses can flush.

        Outputs:
          - None.
        """
        runtime_state: object | None = None
        try:
            runtime_state = _admin_logic.get_admin_runtime_state(self._server())
        except (
            Exception
        ):  # pragma: nocover - defensive against foreign server state objects
            runtime_state = None
        set_restart = getattr(runtime_state, "set_restart_pending", None)
        if callable(set_restart):
            try:
                set_restart(
                    delay_seconds=float(delay_seconds),
                    reason="threaded.restart",
                    signal_name="SIGHUP",
                )
            except (
                Exception
            ):  # pragma: nocover - best-effort restart metadata must not block signal scheduling
                pass
        _admin_logic.add_admin_audit_event(
            runtime_state,
            action="restart.schedule",
            target="process",
            ok=True,
            details={
                "delay_seconds": float(delay_seconds),
                "signal": "SIGHUP",
                "reason": "threaded.restart",
            },
        )

        _schedule_process_signal(signal.SIGHUP, delay_seconds=float(delay_seconds))

    def _admin_runtime_state(self) -> object | None:
        """Brief: Return threaded admin runtime state object when configured.

        Inputs:
          - None.

        Outputs:
          - Admin runtime state object or None.
        """

        return _admin_logic.get_admin_runtime_state(self._server())

    def _enforce_admin_rate_limit(self, *, action: str) -> bool:
        """Brief: Enforce admin API request rate limiting for one action.

        Inputs:
          - action: Stable action identifier for the current endpoint.

        Outputs:
          - bool: True when request may proceed; False after sending 429.
        """

        service = _admin_rate_limit.get_admin_rate_limit_service(
            state_obj=self._server(),
            config=getattr(self._server(), "config", {}) or {},
            plugins=list(getattr(self._server(), "plugins", []) or []),
        )
        decision = service.evaluate(
            action=str(action),
            client_ip=self._client_ip(),
            authorization_header=self.headers.get("Authorization"),
            api_key_header=self.headers.get("X-API-Key"),
        )
        if bool(decision.allowed):
            return True
        self._send_json(
            429,
            {
                "detail": "admin API rate limit exceeded",
                "retry_after_seconds": int(decision.retry_after_seconds),
                "server_time": _utc_now_iso(),
            },
            headers=decision.to_headers(),
        )
        return False

    def _read_admin_json_body(self) -> dict[str, Any] | None:
        """Brief: Parse bounded JSON body for admin action POST endpoints.

        Inputs:
          - None.

        Outputs:
          - Parsed JSON body dict, or None when error response has been sent.
        """

        raw_body = self._read_request_body_limited(
            max_bytes=int(MAX_ADMIN_JSON_BODY_BYTES),
            too_large_detail=(
                f"request body too large (max {int(MAX_ADMIN_JSON_BODY_BYTES):,} bytes)"
            ),
        )
        self._last_admin_json_body = None
        if raw_body is None:
            return None
        if not raw_body:
            self._last_admin_json_body = {}
            return {}
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
            return None
        if not isinstance(body, dict):
            self._send_json(
                400,
                {
                    "detail": "request body must be a JSON object",
                    "server_time": _utc_now_iso(),
                },
            )
            return None
        self._last_admin_json_body = dict(body)
        return body

    def _save_config_to_disk(self, *, body: dict[str, Any]) -> dict[str, Any]:
        """Brief: Persist raw YAML to disk and validate it.

        Inputs:
          - body: Parsed JSON object containing required 'raw_yaml' string field.

        Outputs:
          - Dict containing:
              - cfg_path_abs
              - backup_path
              - desired_cfg
              - analysis

        Notes:
          - On validation failure, restores the backup.
        """

        if not isinstance(body, dict):
            raise ValueError("request body must be a JSON object")

        cfg_path = getattr(self._server(), "config_path", None)
        if not cfg_path:
            raise ValueError("config_path not configured")

        cfg_path_abs = os.path.abspath(cfg_path)
        ts = datetime.now(UTC).isoformat().replace(":", "-")
        backup_path = f"{cfg_path_abs}.bak.{ts}"
        upload_path = f"{cfg_path_abs}.new"

        raw_yaml = body.get("raw_yaml")
        if not isinstance(raw_yaml, str):
            raise ValueError("request body must include 'raw_yaml' string field")

        try:
            _config_persistence.safe_write_raw_yaml(
                dst_path=cfg_path_abs,
                raw_yaml=raw_yaml,
                backup_path=backup_path,
                tmp_path=upload_path,
                strategy="replace",
            )
        except Exception:
            try:
                if os.path.exists(upload_path):
                    os.remove(upload_path)
            except Exception:
                pass
            raise

        from foghorn import runtime_config as _runtime_config

        restored = False
        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_abs
            )
        except Exception as exc:
            try:
                if os.path.exists(backup_path):
                    shutil.copy(backup_path, cfg_path_abs)
                    restored = True
            except Exception:
                restored = False
            raise ValueError(
                f"failed to parse/validate saved config (restored_backup={restored}): {exc}"
            ) from exc

        analysis = _runtime_config.analyze_config_change(
            desired_cfg,
            current_cfg=getattr(self._server(), "config", None) or {},
        )

        # Best-effort: keep the config diagram in sync with the on-disk config.
        # This should never block config persistence.
        if analysis.get("changed"):
            try:
                from ...utils.config_diagram import ensure_config_diagram_png

                ensure_config_diagram_png(config_path=str(cfg_path_abs))
            except Exception:
                pass

        return {
            "cfg_path_abs": cfg_path_abs,
            "backup_path": backup_path,
            "desired_cfg": desired_cfg,
            "analysis": analysis,
        }

    def _handle_config_save(
        self, body: dict[str, Any]
    ) -> None:  # pragma: no cover - threaded /config/save mirrors FastAPI endpoint
        """Brief: Handle POST /config/save to persist config without applying it.

        Inputs:
          - body: Parsed JSON object containing required 'raw_yaml' string field.

        Outputs:
          - JSON describing outcome (status, server_time, path, backed_up_to, analysis).

        Notes:
          - This endpoint intentionally does not reload or restart.
        """

        if not self._require_auth():
            return

        try:
            saved = self._save_config_to_disk(body=body)
        except ValueError as exc:
            self._send_json(400, {"detail": str(exc), "server_time": _utc_now_iso()})
            return
        except Exception as exc:  # pragma: no cover
            self._send_json(
                500,
                {
                    "detail": f"failed to save config: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        analysis = saved["analysis"]
        msg = "saved"
        if analysis.get("restart_required"):
            msg = "saved (restart required to apply some changes)"
        elif analysis.get("reload_required"):
            msg = "saved (reload recommended to apply changes without downtime)"

        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "path": saved["cfg_path_abs"],
                "backed_up_to": saved["backup_path"],
                "message": msg,
                "analysis": analysis,
            },
        )

    def _handle_config_save_and_reload(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /config/save_and_reload to save and reload when possible.

        Inputs:
          - body: Parsed JSON object containing required 'raw_yaml' string field.

        Outputs:
          - JSON describing outcome (status, server_time, path, backed_up_to, reload).

        Notes:
          - If restart_required is detected, returns HTTP 409 and skips reload.
        """

        if not self._require_auth():
            return

        try:
            saved = self._save_config_to_disk(body=body)
        except ValueError as exc:
            self._send_json(400, {"detail": str(exc), "server_time": _utc_now_iso()})
            return
        except Exception as exc:  # pragma: no cover
            self._send_json(
                500,
                {
                    "detail": f"failed to save config: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        analysis = saved["analysis"]
        if analysis.get("restart_required"):
            self._send_json(
                409,
                {
                    "status": "error",
                    "server_time": _utc_now_iso(),
                    "path": saved["cfg_path_abs"],
                    "backed_up_to": saved["backup_path"],
                    "message": "saved but reload refused (restart required; call /restart or /config/save_and_restart)",
                    "analysis": analysis,
                },
            )
            return

        from foghorn import runtime_config as _runtime_config

        reload_res = _runtime_config.reload_from_disk(
            config_path=saved["cfg_path_abs"],
            mode="reload_only",
        )

        if reload_res.ok:
            try:
                snap = _runtime_config.get_runtime_snapshot()
                self._server().config = snap.cfg
                self._server().plugins = list(snap.plugins or [])
            except Exception:
                pass

        if reload_res.ok and reload_res.restart_required:
            self._send_json(
                409,
                {
                    "status": "error",
                    "server_time": _utc_now_iso(),
                    "path": saved["cfg_path_abs"],
                    "backed_up_to": saved["backup_path"],
                    "message": "saved but reload refused (restart required; call /restart or /config/save_and_restart)",
                    "analysis": analysis,
                    "reload": {
                        "ok": bool(reload_res.ok),
                        "generation": int(reload_res.generation),
                        "restart_required": bool(reload_res.restart_required),
                        "restart_reasons": list(reload_res.restart_reasons or []),
                        "error": reload_res.error,
                        "mode": "reload_only",
                    },
                },
            )
            return

        msg = "saved and reloaded" if reload_res.ok else "saved but reload failed"

        self._send_json(
            200 if reload_res.ok else 500,
            {
                "status": "ok" if reload_res.ok else "error",
                "server_time": _utc_now_iso(),
                "path": saved["cfg_path_abs"],
                "backed_up_to": saved["backup_path"],
                "message": msg,
                "analysis": analysis,
                "reload": {
                    "ok": bool(reload_res.ok),
                    "generation": int(reload_res.generation),
                    "restart_required": bool(reload_res.restart_required),
                    "restart_reasons": list(reload_res.restart_reasons or []),
                    "error": reload_res.error,
                    "mode": "reload_only",
                },
                "restart": {
                    "scheduled": bool(reload_res.ok and reload_res.restart_required),
                    "signal": (
                        "SIGHUP"
                        if reload_res.ok and reload_res.restart_required
                        else None
                    ),
                },
            },
        )

    def _handle_config_save_and_restart(self, body: dict[str, Any]) -> None:
        """Brief: Handle POST /config/save_and_restart to save config then restart.

        Inputs:
          - body: Parsed JSON object containing required 'raw_yaml' string field.

        Outputs:
          - JSON describing outcome (status, server_time, path, backed_up_to).
        """

        if not self._require_auth():
            return

        try:
            saved = self._save_config_to_disk(body=body)
        except ValueError as exc:
            self._send_json(400, {"detail": str(exc), "server_time": _utc_now_iso()})
            return
        except Exception as exc:  # pragma: no cover
            self._send_json(
                500,
                {
                    "detail": f"failed to save config: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        self._schedule_restart(delay_seconds=1.0)

        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "path": saved["cfg_path_abs"],
                "backed_up_to": saved["backup_path"],
                "message": "saved; restart scheduled (SIGHUP)",
                "analysis": saved["analysis"],
                "restart": {"scheduled": True, "signal": "SIGHUP"},
            },
        )

    def _handle_config_reload_reloadable(self) -> None:
        """Brief: Handle POST /reload_reloadable to apply a reload-only update.

        Inputs:
          - None (uses self._server().config_path).

        Outputs:
          - JSON describing outcome (status, server_time, path, reload).

        Notes:
          - Always attempts reload_from_config(mode='reload_only').
          - When restart_required is detected, reloadable settings are applied and
            the response includes restart_required=true so operators can restart
            later.
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

        cfg_path_abs = os.path.abspath(cfg_path)

        from foghorn import runtime_config as _runtime_config

        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_abs
            )
        except Exception as exc:
            self._send_json(
                400,
                {
                    "status": "error",
                    "server_time": _utc_now_iso(),
                    "path": cfg_path_abs,
                    "message": f"failed to parse/validate config: {exc}",
                },
            )
            return

        analysis = _runtime_config.analyze_config_change(
            desired_cfg,
            current_cfg=getattr(self._server(), "config", None) or {},
        )

        reload_res = _runtime_config.reload_from_config(desired_cfg, mode="reload_only")

        if reload_res.ok:
            try:
                snap = _runtime_config.get_runtime_snapshot()
                self._server().config = snap.cfg
                self._server().plugins = list(snap.plugins or [])
            except Exception:
                pass

        msg = "reloaded" if reload_res.ok else "reload failed"
        if reload_res.ok and analysis.get("restart_required"):
            msg = "reloaded reloadable settings (restart required for some changes)"

        payload = {
            "status": "ok" if reload_res.ok else "error",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "message": msg,
            "analysis": analysis,
            "reload": {
                "ok": bool(reload_res.ok),
                "generation": int(reload_res.generation),
                "restart_required": bool(reload_res.restart_required),
                "restart_reasons": list(reload_res.restart_reasons or []),
                "error": reload_res.error,
                "mode": "reload_only",
            },
        }

        self._send_json(200 if reload_res.ok else 500, payload)

    def _handle_config_reload(self) -> None:
        """Brief: Handle POST /config/reload to apply an in-process reload.

        Inputs:
          - None (uses self._server().config_path).

        Outputs:
          - JSON describing outcome (status, server_time, path, reload).

        Notes:
          - Refuses reload (HTTP 409) when a full restart is required.
          - Use /reload_reloadable to apply reloadable settings even when restart
            is required.
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

        cfg_path_abs = os.path.abspath(cfg_path)

        from foghorn import runtime_config as _runtime_config

        try:
            desired_cfg = _runtime_config.load_config_from_disk(
                config_path=cfg_path_abs
            )
        except Exception as exc:
            self._send_json(
                400,
                {
                    "status": "error",
                    "server_time": _utc_now_iso(),
                    "path": cfg_path_abs,
                    "message": f"failed to parse/validate config: {exc}",
                },
            )
            return

        analysis = _runtime_config.analyze_config_change(
            desired_cfg,
            current_cfg=getattr(self._server(), "config", None) or {},
        )

        if analysis.get("restart_required"):
            self._send_json(
                409,
                {
                    "status": "error",
                    "server_time": _utc_now_iso(),
                    "path": cfg_path_abs,
                    "message": "reload refused (restart required; call /restart)",
                    "analysis": analysis,
                },
            )
            return

        reload_res = _runtime_config.reload_from_config(desired_cfg, mode="reload_only")

        if reload_res.ok:
            try:
                snap = _runtime_config.get_runtime_snapshot()
                self._server().config = snap.cfg
                self._server().plugins = list(snap.plugins or [])
            except Exception:
                pass

        msg = "reloaded" if reload_res.ok else "reload failed"

        payload = {
            "status": "ok" if reload_res.ok else "error",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "message": msg,
            "analysis": analysis,
            "reload": {
                "ok": bool(reload_res.ok),
                "generation": int(reload_res.generation),
                "restart_required": bool(reload_res.restart_required),
                "restart_reasons": list(reload_res.restart_reasons or []),
                "error": reload_res.error,
                "mode": "reload_only",
            },
        }

        self._send_json(200 if reload_res.ok else 500, payload)

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

    def _config_flag_enabled(self, value: object) -> bool:
        """Brief: Normalize config flag values to booleans.

        Inputs:
          - value: Any scalar-like config value.

        Outputs:
          - bool: True for truthy values such as true/1/yes/on.
        """

        if isinstance(value, bool):
            return bool(value)
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "on"}
        return False

    def _plugin_api_disabled_names(self) -> set[str]:
        """Brief: Return plugin names where config.disable_api is enabled.

        Inputs:
          - None (reads server config and loaded plugins).

        Outputs:
          - set[str]: Plugin names whose API endpoints should be hidden.
        """

        cfg = getattr(self._server(), "config", None) or {}
        entries = cfg.get("plugins")
        if not isinstance(entries, list):
            return set()

        loaded_plugins = list(getattr(self._server(), "plugins", []) or [])
        disabled: set[str] = set()
        loaded_idx = 0
        for entry in entries:
            if not isinstance(entry, dict):
                continue

            entry_cfg = entry.get("config")
            cfg_enabled_obj: object | None = None
            disable_api_obj: object | None = None
            if isinstance(entry_cfg, dict):
                cfg_enabled_obj = entry_cfg.get("enabled")
                disable_api_obj = entry_cfg.get("disable_api")

            enabled_obj = (
                cfg_enabled_obj if cfg_enabled_obj is not None else entry.get("enabled")
            )
            if enabled_obj is not None and not self._config_flag_enabled(enabled_obj):
                continue

            if disable_api_obj is None:
                disable_api_obj = entry.get("disable_api")

            resolved_name = ""
            if loaded_idx < len(loaded_plugins):
                try:
                    resolved_name = str(
                        getattr(loaded_plugins[loaded_idx], "name", "") or ""
                    ).strip()
                except Exception:
                    resolved_name = ""
                loaded_idx += 1

            explicit_name = str(entry.get("name") or entry.get("id") or "").strip()
            plugin_name = resolved_name or explicit_name
            if plugin_name and self._config_flag_enabled(disable_api_obj):
                disabled.add(plugin_name)

        return disabled

    def _is_plugin_api_disabled(self, plugin_name: str) -> bool:
        """Brief: Return whether per-plugin API exposure is disabled.

        Inputs:
          - plugin_name: Plugin instance name.

        Outputs:
          - bool.
        """

        return str(plugin_name or "").strip() in self._plugin_api_disabled_names()

    def _filter_plugins_for_api(self, plugins_list: list[object]) -> list[object]:
        """Brief: Exclude plugins whose per-instance API is disabled.

        Inputs:
          - plugins_list: Loaded plugin instances.

        Outputs:
          - list[object]: Filtered plugin list.
        """

        disabled = self._plugin_api_disabled_names()
        if not disabled:
            return list(plugins_list or [])

        filtered: list[object] = []
        for plugin in plugins_list or []:
            try:
                name = str(getattr(plugin, "name", "") or "").strip()
            except Exception:
                name = ""
            if name and name in disabled:
                continue
            filtered.append(plugin)
        return filtered

    def _log_api_audit_event(
        self,
        *,
        method: str,
        path: str,
        params: dict[str, list[str]],
        duration_ms: float,
        error_text: str | None = None,
    ) -> None:
        """Brief: Persist one threaded API request audit row when configured.

        Inputs:
          - method: HTTP method.
          - path: Request path.
          - params: Query-parameter mapping.
          - duration_ms: Request duration in milliseconds.
          - error_text: Optional exception text.

        Outputs:
          - None.
        """

        audit_logger = getattr(self._server(), "api_request_audit_logger", None)
        if not isinstance(audit_logger, ApiRequestAuditLogger):
            return
        status_obj = getattr(self, "_last_status_code", None)
        status_code = int(status_obj) if isinstance(status_obj, int) else None
        body_obj = getattr(self, "_last_admin_json_body", None)
        headers_obj = {k: v for k, v in self.headers.items()}
        normalized_query: dict[str, Any] = {}
        for key, values in dict(params or {}).items():
            if isinstance(values, list):
                if not values:
                    normalized_query[str(key)] = ""
                else:
                    normalized_query[str(key)] = str(values[-1])
            elif values is None:
                normalized_query[str(key)] = ""
            else:
                normalized_query[str(key)] = str(values)

        audit_logger.log_event(
            method=method,
            path=path,
            query=normalized_query,
            headers=headers_obj,
            body=body_obj,
            status_code=status_code,
            duration_ms=float(duration_ms),
            client_ip=self._client_ip(),
            error_text=error_text,
        )

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
        ) as exc:  # pragma: nocover - [defensive: static file I/O race condition hard to test reliably]
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
    ) -> None:  # pragma: nocover - [low-level HTTP verb handler for fallback server]
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
        if not self._require_auth():
            return

        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )
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
        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )
        disabled = self._plugin_api_disabled_names()

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
                cache_name = str(getattr(cache, "name", "") or "").strip()
                if not cache_name or cache_name not in disabled:
                    plugins_list.append(cache)

        items = _admin_logic.collect_plugin_ui_descriptors(plugins_list)
        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "items": _json_safe(items),
            },
        )

    def _table_path_from_descriptor(
        self, desc: object, table_id: str
    ) -> tuple[str, str | None, str]:
        """Brief: Resolve a table section path and default sort from an admin descriptor.

        Inputs:
          - desc: Plugin/cache admin UI descriptor (dict-like).
          - table_id: Section id from the frontend.

        Outputs:
          - (path, default_sort_key, default_sort_dir)
        """

        table_id_norm = str(table_id or "").strip()
        default_sort_key: str | None = None
        default_sort_dir = "asc"

        if not isinstance(desc, dict):
            return table_id_norm, default_sort_key, default_sort_dir

        layout = desc.get("layout")
        if not isinstance(layout, dict):
            return table_id_norm, default_sort_key, default_sort_dir

        sections = layout.get("sections")
        if not isinstance(sections, list):
            return table_id_norm, default_sort_key, default_sort_dir

        for sec in sections:
            if not isinstance(sec, dict):
                continue
            if str(sec.get("id") or "") != table_id_norm:
                continue
            if str(sec.get("type") or "") != "table":
                continue

            path = str(sec.get("path") or "").strip()

            sort_hint = sec.get("sort")
            if sort_hint == "by_calls":
                default_sort_key = "calls_total"
                default_sort_dir = "desc"

            return path, default_sort_key, default_sort_dir

        return "", default_sort_key, default_sort_dir

    def _is_hex_hash_like(self, name: object) -> bool:
        """Brief: Return True for hash-like labels (12–64 hex characters).

        Inputs:
          - name: Hostname-like value; only the left-most label is inspected.

        Outputs:
          - bool: True when the first label looks like a short/long hex hash.
        """

        token = str(name or "").split(".", 1)[0].lower().strip()
        if len(token) < 12 or len(token) > 64:
            return False
        return all(ch in "0123456789abcdef" for ch in token)

    def _handle_cache_snapshot(self) -> None:
        """Brief: Handle GET /api/v1/cache.

        Inputs:
          - None (uses the global DNS cache instance).

        Outputs:
          - None (sends JSON response with cache snapshot or 404).
        """

        if not self._require_auth():
            return

        try:
            from ...plugins.resolve import base as plugin_base

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is None or not hasattr(cache, "get_http_snapshot"):
            self._send_json(
                404,
                {
                    "detail": "cache plugin not found or does not expose get_http_snapshot",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        try:
            snapshot = cache.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            self._send_json(
                500,
                {
                    "detail": f"failed to build cache snapshot: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        cache_name = getattr(cache, "name", None) or cache.__class__.__name__
        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "cache": str(cache_name),
                "data": _json_safe(snapshot),
            },
        )

    def _handle_cache_table(self, path: str, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/cache/table/{table_id}.

        Inputs:
          - path: Request path including the table_id segment.
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response with a paged table payload).
        """

        if not self._require_auth():
            return

        try:
            from ...plugins.resolve import base as plugin_base

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is None or not hasattr(cache, "get_http_snapshot"):
            self._send_json(
                404,
                {
                    "detail": "cache plugin not found or does not expose get_http_snapshot",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        prefix = "/api/v1/cache/table/"
        table_id_raw = path[len(prefix) :].strip("/")
        table_id = urllib.parse.unquote(table_id_raw)
        if not table_id:
            self._send_json(
                404,
                {"detail": "cache table not found", "server_time": _utc_now_iso()},
            )
            return

        try:
            snapshot = cache.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            self._send_json(
                500,
                {
                    "detail": f"failed to build cache snapshot: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        desc = None
        get_desc = getattr(cache, "get_admin_ui_descriptor", None)
        if callable(get_desc):
            try:
                desc = get_desc()
            except Exception:
                desc = None

        table_path, default_sort_key, default_sort_dir = (
            self._table_path_from_descriptor(desc, table_id)
        )
        if not table_path:
            self._send_json(
                404,
                {"detail": "cache table not found", "server_time": _utc_now_iso()},
            )
            return

        raw_rows = _admin_logic._resolve_path(snapshot, table_path)
        rows: list[dict[str, Any]] = (
            [r for r in (raw_rows or []) if isinstance(r, dict)]
            if isinstance(raw_rows, list)
            else []
        )

        if self._get_bool_param(params, "hide_zero_calls", False):
            rows = [
                r
                for r in rows
                if not (
                    isinstance(r.get("calls_total"), int)
                    and int(r.get("calls_total") or 0) == 0
                )
            ]
        if self._get_bool_param(params, "hide_zero_hits", False):
            rows = [
                r
                for r in rows
                if not (
                    isinstance(r.get("cache_hits"), int)
                    and int(r.get("cache_hits") or 0) == 0
                )
            ]

        payload = _admin_logic.build_table_page_payload(
            rows,
            page=self._get_int_param(params, "page", 1),
            page_size=self._get_int_param(params, "page_size", 50),
            sort_key=self._get_query_param(params, "sort_key"),
            sort_dir=self._get_query_param(params, "sort_dir"),
            search=self._get_query_param(params, "search"),
            hide_zero_calls=self._get_bool_param(params, "hide_zero_calls", False),
            hide_zero_hits=self._get_bool_param(params, "hide_zero_hits", False),
            show_down_services=True,
            hide_hash_like=False,
            default_sort_key=default_sort_key,
            default_sort_dir=default_sort_dir,
        )
        payload["server_time"] = _utc_now_iso()
        payload["table_id"] = str(table_id)
        self._send_json(200, payload)

    def _handle_plugin_table(self, path: str, params: dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/table/{table_id}.

        Inputs:
          - path: Request path containing plugin_name and table_id.
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response with a paged table payload).
        """

        if not self._require_auth():
            return

        prefix = "/api/v1/plugins/"
        suffix = "/table/"
        rest = path[len(prefix) :]
        if suffix not in rest:
            self._send_json(
                404,
                {"detail": "plugin table not found", "server_time": _utc_now_iso()},
            )
            return

        plugin_part, table_part = rest.split(suffix, 1)
        plugin_name = urllib.parse.unquote(plugin_part.strip("/"))
        table_id = urllib.parse.unquote(table_part.strip("/"))
        if not plugin_name or not table_id:
            self._send_json(
                404,
                {"detail": "plugin table not found", "server_time": _utc_now_iso()},
            )
            return
        if self._is_plugin_api_disabled(plugin_name):
            self._send_json(
                404,
                {
                    "detail": f"plugin API disabled for '{plugin_name}'",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )
        target = _admin_logic.find_plugin_instance_by_name(plugins_list, plugin_name)
        if target is None or not hasattr(target, "get_http_snapshot"):
            self._send_json(
                404,
                {
                    "detail": "plugin not found or does not expose get_http_snapshot",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        desc = None
        get_desc = getattr(target, "get_admin_ui_descriptor", None)
        if callable(get_desc):
            try:
                desc = get_desc()
            except Exception:
                desc = None

        table_path, default_sort_key, default_sort_dir = (
            self._table_path_from_descriptor(desc, table_id)
        )
        if not table_path:
            self._send_json(
                404,
                {"detail": "plugin table not found", "server_time": _utc_now_iso()},
            )
            return

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            self._send_json(
                500,
                {
                    "detail": f"failed to build plugin snapshot: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        raw_rows = _admin_logic._resolve_path(snapshot, table_path)
        rows: list[dict[str, Any]] = (
            [r for r in (raw_rows or []) if isinstance(r, dict)]
            if isinstance(raw_rows, list)
            else []
        )

        if self._get_bool_param(params, "hide_hash_like", False):
            rows = [r for r in rows if not self._is_hex_hash_like(r.get("name"))]

        payload = _admin_logic.build_table_page_payload(
            rows,
            page=self._get_int_param(params, "page", 1),
            page_size=self._get_int_param(params, "page_size", 50),
            sort_key=self._get_query_param(params, "sort_key"),
            sort_dir=self._get_query_param(params, "sort_dir"),
            search=self._get_query_param(params, "search"),
            hide_zero_calls=False,
            hide_zero_hits=False,
            show_down_services=True,
            hide_hash_like=self._get_bool_param(params, "hide_hash_like", False),
            default_sort_key=default_sort_key,
            default_sort_dir=default_sort_dir,
        )
        payload["server_time"] = _utc_now_iso()
        payload["plugin"] = str(plugin_name)
        payload["table_id"] = str(table_id)
        self._send_json(200, payload)

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
        if self._is_plugin_api_disabled(plugin_name):
            self._send_json(
                404,
                {
                    "detail": f"plugin API disabled for '{plugin_name}'",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )
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

    def _handle_plugin_api_get(self, path: str, params: dict[str, list[str]]) -> bool:
        """Brief: Handle expanded plugin GET endpoints under /api/v1/plugins/{name}/.

        Inputs:
          - path: Parsed URL path.
          - params: Query-string mapping from urllib.parse.parse_qs.

        Outputs:
          - bool: True when this method handled/sent a response.
        """

        prefix = "/api/v1/plugins/"
        if not path.startswith(prefix):
            return False

        rest = path[len(prefix) :]
        if "/" not in rest:
            return False
        plugin_part, endpoint_part = rest.split("/", 1)
        plugin_name = urllib.parse.unquote(plugin_part.strip("/"))
        endpoint = urllib.parse.unquote(endpoint_part.strip("/"))
        if not plugin_name or not endpoint:
            return False

        if not self._require_auth():
            return True
        if self._is_plugin_api_disabled(plugin_name):
            self._send_json(
                404,
                {
                    "detail": f"plugin API disabled for '{plugin_name}'",
                    "server_time": _utc_now_iso(),
                },
            )
            return True

        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )

        def _send_snapshot() -> None:
            try:
                snap = _admin_logic.build_plugin_snapshot_payload(
                    plugins_list, plugin_name
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
                    "plugin": snap.get("plugin"),
                    "data": _json_safe(snap.get("data")),
                },
            )

        if endpoint in {
            "snapshot",
            "access_control",
            "rate_limit",
            "docker_hosts",
            "etc_hosts",
            "mdns",
            "zone_records",
        }:
            _send_snapshot()
            return True

        try:
            if endpoint == "access_control/rules":
                payload = _admin_logic.build_plugin_access_control_rules_payload(
                    plugins_list, plugin_name
                )
            elif endpoint == "etc_hosts/lookup":
                payload = _admin_logic.build_plugin_etc_hosts_lookup_payload(
                    plugins_list,
                    plugin_name,
                    name=str(self._get_query_param(params, "name", "") or ""),
                )
            elif endpoint.startswith("docker_hosts/containers/"):
                container_name = endpoint[len("docker_hosts/containers/") :].strip()
                payload = _admin_logic.build_plugin_docker_container_payload(
                    plugins_list,
                    plugin_name,
                    name=container_name,
                )
            elif endpoint == "mdns/services":
                payload = _admin_logic.build_plugin_mdns_services_payload(
                    plugins_list,
                    plugin_name,
                    status=self._get_query_param(params, "status"),
                    service_type=self._get_query_param(params, "type"),
                )
            elif endpoint == "rate_limit/profiles":
                payload = _admin_logic.build_plugin_rate_limit_profiles_payload(
                    plugins_list,
                    plugin_name,
                    limit=self._get_int_param(params, "limit", 50),
                    sort=self._get_query_param(params, "sort"),
                )
            elif endpoint == "zone_records/lookup":
                payload = _admin_logic.build_plugin_zone_records_lookup_payload(
                    plugins_list,
                    plugin_name,
                    owner=str(self._get_query_param(params, "owner", "") or ""),
                    qtype=self._get_query_param(params, "qtype"),
                )
            elif endpoint.startswith("zone_records/dns_update/zones/"):
                zone = endpoint[len("zone_records/dns_update/zones/") :].strip()
                payload = (
                    _admin_logic.build_plugin_zone_records_dns_update_zone_payload(
                        plugins_list,
                        plugin_name,
                        zone=zone,
                    )
                )
            elif endpoint == "upstream_router/evaluate":
                payload = _admin_logic.build_plugin_upstream_evaluate_payload(
                    plugins_list,
                    plugin_name,
                    qname=str(self._get_query_param(params, "qname", "") or ""),
                )
            else:
                return False
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return True

        payload["server_time"] = _utc_now_iso()
        self._send_json(200, _json_safe(payload))
        return True

    def _handle_named_plugin_snapshot(
        self, path: str, *, suffix: str, label: str
    ) -> None:
        """Brief: Handle GET named-plugin snapshot endpoints with shared logic.

        Inputs:
          - path: Full request path.
          - suffix: Route suffix (for example '/docker_hosts').
          - label: Plugin label passed to build_named_plugin_snapshot().

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        if not self._require_auth():
            return
        prefix = "/api/v1/plugins/"
        raw_segment = path[len(prefix) : -len(str(suffix))]
        plugin_name = raw_segment.strip("/")
        if self._is_plugin_api_disabled(plugin_name):
            self._send_json(
                404,
                {
                    "detail": f"plugin API disabled for '{plugin_name}'",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label=label
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

    def _handle_plugin_api_post(self, path: str) -> bool:
        """Brief: Handle plugin POST endpoints under /api/v1/plugins/{name}/.

        Inputs:
          - path: Parsed URL path.

        Outputs:
          - bool: True when this method handled/sent a response.
        """

        prefix = "/api/v1/plugins/"
        if not path.startswith(prefix):
            return False

        rest = path[len(prefix) :]
        if "/" not in rest:
            return False
        plugin_part, endpoint_part = rest.split("/", 1)
        plugin_name = urllib.parse.unquote(plugin_part.strip("/"))
        endpoint = urllib.parse.unquote(endpoint_part.strip("/"))
        if not plugin_name or not endpoint:
            return False
        if not self._require_auth():
            return True
        if self._is_plugin_api_disabled(plugin_name):
            self._send_json(
                404,
                {
                    "detail": f"plugin API disabled for '{plugin_name}'",
                    "server_time": _utc_now_iso(),
                },
            )
            return True

        plugins_list = self._filter_plugins_for_api(
            getattr(self._server(), "plugins", []) or []
        )
        try:
            if endpoint in {"etc_hosts/reload", "docker_hosts/reload"}:
                plugin_kind = (
                    "etc_hosts" if endpoint.startswith("etc_hosts/") else "docker_hosts"
                )
                payload = _admin_logic.build_plugin_reload_payload(
                    plugins_list,
                    plugin_name,
                    plugin_kind=plugin_kind,
                )
            elif endpoint == "zone_records/reload":
                payload = _admin_logic.build_plugin_reload_payload(
                    plugins_list,
                    plugin_name,
                    plugin_kind="zone_records",
                )
            elif endpoint == "zone_records/compact":
                body = self._read_admin_json_body()
                if body is None:
                    return True
                zone_raw = body.get("zone")
                if zone_raw is not None and not isinstance(zone_raw, str):
                    self._send_json(
                        400,
                        {
                            "detail": "zone must be a string",
                            "server_time": _utc_now_iso(),
                        },
                    )
                    return True
                payload = _admin_logic.build_plugin_zone_records_compact_payload(
                    plugins_list,
                    plugin_name,
                    zone=(str(zone_raw) if isinstance(zone_raw, str) else None),
                )
            else:
                return False
        except _admin_logic.AdminLogicHttpError as exc:
            self._send_json(
                exc.status_code,
                {"detail": exc.detail, "server_time": _utc_now_iso()},
            )
            return True

        payload["server_time"] = _utc_now_iso()
        self._send_json(200, _json_safe(payload))
        return True

    def _handle_docker_hosts_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/docker_hosts.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        self._handle_named_plugin_snapshot(
            path,
            suffix="/docker_hosts",
            label="DockerHosts",
        )

    def _handle_mdns_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/mdns.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        self._handle_named_plugin_snapshot(
            path,
            suffix="/mdns",
            label="MdnsBridge",
        )

    def _handle_etc_hosts_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/etc_hosts.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        self._handle_named_plugin_snapshot(
            path,
            suffix="/etc_hosts",
            label="EtcHosts",
        )

    def _handle_access_control_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/access_control.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        self._handle_named_plugin_snapshot(
            path,
            suffix="/access_control",
            label="AccessControl",
        )

    def _handle_rate_limit_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/rate_limit.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        self._handle_named_plugin_snapshot(
            path,
            suffix="/rate_limit",
            label="RateLimit",
        )

    def do_GET(
        self,
    ) -> None:  # pragma: no cover - low-level HTTP verb handler for fallback server
        """Brief: Dispatch GET requests to admin endpoints.

        Inputs: none
        Outputs: None
        """

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        self._begin_api_audit_context(path=path, params=params)

        web_cfg = self._web_cfg()
        enable_api = bool(web_cfg.get("enable_api", False))
        enable_admin = bool(web_cfg.get("enable_admin", False))

        if not enable_api:
            # Keep a minimal surface when the admin API is disabled.
            # - Allow / and /index.html (static UI)
            # - Allow /docs and /openapi.json only when separately enabled
            # - Block all other known API endpoints (both /api/v1/* and short aliases)
            blocked_prefixes = (
                "/api/v1/",
                "/config",
                "/stats",
                "/traffic",
                "/health",
                "/about",
                "/ready",
                "/logs",
                "/query_log",
                "/reload",
                "/restart",
            )
            if path.startswith(blocked_prefixes):
                # /openapi.json and /docs are handled below and may still be enabled
                # even when the API is disabled.
                if path not in {"/openapi.json", "/docs", "/docs/oauth2-redirect"}:
                    self._send_text(404, "not found")
                    return
        elif not enable_admin and _is_control_plane_path(path):
            self._send_text(404, "not found")
            return

        def _handle_rate_limit_stats_get() -> None:
            """Brief: Handle GET /api/v1/ratelimit.

            Inputs: none
            Outputs: None (sends JSON response).
            """

            if not self._require_auth():
                return
            status_code, payload = _endpoint_services.build_rate_limit_result(
                config=getattr(self._server(), "config", None),
                plugins=getattr(self._server(), "plugins", None),
                collect_stats=_collect_rate_limit_stats,
            )
            self._send_json(int(status_code), payload)

        if path == "/api/v1/ratelimit":
            return _handle_rate_limit_stats_get()
        static_handler_name = self.HTTP_GET_MAP_STATIC.get(path)
        if static_handler_name:
            return getattr(self, static_handler_name)()
        param_handler_name = self.HTTP_GET_MAP_PARAM.get(path)
        if param_handler_name:
            return getattr(self, param_handler_name)(params)

        # Prefix and special routes
        if path.startswith("/api/v1/stats/table/"):
            return self._handle_stats_table(path, params)
        if path.startswith("/api/v1/cache/table/"):
            return self._handle_cache_table(path, params)
        if path.startswith("/api/v1/plugins/") and "/table/" in path:
            return self._handle_plugin_table(path, params)

        def _dispatch_if_path_matches(
            route_paths: set[str],
            handler: Any,
            *,
            pass_params: bool = False,
        ) -> bool:
            """Brief: Invoke handler when the request path matches any alias.

            Inputs:
              - route_paths: Alias paths that map to one handler.
              - handler: Bound handler callable to invoke.
              - pass_params: Whether to pass parsed query parameters.

            Outputs:
              - True when a matching route was dispatched, else False.
            """

            if path not in route_paths:
                return False
            if pass_params:
                handler(params)
            else:
                handler()
            return True

        if _dispatch_if_path_matches(
            {"/traffic", "/api/v1/traffic"},
            self._handle_traffic,
            pass_params=True,
        ):
            return
        if _dispatch_if_path_matches(
            {"/config", "/api/v1/config"}, self._handle_config
        ):
            return
        if _dispatch_if_path_matches(
            {"/config.json", "/api/v1/config.json"},
            self._handle_config_json,
        ):
            return
        if _dispatch_if_path_matches(
            {"/config/raw", "/api/v1/config/raw"},
            self._handle_config_raw,
        ):
            return
        if _dispatch_if_path_matches(
            {"/config/raw.json", "/api/v1/config/raw.json"},
            self._handle_config_raw_json,
        ):
            return
        if _dispatch_if_path_matches(
            {"/config/schema", "/api/v1/config/schema"},
            self._handle_config_schema,
        ):
            return
        if _dispatch_if_path_matches(
            {"/api/v1/config/diagram.png", "/config/diagram.png"},
            self._handle_config_diagram_png,
            pass_params=True,
        ):
            return
        if _dispatch_if_path_matches(
            {"/api/v1/config/diagram-dark.png", "/config/diagram-dark.png"},
            self._handle_config_diagram_png_dark,
            pass_params=True,
        ):
            return
        if _dispatch_if_path_matches(
            {"/api/v1/config/diagram.dot", "/config/diagram.dot"},
            self._handle_config_diagram_dot,
            pass_params=True,
        ):
            return
        if _dispatch_if_path_matches(
            {"/logs", "/api/v1/logs"},
            self._handle_logs,
            pass_params=True,
        ):
            return
        if _dispatch_if_path_matches(
            {"/query_log", "/api/v1/query_log"},
            self._handle_query_log,
            pass_params=True,
        ):
            return
        if _dispatch_if_path_matches(
            {"/api/v1/query_log/aggregate", "/query_log/aggregate"},
            self._handle_query_log_aggregate,
            pass_params=True,
        ):
            return
        if path.startswith("/api/v1/plugin_pages/"):
            return self._handle_plugin_page_detail_route(path)
        # plugin named snapshots and plugin-specific suffix-based routes
        for suffix, label in [
            ("/docker_hosts", "DockerHosts"),
            ("/mdns", "MdnsBridge"),
            ("/etc_hosts", "EtcHosts"),
            ("/access_control", "AccessControl"),
            ("/rate_limit", "RateLimit"),
        ]:
            if path.startswith("/api/v1/plugins/") and path.endswith(suffix):
                return self._handle_named_plugin_snapshot(
                    path, suffix=suffix, label=label
                )
        # plugin expanded GET handlers
        if self._handle_plugin_api_get(path, params):
            return
        # fallback to static
        if self._try_serve_www(path):
            return
        self._send_text(404, "not found")

    def do_POST(
        self,
    ) -> None:  # pragma: no cover - low-level HTTP verb handler for fallback server
        """Brief: Dispatch POST requests to admin endpoints.

        Inputs: none
        Outputs: None
        """

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)
        self._begin_api_audit_context(path=path, params=params)

        web_cfg = self._web_cfg()
        enable_api = bool(web_cfg.get("enable_api", False))
        enable_admin = bool(web_cfg.get("enable_admin", False))

        if not enable_api:
            self._send_text(404, "not found")
            return
        if not enable_admin and _is_control_plane_path(path):
            self._send_text(404, "not found")
            return

        def _dispatch_json_body(handler: Any) -> None:
            """Brief: Parse JSON body and call a one-arg handler.

            Inputs:
              - handler: Callable that accepts parsed body dict.

            Outputs:
              - None.
            """

            body = self._read_admin_json_body()
            if body is None:
                return
            handler(body)

        def _read_authed_admin_json_body() -> dict[str, Any] | None:
            """Brief: Enforce auth then parse bounded JSON request body.

            Inputs: none.
            Outputs: Parsed body dict or None when request handling already replied.
            """

            if not self._require_auth():
                return None
            return self._read_admin_json_body()

        post_no_body_handler_name = self.HTTP_POST_MAP_NO_BODY.get(path)
        if post_no_body_handler_name:
            return getattr(self, post_no_body_handler_name)()
        post_json_handler_name = self.HTTP_POST_MAP_JSON_BODY.get(path)
        if post_json_handler_name:
            return _dispatch_json_body(getattr(self, post_json_handler_name))
        if path.startswith("/api/v1/admin/records/"):
            suffix = path[len("/api/v1/admin/records/") :]
            parts = [p for p in suffix.split("/") if p]
            if len(parts) != 2:
                self._send_text(404, "not found")
                return
            target, action = parts[0], parts[1]
            body = self._read_admin_json_body()
            if body is None:
                return
            self._handle_admin_records_action(target=target, action=action, body=body)
            return
        if path in {"/api/v1/config/diagram.png", "/config/diagram.png"}:
            if not self._require_auth():
                return
            raw_body = self._read_request_body_limited(
                max_bytes=1_001_024,
                too_large_detail="file too large (max 1,000,000 bytes)",
            )
            if raw_body is None:
                return
            self._handle_config_diagram_png_upload(raw_body)
            return
        if path in {
            "/config/save",
            "/api/v1/config/save",
            "/config/save_and_reload",
            "/api/v1/config/save_and_reload",
            "/config/save_and_restart",
            "/api/v1/config/save_and_restart",
        }:
            body = _read_authed_admin_json_body()
            if body is None:
                return
            config_save_handlers: dict[str, Any] = {
                "/config/save": self._handle_config_save,
                "/api/v1/config/save": self._handle_config_save,
                "/config/save_and_reload": self._handle_config_save_and_reload,
                "/api/v1/config/save_and_reload": self._handle_config_save_and_reload,
                "/config/save_and_restart": self._handle_config_save_and_restart,
                "/api/v1/config/save_and_restart": self._handle_config_save_and_restart,
            }
            handler = config_save_handlers.get(path)
            if handler is None:
                self._send_text(404, "not found")
                return
            handler(body)
            return
        if path in {"/restart", "/api/v1/restart"}:
            body = _read_authed_admin_json_body()
            if body is None:
                return
            delay_seconds = 1.0
            try:
                delay_seconds = float(body.get("delay_seconds", delay_seconds))
            except Exception:
                delay_seconds = 1.0
            self._schedule_restart(delay_seconds=delay_seconds)
            self._send_json(
                200,
                {
                    "status": "ok",
                    "server_time": _utc_now_iso(),
                    "message": f"restart scheduled via SIGHUP (delay_seconds={delay_seconds})",
                    "restart": {
                        "scheduled": True,
                        "signal": "SIGHUP",
                        "delay_seconds": float(delay_seconds),
                    },
                },
            )
            return
        if self._handle_plugin_api_post(path):
            return
        self._send_text(404, "not found")

    def log_message(
        self, format: str, *args: Any
    ) -> None:  # pragma: no cover - logging-only fallback path
        """Brief: Suppress BaseHTTPRequestHandler's default request logging.

        Note: This implementation is intentionally quiet (no-op) during normal
        request handling. If string formatting fails, it logs the raw message at
        DEBUG level as a best-effort fallback.

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
