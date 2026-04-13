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
from datetime import datetime, timezone

# Forward declaration - _AdminHTTPServer is defined in server_management
from typing import TYPE_CHECKING, Any, Dict, Optional

import yaml
from ...config.config_schema import get_default_schema_path
from ...security_limits import MAX_ADMIN_JSON_BODY_BYTES, maybe_parse_content_length

from ...stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from ...utils.config_diagram import (
    diagram_dark_png_candidate_paths_for_config,
    diagram_dot_candidate_paths_for_config,
    diagram_png_candidate_paths_for_config,
    find_first_existing_path,
    generate_dot_text_from_config_path,
    stale_diagram_warning,
)
from ..udp_server import DNSUDPHandler
from . import admin_logic as _admin_logic
from . import config_persistence as _config_persistence
from .config_helpers import (
    _get_config_raw_json,
    _get_config_raw_text,
    _get_redact_keys,
    _get_sanitized_config_yaml_cached,
    _get_web_cfg,
    _parse_utc_datetime,
    sanitize_config,
)
from .http_helpers import (
    _evaluate_web_auth,
    _json_safe,
    _schedule_process_signal,
    resolve_www_root,
)
from .logging_utils import RingBuffer
from .meta_helpers import FOGHORN_VERSION, _get_about_payload
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
        self,
        status_code: int,
        text: str,
        headers: Dict[str, str] | None = None,
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
        self.send_response(status_code)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
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
                "Client disconnected while sending text response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _get_query_param(
        self,
        params: Dict[str, list[str]],
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
        params: Dict[str, list[str]],
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
        params: Dict[str, list[str]],
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
    ) -> None:  # pragma: nocover - [low-level HTTP I/O helper tested via FastAPI]
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

    def _get_openapi_schema_cached(self) -> Dict[str, Any] | None:
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
        setattr(server, "_openapi_schema_cache", schema)
        return schema

    def _handle_openapi_json(self) -> None:
        """Brief: Handle GET /openapi.json.

        Inputs: none
        Outputs: None (writes JSON response).
        """

        web_cfg = self._web_cfg()
        if not bool(web_cfg.get("enable_schema", True)):
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
        if not bool(web_cfg.get("enable_docs", True)) or not bool(
            web_cfg.get("enable_schema", True)
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
        if not bool(web_cfg.get("enable_docs", True)) or not bool(
            web_cfg.get("enable_schema", True)
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

    def _handle_stats_table(self, path: str, params: Dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/stats/table/{table_id}.

        Inputs:
          - path: Request path including the table_id segment.
          - params: Query parameters mapping.

        Outputs:
          - None (sends JSON response with a paged table payload).
        """

        if not self._require_auth():
            return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
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

        def _pairs_to_rows(pairs: object) -> list[dict[str, object]]:
            out: list[dict[str, object]] = []
            if not isinstance(pairs, list):
                return out
            for item in pairs:
                if not isinstance(item, (list, tuple)) or len(item) < 2:
                    continue
                name, count = item[0], item[1]
                try:
                    count_i = int(count)
                except Exception:
                    continue
                out.append({"name": str(name), "count": count_i})
            return out

        group_key = self._get_query_param(params, "group_key")
        tid = str(table_id).strip()

        rows: list[dict[str, object]]
        if tid in {
            "top_clients",
            "top_domains",
            "top_subdomains",
            "cache_hit_domains",
            "cache_miss_domains",
            "cache_hit_subdomains",
            "cache_miss_subdomains",
        }:
            pairs = getattr(snap, tid, None)
            rows = _pairs_to_rows(pairs)
        elif tid in {"qtype_qnames", "rcode_domains", "rcode_subdomains"}:
            if not group_key:
                self._send_json(
                    400,
                    {
                        "detail": "group_key is required for grouped stats tables",
                        "server_time": _utc_now_iso(),
                    },
                )
                return
            mapping = getattr(snap, tid, None)
            if not isinstance(mapping, dict):
                rows = []
            else:
                rows = _pairs_to_rows(mapping.get(str(group_key)))
        else:
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

        Inputs:
          - params: Query string parameters mapping

        Outputs:
          - None (sends JSON response).
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
        """Brief: Handle GET /config.json (sanitized JSON config).

        Inputs:
          - None (uses in-memory server config).

        Outputs:
          - JSON payload containing server_time and sanitized config mapping.
        """

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
        """Brief: Handle GET /config/raw to return on-disk configuration as raw YAML.

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

        schema_path_str = "<unknown>"
        try:
            schema_path = get_default_schema_path()
            schema_path_str = str(schema_path)
            with schema_path.open("r", encoding="utf-8") as f:
                schema = json.load(f)
        except Exception as exc:  # pragma: no cover - environment-specific I/O
            self._send_json(
                500,
                {
                    "detail": f"failed to read config schema from {schema_path_str}: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "schema_path": schema_path_str,
                "schema": schema,
            },
        )

    def _handle_config_diagram_png(self, params: Dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/config/diagram.png.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends image/png body when present).
          - When meta=1 is provided, sends an empty 200 with:
              - X-Foghorn-Exists: '1' or '0'
              - X-Foghorn-Warning (optional)
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

        # Allow a best-effort on-demand build attempt, but only once per config
        # signature for this process.
        try:
            st = os.stat(str(cfg_path))
            cfg_sig = f"{cfg_path}:{int(st.st_mtime_ns)}:{int(st.st_size)}"
        except Exception:
            cfg_sig = str(cfg_path)

        attempted_sig = getattr(
            self._server(), "_config_diagram_build_attempt_sig", None
        )

        png_file = find_first_existing_path(
            diagram_png_candidate_paths_for_config(cfg_path)
        )

        # If missing and dot exists, attempt an on-demand build once.
        if png_file is None and attempted_sig != cfg_sig:
            try:
                from ...utils.config_diagram import (
                    _find_dot_cmd,
                    ensure_config_diagram_png,
                )

                if _find_dot_cmd() is not None:
                    setattr(
                        self._server(), "_config_diagram_build_attempt_sig", cfg_sig
                    )
                    ensure_config_diagram_png(config_path=str(cfg_path))
                    png_file = find_first_existing_path(
                        diagram_png_candidate_paths_for_config(cfg_path)
                    )
            except Exception:
                pass

        warn: str | None = None
        if png_file is not None:
            warn = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(png_file)
            )

            # If stale and dot exists, try to refresh the PNG in-place once.
            if (
                warn
                and getattr(self._server(), "_config_diagram_build_attempt_sig", None)
                != cfg_sig
            ):
                try:
                    from ...utils.config_diagram import (
                        _find_dot_cmd,
                        ensure_config_diagram_png,
                    )

                    if _find_dot_cmd() is not None:
                        setattr(
                            self._server(), "_config_diagram_build_attempt_sig", cfg_sig
                        )
                        ok, _detail, refreshed = ensure_config_diagram_png(
                            config_path=str(cfg_path)
                        )
                        if ok and refreshed:
                            from pathlib import Path

                            png_file = Path(str(refreshed))
                            warn = stale_diagram_warning(
                                config_path=str(cfg_path), diagram_path=str(png_file)
                            )
                except Exception:
                    # Non-fatal: prefer serving the existing file.
                    pass

        headers: dict[str, str] = {
            "X-Foghorn-Exists": "1" if png_file is not None else "0",
        }

        if warn:
            headers["X-Foghorn-Warning"] = warn

        meta_only = False
        try:
            meta_only = bool(
                params.get("meta")
                and str(params.get("meta")[0]) not in {"", "0", "false"}
            )
        except Exception:
            meta_only = False

        if meta_only:
            self._send_text(200, "", headers=headers)
            return

        if png_file is None:
            self._send_text(404, "config diagram not found")
            return

        try:
            with open(str(png_file), "rb") as f:
                data = f.read()
        except Exception as exc:  # pragma: no cover - environment specific
            self._send_text(500, f"failed to read diagram: {exc}")
            return

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

    def _handle_config_diagram_png_dark(self, params: Dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/config/diagram-dark.png.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends image/png body when present).
          - When meta=1 is provided, sends an empty 200 with:
              - X-Foghorn-Exists: '1' or '0'
              - X-Foghorn-Warning (optional)
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

        # Allow a best-effort on-demand build attempt, but only once per config signature.
        try:
            st = os.stat(str(cfg_path))
            cfg_sig = f"{cfg_path}:{int(st.st_mtime_ns)}:{int(st.st_size)}"
        except Exception:
            cfg_sig = str(cfg_path)

        attempted_sig = getattr(
            self._server(), "_config_diagram_build_attempt_sig", None
        )

        png_file = find_first_existing_path(
            diagram_dark_png_candidate_paths_for_config(cfg_path)
        )

        # If missing and dot exists, attempt an on-demand build once.
        if png_file is None and attempted_sig != cfg_sig:
            try:
                from ...utils.config_diagram import (
                    _find_dot_cmd,
                    ensure_config_diagram_png,
                )

                if _find_dot_cmd() is not None:
                    setattr(
                        self._server(), "_config_diagram_build_attempt_sig", cfg_sig
                    )
                    ensure_config_diagram_png(config_path=str(cfg_path))
                    png_file = find_first_existing_path(
                        diagram_dark_png_candidate_paths_for_config(cfg_path)
                    )
            except Exception:
                pass

        warn: str | None = None
        if png_file is not None:
            warn = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(png_file)
            )

        headers: dict[str, str] = {
            "X-Foghorn-Exists": "1" if png_file is not None else "0",
        }
        if warn:
            headers["X-Foghorn-Warning"] = warn

        meta_only = False
        try:
            meta_only = bool(
                params.get("meta")
                and str(params.get("meta")[0]) not in {"", "0", "false"}
            )
        except Exception:
            meta_only = False

        if meta_only:
            self._send_text(200, "", headers=headers)
            return

        if png_file is None:
            self._send_text(404, "config diagram not found")
            return

        try:
            with open(str(png_file), "rb") as f:
                data = f.read()
        except Exception as exc:  # pragma: no cover
            self._send_text(500, f"failed to read diagram: {exc}")
            return

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
        except BrokenPipeError:  # pragma: no cover
            logger.warning(
                "Client disconnected while sending diagram for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

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

        cfg_path = getattr(self._server(), "config_path", None)
        if not cfg_path:
            self._send_json(
                500,
                {"detail": "config_path not configured", "server_time": _utc_now_iso()},
            )
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

    def _handle_config_diagram_dot(self, params: Dict[str, list[str]]) -> None:
        """Brief: Handle GET /api/v1/config/diagram.dot.

        Inputs:
          - params: Query parameters mapping.

        Outputs:
          - None (sends dot text).
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

        headers: dict[str, str] = {}

        png_file = find_first_existing_path(
            diagram_png_candidate_paths_for_config(cfg_path)
        )
        if png_file is not None:
            warn_png = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(png_file)
            )
            if warn_png:
                headers["X-Foghorn-Warning"] = warn_png

        dot_file = find_first_existing_path(
            diagram_dot_candidate_paths_for_config(cfg_path)
        )
        if dot_file is not None:
            warn_dot = stale_diagram_warning(
                config_path=str(cfg_path), diagram_path=str(dot_file)
            )
            if warn_dot and "X-Foghorn-Warning" not in headers:
                headers["X-Foghorn-Warning"] = warn_dot

        meta_only = False
        try:
            meta_only = bool(
                params.get("meta")
                and str(params.get("meta")[0]) not in {"", "0", "false"}
            )
        except Exception:
            meta_only = False

        if meta_only:
            self._send_text(200, "", headers=headers)
            return

        if dot_file is not None:
            try:
                text = dot_file.read_text(encoding="utf-8")
            except Exception as exc:  # pragma: no cover - environment dependent
                self._send_text(
                    500, f"failed to read config diagram from {dot_file}: {exc}"
                )
                return
            self._send_text(200, text, headers=headers)
            return

        try:
            text = generate_dot_text_from_config_path(str(cfg_path))
        except Exception as exc:  # pragma: no cover - environment dependent
            self._send_text(500, f"failed to generate config diagram: {exc}")
            return

        self._send_text(200, text, headers=headers)

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
            status=str(status) if status is not None else None,
            source=str(source) if source is not None else None,
            ede_code=str(ede_code) if ede_code is not None else None,
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

    def _schedule_restart(self, *, delay_seconds: float = 1.0) -> None:
        """Brief: Schedule a process restart by delivering SIGHUP.

        Inputs:
          - delay_seconds: Delay before sending SIGHUP so HTTP responses can flush.

        Outputs:
          - None.
        """

        _schedule_process_signal(signal.SIGHUP, delay_seconds=float(delay_seconds))

    def _save_config_to_disk(self, *, body: Dict[str, Any]) -> Dict[str, Any]:
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
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-")
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
        self, body: Dict[str, Any]
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

    def _handle_config_save_and_reload(self, body: Dict[str, Any]) -> None:
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
                setattr(self._server(), "config", snap.cfg)
                setattr(self._server(), "plugins", list(snap.plugins or []))
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

    def _handle_config_save_and_restart(self, body: Dict[str, Any]) -> None:
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
                setattr(self._server(), "config", snap.cfg)
                setattr(self._server(), "plugins", list(snap.plugins or []))
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
                setattr(self._server(), "config", snap.cfg)
                setattr(self._server(), "plugins", list(snap.plugins or []))
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
    ) -> (
        None
    ):  # noqa: N802  # pragma: nocover - [low-level HTTP verb handler for fallback server]
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

    def _handle_cache_table(self, path: str, params: Dict[str, list[str]]) -> None:
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

    def _handle_plugin_table(self, path: str, params: Dict[str, list[str]]) -> None:
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

        plugins_list = getattr(self._server(), "plugins", []) or []
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

    def _handle_access_control_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/access_control.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        if not self._require_auth():
            return
        prefix = "/api/v1/plugins/"
        suffix = "/access_control"
        raw_segment = path[len(prefix) : -len(suffix)]
        plugin_name = raw_segment.strip("/")
        plugins_list = getattr(self._server(), "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="AccessControl"
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

    def _handle_rate_limit_snapshot(self, path: str) -> None:
        """Brief: Handle GET /api/v1/plugins/{plugin_name}/rate_limit.

        Inputs:
          - path: Request path including the plugin_name segment.

        Outputs:
          - None (sends JSON response with snapshot or error).
        """

        if not self._require_auth():
            return
        prefix = "/api/v1/plugins/"
        suffix = "/rate_limit"
        raw_segment = path[len(prefix) : -len(suffix)]
        plugin_name = raw_segment.strip("/")
        plugins_list = getattr(self._server(), "plugins", []) or []
        try:
            snap = _admin_logic.build_named_plugin_snapshot(
                plugins_list, plugin_name, label="RateLimit"
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

        web_cfg = self._web_cfg()
        enable_api = bool(web_cfg.get("enable_api", True))

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

        if path == "/openapi.json":
            self._handle_openapi_json()
        elif path == "/docs":
            self._handle_docs()
        elif path == "/docs/oauth2-redirect":
            self._handle_docs_oauth2_redirect()
        elif path in {"/health", "/api/v1/health"}:
            self._handle_health()
        elif path in {"/about", "/api/v1/about"}:
            self._handle_about()
        elif path in {"/ready", "/api/v1/ready"}:
            self._handle_ready()
        elif path in {"/stats", "/api/v1/stats"}:
            self._handle_stats(params)
        elif path.startswith("/api/v1/stats/table/"):
            self._handle_stats_table(path, params)
        elif path == "/api/v1/cache":
            self._handle_cache_snapshot()
        elif path.startswith("/api/v1/cache/table/"):
            self._handle_cache_table(path, params)
        elif path.startswith("/api/v1/plugins/") and "/table/" in path:
            self._handle_plugin_table(path, params)
        elif path in {"/traffic", "/api/v1/traffic"}:
            self._handle_traffic(params)
        elif path in {"/config", "/api/v1/config"}:
            self._handle_config()
        elif path in {"/config.json", "/api/v1/config.json"}:
            self._handle_config_json()
        elif path in {"/config/raw", "/api/v1/config/raw"}:
            self._handle_config_raw()
        elif path in {"/config/raw.json", "/api/v1/config/raw.json"}:
            self._handle_config_raw_json()
        elif path in {"/config/schema", "/api/v1/config/schema"}:
            self._handle_config_schema()
        elif path in {"/api/v1/config/diagram.png", "/config/diagram.png"}:
            self._handle_config_diagram_png(params)
        elif path in {"/api/v1/config/diagram-dark.png", "/config/diagram-dark.png"}:
            self._handle_config_diagram_png_dark(params)
        elif path in {"/api/v1/config/diagram.dot", "/config/diagram.dot"}:
            self._handle_config_diagram_dot(params)
        elif path in {"/logs", "/api/v1/logs"}:
            self._handle_logs(params)
        elif path in {"/query_log", "/api/v1/query_log"}:
            self._handle_query_log(params)
        elif path in {"/api/v1/query_log/aggregate", "/query_log/aggregate"}:
            self._handle_query_log_aggregate(params)
        elif path == "/api/v1/upstream_status":
            self._handle_upstream_status()
        elif path == "/api/v1/ratelimit":
            if not self._require_auth():
                return
            # Rate-limit statistics are derived from config and sqlite profile DBs.
            cfg = getattr(self._server(), "config", None)
            plugins_list = getattr(self._server(), "plugins", None)
            data = _collect_rate_limit_stats(cfg, plugins=plugins_list)
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
        elif path.startswith("/api/v1/plugins/") and path.endswith("/access_control"):
            self._handle_access_control_snapshot(path)
        elif path.startswith("/api/v1/plugins/") and path.endswith("/rate_limit"):
            self._handle_rate_limit_snapshot(path)
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

        web_cfg = self._web_cfg()
        enable_api = bool(web_cfg.get("enable_api", True))

        if not enable_api:
            self._send_text(404, "not found")
            return

        if path in {"/stats/reset", "/api/v1/stats/reset"}:
            self._handle_stats_reset()
        elif path in {"/api/v1/config/diagram.png", "/config/diagram.png"}:
            if not self._require_auth():
                return
            raw_body = self._read_request_body_limited(
                max_bytes=1_001_024,
                too_large_detail="file too large (max 1,000,000 bytes)",
            )
            if raw_body is None:
                return
            self._handle_config_diagram_png_upload(raw_body)
        elif path in {
            "/config/save",
            "/api/v1/config/save",
            "/config/save_and_reload",
            "/api/v1/config/save_and_reload",
            "/config/save_and_restart",
            "/api/v1/config/save_and_restart",
        }:
            if not self._require_auth():
                return
            raw_body = self._read_request_body_limited(
                max_bytes=int(MAX_ADMIN_JSON_BODY_BYTES),
                too_large_detail=(
                    f"request body too large (max {int(MAX_ADMIN_JSON_BODY_BYTES):,} bytes)"
                ),
            )
            if raw_body is None:
                return
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
            if path in {"/config/save", "/api/v1/config/save"}:
                self._handle_config_save(body)
            elif path in {"/config/save_and_reload", "/api/v1/config/save_and_reload"}:
                self._handle_config_save_and_reload(body)
            else:
                self._handle_config_save_and_restart(body)
        elif path in {
            "/config/reload",
            "/api/v1/config/reload",
            "/reload",
            "/api/v1/reload",
        }:
            self._handle_config_reload()
        elif path in {
            "/config/reload_reloadable",
            "/api/v1/config/reload_reloadable",
            "/reload_reloadable",
            "/api/v1/reload_reloadable",
        }:
            self._handle_config_reload_reloadable()
        elif path in {"/restart", "/api/v1/restart"}:
            if not self._require_auth():
                return
            raw_body = self._read_request_body_limited(
                max_bytes=int(MAX_ADMIN_JSON_BODY_BYTES),
                too_large_detail=(
                    f"request body too large (max {int(MAX_ADMIN_JSON_BODY_BYTES):,} bytes)"
                ),
            )
            if raw_body is None:
                return
            delay_seconds = 1.0
            if raw_body:
                try:
                    body = json.loads(raw_body.decode("utf-8") or "{}")
                except Exception:
                    body = {}
                if isinstance(body, dict):
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
        else:
            self._send_text(404, "not found")

    def log_message(
        self, format: str, *args: Any
    ) -> None:  # noqa: A003  # pragma: no cover - logging-only fallback path
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
