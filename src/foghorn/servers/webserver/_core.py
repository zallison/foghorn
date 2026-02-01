"""Admin HTTP server for Foghorn (statistics, config, logs, health).

This module provides a small FastAPI application and helpers to run it in a
background thread alongside the main DNS listeners.

All handlers return JSON data structures (never raw JSON strings) and are
backed by the in-process StatsCollector and current configuration dict.
"""

from __future__ import annotations

import copy
import dataclasses
import http.server
import importlib.metadata as importlib_metadata
import json
import logging
import mimetypes
import os
import re
import shutil
import signal
import socket
import sqlite3
import threading
import time
import urllib.parse
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
import yaml
from cachetools import TTLCache
from foghorn.utils.register_caches import registered_cached, registered_lru_cached
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    PlainTextResponse,
)
from pydantic import BaseModel

from .meta_helpers import (
    _get_about_payload,
    _get_package_build_info,
    FOGHORN_VERSION,
    _GITHUB_URL,
)
from .http_helpers import (
    _build_auth_dependency,
    _json_safe,
    _schedule_sighup_after_config_save,
    resolve_www_root,
)
from .rate_limit_helpers import _collect_rate_limit_stats
from .types_and_buffers import LogEntry, WebServerHandle

from .logging_utils import (
    RingBuffer,
    _Suppress2xxAccessFilter,
    install_uvicorn_2xx_suppression,
)

# Helper modules split out from this monolithic implementation; we import and
# re-export their symbols so that tests and callers can continue to access them
# via ``foghorn.servers.webserver``.
from .runtime import (
    _ListenerRuntime,
    RuntimeState,
    _thread_is_alive,
    _expected_listeners_from_config,
    evaluate_readiness,
)
from .config_helpers import (
    _get_web_cfg,
    _get_redact_keys,
    _split_yaml_value_and_comment,
    _redact_yaml_text_preserving_layout,
    _get_config_raw_text,
    _get_config_raw_json,
    _ts_to_utc_iso,
    _parse_utc_datetime,
    sanitize_config,
    _get_sanitized_config_yaml_cached,
)
from . import config_helpers as _config_helpers
from . import stats_helpers as _stats_helpers
from .stats_helpers import (
    _trim_top_fields,
    _build_stats_payload_from_snapshot,
    _build_traffic_payload_from_snapshot,
    _get_stats_snapshot_cached,
    get_system_info,
    _read_proc_meminfo,
    _find_rate_limit_db_paths_from_config,
    _utc_now_iso,
)

# Re-export stats snapshot cache internals so tests can configure and inspect
# them via foghorn.servers.webserver.
_STATS_SNAPSHOT_CACHE_TTL_SECONDS = _stats_helpers._STATS_SNAPSHOT_CACHE_TTL_SECONDS
_STATS_SNAPSHOT_CACHE_LOCK = _stats_helpers._STATS_SNAPSHOT_CACHE_LOCK
_last_stats_snapshots = _stats_helpers._last_stats_snapshots

# Re-export system info cache TTL for tests that tune and assert on it. The
# canonical value still lives in stats_helpers; get_system_info() reads the
# value from this module when available.
_SYSTEM_INFO_CACHE_TTL_SECONDS = _stats_helpers._SYSTEM_INFO_CACHE_TTL_SECONDS

from .routes_static import _register_static_routes
from .routes_stats import _register_stats_routes
from .routes_core import (
    _register_core_routes,
    _register_config_routes,
    _register_query_log_routes,
    _register_plugin_routes,
)

from ...stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from ..udp_server import DNSUDPHandler
from ...plugins.resolve.base import AdminPageSpec


logger = logging.getLogger("foghorn.webserver")

# Short-lived cache for RateLimit statistics derived from its SQLite
# profile database(s). This keeps /api/v1/ratelimit lightweight even when
# rate_profiles contains many entries.
_RATE_LIMIT_CACHE_TTL_SECONDS = 5.0
_RATE_LIMIT_CACHE_LOCK = threading.Lock()
_last_rate_limit_snapshot: Dict[str, Any] | None = None
_last_rate_limit_snapshot_ts: float = 0.0

# Forwarders for the config YAML cache so tests can continue to access and
# tweak the cache state via foghorn.servers.webserver, while the canonical
# implementation lives in config_helpers.
_CONFIG_TEXT_CACHE_TTL_SECONDS = _config_helpers._CONFIG_TEXT_CACHE_TTL_SECONDS
_CONFIG_TEXT_CACHE_LOCK = _config_helpers._CONFIG_TEXT_CACHE_LOCK
_last_config_text_key = None  # type: ignore[assignment]
_last_config_text = None  # type: ignore[assignment]
_last_config_text_ts = 0.0


def create_app(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer] = None,
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> FastAPI:
    """Create and configure FastAPI app exposing Foghorn admin endpoints.

    Inputs:
      - stats: Optional StatsCollector instance used by the DNS server.
      - config: Current configuration dictionary loaded from YAML.
      - log_buffer: Optional RingBuffer for recent log-like entries.
      - config_path: Optional filesystem path to the active YAML config file.

    Outputs:
      - Configured FastAPI application instance exposing health, stats,
        traffic, config, logs, and configuration management endpoints.

    Example:
      >>> from foghorn.stats import StatsCollector
      >>> collector = StatsCollector()
      >>> app = create_app(collector, {"webserver": {"enabled": True}}, config_path="config.yaml")
    """

    web_cfg = (config.get("webserver") or {}) if isinstance(config, dict) else {}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        """FastAPI lifespan context that installs the 2xx access-log suppression filter.

        Inputs:
          - app: FastAPI application instance.

        Outputs:
          - Async context manager that runs install_uvicorn_2xx_suppression() on startup
            and yields control back to FastAPI for normal request handling.
        """

        install_uvicorn_2xx_suppression()
        yield

    app = FastAPI(title="Foghorn Admin HTTP API", lifespan=lifespan)

    # Allow configuration to tune the system info cache TTL used by
    # get_system_info(), while keeping a conservative default.
    global _CONFIG_TEXT_CACHE_TTL_SECONDS, _SYSTEM_INFO_CACHE_TTL_SECONDS

    # Optional tuning for system metrics cache TTL.
    ttl_raw = web_cfg.get("system_info_ttl_seconds")
    if isinstance(ttl_raw, (int, float)) and ttl_raw > 0:
        _SYSTEM_INFO_CACHE_TTL_SECONDS = float(ttl_raw)
        _stats_helpers._SYSTEM_INFO_CACHE_TTL_SECONDS = float(ttl_raw)

    # Optional tuning for how often StatsCollector.snapshot() is recomputed.
    stats_ttl_raw = web_cfg.get("stats_snapshot_ttl_seconds")
    if isinstance(stats_ttl_raw, (int, float)) and stats_ttl_raw > 0:
        _stats_helpers._STATS_SNAPSHOT_CACHE_TTL_SECONDS = float(stats_ttl_raw)

    # Optional tuning for how often sanitized YAML text is recomputed for /config.
    cfg_ttl_raw = web_cfg.get("config_cache_ttl_seconds")
    if isinstance(cfg_ttl_raw, (int, float)) and cfg_ttl_raw > 0:
        _CONFIG_TEXT_CACHE_TTL_SECONDS = float(cfg_ttl_raw)

    # Optional control over how heavy the system metrics collection is.
    detail_raw = str(web_cfg.get("system_metrics_detail", "full")).lower()
    if detail_raw in {"full", "basic"}:
        _stats_helpers._SYSTEM_INFO_DETAIL_MODE = detail_raw

    # Derived paths for optional static assets
    www_root = resolve_www_root(config)

    # Attach shared state
    app.state.stats_collector = stats
    app.state.config = config
    app.state.config_path = config_path
    app.state.log_buffer = log_buffer or RingBuffer(
        capacity=int(web_cfg.get("logs", {}).get("buffer_size", 500))
    )
    app.state.www_root = www_root
    app.state.debug_stats_timings = bool(web_cfg.get("debug_timings", False))
    app.state.runtime_state = runtime_state
    # Expose loaded plugin instances so plugin-aware endpoints (such as
    # DockerHosts UI helpers) can look up instances by their configured name.
    app.state.plugins = list(plugins or [])

    # Best-effort: register the webserver as enabled. The thread/handle liveness
    # is tracked by foghorn.main when runtime_state is provided.
    if runtime_state is not None:
        runtime_state.set_listener("webserver", enabled=True, thread=None)

    # CORS configuration
    cors_cfg = web_cfg.get("cors") or {}
    if cors_cfg.get("enabled"):
        allow_origins = cors_cfg.get("allowlist") or []
        allow_methods = ["GET", "POST", "OPTIONS"]
        allow_headers = ["*"]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins or ["*"],
            allow_credentials=False,
            allow_methods=allow_methods,
            allow_headers=allow_headers,
        )

    auth_dep = _build_auth_dependency(web_cfg)

    # Register route groups via helper functions to keep create_app concise.
    _register_core_routes(app)
    _register_stats_routes(app, auth_dep, FOGHORN_VERSION)
    _register_config_routes(app, auth_dep)
    _register_query_log_routes(app, auth_dep)
    _register_plugin_routes(app, auth_dep)
    _register_static_routes(app, web_cfg, www_root, auth_dep)

    return app


class _AdminHTTPServer(http.server.ThreadingHTTPServer):
    """ThreadingHTTPServer carrying shared admin state (stats, config, logs).

    Inputs (constructor):
      - server_address: (host, port) tuple
      - RequestHandlerClass: handler class (typically _ThreadedAdminRequestHandler)
      - stats: Optional StatsCollector
      - config: Configuration dict loaded from YAML
      - log_buffer: Optional RingBuffer instance

    Outputs:
      - Initialized HTTP server suitable for use with serve_forever().

    Example:
      >>> # internal use by _start_admin_server_threaded()
    """

    allow_reuse_address = True

    def __init__(
        self,
        server_address: tuple[str, int],
        RequestHandlerClass: type[http.server.BaseHTTPRequestHandler],
        stats: Optional[StatsCollector],
        config: Dict[str, Any],
        log_buffer: Optional[RingBuffer],
        config_path: str | None = None,
        runtime_state: RuntimeState | None = None,
        plugins: list[object] | None = None,
    ) -> None:
        """Initialize admin HTTP server with shared state and host metadata.

        Inputs:
          - server_address: (host, port) tuple for the HTTP server bind.
          - RequestHandlerClass: Request handler type.
          - stats: Optional StatsCollector instance.
          - config: Loaded configuration mapping.
          - log_buffer: Optional RingBuffer for recent log entries.
          - config_path: Optional path to the active YAML config file.

        Outputs:
          - None. The instance exposes attributes used by request handlers,
            including cached hostname/ip values that are stable for the
            lifetime of the process.
        """

        super().__init__(server_address, RequestHandlerClass)
        self.stats = stats
        self.config = config
        self.log_buffer = log_buffer
        self.config_path = config_path
        self.runtime_state = runtime_state
        # Preserve the plugin list so threaded handlers can look up plugin
        # instances by name when serving plugin-specific pages or APIs.
        self.plugins = list(plugins or [])

        if runtime_state is not None:
            runtime_state.set_listener("webserver", enabled=True, thread=None)

        # Cache hostname and IP once; they are stable for the process lifetime
        # and may be relatively expensive to resolve repeatedly in hot paths
        # such as /stats.
        try:
            self.hostname = socket.gethostname()
        except Exception:  # pragma: no cover - environment specific
            self.hostname = "unknown-host"
        try:
            self.host_ip = socket.gethostbyname(self.hostname)
        except Exception:  # pragma: no cover - environment specific
            self.host_ip = "0.0.0.0"


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

        res = store.select_query_log(
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            start_ts=start_ts,
            end_ts=end_ts,
            page=page,
            page_size=ps,
        )

        items = []
        for item in res.get("items", []) or []:
            if isinstance(item, dict) and "ts" in item:
                out = dict(item)
                out["timestamp"] = _ts_to_utc_iso(float(out.get("ts") or 0.0))
                items.append(out)
            else:
                items.append(item)

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "total": res.get("total", 0),
                "page": res.get("page", page),
                "page_size": res.get("page_size", ps),
                "total_pages": res.get("total_pages", 0),
                "items": items,
            },
        )

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

        res = store.aggregate_query_log_counts(
            start_ts=start_dt.timestamp(),
            end_ts=end_dt.timestamp(),
            interval_seconds=interval_seconds,
            client_ip=client_ip,
            qtype=qtype,
            qname=qname,
            rcode=rcode,
            group_by=group_by,
        )

        items = []
        for item in res.get("items", []) or []:
            if isinstance(item, dict):
                out = dict(item)
                if "bucket_start_ts" in out:
                    out["bucket_start"] = _ts_to_utc_iso(
                        float(out.get("bucket_start_ts") or 0.0)
                    )
                if "bucket_end_ts" in out:
                    out["bucket_end"] = _ts_to_utc_iso(
                        float(out.get("bucket_end_ts") or 0.0)
                    )
                items.append(out)

        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "start": start_dt.isoformat().replace("+00:00", "Z"),
                "end": end_dt.isoformat().replace("+00:00", "Z"),
                "interval_seconds": interval_seconds,
                "items": items,
            },
        )

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
        upstream_cfg = cfg.get("upstreams") or []
        if not isinstance(upstream_cfg, list):
            upstream_cfg = []

        health = getattr(DNSUDPHandler, "upstream_health", {}) or {}
        strategy = str(getattr(DNSUDPHandler, "upstream_strategy", "failover"))
        try:
            max_concurrent = int(
                getattr(DNSUDPHandler, "upstream_max_concurrent", 1) or 1
            )
        except Exception:
            max_concurrent = 1
        if max_concurrent < 1:
            max_concurrent = 1

        now = time.time()
        items: list[Dict[str, Any]] = []
        seen_ids: set[str] = set()

        for up in upstream_cfg:
            if not isinstance(up, dict):
                continue
            up_id = DNSUDPHandler._upstream_id(up)
            if not up_id:
                continue
            seen_ids.add(up_id)
            entry = health.get(up_id) or {}
            try:
                fail_count = int(entry.get("fail_count", 0))
            except Exception:
                fail_count = 0
            try:
                down_until = float(entry.get("down_until", 0.0) or 0.0)
            except Exception:
                down_until = 0.0
            state = "down" if entry and down_until > now else "up"

            cfg_view: Dict[str, Any] = {}
            for key in ("host", "port", "transport", "url"):
                if key in up:
                    cfg_view[key] = up[key]

            items.append(
                {
                    "id": up_id,
                    "config": cfg_view,
                    "state": state,
                    "fail_count": fail_count,
                    "down_until": down_until if down_until else None,
                }
            )

        for up_id, entry in health.items():
            if up_id in seen_ids or not up_id:
                continue
            try:
                fail_count = int(entry.get("fail_count", 0))
            except Exception:
                fail_count = 0
            try:
                down_until = float(entry.get("down_until", 0.0) or 0.0)
            except Exception:
                down_until = 0.0
            state = "down" if down_until > now else "up"
            items.append(
                {
                    "id": up_id,
                    "config": {},
                    "state": state,
                    "fail_count": fail_count,
                    "down_until": down_until if down_until else None,
                }
            )

        payload: Dict[str, Any] = {
            "server_time": _utc_now_iso(),
            "strategy": strategy,
            "max_concurrent": max_concurrent,
            "items": items,
        }
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

            # Validated.  Now Backup the config.
            if os.path.exists(cfg_path_abs):
                with open(cfg_path_abs, "rb") as src, open(backup_path, "wb") as dst:
                    dst.write(src.read())

            # Upload and atomic move
            with open(upload_path, "w", encoding="utf-8") as tmp:
                tmp.write(raw_yaml)

            os.replace(upload_path, cfg_path_abs)
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

        pages = []
        plugins_list = getattr(self._server(), "plugins", []) or []
        for plugin in plugins_list:
            try:
                plugin_name = getattr(plugin, "name", None)
            except Exception:
                plugin_name = None
            if not plugin_name:
                continue
            get_pages = getattr(plugin, "get_admin_pages", None)
            if not callable(get_pages):
                continue
            try:
                specs = get_pages()
            except Exception:
                logger.debug(
                    "threaded webserver: get_admin_pages() failed for plugin %r",
                    plugin_name,
                    exc_info=True,
                )
                continue
            for spec in specs or []:
                try:
                    if isinstance(spec, AdminPageSpec):
                        slug = spec.slug
                        title = spec.title
                        description = spec.description
                        layout = spec.layout or "one_column"
                        kind = spec.kind
                    elif isinstance(spec, dict):
                        slug = spec.get("slug")
                        title = spec.get("title")
                        description = spec.get("description")
                        layout = spec.get("layout") or "one_column"
                        kind = spec.get("kind")
                    else:
                        slug = getattr(spec, "slug", None)
                        title = getattr(spec, "title", None)
                        description = getattr(spec, "description", None)
                        layout = getattr(spec, "layout", "one_column")
                        kind = getattr(spec, "kind", None)
                except Exception:
                    continue

                slug_str = str(slug or "").strip()
                title_str = str(title or "").strip()
                if not slug_str or not title_str:
                    continue

                layout_str = str(layout or "one_column").strip().lower()
                if layout_str not in {"one_column", "two_column"}:
                    layout_str = "one_column"

                pages.append(
                    {
                        "plugin": str(plugin_name),
                        "slug": slug_str,
                        "title": title_str,
                        "description": (
                            str(description) if description is not None else None
                        ),
                        "layout": layout_str,
                        "kind": str(kind) if kind is not None else None,
                    }
                )

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
        plugins_list = getattr(self._server(), "plugins", []) or []
        items: list[dict[str, Any]] = []

        def _normalise_descriptor(
            source: object, desc: dict[str, Any]
        ) -> dict[str, Any] | None:
            if not isinstance(desc, dict):
                return None
            name = str(desc.get("name") or getattr(source, "name", "")).strip()
            title = str(desc.get("title") or name).strip()
            if not name or not title:
                return None
            kind = desc.get("kind")
            order_val = desc.get("order")
            try:
                order = int(order_val) if order_val is not None else 100
            except Exception:
                order = 100
            item = dict(desc)
            item["name"] = name
            item["title"] = title
            item["kind"] = str(kind) if kind is not None else None
            item["order"] = order
            return item

        for plugin in plugins_list:
            try:
                get_desc = getattr(plugin, "get_admin_ui_descriptor", None)
            except Exception:
                continue
            if not callable(get_desc):
                continue
            try:
                desc = get_desc()
            except Exception:
                continue
            item = _normalise_descriptor(plugin, desc)  # type: ignore[arg-type]
            if item is not None:
                items.append(item)

        # Also surface the global DNS cache plugin when it exposes admin UI.
        try:
            from ..plugins import base as plugin_base

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is not None:
            try:
                get_desc = getattr(cache, "get_admin_ui_descriptor", None)
            except Exception:
                get_desc = None
            if callable(get_desc):
                try:
                    desc = get_desc()
                except Exception:
                    desc = None
                if isinstance(desc, dict):
                    item = _normalise_descriptor(cache, desc)  # type: ignore[arg-type]
                    if item is not None:
                        items.append(item)

        # Apply the same multi-instance title normalisation as the FastAPI
        # endpoint. We group on a base title that strips a trailing
        # " (name)" when it matches the instance name, then only append the
        # suffix when there are multiple instances for that base title.
        title_counts: dict[str, int] = {}
        for it in items:
            raw_title = str(it.get("title", ""))
            name = str(it.get("name", ""))
            base_title = raw_title
            if raw_title and name and raw_title.endswith(f" ({name})"):
                base_title = raw_title[: -len(f" ({name})")]
            it["_base_title"] = base_title
            if base_title:
                title_counts[base_title] = title_counts.get(base_title, 0) + 1

        for it in items:
            base_title = str(it.get("_base_title", ""))
            name = str(it.get("name", ""))
            if not base_title:
                continue
            if title_counts.get(base_title, 0) > 1 and name:
                it["title"] = f"{base_title} ({name})"
            else:
                it["title"] = base_title
            it.pop("_base_title", None)
        items.sort(
            key=lambda d: (int(d.get("order", 100) or 100), str(d.get("title", "")))
        )
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
        target = None
        for plugin in plugins_list:
            try:
                if getattr(plugin, "name", None) == plugin_name:
                    target = plugin
                    break
            except Exception:
                continue

        if target is None:
            self._send_json(
                404,
                {
                    "detail": "plugin page not found",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        get_pages = getattr(target, "get_admin_pages", None)
        if not callable(get_pages):
            self._send_json(
                404,
                {
                    "detail": "plugin page not found",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        try:
            specs = get_pages()
        except Exception:
            self._send_json(
                500,
                {
                    "detail": "failed to build plugin page list",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        detail = None
        for spec in specs or []:
            try:
                if isinstance(spec, AdminPageSpec):
                    slug = spec.slug
                    title = spec.title
                    description = spec.description
                    layout = spec.layout or "one_column"
                    kind = spec.kind
                    html_left = spec.html_left
                    html_right = spec.html_right
                elif isinstance(spec, dict):
                    slug = spec.get("slug")
                    title = spec.get("title")
                    description = spec.get("description")
                    layout = spec.get("layout") or "one_column"
                    kind = spec.get("kind")
                    html_left = spec.get("html_left")
                    html_right = spec.get("html_right")
                else:
                    slug = getattr(spec, "slug", None)
                    title = getattr(spec, "title", None)
                    description = getattr(spec, "description", None)
                    layout = getattr(spec, "layout", "one_column")
                    kind = getattr(spec, "kind", None)
                    html_left = getattr(spec, "html_left", None)
                    html_right = getattr(spec, "html_right", None)
            except Exception:
                continue

            slug_str = str(slug or "").strip()
            if slug_str != page_slug:
                continue
            title_str = str(title or "").strip()
            if not title_str:
                continue

            layout_str = str(layout or "one_column").strip().lower()
            if layout_str not in {"one_column", "two_column"}:
                layout_str = "one_column"

            detail = {
                "plugin": str(plugin_name),
                "slug": slug_str,
                "title": title_str,
                "description": (str(description) if description is not None else None),
                "layout": layout_str,
                "kind": str(kind) if kind is not None else None,
                "html_left": str(html_left) if html_left is not None else None,
                "html_right": str(html_right) if html_right is not None else None,
            }
            break

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
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue
        if target is None or not hasattr(target, "get_http_snapshot"):
            self._send_json(
                404,
                {
                    "detail": "plugin not found or does not expose get_http_snapshot",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            self._send_json(
                500,
                {
                    "detail": f"failed to build DockerHosts snapshot: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "plugin": plugin_name,
                "data": _json_safe(snapshot),
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
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue
        if target is None or not hasattr(target, "get_http_snapshot"):
            self._send_json(
                404,
                {
                    "detail": "plugin not found or does not expose get_http_snapshot",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            self._send_json(
                500,
                {
                    "detail": f"failed to build MdnsBridge snapshot: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "plugin": plugin_name,
                "data": _json_safe(snapshot),
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
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue
        if target is None or not hasattr(target, "get_http_snapshot"):
            self._send_json(
                404,
                {
                    "detail": "plugin not found or does not expose get_http_snapshot",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:
            self._send_json(
                500,
                {
                    "detail": f"failed to build EtcHosts snapshot: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return
        self._send_json(
            200,
            {
                "server_time": _utc_now_iso(),
                "plugin": plugin_name,
                "data": _json_safe(snapshot),
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


def _start_admin_server_threaded(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer],
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> Optional[
    "WebServerHandle"
]:  # pragma: no cover - environment-dependent threaded fallback; exercised via start_webserver tests
    """Brief: Start threaded admin HTTP server without using asyncio.

    Inputs:
      - stats: Optional StatsCollector
      - config: Full configuration dict
      - log_buffer: Optional RingBuffer for log entries

    Outputs:
      - WebServerHandle if server started successfully, else None.

    Example:
      >>> handle = _start_admin_server_threaded(
      ...     None,
      ...     {"server": {"http": {"enabled": True}}},
      ...     None,
      ... )
    """

    if isinstance(config, dict):
        server_cfg = config.get("server") or {}
        web_cfg = server_cfg.get("http") or {}
    else:
        web_cfg = {}
    if not web_cfg.get("enabled"):
        return None

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 5380))

    try:
        httpd = _AdminHTTPServer(
            (host, port),
            _ThreadedAdminRequestHandler,
            stats=stats,
            config=config,
            log_buffer=log_buffer,
            config_path=config_path,
            runtime_state=runtime_state,
            plugins=plugins,
        )
    except (
        OSError
    ) as exc:  # pragma: no cover - binding failures are environment-specific
        logger.error(
            "Failed to bind threaded admin webserver on %s:%d: %s", host, port, exc
        )
        return None

    def _serve() -> None:
        try:
            httpd.serve_forever()
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.exception("Unhandled exception in threaded admin webserver")
        finally:
            try:
                httpd.server_close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass

    thread = threading.Thread(
        target=_serve,
        name="foghorn-webserver-threaded",
        daemon=True,
    )
    thread.start()
    logger.info("Started threaded admin webserver on %s:%d", host, port)
    return WebServerHandle(thread, server=httpd)


def start_webserver(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer] = None,
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> Optional[WebServerHandle]:
    """Start admin HTTP server, preferring uvicorn and falling back to threaded HTTP."""

    if isinstance(config, dict):
        # Only accept webserver enable/host/port configuration from the
        # v2-style server-level ``server.http`` block. Root-level ``http`` and
        # ``webserver`` blocks are intentionally ignored.
        server_cfg = config.get("server") or {}
        web_cfg = server_cfg.get("http") or {}
    else:
        web_cfg = {}

    # Treat presence of a webserver block as enabled by default so that
    # configurations that declare webserver: {} behave as "on" unless
    # explicitly disabled with enabled: false.
    has_web_cfg = bool(web_cfg)
    raw_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    enabled = bool(raw_enabled) if raw_enabled is not None else has_web_cfg
    if not enabled:
        return None

    foghorn_cfg = (config.get("foghorn") or {}) if isinstance(config, dict) else {}
    use_asyncio = bool(foghorn_cfg.get("use_asyncio", True))

    # Helper: call the threaded fallback in a way that remains compatible with
    # legacy tests that monkeypatch _start_admin_server_threaded() with a
    # simplified signature. When the real implementation is present, we pass
    # plugins/runtime_state so that threaded and uvicorn paths see the same
    # plugin instances.
    def _call_threaded(
        *,
        stats_obj: Optional[StatsCollector],
        cfg_obj: Dict[str, Any],
        buf_obj: Optional[RingBuffer],
        cfg_path_obj: str | None,
        rt_state: RuntimeState | None,
        plugins_obj: list[object] | None,
    ) -> Optional["WebServerHandle"]:
        try:
            import inspect as _inspect  # local import to avoid module-level cost

            fn = _start_admin_server_threaded
            sig = _inspect.signature(fn)
            params = sig.parameters
            kwargs: Dict[str, Any] = {}
            if "config_path" in params:
                kwargs["config_path"] = cfg_path_obj
            if rt_state is not None and "runtime_state" in params:
                kwargs["runtime_state"] = rt_state
            if "plugins" in params:
                kwargs["plugins"] = plugins_obj
            return fn(stats_obj, cfg_obj, buf_obj, **kwargs)
        except Exception:
            # Best-effort fallback: use the original minimal calling convention.
            return _start_admin_server_threaded(
                stats_obj,
                cfg_obj,
                buf_obj,
                config_path=cfg_path_obj,
            )

    # Detect restricted environments where asyncio cannot create its self-pipe
    # and skip uvicorn entirely in that case, or when explicitly disabled via
    # foghorn.use_asyncio.
    can_use_asyncio = use_asyncio
    if can_use_asyncio:
        try:  # pragma: no cover - difficult to exercise PermissionError in CI
            import asyncio

            loop = asyncio.new_event_loop()
            loop.close()

        except PermissionError as exc:  # pragma: no cover - best effort
            logger.warning(
                "Asyncio loop creation failed for admin webserver: %s falling back to threaded HTTP server.",
                exc,
            )
            # Always disable asyncio path on PermissionError, regardless of whether
            # we are running inside a container. This mirrors the DoH server logic
            # and ensures we reliably use the threaded fallback when self-pipe
            # creation is not permitted.
            can_use_asyncio = False
            container_path = "/.dockerenv"
            if os.path.exists(container_path):
                logger.warning(
                    "Possible container permission issues. Update, check seccomp settings, or run with --privileged "
                )
                logger.warning(
                    "Now enjoy this exception and wait for the threaded server to start: \n"
                )
        except Exception:
            can_use_asyncio = use_asyncio

    if not can_use_asyncio:
        handle = _call_threaded(
            stats_obj=stats,
            cfg_obj=config,
            buf_obj=log_buffer,
            cfg_path_obj=config_path,
            rt_state=runtime_state,
            plugins_obj=plugins,
        )
        if runtime_state is not None and handle is not None:
            runtime_state.set_listener("webserver", enabled=True, thread=handle)
        return handle

    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover - missing optional dependency
        logger.error(
            "webserver.enabled=true but uvicorn is not available: %s; using threaded fallback",
            exc,
        )
        handle = _call_threaded(
            stats_obj=stats,
            cfg_obj=config,
            buf_obj=log_buffer,
            cfg_path_obj=config_path,
            rt_state=runtime_state,
            plugins_obj=plugins,
        )
        if runtime_state is not None and handle is not None:
            runtime_state.set_listener("webserver", enabled=True, thread=handle)
        return handle

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 5380))

    # Warn if unauthenticated and binding to all interfaces
    auth_cfg = web_cfg.get("auth") or {}
    mode = str(auth_cfg.get("mode", "none")).lower()
    if mode == "none" and host in ("0.0.0.0", "::"):
        logger.warning(
            "Foghorn webserver is bound to %s without authentication; consider using auth.mode or restricting host",
            host,
        )

    app = create_app(
        stats,
        config,
        log_buffer,
        config_path=config_path,
        runtime_state=runtime_state,
        plugins=plugins,
    )

    config_uvicorn = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uvicorn)

    def _runner() -> None:
        try:
            server.run()
        except (
            PermissionError
        ) as exc:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.error(
                "Webserver disabled: PermissionError while creating asyncio self-pipe/socketpair: %s; "
                "this usually indicates a restricted container or seccomp profile.",
                exc,
            )
        except (
            Exception
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.exception("Unhandled exception in webserver thread")

    thread = threading.Thread(target=_runner, name="foghorn-webserver", daemon=True)
    thread.start()

    if runtime_state is not None:
        runtime_state.set_listener("webserver", enabled=True, thread=thread)

    logger.info("Started Foghorn webserver on %s:%d", host, port)
    return WebServerHandle(thread)
