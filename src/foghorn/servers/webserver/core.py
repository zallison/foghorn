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

# psutil is an optional dependency. stats_helpers.get_system_info() consults
# foghorn.servers.webserver.psutil so tests can monkeypatch it.
try:  # pragma: no cover - optional dependency
    import psutil  # type: ignore
except Exception:  # pragma: no cover - environment dependent
    psutil = None

from .meta_helpers import (
    _get_about_payload,
    _get_package_build_info,
    FOGHORN_VERSION,
    _GITHUB_URL,
)
from .http_helpers import (
    _build_auth_dependency,
    _json_safe,
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

    web_cfg = _config_helpers._get_web_cfg(config)

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

    enable_api = bool(web_cfg.get("enable_api", True))
    enable_schema = bool(web_cfg.get("enable_schema", True))
    enable_docs = bool(web_cfg.get("enable_docs", True))

    # FastAPI only supports Swagger UI when OpenAPI is enabled.
    docs_url = "/docs" if enable_docs and enable_schema else None
    openapi_url = "/openapi.json" if enable_schema else None

    app = FastAPI(
        title="Foghorn Admin HTTP API",
        lifespan=lifespan,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url=openapi_url,
    )

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
    if enable_api:
        _register_core_routes(app)
        _register_stats_routes(app, auth_dep, FOGHORN_VERSION)
        _register_config_routes(app, auth_dep)
        _register_query_log_routes(app, auth_dep)
        _register_plugin_routes(app, auth_dep)

    _register_static_routes(app, web_cfg, www_root, auth_dep)

    return app


# Import server management classes and functions from extracted modules
from .server_management import (
    _AdminHTTPServer,
    _start_admin_server_threaded,
    start_webserver,
)
from .threaded_handlers import _ThreadedAdminRequestHandler

# The following classes and functions have been extracted to separate modules:
# - _AdminHTTPServer: now in server_management.py
# - _ThreadedAdminRequestHandler: now in threaded_handlers.py
# - _start_admin_server_threaded: now in server_management.py
# - start_webserver: now in server_management.py
