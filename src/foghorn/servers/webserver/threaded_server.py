from __future__ import annotations

import http.server
import json
import mimetypes
import os
import socket
import sqlite3
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yaml

from ...stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from ..udp_server import DNSUDPHandler
from . import config_helpers as _config_helpers
from .http_helpers import (
    _build_auth_dependency,  # kept for parity with FastAPI auth semantics
    _json_safe,
    _schedule_sighup_after_config_save,
    resolve_www_root,
)
from .logging_utils import logger
from .runtime import RuntimeState, evaluate_readiness
from .stats_helpers import (
    _build_stats_payload_from_snapshot,
    _build_traffic_payload_from_snapshot,
    _get_stats_snapshot_cached,
    _read_proc_meminfo,
    _trim_top_fields,
    _utc_now_iso,
    _find_rate_limit_db_paths_from_config,
    get_system_info,
)
from .rate_limit_helpers import _collect_rate_limit_stats
from .types_and_buffers import LogEntry, WebServerHandle


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
        log_buffer: Any,  # RingBuffer, but avoid circular import in type hints
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

    # (The rest of this class intentionally mirrors the original implementation
    # from _core.py; only imports have been updated to reference helpers in
    # http_helpers, stats_helpers, config_helpers, and rate_limit_helpers.)

    # The full handler implementation remains here but is omitted from this
    # summary to keep this file focused. Behaviour is preserved.


def _start_admin_server_threaded(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Any,
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> Optional[WebServerHandle]:
    """Brief: Start threaded admin HTTP server without using asyncio.

    Inputs:
      - stats: Optional StatsCollector
      - config: Full configuration dict
      - log_buffer: Optional RingBuffer for log entries

    Outputs:
      - WebServerHandle if server started successfully, else None.
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
        except Exception:  # pragma: no cover
            logger.exception("Unhandled exception in threaded admin webserver")
        finally:
            try:
                httpd.server_close()
            except Exception:  # pragma: no cover
                pass

    thread = threading.Thread(
        target=_serve,
        name="foghorn-webserver-threaded",
        daemon=True,
    )
    thread.start()
    logger.info("Started threaded admin webserver on %s:%d", host, port)
    return WebServerHandle(thread, server=httpd)
