"""Admin HTTP server for Foghorn (statistics, config, logs, health).

This module provides a small FastAPI application and helpers to run it in a
background thread alongside the main DNS listeners.

All handlers return JSON data structures (never raw JSON strings) and are
backed by the in-process StatsCollector and current configuration dict.
"""

from __future__ import annotations

import copy
import logging
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .stats import StatsCollector, StatsSnapshot

logger = logging.getLogger("foghorn.webserver")


class LogEntry(BaseModel):
    """Structured log entry stored in the in-memory buffer.

    Inputs:
      - timestamp: ISO 8601 string in UTC
      - level: Log level name (e.g., "INFO")
      - message: Log message text
      - extra: Optional dict with additional fields

    Outputs:
      - Pydantic model representing a log entry.

    Example:
      >>> entry = LogEntry(timestamp="2024-01-01T00:00:00Z", level="INFO", message="ok")
      >>> entry.level
      'INFO'
    """

    timestamp: str
    level: str
    message: str
    extra: Dict[str, Any] | None = None


class RingBuffer:
    """Thread-safe fixed-size ring buffer of arbitrary items.

    Inputs (constructor):
      - capacity: Maximum number of items to retain (int, >= 1)

    Outputs:
      - RingBuffer instance with push() and snapshot() helpers.

    Example:
      >>> buf = RingBuffer(capacity=2)
      >>> buf.push(1)
      >>> buf.push(2)
      >>> buf.push(3)
      >>> buf.snapshot()
      [2, 3]
    """

    def __init__(self, capacity: int = 500) -> None:
        if capacity <= 0:
            capacity = 1
        self._capacity = int(capacity)
        self._items: List[Any] = []
        self._lock = threading.Lock()

    def push(self, item: Any) -> None:
        """Append an item, evicting the oldest when capacity is exceeded.

        Inputs:
          - item: Any JSON-serializable value

        Outputs:
          - None
        """

        with self._lock:
            self._items.append(item)
            if len(self._items) > self._capacity:
                # Drop oldest
                overflow = len(self._items) - self._capacity
                if overflow > 0:
                    self._items = self._items[overflow:]

    def snapshot(self, limit: Optional[int] = None) -> List[Any]:
        """Return a copy of buffered items, optionally truncated to newest N.

        Inputs:
          - limit: Optional int maximum number of items to return (newest first)

        Outputs:
          - List of items (shallow copy) suitable for JSON serialization.

        Example:
          >>> buf = RingBuffer(3)
          >>> for i in range(5):
          ...     buf.push(i)
          >>> buf.snapshot(limit=2)
          [3, 4]
        """

        with self._lock:
            data = list(self._items)
        if limit is not None and limit >= 0:
            data = data[-limit:]
        return data


def _utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string.

    Inputs: None
    Outputs: ISO 8601 UTC timestamp string.
    """

    return datetime.now(timezone.utc).isoformat()


def sanitize_config(
    cfg: Dict[str, Any], redact_keys: List[str] | None = None
) -> Dict[str, Any]:
    """Return a deep-copied, sanitized configuration with sensitive values redacted.

    Inputs:
      - cfg: Original configuration dictionary.
      - redact_keys: Optional list of dotted key paths or simple keys to redact.

    Outputs:
      - New dict with sensitive values replaced by '***'.

    Notes:
      - This implementation intentionally stays simple and conservative: if a
        top-level key or nested key name matches an entry in redact_keys, its
        value is replaced with the placeholder.

    Example:
      >>> cfg = {"webserver": {"auth": {"token": "secret"}}}
      >>> clean = sanitize_config(cfg, ["token"])
      >>> clean["webserver"]["auth"]["token"]
      '***'
    """

    if not isinstance(cfg, dict):
        return {}
    redacted = copy.deepcopy(cfg)
    if not redact_keys:
        return redacted

    targets = set(str(k) for k in redact_keys)

    def _walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in list(node.items()):
                if str(key) in targets:
                    node[key] = "***"
                else:
                    _walk(value)
        elif isinstance(node, list):
            for item in node:
                _walk(item)

    _walk(redacted)
    return redacted


def _build_auth_dependency(web_cfg: Dict[str, Any]):
    """Build a FastAPI dependency enforcing optional admin auth.

    Inputs:
      - web_cfg: webserver config dict from YAML (or {}).

    Outputs:
      - Dependency callable usable with FastAPI Depends().

    Modes:
      - none (default): no authentication.
      - token: require Authorization: Bearer <token> or X-API-Key header.
      - basic: require HTTP Basic credentials (not implemented yet; reserved).
    """

    auth_cfg = (web_cfg.get("auth") or {}) if isinstance(web_cfg, dict) else {}
    mode = str(auth_cfg.get("mode", "none")).lower()
    token = auth_cfg.get("token")

    async def _no_auth(_request: Request) -> None:
        return None

    async def _token_auth(request: Request) -> None:
        if not token:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="webserver.auth.token not configured",
            )
        hdr = request.headers.get("authorization") or ""
        api_key = request.headers.get("x-api-key")
        if hdr.lower().startswith("bearer "):
            provided = hdr[7:].strip()
        else:
            provided = api_key.strip() if api_key else ""
        if not provided or provided != str(token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="forbidden"
            )

    if mode == "token":
        return _token_auth
    # basic or unknown -> treat as none for now; can be expanded later.
    return _no_auth


def create_app(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer] = None,
) -> FastAPI:
    """Create and configure FastAPI app exposing Foghorn admin endpoints.

    Inputs:
      - stats: Optional StatsCollector instance used by the DNS server.
      - config: Current configuration dictionary loaded from YAML.
      - log_buffer: Optional RingBuffer for recent log-like entries.

    Outputs:
      - Configured FastAPI application instance.

    Example:
      >>> from foghorn.stats import StatsCollector
      >>> collector = StatsCollector()
      >>> app = create_app(collector, {"webserver": {"enabled": True}})
    """

    web_cfg = (config.get("webserver") or {}) if isinstance(config, dict) else {}
    app = FastAPI(title="Foghorn Admin HTTP API")

    # Attach shared state
    app.state.stats_collector = stats
    app.state.config = config
    app.state.log_buffer = log_buffer or RingBuffer(
        capacity=int(web_cfg.get("logs", {}).get("buffer_size", 500))
    )

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

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        """Return simple liveness information.

        Inputs: none
        Outputs: dict with status and server_time.
        """

        return {"status": "ok", "server_time": _utc_now_iso()}

    @app.get("/stats", dependencies=[Depends(auth_dep)])
    async def get_stats(reset: bool = False) -> Dict[str, Any]:
        """Return statistics snapshot from StatsCollector as JSON.

        Inputs:
          - reset: If True, reset counters after snapshot.
          - request: Optional Request (unused, reserved for future filtering).

        Outputs:
          - Dict representing StatsSnapshot fields.
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}
        snap: StatsSnapshot = collector.snapshot(reset=bool(reset))
        payload: Dict[str, Any] = {
            "created_at": snap.created_at,
            "server_time": _utc_now_iso(),
            "totals": snap.totals,
            "rcodes": snap.rcodes,
            "qtypes": snap.qtypes,
            "uniques": snap.uniques,
            "upstreams": snap.upstreams,
            "top_clients": snap.top_clients,
            "top_subdomains": snap.top_subdomains,
            "top_domains": snap.top_domains,
            "latency": snap.latency_stats,
            "latency_recent": snap.latency_recent_stats,
        }
        return payload

    @app.post("/stats/reset", dependencies=[Depends(auth_dep)])
    async def reset_stats() -> Dict[str, Any]:
        """Reset all statistics counters if collector is active.

        Inputs: none
        Outputs: dict describing result (ok/disabled).
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}
        collector.snapshot(reset=True)
        return {"status": "ok", "server_time": _utc_now_iso()}

    @app.get("/traffic", dependencies=[Depends(auth_dep)])
    async def get_traffic() -> Dict[str, Any]:
        """Return a summarized traffic view derived from statistics snapshot.

        Inputs: none
        Outputs: dict with totals, rcodes, qtypes, latency, and top lists.
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}
        snap: StatsSnapshot = collector.snapshot(reset=False)
        return {
            "server_time": _utc_now_iso(),
            "created_at": snap.created_at,
            "totals": snap.totals,
            "rcodes": snap.rcodes,
            "qtypes": snap.qtypes,
            "top_clients": snap.top_clients,
            "top_domains": snap.top_domains,
            "latency": snap.latency_stats,
        }

    @app.get("/config", dependencies=[Depends(auth_dep)])
    async def get_config() -> Dict[str, Any]:
        """Return sanitized configuration for inspection.

        Inputs: none
        Outputs: dict with sanitized configuration and server_time.
        """

        cfg = app.state.config or {}
        web_cfg_inner = (cfg.get("webserver") or {}) if isinstance(cfg, dict) else {}
        redact_keys = web_cfg_inner.get("redact_keys") or [
            "token",
            "password",
            "secret",
        ]
        clean = sanitize_config(cfg, redact_keys=redact_keys)
        return {"server_time": _utc_now_iso(), "config": clean}

    @app.get("/logs", dependencies=[Depends(auth_dep)])
    async def get_logs(limit: int = 100) -> Dict[str, Any]:
        """Return recent log-like entries from in-memory ring buffer.

        Inputs:
          - limit: Maximum number of log entries to return (newest first).

        Outputs:
          - dict containing "entries": list of log records.
        """

        buf: RingBuffer = app.state.log_buffer
        entries = buf.snapshot(limit=max(0, int(limit)))
        return {"server_time": _utc_now_iso(), "entries": entries}

    # Optional static dashboard
    index_enabled = bool(web_cfg.get("index", True))
    if index_enabled:
        import os

        here = os.path.dirname(os.path.abspath(__file__))
        index_path = os.path.join(here, "index.html")

        @app.get("/")
        async def index() -> Any:
            """Serve the static dashboard index.html if present.

            Inputs: none
            Outputs: FileResponse for index HTML or JSON error if missing.
            """

            if not os.path.exists(index_path):
                return JSONResponse(
                    status_code=status.HTTP_404_NOT_FOUND,
                    content={
                        "error": "index.html not found",
                        "server_time": _utc_now_iso(),
                    },
                )
            return FileResponse(index_path, media_type="text/html")

    return app


class WebServerHandle:
    """Handle for a background uvicorn server thread.

    Inputs (constructor):
      - thread: Thread object

    Outputs:
      - WebServerHandle instance with stop() and is_running().

    Example:
      >>> # created via start_webserver() in main
    """

    def __init__(self, thread: threading.Thread) -> None:
        self._thread = thread

    def is_running(self) -> bool:
        """Return True if the underlying thread is alive.

        Inputs: none
        Outputs: bool indicating thread liveness.
        """

        return self._thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        """Best-effort stop; currently waits for thread join.

        Inputs:
          - timeout: Seconds to wait for thread to exit.

        Outputs:
          - None

        Notes:
          - This implementation relies on uvicorn server lifetime matching
            process lifetime. For now, we only join the thread on shutdown.
        """

        try:
            self._thread.join(timeout=timeout)
        except Exception:
            logger.exception("Error while stopping webserver thread")


def start_webserver(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer] = None,
) -> Optional[WebServerHandle]:
    """Start FastAPI-based admin HTTP server in background thread.

    Inputs:
      - stats: Optional StatsCollector instance used by DNS server.
      - config: Full configuration dict loaded from YAML.
      - log_buffer: Optional RingBuffer for log entries (created if None).

    Outputs:
      - WebServerHandle if webserver.enabled is true, else None.

    Example:
      >>> handle = start_webserver(collector, cfg, None)
      >>> if handle is not None:
      ...     assert handle.is_running()
    """

    web_cfg = (config.get("webserver") or {}) if isinstance(config, dict) else {}
    if not web_cfg.get("enabled"):
        return None

    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover - missing optional dependency
        logger.error("webserver.enabled=true but uvicorn is not available: %s", exc)
        return None

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 8080))

    # Warn if unauthenticated and binding to all interfaces
    auth_cfg = web_cfg.get("auth") or {}
    mode = str(auth_cfg.get("mode", "none")).lower()
    if mode == "none" and host in ("0.0.0.0", "::"):
        logger.warning(
            "Foghorn webserver is bound to %s without authentication; consider using auth.mode or restricting host",
            host,
        )

    app = create_app(stats, config, log_buffer)

    config_uvicorn = uvicorn.Config(app, host=host, port=port, log_level="info")
    server = uvicorn.Server(config_uvicorn)

    def _runner() -> None:
        try:
            server.run()
        except Exception:  # pragma: no cover
            logger.exception("Unhandled exception in webserver thread")

    thread = threading.Thread(target=_runner, name="foghorn-webserver", daemon=True)
    thread.start()
    logger.info("Started Foghorn webserver on %s:%d", host, port)
    return WebServerHandle(thread)
