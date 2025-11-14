"""Admin HTTP server for Foghorn (statistics, config, logs, health).

This module provides a small FastAPI application and helpers to run it in a
background thread alongside the main DNS listeners.

All handlers return JSON data structures (never raw JSON strings) and are
backed by the in-process StatsCollector and current configuration dict.
"""

from __future__ import annotations

import copy
import http.server
import json
import logging
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from .stats import StatsCollector, StatsSnapshot

logger = logging.getLogger("foghorn.webserver")


class _Suppress2xxAccessFilter(logging.Filter):
    """Logging filter that drops uvicorn access records for HTTP 2xx responses.

    Inputs:
      - record: logging.LogRecord instance from uvicorn.access or other loggers.

    Outputs:
      - bool: False for records that clearly correspond to HTTP 2xx status codes,
        True otherwise (including when no status code can be determined).

    Example:
      >>> import logging
      >>> access_logger = logging.getLogger("uvicorn.access")
      >>> access_logger.addFilter(_Suppress2xxAccessFilter())
    """

    def filter(self, record: logging.LogRecord) -> bool:
        # Fast-path: use explicit status_code attribute if present
        status = getattr(record, "status_code", None)

        # Fallbacks: inspect record.args as used by uvicorn access logger
        if status is None:
            args = getattr(record, "args", None)
            if isinstance(args, dict):
                # Common uvicorn mapping keys: status_code or status
                status = args.get("status_code") or args.get("status")
            elif isinstance(args, (tuple, list)) and args:
                # Heuristic: last positional arg is often the status code
                status = args[-1]

        try:
            code = int(status)
        except Exception:
            # If we cannot confidently determine a numeric status code, keep record
            return True

        # Suppress all 2xx access logs
        return not (200 <= code <= 299)


def install_uvicorn_2xx_suppression() -> None:
    """Attach _Suppress2xxAccessFilter to uvicorn.access logger if not present.

    Inputs:
      - None (operates on the global logging configuration).

    Outputs:
      - None. The uvicorn.access logger will drop 2xx HTTP access records by default.

    Example:
      >>> install_uvicorn_2xx_suppression()
      >>> # Subsequent FastAPI/uvicorn 2xx responses will not emit access logs.
    """

    access_logger = logging.getLogger("uvicorn.access")
    # Avoid adding duplicate filters if called multiple times (e.g., reloads)
    for f in getattr(access_logger, "filters", []):
        if isinstance(f, _Suppress2xxAccessFilter):
            return
    access_logger.addFilter(_Suppress2xxAccessFilter())


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

    # Install default suppression of 2xx uvicorn access logs on startup so it
    # applies both to embedded and external uvicorn usage.
    @app.on_event("startup")
    async def _install_logging_filter() -> None:
        """FastAPI startup hook that installs the 2xx access-log suppression filter.

        Inputs:
          - None
        Outputs:
          - None (mutates global logging configuration).
        """

        install_uvicorn_2xx_suppression()

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
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.stats = stats
        self.config = config
        self.log_buffer = log_buffer


class _ThreadedAdminRequestHandler(http.server.BaseHTTPRequestHandler):
    """Brief: Minimal admin HTTP handler using the standard library.

    Inputs:
      - Inherits request/connection attributes from BaseHTTPRequestHandler.

    Outputs:
      - Serves /health, /stats, /stats/reset, /traffic, /config, /logs, and
        optionally / when index.html is present.
    """

    def _server(self) -> _AdminHTTPServer:
        """Brief: Return typed reference to the underlying HTTP server.

        Inputs: none
        Outputs: _AdminHTTPServer instance.
        """

        return self.server  # type: ignore[return-value]

    # ---------- Helpers ----------

    def _client_ip(self) -> str:
        """Brief: Return best-effort client IP address.

        Inputs: none
        Outputs: str IP address.
        """

        addr = getattr(self, "client_address", None)
        if isinstance(addr, tuple) and addr:
            return str(addr[0])
        return "0.0.0.0"

    def _web_cfg(self) -> Dict[str, Any]:
        """Brief: Return webserver config subsection from global config.

        Inputs: none
        Outputs: dict representing config['webserver'] or {}.
        """

        cfg = getattr(self._server(), "config", {}) or {}
        if isinstance(cfg, dict):
            return cfg.get("webserver", {}) or {}
        return {}

    def _apply_cors_headers(self) -> None:
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

    def _send_json(self, status_code: int, payload: Dict[str, Any]) -> None:
        """Brief: Send JSON response with appropriate headers.

        Inputs:
          - status_code: HTTP status code
          - payload: JSON-serializable dict
        Outputs:
          - None
        """

        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status_code: int, text: str) -> None:
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
        self.wfile.write(body)

    def _require_auth(self) -> bool:
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
                403,
                {"detail": "forbidden", "server_time": _utc_now_iso()},
            )
            return False
        return True

    # ---------- Endpoint handlers ----------

    def _handle_health(self) -> None:
        """Brief: Handle GET /health.

        Inputs: none
        Outputs: None (sends JSON response).
        """

        self._send_json(200, {"status": "ok", "server_time": _utc_now_iso()})

    def _handle_stats(self, params: Dict[str, list[str]]) -> None:
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
        snap: StatsSnapshot = collector.snapshot(reset=reset)
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
        self._send_json(200, payload)

    def _handle_stats_reset(self) -> None:
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

    def _handle_traffic(self) -> None:
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
        snap: StatsSnapshot = collector.snapshot(reset=False)
        payload = {
            "server_time": _utc_now_iso(),
            "created_at": snap.created_at,
            "totals": snap.totals,
            "rcodes": snap.rcodes,
            "qtypes": snap.qtypes,
            "top_clients": snap.top_clients,
            "top_domains": snap.top_domains,
            "latency": snap.latency_stats,
        }
        self._send_json(200, payload)

    def _handle_config(self) -> None:
        """Brief: Handle GET /config.

        Inputs: none
        Outputs: None
        """

        if not self._require_auth():
            return

        cfg = getattr(self._server(), "config", {}) or {}
        web_cfg_inner = (cfg.get("webserver") or {}) if isinstance(cfg, dict) else {}
        redact_keys = web_cfg_inner.get("redact_keys") or [
            "token",
            "password",
            "secret",
        ]
        clean = sanitize_config(cfg, redact_keys=redact_keys)
        self._send_json(
            200,
            {"server_time": _utc_now_iso(), "config": clean},
        )

    def _handle_logs(self, params: Dict[str, list[str]]) -> None:
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

    def _handle_index(self) -> None:
        """Brief: Handle GET / when index.html is enabled.

        Inputs: none
        Outputs: None
        """

        web_cfg = self._web_cfg()
        index_enabled = bool(web_cfg.get("index", True))
        if not index_enabled:
            self._send_text(404, "index disabled")
            return

        import os

        here = os.path.dirname(os.path.abspath(__file__))
        index_path = os.path.join(here, "index.html")
        if not os.path.exists(index_path):
            self._send_json(
                404,
                {
                    "error": "index.html not found",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        try:
            with open(index_path, "rb") as f:
                data = f.read()
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to read index.html: %s", exc)
            self._send_text(500, "failed to read index.html")
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(data)))
        self._apply_cors_headers()
        self.end_headers()
        self.wfile.write(data)

    # ---------- HTTP verb handlers ----------

    def do_OPTIONS(self) -> None:  # noqa: N802
        """Brief: Handle CORS preflight requests.

        Inputs: none
        Outputs: None
        """

        self.send_response(204)
        self._apply_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        """Brief: Dispatch GET requests to admin endpoints.

        Inputs: none
        Outputs: None
        """

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        params = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            self._handle_health()
        elif path == "/stats":
            self._handle_stats(params)
        elif path == "/traffic":
            self._handle_traffic()
        elif path == "/config":
            self._handle_config()
        elif path == "/logs":
            self._handle_logs(params)
        elif path == "/":
            self._handle_index()
        else:
            self._send_text(404, "not found")

    def do_POST(self) -> None:  # noqa: N802
        """Brief: Dispatch POST requests to admin endpoints.

        Inputs: none
        Outputs: None
        """

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path == "/stats/reset":
            self._handle_stats_reset()
        else:
            self._send_text(404, "not found")

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
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
        logger.info("webserver HTTP: %s", msg)


def _start_admin_server_threaded(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer],
) -> Optional["WebServerHandle"]:
    """Brief: Start threaded admin HTTP server without using asyncio.

    Inputs:
      - stats: Optional StatsCollector
      - config: Full configuration dict
      - log_buffer: Optional RingBuffer for log entries

    Outputs:
      - WebServerHandle if server started successfully, else None.

    Example:
      >>> handle = _start_admin_server_threaded(None, {"webserver": {"enabled": True}}, None)
    """

    web_cfg = (config.get("webserver") or {}) if isinstance(config, dict) else {}
    if not web_cfg.get("enabled"):
        return None

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 8053))

    try:
        httpd = _AdminHTTPServer(
            (host, port),
            _ThreadedAdminRequestHandler,
            stats=stats,
            config=config,
            log_buffer=log_buffer,
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


class WebServerHandle:
    """Handle for a background admin webserver thread.

    Inputs (constructor):
      - thread: Thread object running the HTTP/uvicorn server loop.
      - server: Optional server instance with shutdown/server_close methods.

    Outputs:
      - WebServerHandle instance with stop() and is_running().

    Example:
      >>> # created via start_webserver() in main
    """

    def __init__(self, thread: threading.Thread, server: Any | None = None) -> None:
        self._thread = thread
        self._server = server

    def is_running(self) -> bool:
        """Return True if the underlying thread is alive.

        Inputs: none
        Outputs: bool indicating thread liveness.
        """

        return self._thread.is_alive()

    def stop(self, timeout: float = 5.0) -> None:
        """Best-effort stop; shuts down server if possible and waits for thread.

        Inputs:
          - timeout: Seconds to wait for thread to exit.

        Outputs:
          - None

        Notes:
          - For uvicorn-based servers, this relies on process lifetime matching
            server lifetime and only joins the thread.
          - For threaded HTTP fallbacks, this also calls shutdown/server_close
            on the underlying server instance when present.
        """

        try:
            if self._server is not None:
                try:
                    shutdown = getattr(self._server, "shutdown", None)
                    if callable(shutdown):
                        shutdown()
                    close = getattr(self._server, "server_close", None)
                    if callable(close):
                        close()
                except Exception:
                    logger.exception("Error while shutting down webserver instance")
            self._thread.join(timeout=timeout)
        except Exception:
            logger.exception("Error while stopping webserver thread")


def start_webserver(
    stats: Optional[StatsCollector],
    config: Dict[str, Any],
    log_buffer: Optional[RingBuffer] = None,
) -> Optional[WebServerHandle]:
    """Start admin HTTP server, preferring uvicorn but falling back to threaded HTTP.

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

    # Detect restricted environments where asyncio cannot create its self-pipe
    # and skip uvicorn entirely in that case.
    can_use_asyncio = True
    try:  # pragma: no cover - difficult to exercise PermissionError in CI
        import asyncio

        loop = asyncio.new_event_loop()
        loop.close()
    except PermissionError as exc:  # pragma: no cover
        logger.warning(
            "Asyncio loop creation failed for admin webserver; falling back to threaded HTTP server: %s",
            exc,
        )
        can_use_asyncio = False
    except Exception:
        can_use_asyncio = True

    if not can_use_asyncio:
        return _start_admin_server_threaded(stats, config, log_buffer)

    try:
        import uvicorn
    except Exception as exc:  # pragma: no cover - missing optional dependency
        logger.error(
            "webserver.enabled=true but uvicorn is not available: %s; using threaded fallback",
            exc,
        )
        return _start_admin_server_threaded(stats, config, log_buffer)

    host = str(web_cfg.get("host", "127.0.0.1"))
    port = int(web_cfg.get("port", 8053))

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
        except PermissionError as exc:  # pragma: no cover
            logger.error(
                "Webserver disabled: PermissionError while creating asyncio self-pipe/socketpair: %s; "
                "this usually indicates a restricted container or seccomp profile.",
                exc,
            )
        except Exception:  # pragma: no cover
            logger.exception("Unhandled exception in webserver thread")

    thread = threading.Thread(target=_runner, name="foghorn-webserver", daemon=True)
    thread.start()
    logger.info("Started Foghorn webserver on %s:%d", host, port)
    return WebServerHandle(thread)
