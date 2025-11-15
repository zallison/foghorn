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
import mimetypes
import os
import signal
import threading
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import yaml

from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
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


def _read_proc_meminfo(path: str = "/proc/meminfo") -> Dict[str, int]:
    """Brief: Parse a /proc/meminfo-style file into byte counts.

    Inputs:
      - path: Filesystem path to a meminfo-style file (default "/proc/meminfo").

    Outputs:
      - Dict mapping field name (e.g. "MemTotal") to integer byte values.

    Example:
      >>> info = _read_proc_meminfo()  # doctest: +SKIP (depends on host)
      >>> isinstance(info.get("MemTotal"), int)
      True
    """

    result: Dict[str, int] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                if ":" not in line:
                    continue
                key, rest = line.split(":", 1)
                key = key.strip()
                parts = rest.strip().split()
                if not parts:
                    continue
                try:
                    # meminfo reports kB (KiB) values by default
                    kib_val = float(parts[0])
                except Exception:
                    continue
                result[key] = int(kib_val * 1024)
    except Exception:  # pragma: no cover - depends on host environment
        return {}
    return result


def get_system_info() -> Dict[str, Any]:
    """Brief: Collect simple system load and memory usage snapshot.

    Inputs:
      - None.

    Outputs:
      - Dict containing keys such as "load_1m", "load_5m", "load_15m",
        "memory_total_bytes", "memory_used_bytes", "memory_free_bytes", and
        "memory_available_bytes". Values are floats or integers when
        available, or None when the metric cannot be determined.

    Example:
      >>> info = get_system_info()  # doctest: +SKIP (depends on host)
      >>> "load_1m" in info
      True
    """

    payload: Dict[str, Any] = {
        "load_1m": None,
        "load_5m": None,
        "load_15m": None,
        "memory_total_bytes": None,
        "memory_used_bytes": None,
        "memory_free_bytes": None,
        "memory_available_bytes": None,
    }

    # Load averages
    try:
        if hasattr(os, "getloadavg"):
            load1, load5, load15 = os.getloadavg()  # type: ignore[assignment]
            payload["load_1m"] = float(load1)
            payload["load_5m"] = float(load5)
            payload["load_15m"] = float(load15)
    except Exception:  # pragma: no cover - environment specific
        pass

    # Memory statistics from /proc/meminfo when available
    meminfo = _read_proc_meminfo()
    if meminfo:
        total = meminfo.get("MemTotal")
        free = meminfo.get("MemFree")
        available = meminfo.get("MemAvailable")

        if isinstance(total, int):
            payload["memory_total_bytes"] = total
        if isinstance(free, int):
            payload["memory_free_bytes"] = free
        if isinstance(available, int):
            payload["memory_available_bytes"] = available
        if isinstance(total, int) and isinstance(available, int):
            used = total - available
            if used >= 0:
                payload["memory_used_bytes"] = used

    return payload


def _build_stats_payload_for_index(
    collector: Optional[StatsCollector],
) -> Dict[str, Any]:
    """Return statistics payload suitable for embedding in the index page.

    Inputs:
      - collector: Optional StatsCollector instance.

    Outputs:
      - Dict with either disabled status or a snapshot of current statistics.
    """

    if collector is None:
        return {"status": "disabled", "server_time": _utc_now_iso()}

    snap: StatsSnapshot = collector.snapshot(reset=False)
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
        "system": get_system_info(),
    }
    return payload


def _render_index_html(
    logo_url: str,
    stats_payload: Dict[str, Any],
    config_payload: Dict[str, Any],
) -> str:
    """Return HTML string for the virtual /index.html dashboard.

    Inputs:
      - logo_url: URL path to the logo image (e.g., "/logo.png").
      - stats_payload: Dict of statistics to render.
      - config_payload: Dict of sanitized configuration to render.

    Outputs:
      - HTML document as a string that references an external stylesheet
        (served from /styles.css under the html/ static root).
    """

    stats_pretty = html.escape(json.dumps(stats_payload, indent=2, sort_keys=True))
    config_pretty = html.escape(json.dumps(config_payload, indent=2, sort_keys=True))

    generated_at = html.escape(_utc_now_iso())

    return f"""<!DOCTYPE html>
<html lang=\"en\">
  <head>
    <meta charset=\"utf-8\" />
    <title>Foghorn statistics</title>
    <link rel=\"stylesheet\" href=\"/styles.css\" />
  </head>
  <body>
    <div class=\"page\">
      <header class=\"hero\">
        <img class=\"logo\" src=\"{logo_url}\" alt=\"Foghorn logo\" />
        <h1>Foghorn statistics</h1>
        <p class=\"meta\">Generated at {generated_at}</p>
      </header>

      <main class=\"panels\">
        <section class=\"panel panel-stats\">
          <h2>Statistics</h2>
          <pre>{stats_pretty}</pre>
        </section>

        <section class=\"panel panel-config\">
          <h2>Configuration (sanitized)</h2>
          <pre>{config_pretty}</pre>
        </section>
      </main>
    </div>
  </body>
</html>
"""


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
    config_path: str | None = None,
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
    app.state.config_path = config_path
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
            "system": get_system_info(),
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

    @app.get("/config/raw", dependencies=[Depends(auth_dep)])
    async def get_config_raw() -> Dict[str, Any]:
        """Return raw on-disk configuration without sanitization.

        Inputs:
          - None (uses app.state.config_path to locate YAML file).

        Outputs:
          - Dict containing server_time, raw_yaml (string with the exact file
            contents), and config keys, where config is the configuration
            mapping loaded from the YAML file on disk.

        Example:
          >>> # With app created via create_app(..., config_path="config.yaml")
          >>> # a GET /config/raw will return {"server_time": "...", "config": {...}, "raw_yaml": "..."}
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw_text = f.read()
            raw_cfg = yaml.safe_load(raw_text) or {}
        except (
            Exception
        ) as exc:  # pragma: no cover - I/O errors are environment-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to read config from {cfg_path}: {exc}",
            ) from exc
        return {"server_time": _utc_now_iso(), "config": raw_cfg, "raw_yaml": raw_text}

    @app.post("/config/save", dependencies=[Depends(auth_dep)])
    async def save_config(body: Dict[str, Any]) -> Dict[str, Any]:
        """Persist new configuration to disk and signal SIGUSR1 for reload.

        Inputs:
          - body: JSON object representing the full configuration mapping to
            serialize back to YAML.

        Outputs:
          - Dict with status, server_time, path to the written config, and
            backed_up_to indicating the backup file path.

        Notes:
          - The YAML file is written atomically via a temporary file and
            rename to avoid partial writes.
          - A timestamped backup copy of the previous config is created in the
            same directory before the overwrite.

        Example:
          >>> payload = {"listen": {"host": "127.0.0.1", "port": 5353}}
          >>> # POST /config/save with JSON body payload
        """

        if not isinstance(body, dict):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="request body must be a JSON object",
            )

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )

        # Prepare backup and atomic write paths
        cfg_path_abs = os.path.abspath(cfg_path)
        cfg_dir = os.path.dirname(cfg_path_abs)
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-")
        backup_path = f"{cfg_path_abs}.bak.{ts}"
        tmp_path = os.path.join(cfg_dir, f".tmp-{os.path.basename(cfg_path_abs)}-{ts}")

        try:
            # Best-effort backup of existing file
            if os.path.exists(cfg_path_abs):
                with open(cfg_path_abs, "rb") as src, open(backup_path, "wb") as dst:
                    dst.write(src.read())

            # Serialize new configuration to YAML
            yaml_text = yaml.safe_dump(
                body,
                default_flow_style=False,
                sort_keys=False,
                indent=2,
                allow_unicode=True,
            )

            with open(tmp_path, "w", encoding="utf-8") as tmp:
                tmp.write(yaml_text)
            os.replace(tmp_path, cfg_path_abs)
        except Exception as exc:  # pragma: no cover - file system specific
            # Clean up tmp file if something went wrong
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to write config to {cfg_path_abs}: {exc}",
            ) from exc

        # Signal main process to reload configuration
        try:
            os.kill(os.getpid(), signal.SIGUSR1)
        except Exception as exc:  # pragma: no cover - platform specific
            logger.error("Failed to send SIGUSR1 after config save: %s", exc)

        return {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "backed_up_to": backup_path,
        }

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

    @app.get("/index.html", response_class=HTMLResponse)
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve HTML index page.

        Inputs:
          - None.

        Outputs:
          - HTMLResponse. If html/index.html exists under the project html
            directory it is served directly; otherwise a virtual dashboard
            with stats and sanitized config is rendered.
        """

        # Prefer a real html/index.html from the project when present
        # Prefer an index.html next to this module (used by tests/legacy setups)
        module_dir = os.path.dirname(os.path.abspath(__file__))
        legacy_index = os.path.abspath(os.path.join(module_dir, "index.html"))
        if os.path.isfile(legacy_index):
            return FileResponse(legacy_index)

        # Otherwise, look under the configured html/ root
        www_root_local = getattr(app.state, "www_root", www_root)
        index_path = os.path.abspath(os.path.join(www_root_local, "index.html"))
        if os.path.isfile(index_path):
            return FileResponse(index_path)

        # Fallback to virtual dashboard when no static index is present
        collector: Optional[StatsCollector] = app.state.stats_collector
        stats_payload = _build_stats_payload_for_index(collector)

        cfg = app.state.config or {}
        web_cfg_inner = (cfg.get("webserver") or {}) if isinstance(cfg, dict) else {}
        redact_keys = web_cfg_inner.get("redact_keys") or [
            "token",
            "password",
            "secret",
        ]
        clean_cfg = sanitize_config(cfg, redact_keys=redact_keys)

        logo_url = "/logo.png"
        html_body = _render_index_html(logo_url, stats_payload, clean_cfg)
        return HTMLResponse(content=html_body)

    @app.get("/{path:path}")
    async def static_www(path: str) -> Any:
        """Serve files from the project-level html/ directory when they exist.

        Inputs:
          - path: Requested path segment (e.g., "logo.png" or "css/app.css").

        Outputs:
          - FileResponse when the file exists under html/, otherwise 404.
        """

        if not path:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="not found"
            )

        www_root_local = getattr(app.state, "www_root", www_root)
        root_abs = os.path.abspath(www_root_local)
        candidate = os.path.abspath(os.path.join(root_abs, path))

        # Simple path traversal protection: require candidate under html root.
        if not candidate.startswith(root_abs + os.sep):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="not found"
            )
        if not os.path.isfile(candidate):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="not found"
            )

        return FileResponse(candidate)

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
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self.stats = stats
        self.config = config
        self.log_buffer = log_buffer
        self.config_path = config_path


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
            "system": get_system_info(),
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

    def _handle_config_raw(self) -> None:
        """Brief: Handle GET /config_raw to return on-disk configuration.

        Inputs:
          - None (uses self.server.config_path to locate YAML file).

        Outputs:
          - JSON with server_time, raw_yaml (exact file contents), and config
            mapping loaded from disk.
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
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw_text = f.read()
            raw_cfg = yaml.safe_load(raw_text) or {}
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
            {"server_time": _utc_now_iso(), "config": raw_cfg, "raw_yaml": raw_text},
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

    def _handle_config_save(self, body: Dict[str, Any]) -> None:
        """Brief: Handle POST /config/save to persist config and signal SIGUSR1.

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
        cfg_dir = os.path.dirname(cfg_path_abs)
        ts = datetime.now(timezone.utc).isoformat().replace(":", "-")
        backup_path = f"{cfg_path_abs}.bak.{ts}"
        tmp_path = os.path.join(cfg_dir, f".tmp-{os.path.basename(cfg_path_abs)}-{ts}")

        try:
            if os.path.exists(cfg_path_abs):
                with open(cfg_path_abs, "rb") as src, open(backup_path, "wb") as dst:
                    dst.write(src.read())

            yaml_text = yaml.safe_dump(
                body,
                default_flow_style=False,
                sort_keys=False,
                indent=2,
                allow_unicode=True,
            )
            with open(tmp_path, "w", encoding="utf-8") as tmp:
                tmp.write(yaml_text)
            os.replace(tmp_path, cfg_path_abs)
        except Exception as exc:  # pragma: no cover
            try:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
            except Exception:
                pass
            self._send_json(
                500,
                {
                    "detail": f"failed to write config to {cfg_path_abs}: {exc}",
                    "server_time": _utc_now_iso(),
                },
            )
            return

        try:
            os.kill(os.getpid(), signal.SIGUSR1)
        except Exception as exc:  # pragma: no cover
            logger.error("Failed to send SIGUSR1 after config save (threaded): %s", exc)

        self._send_json(
            200,
            {
                "status": "ok",
                "server_time": _utc_now_iso(),
                "path": cfg_path_abs,
                "backed_up_to": backup_path,
            },
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

        # Prefer static html/index.html when available
        index_path = os.path.abspath(os.path.join(self._www_root(), "index.html"))
        if os.path.isfile(index_path):
            try:
                with open(index_path, "rb") as f:
                    data = f.read()
            except Exception as exc:  # pragma: no cover
                logger.error("Failed to read static index.html: %s", exc)
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Connection", "close")
                self.send_header("Content-Length", str(len(data)))
                self._apply_cors_headers()
                self.end_headers()
                self.wfile.write(data)
                return

        collector: Optional[StatsCollector] = getattr(self._server(), "stats", None)
        stats_payload = _build_stats_payload_for_index(collector)

        cfg = getattr(self._server(), "config", {}) or {}
        web_cfg_inner = (cfg.get("webserver") or {}) if isinstance(cfg, dict) else {}
        redact_keys = web_cfg_inner.get("redact_keys") or [
            "token",
            "password",
            "secret",
        ]
        clean = sanitize_config(cfg, redact_keys=redact_keys)

        logo_url = "/logo.png"
        html_body = _render_index_html(logo_url, stats_payload, clean)
        self._send_html(200, html_body)

    def _www_root(self) -> str:
        """Brief: Return absolute path to the project-level html directory.

        Inputs: none
        Outputs: str absolute path to html/.
        """

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
        elif path in {"/config/raw", "/config_raw"}:
            self._handle_config_raw()
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
        elif path == "/config/save":
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
    config_path: str | None = None,
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
            config_path=config_path,
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
    config_path: str | None = None,
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
        return _start_admin_server_threaded(
            stats, config, log_buffer, config_path=config_path
        )

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

    app = create_app(stats, config, log_buffer, config_path=config_path)

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
