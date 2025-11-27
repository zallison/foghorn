"""Admin HTTP server for Foghorn (statistics, config, logs, health).

This module provides a small FastAPI application and helpers to run it in a
background thread alongside the main DNS listeners.

All handlers return JSON data structures (never raw JSON strings) and are
backed by the in-process StatsCollector and current configuration dict.
"""

from __future__ import annotations

import copy
import http.server
import importlib
import json
import logging
import mimetypes
import os
import shutil
import signal
import socket
import threading
import time
import urllib.parse
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel

from .stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds

try:
    import psutil  # type: ignore[import]
except Exception:  # pragma: no cover - optional dependency fallback
    psutil = None  # type: ignore[assignment]


FOGHORN_VERSION = importlib.metadata.version("foghorn")
logger = logging.getLogger("foghorn.webserver")

# Lightweight cache for expensive system metrics to keep /stats fast under load.
_SYSTEM_INFO_CACHE_TTL_SECONDS = 2.0
_SYSTEM_INFO_CACHE_LOCK = threading.Lock()
_last_system_info: Dict[str, Any] | None = None
_last_system_info_ts: float = 0.0
_SYSTEM_INFO_DETAIL_MODE = "full"  # "full" or "basic"


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


def _json_safe(value: Any) -> Any:
    """Brief: Return a JSON-serializable representation of value.

    Inputs:
      - value: Arbitrary Python object that may not be JSON serializable.

    Outputs:
      - JSON-serializable structure where non-serializable objects (including
        exceptions) have been converted to strings or simple dicts.
    """

    # Fast path for primitives
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    # Preserve mapping and sequence structure
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]

    # Represent exceptions explicitly
    if isinstance(value, Exception):
        return {"type": type(value).__name__, "message": str(value)}

    # Fallback: string representation for anything else (e.g., datetime, Path).
    return str(value)


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
    """Brief: Collect simple system and process memory usage snapshot.

    Inputs:
      - None.

    Outputs:
      - Dict containing keys such as "load_1m", "load_5m", "load_15m",
        "memory_total_bytes", "memory_used_bytes", "memory_free_bytes",
        "memory_available_bytes", "process_rss_bytes", and "process_rss_mb".
        Values are floats or integers when available, or None when the metric
        cannot be determined.

    Example:
      >>> info = get_system_info()  # doctest: +SKIP (depends on host)
      >>> "load_1m" in info
      True
    """

    global _last_system_info, _last_system_info_ts

    now = time.time()
    cached = _last_system_info
    cached_ts = _last_system_info_ts
    if cached is not None and now - cached_ts < _SYSTEM_INFO_CACHE_TTL_SECONDS:
        return dict(cached)

    payload: Dict[str, Any] = {
        "load_1m": None,
        "load_5m": None,
        "load_15m": None,
        "memory_total_bytes": None,
        "memory_used_bytes": None,
        "memory_free_bytes": None,
        "memory_available_bytes": None,
        "process_rss_bytes": None,
        "process_rss_mb": None,
        "process_cpu_times": None,
        "process_cpu_percent": None,
        "process_io_counters": None,
        "process_open_files_count": None,
        "process_connections_count": None,
    }

    # Process metrics when psutil is available
    if psutil is not None:
        try:
            proc = psutil.Process(os.getpid())
            detail_mode = _SYSTEM_INFO_DETAIL_MODE

            # Memory (RSS) in bytes and MB
            rss_bytes = int(proc.memory_info().rss)
            payload["process_rss_bytes"] = rss_bytes
            payload["process_rss_mb"] = round(rss_bytes / (1024 * 1024), 2)

            # CPU times as a plain dict
            try:
                cpu_times = proc.cpu_times()
                payload["process_cpu_times"] = (
                    cpu_times._asdict()
                    if hasattr(cpu_times, "_asdict")
                    else tuple(cpu_times)
                )
            except Exception:
                pass

            # Non-blocking CPU percent sample (interval=0.0)
            try:
                payload["process_cpu_percent"] = float(proc.cpu_percent(interval=0.0))
            except Exception:
                pass

            # I/O counters as a plain dict
            try:
                io_counters = proc.io_counters()
                payload["process_io_counters"] = (
                    io_counters._asdict()
                    if hasattr(io_counters, "_asdict")
                    else tuple(io_counters)
                )
            except Exception:
                pass

            # Counts of open files and connections can be relatively expensive,
            # so only collect them when detail_mode is "full". The keys remain
            # present in the payload and default to None when skipped.
            if detail_mode == "full":
                try:
                    files = proc.open_files()
                    payload["process_open_files_count"] = (
                        len(files) if files is not None else 0
                    )
                except Exception:
                    pass

                try:
                    conns = proc.connections()
                    payload["process_connections_count"] = (
                        len(conns) if conns is not None else 0
                    )
                except Exception:
                    pass
        except Exception:  # pragma: no cover - environment specific
            pass

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

    # Publish into cache for subsequent callers.
    now = time.time()
    with _SYSTEM_INFO_CACHE_LOCK:
        _last_system_info = dict(payload)
        _last_system_info_ts = now

    return payload


def resolve_www_root(config: Dict[str, Any] | None = None) -> str:
    """Brief: Resolve absolute html root directory for static admin assets.

    Inputs:
      - config: Optional full configuration mapping (e.g. loaded from YAML).

    Outputs:
      - str absolute path to the directory from which static files are served.

    Example:
      >>> cfg = {"webserver": {"www_root": "/srv/foghorn/html"}}
      >>> path = resolve_www_root(cfg)
      >>> path.endswith("/srv/foghorn/html")
      True
    """

    # 1) Config override: webserver.www_root
    if isinstance(config, dict):
        web_cfg = (config.get("webserver") or {}) if isinstance(config, dict) else {}
        candidate = web_cfg.get("www_root")
        if isinstance(candidate, str) and candidate:
            cfg_path = Path(candidate).expanduser()
            if cfg_path.is_dir():
                return str(cfg_path.resolve())

    # 2) Environment variable override
    env_root = os.environ.get("FOGHORN_WWW_ROOT")
    if env_root:
        env_path = Path(env_root).expanduser()
        if env_path.is_dir():
            return str(env_path.resolve())

    # 3) Current working directory ./html
    cwd_html = Path(os.getcwd()) / "html"
    if cwd_html.is_dir():
        return str(cwd_html.resolve())

    # 4) Fallback to package-relative html directory (existing behavior)
    here = Path(__file__).resolve()
    pkg_html = here.parent.parent / "html"
    return str(pkg_html.resolve())


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
    global _SYSTEM_INFO_CACHE_TTL_SECONDS, _SYSTEM_INFO_DETAIL_MODE
    ttl_raw = web_cfg.get("system_info_ttl_seconds")
    if isinstance(ttl_raw, (int, float)) and ttl_raw > 0:
        _SYSTEM_INFO_CACHE_TTL_SECONDS = float(ttl_raw)

    detail_raw = str(web_cfg.get("system_metrics_detail", "full")).lower()
    if detail_raw in {"full", "basic"}:
        _SYSTEM_INFO_DETAIL_MODE = detail_raw

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

        # Measure timings for optional debug logging.
        t_start = time.time()
        snap: StatsSnapshot = collector.snapshot(reset=bool(reset))
        t_after_snapshot = time.time()

        try:
            hostname = socket.gethostname()
        except Exception:  # pragma: no cover - environment specific
            hostname = "unknown-host"
        try:
            host_ip = socket.gethostbyname(hostname)
        except Exception:  # pragma: no cover - environment specific
            host_ip = "0.0.0.0"

        # Round uptime to the nearest second for display.
        uptime_seconds = int(round(get_process_uptime_seconds()))

        meta: Dict[str, Any] = {
            "created_at": snap.created_at,
            "server_time": _utc_now_iso(),
            "hostname": hostname,
            "ip": host_ip,
            "version": FOGHORN_VERSION,
            "uptime": uptime_seconds,
        }

        system_info = get_system_info()
        t_after_system = time.time()

        # Optional DEBUG timings log for /stats when enabled in config.
        if getattr(app.state, "debug_stats_timings", False):
            logger.debug(
                "/stats timings: snapshot=%.6fs system_info=%.6fs total=%.6fs",
                t_after_snapshot - t_start,
                t_after_system - t_after_snapshot,
                t_after_system - t_start,
            )

        if snap.uniques:
            meta_with_uniques = meta | snap.uniques
        else:
            meta_with_uniques = meta

        payload: Dict[str, Any] = {
            "server_time": _utc_now_iso(),
            "totals": snap.totals,
            "rcodes": snap.rcodes,
            "qtypes": snap.qtypes,
            "uniques": snap.uniques,
            "upstreams": snap.upstreams,
            "meta": meta_with_uniques,
            "top_clients": snap.top_clients,
            "top_subdomains": snap.top_subdomains,
            "top_domains": snap.top_domains,
            "latency": snap.latency_stats,
            "latency_recent": snap.latency_recent_stats,
            "system": system_info,
            "upstream_rcodes": snap.upstream_rcodes,
            "upstream_qtypes": snap.upstream_qtypes,
            "qtype_qnames": snap.qtype_qnames,
            "rcode_domains": snap.rcode_domains,
            "rcode_subdomains": snap.rcode_subdomains,
            "cache_hit_domains": snap.cache_hit_domains,
            "cache_miss_domains": snap.cache_miss_domains,
            "cache_hit_subdomains": snap.cache_hit_subdomains,
            "cache_miss_subdomains": snap.cache_miss_subdomains,
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

        try:
            hostname = socket.gethostname()
        except Exception:  # pragma: no cover - environment specific
            hostname = "unknown-host"
        try:
            host_ip = socket.gethostbyname(hostname)
        except Exception:  # pragma: no cover - environment specific
            host_ip = "0.0.0.0"

        meta: Dict[str, Any] = {
            "created_at": snap.created_at,
            "server_time": _utc_now_iso(),
            "hostname": hostname,
            "ip": host_ip,
            "version": FOGHORN_VERSION,
        }

        return {
            "server_time": _utc_now_iso(),
            "created_at": snap.created_at,
            "totals": snap.totals,
            "rcodes": snap.rcodes,
            "qtypes": snap.qtypes,
            "meta": meta,
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
        """Persist new configuration to disk and signal SIGUSR1 for plugin notification.

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
                shutil.copy(cfg_path_abs, backup_path)

            raw_yaml = body.get("raw_yaml")
            if not isinstance(raw_yaml, str):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="request body must include 'raw_yaml' string field",
                )

            with open(cfg_path_abs + ".new", "w", encoding="utf-8") as tmp:
                tmp.write(raw_yaml)

            shutil.copy(cfg_path_abs + ".new", cfg_path_abs)

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

        # Signal main process so plugins can react to the updated configuration
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

    # Optional static HTML index and static file serving from www/
    index_enabled = bool(web_cfg.get("index", True))

    @app.get("/index.html", response_class=HTMLResponse)
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        """Serve html/index.html for root and index when enabled.

        Inputs:
          - None.

        Outputs:
          - HTMLResponse with the contents of html/index.html when it exists
            and webserver.index is true; otherwise HTTP 404.

        Example:
          >>> # GET / or /index.html will return the same html/index.html file
        """

        if not index_enabled:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="index disabled",
            )

        # Always serve the project-level html/index.html when present
        www_root_local = getattr(app.state, "www_root", www_root)
        index_path = os.path.abspath(os.path.join(www_root_local, "index.html"))
        if not os.path.isfile(index_path):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="index not found",
            )
        return FileResponse(index_path)

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
          - payload: Dict that will be converted to a JSON-safe structure.
        Outputs:
          - None
        """

        safe_payload = _json_safe(payload)
        body = json.dumps(safe_payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Connection", "close")
        self.send_header("Content-Length", str(len(body)))
        self._apply_cors_headers()
        self.end_headers()
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            logger.warning(
                "Client disconnected while sending JSON response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

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
        try:
            self.wfile.write(body)
        except BrokenPipeError:
            logger.warning(
                "Client disconnected while sending text response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

    def _send_html(self, status_code: int, html_body: str) -> None:
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
        except BrokenPipeError:
            logger.warning(
                "Client disconnected while sending HTML response for %s %s",
                getattr(self, "command", "GET"),
                getattr(self, "path", ""),
            )
            return

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

        payload: Dict[str, Any] = {
            "created_at": snap.created_at,
            "server_time": _utc_now_iso(),
            "totals": snap.totals,
            "rcodes": snap.rcodes,
            "qtypes": snap.qtypes,
            "uniques": snap.uniques,
            "upstreams": snap.upstreams,
            "meta": meta,
            "top_clients": snap.top_clients,
            "top_subdomains": snap.top_subdomains,
            "top_domains": snap.top_domains,
            "latency": snap.latency_stats,
            "latency_recent": snap.latency_recent_stats,
            "system": get_system_info(),
            "upstream_rcodes": snap.upstream_rcodes,
            "upstream_qtypes": snap.upstream_qtypes,
            "qtype_qnames": snap.qtype_qnames,
            "rcode_domains": snap.rcode_domains,
            "rcode_subdomains": snap.rcode_subdomains,
            "cache_hit_domains": snap.cache_hit_domains,
            "cache_miss_domains": snap.cache_miss_domains,
            "cache_hit_subdomains": snap.cache_hit_subdomains,
            "cache_miss_subdomains": snap.cache_miss_subdomains,
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
        """Brief: Handle POST /config/save to persist config and signal SIGUSR1 for plugins.

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
        except Exception as exc:  # pragma: no cover
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

        try:
            os.kill(os.getpid(), signal.SIGUSR1)
        except Exception as exc:  # pragma: no cover
            logger.error(
                "Failed to send SIGUSR1 after config save (threaded) for plugin notification: %s",
                exc,
            )

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
        except Exception as exc:  # pragma: no cover
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

    def _www_root(self) -> str:
        """Brief: Resolve absolute path to the html directory for static assets.

        Inputs: none
        Outputs: str absolute path to html/.
        """

        cfg = getattr(self._server(), "config", None)
        return resolve_www_root(cfg)

    def _try_serve_www(self, path: str) -> bool:
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
        except Exception as exc:  # pragma: no cover
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
        elif path in {"/", "/index.html"}:
            self._handle_index()
        else:
            # As a last resort, try to serve from html/ if the file exists.
            if self._try_serve_www(path):
                return
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
            logger.debug("webserver HTTP: %s", msg)


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
            # Always wait for the thread to exit, regardless of whether
            # a server instance was attached or shutdown raised.
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
            logger.warning("Now enjoy this exception I can do nothing about: \n")
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
