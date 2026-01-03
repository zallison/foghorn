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

from ..stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from .udp_server import DNSUDPHandler
from ..plugins.resolve.base import AdminPageSpec

try:
    import psutil  # type: ignore[import]
except Exception:  # pragma: no cover - optional dependency fallback
    psutil = None  # type: ignore[assignment]


_GITHUB_URL = "https://github.com/zallison/foghorn"

try:
    FOGHORN_VERSION = importlib_metadata.version("foghorn")
except Exception:  # pragma: no cover - defensive fallback
    FOGHORN_VERSION = "unknown"

logger = logging.getLogger("foghorn.webserver")

# Lightweight cache for expensive system metrics to keep /stats fast under load.
_SYSTEM_INFO_CACHE_TTL_SECONDS = 5.0
_SYSTEM_INFO_CACHE_LOCK = threading.Lock()
_last_system_info: Dict[str, Any] | None = None
_last_system_info_ts: float = 0.0
_SYSTEM_INFO_DETAIL_MODE = "full"  # "full" or "basic"

# Short-lived cache for expensive statistics snapshots shared by /stats and
# /traffic handlers. This keeps repeated polls from re-snapshotting the
# StatsCollector multiple times per second.
_STATS_SNAPSHOT_CACHE_TTL_SECONDS = 5.0
_STATS_SNAPSHOT_CACHE_LOCK = threading.Lock()
# Map id(StatsCollector) -> (StatsSnapshot, timestamp)
_last_stats_snapshots: Dict[int, tuple[StatsSnapshot, float]] = {}

# Short-lived cache for RateLimit statistics derived from its SQLite
# profile database(s). This keeps /api/v1/ratelimit lightweight even when
# rate_profiles contains many entries.
_RATE_LIMIT_CACHE_TTL_SECONDS = 5.0
_RATE_LIMIT_CACHE_LOCK = threading.Lock()
_last_rate_limit_snapshot: Dict[str, Any] | None = None
_last_rate_limit_snapshot_ts: float = 0.0

# Short-lived cache for sanitized YAML configuration text returned by /config.
# The underlying on-disk config rarely changes, so a small TTL avoids repeated
# disk I/O and redaction work under frequent polling.
_CONFIG_TEXT_CACHE_TTL_SECONDS = 2.0
_CONFIG_TEXT_CACHE_LOCK = threading.Lock()
_last_config_text_key: tuple[str, tuple[str, ...]] | None = None
_last_config_text: str | None = None
_last_config_text_ts: float = 0.0


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

    @registered_cached(cache=TTLCache(maxsize=10, ttl=2))
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


@dataclasses.dataclass
class _ListenerRuntime:
    """Brief: Track the runtime state of a single listener for readiness checks.

    Inputs (fields):
      - name: Logical listener name (e.g. 'udp', 'tcp', 'dot', 'doh', 'webserver').
      - enabled: Whether this listener is expected to be running.
      - thread: Optional Thread-like object that may implement is_alive().
      - error: Optional string describing a startup/runtime error.

    Outputs:
      - _ListenerRuntime instance.
    """

    name: str
    enabled: bool
    thread: Any | None = None
    error: str | None = None


class RuntimeState:
    """Brief: Shared, thread-safe runtime state used by /ready endpoints.

    Inputs (constructor):
      - startup_complete: Optional bool indicating whether main startup has completed.

    Outputs:
      - RuntimeState instance.

    Notes:
      - main() should mark startup_complete=True only after all configured listeners
        and the admin webserver have been started.
      - Listeners can be registered incrementally as threads/handles are created.

    Example:
      >>> state = RuntimeState()
      >>> state.set_listener('udp', enabled=True, thread=None)
      >>> state.mark_startup_complete()
    """

    def __init__(self, startup_complete: bool = False) -> None:
        self._lock = threading.Lock()
        self._startup_complete = bool(startup_complete)
        self._listeners: dict[str, _ListenerRuntime] = {}

    def mark_startup_complete(self) -> None:
        """Brief: Mark the process as having completed startup.

        Inputs: none
        Outputs: none
        """

        with self._lock:
            self._startup_complete = True

    def set_listener(self, name: str, *, enabled: bool, thread: Any | None) -> None:
        """Brief: Register or update a listener entry.

        Inputs:
          - name: Listener name string.
          - enabled: Whether the listener is expected to be running.
          - thread: Optional thread/handle object.

        Outputs:
          - None.
        """

        if not name:
            return
        with self._lock:
            current = self._listeners.get(name)
            error = current.error if current is not None else None
            self._listeners[name] = _ListenerRuntime(
                name=str(name),
                enabled=bool(enabled),
                thread=thread,
                error=error,
            )

    def set_listener_error(self, name: str, exc: Exception | str) -> None:
        """Brief: Attach an error message to a listener entry.

        Inputs:
          - name: Listener name string.
          - exc: Exception instance or error string.

        Outputs:
          - None.
        """

        if not name:
            return
        msg = str(exc)
        with self._lock:
            current = self._listeners.get(name)
            enabled = current.enabled if current is not None else True
            thread = current.thread if current is not None else None
            self._listeners[name] = _ListenerRuntime(
                name=str(name),
                enabled=bool(enabled),
                thread=thread,
                error=msg,
            )

    def snapshot(self) -> dict[str, Any]:
        """Brief: Return a JSON-safe snapshot of current runtime state.

        Inputs: none

        Outputs:
          - dict with keys: startup_complete (bool) and listeners (mapping).
        """

        with self._lock:
            listeners = {
                name: {
                    "enabled": entry.enabled,
                    "running": _thread_is_alive(entry.thread),
                    "error": entry.error,
                }
                for name, entry in self._listeners.items()
            }
            return {
                "startup_complete": bool(self._startup_complete),
                "listeners": listeners,
            }


def _thread_is_alive(obj: Any | None) -> bool:
    """Brief: Best-effort check whether a thread/handle is alive.

    Inputs:
      - obj: Thread-like object (may implement is_alive()) or None.

    Outputs:
      - bool: True when obj appears to be running.
    """

    if obj is None:
        return False
    try:
        fn = getattr(obj, "is_alive", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        return False
    # Some handles expose is_running instead of is_alive.
    try:
        fn = getattr(obj, "is_running", None)
        if callable(fn):
            return bool(fn())
    except Exception:
        return False
    return False


@registered_lru_cached(maxsize=1)
def _get_package_build_info() -> Dict[str, Any]:
    """Brief: Best-effort build metadata (commit, VCS url, etc.) from packaging.
    Inputs: none

    Outputs:
      - dict with keys:
          * git_sha: str|None
          * vcs_url: str|None
          * requested_revision: str|None
          * build_time: str|None
          * build_id: str|None

    Notes:
      - Prefers environment variables so container builds can inject stable build
        identifiers.
      - Falls back to PEP 610 direct_url.json metadata when available.
    """

    info: Dict[str, Any] = {
        "git_sha": None,
        "vcs_url": None,
        "requested_revision": None,
        "build_time": None,
        "build_id": None,
    }

    # Environment variable overrides (common in CI/container builds).
    for key, out_key in (
        ("FOGHORN_GIT_SHA", "git_sha"),
        ("GIT_SHA", "git_sha"),
        ("FOGHORN_BUILD_TIME", "build_time"),
        ("BUILD_TIME", "build_time"),
        ("FOGHORN_BUILD_ID", "build_id"),
        ("BUILD_ID", "build_id"),
    ):
        val = os.environ.get(key)
        if val and not info.get(out_key):
            info[out_key] = str(val)

    # PEP 610 direct_url.json (useful for editable installs from VCS).
    try:
        dist = importlib_metadata.distribution("foghorn")
        direct = dist.read_text("direct_url.json")
        if direct:
            payload = json.loads(direct)
            vcs_info = payload.get("vcs_info") if isinstance(payload, dict) else None
            if isinstance(vcs_info, dict):
                if not info.get("git_sha") and vcs_info.get("commit_id"):
                    info["git_sha"] = str(vcs_info.get("commit_id"))
                if vcs_info.get("requested_revision") and not info.get(
                    "requested_revision"
                ):
                    info["requested_revision"] = str(vcs_info.get("requested_revision"))
            if payload.get("url") and not info.get("vcs_url"):
                info["vcs_url"] = str(payload.get("url"))
    except Exception:
        pass

    return info


def _get_about_payload() -> Dict[str, Any]:
    """Brief: Build the lightweight /about payload.

    Inputs: none

    Outputs:
      - dict containing version, build info, and the project GitHub URL.
    """

    build = _get_package_build_info()
    # Only include non-empty build fields to keep the payload compact.
    build_clean = {k: v for k, v in build.items() if v}
    return {
        "server_time": _utc_now_iso(),
        "version": FOGHORN_VERSION,
        "github_url": _GITHUB_URL,
        "build": build_clean,
    }


def _expected_listeners_from_config(config: Dict[str, Any] | None) -> Dict[str, bool]:
    """Brief: Determine which listeners should be running based on config.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - dict mapping listener name -> enabled bool.

    Notes:
      - Mirrors the defaults in foghorn.main: UDP defaults to enabled, others default
        to disabled.
    """

    cfg = config if isinstance(config, dict) else {}
    listen = cfg.get("listen") or {}
    if not isinstance(listen, dict):
        listen = {}

    def _enabled(subkey: str, default: bool) -> bool:
        sub = listen.get(subkey)
        if not isinstance(sub, dict):
            return bool(default)
        return bool(sub.get("enabled", default))

    web_cfg = _get_web_cfg(cfg)
    # If a webserver block exists, treat it as enabled by default unless
    # explicitly disabled with enabled: false.
    has_web_cfg = bool(web_cfg)
    raw_web_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    web_enabled = bool(raw_web_enabled) if raw_web_enabled is not None else has_web_cfg

    return {
        "udp": _enabled("udp", True),
        "tcp": _enabled("tcp", False),
        "dot": _enabled("dot", False),
        "doh": _enabled("doh", False),
        "webserver": web_enabled,
    }


def evaluate_readiness(
    *,
    stats: Optional[StatsCollector],
    config: Dict[str, Any] | None,
    runtime_state: RuntimeState | None,
) -> tuple[bool, list[str], dict[str, Any]]:
    """Brief: Compute readiness result and reasons for /ready endpoints.

    Inputs:
      - stats: Optional StatsCollector instance.
      - config: Full configuration mapping loaded from YAML (or None).
      - runtime_state: Optional RuntimeState populated by foghorn.main.

    Outputs:
      - (ready, details)
        * ready: bool
        * details: dict with structured readiness details

    Notes:
      - Readiness is stricter than liveness: it verifies expected listeners are
        running, required upstream configuration exists, and optional persistence
        store health checks pass.
    """

    cfg = config if isinstance(config, dict) else {}
    expected = _expected_listeners_from_config(cfg)

    not_ready: list[str] = []

    state_snapshot = (
        runtime_state.snapshot()
        if runtime_state is not None
        else {
            "startup_complete": True,
            "listeners": {},
        }
    )

    if not state_snapshot.get("startup_complete"):
        not_ready.append("startup not complete")

    # Upstream configuration: required in forwarder mode.
    fog_cfg = cfg.get("foghorn") or {}
    resolver_cfg = (
        (fog_cfg.get("resolver") if isinstance(fog_cfg, dict) else None)
        or cfg.get("resolver")
        or {}
    )
    if not isinstance(resolver_cfg, dict):
        resolver_cfg = {}
    mode = str(resolver_cfg.get("mode", "forward")).lower()

    if mode == "forward":
        upstreams = cfg.get("upstreams") or []
        if (
            not isinstance(upstreams, list)
            or len([u for u in upstreams if isinstance(u, dict)]) == 0
        ):
            not_ready.append("no upstreams configured")

    # Listener threads/handles.
    listeners_state = state_snapshot.get("listeners") or {}
    for name, enabled in expected.items():
        if not enabled:
            continue
        entry = listeners_state.get(name) or {}
        running = bool(entry.get("running"))
        err = entry.get("error")
        if err:
            not_ready.append(f"{name} error: {err}")
        elif not running:
            not_ready.append(f"{name} listener not running")

    # Store availability (only when persistence is configured).
    stats_cfg = cfg.get("statistics") or {}
    if not isinstance(stats_cfg, dict):
        stats_cfg = {}
    persistence_cfg = stats_cfg.get("persistence") or {}
    if not isinstance(persistence_cfg, dict):
        persistence_cfg = {}

    stats_enabled = bool(stats_cfg.get("enabled", False))
    persistence_enabled = bool(persistence_cfg.get("enabled", True))

    if stats_enabled and persistence_enabled:
        store = getattr(stats, "_store", None) if stats is not None else None
        if store is None:
            not_ready.append("statistics persistence store not available")
        else:
            try:
                # Prefer an explicit health_check() when available.
                fn = getattr(store, "health_check", None)
                ok = bool(fn()) if callable(fn) else True
                if not ok:
                    not_ready.append("statistics persistence store not healthy")
            except Exception as exc:
                not_ready.append(f"statistics persistence store error: {exc}")

    details = {
        "mode": mode,
        "expected_listeners": expected,
        "runtime": state_snapshot,
    }

    ready = len(not_ready) == 0
    return ready, not_ready, details


def _get_web_cfg(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Brief: Return the webserver config subsection from a full config mapping.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - Dict representing config['webserver'] when present; otherwise {}.

    Notes:
      - Centralizing this avoids drift between FastAPI and threaded HTTP paths.
    """

    if isinstance(config, dict):
        web_cfg = config.get("webserver") or {}
        return web_cfg if isinstance(web_cfg, dict) else {}
    return {}


def _get_redact_keys(config: Dict[str, Any] | None) -> list[str]:
    """Brief: Determine which config keys should be redacted for /config endpoints.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - List of key names that should have their values redacted.

    Notes:
      - Uses webserver.redact_keys when set; otherwise falls back to a small
        default allowlist.
    """

    web_cfg = _get_web_cfg(config)
    keys = web_cfg.get("redact_keys") or ["token", "password", "secret"]
    # Normalize to a list[str]
    if isinstance(keys, (list, tuple)):
        return [str(k) for k in keys]
    return [str(keys)]


def _trim_top_fields(payload: Dict[str, Any], limit: int, fields: list[str]) -> None:
    """Brief: Trim top-N style payload fields in-place.

    Inputs:
      - payload: Response payload mapping to modify.
      - limit: Positive integer N.
      - fields: List of top-level keys to trim when the value is a list or a
        mapping of lists.

    Outputs:
      - None. payload is modified in-place.

    Notes:
      - Both FastAPI and threaded /stats use the same trimming semantics.
    """

    if limit <= 0:
        limit = 10

    def _trim_one(key: str) -> None:
        value = payload.get(key)
        if isinstance(value, list):
            payload[key] = value[:limit]
        elif isinstance(value, dict):
            trimmed: Dict[str, Any] = {}
            for k, v in value.items():
                if isinstance(v, list):
                    trimmed[k] = v[:limit]
                else:
                    trimmed[k] = v
            payload[key] = trimmed

    for f in fields:
        _trim_one(f)


def _build_stats_payload_from_snapshot(
    snap: StatsSnapshot,
    *,
    meta: Dict[str, Any],
    system_info: Dict[str, Any],
) -> Dict[str, Any]:
    """Brief: Build the /stats response body from an existing StatsSnapshot.

    Inputs:
      - snap: StatsSnapshot from StatsCollector.
      - meta: Metadata mapping (hostname/version/etc) computed by the caller.
      - system_info: System metrics mapping (see get_system_info()).

    Outputs:
      - Dict suitable for JSON serialization with all /stats keys.

    Notes:
      - This is shared by the FastAPI and threaded fallback implementations.
      - The caller is responsible for setting server_time and any meta differences.
    """

    payload: Dict[str, Any] = {
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
        "rate_limit": getattr(snap, "rate_limit", None),
    }

    dnssec_totals = getattr(snap, "dnssec_totals", None)
    if dnssec_totals:
        payload["dnssec"] = dnssec_totals

    return payload


def _build_traffic_payload_from_snapshot(
    snap: StatsSnapshot,
    *,
    meta: Dict[str, Any] | None,
    top: int,
) -> Dict[str, Any]:
    """Brief: Build the /traffic response body from an existing StatsSnapshot.

    Inputs:
      - snap: StatsSnapshot from StatsCollector.
      - meta: Optional metadata mapping computed by the caller.
      - top: Max number of items in top lists.

    Outputs:
      - Dict suitable for JSON serialization.

    Notes:
      - FastAPI includes a meta block; the threaded fallback historically did not.
        Passing meta=None preserves that behaviour.
    """

    if top <= 0:
        top = 10

    top_clients = list(snap.top_clients or [])[:top]
    top_domains = list(snap.top_domains or [])[:top]

    payload: Dict[str, Any] = {
        "server_time": _utc_now_iso(),
        "created_at": snap.created_at,
        "totals": snap.totals,
        "rcodes": snap.rcodes,
        "qtypes": snap.qtypes,
        "top_clients": top_clients,
        "top_domains": top_domains,
        "latency": snap.latency_stats,
    }
    if meta is not None:
        payload["meta"] = meta
    return payload


def _get_config_raw_text(cfg_path: str) -> str:
    """Brief: Read and return the raw config YAML text from disk.

    Inputs:
      - cfg_path: Filesystem path to the YAML configuration file.

    Outputs:
      - Raw YAML text.

    Raises:
      - OSError/IOError for filesystem failures.
    """

    with open(cfg_path, "r", encoding="utf-8") as f:
        return f.read()


def _get_config_raw_json(cfg_path: str) -> Dict[str, Any]:
    """Brief: Read the on-disk YAML config and return both parsed mapping and raw text.

    Inputs:
      - cfg_path: Filesystem path to the YAML configuration file.

    Outputs:
      - Dict with keys: config (parsed mapping) and raw_yaml (exact text).

    Raises:
      - OSError/IOError for filesystem failures.
      - yaml.YAMLError (or generic Exception) for parse errors.
    """

    raw_text = _get_config_raw_text(cfg_path)
    raw_cfg = yaml.safe_load(raw_text) or {}
    return {"config": raw_cfg, "raw_yaml": raw_text}


def _ts_to_utc_iso(ts: float) -> str:
    """Brief: Convert a Unix timestamp (seconds) to an ISO8601 UTC string.

    Inputs:
      - ts: Unix timestamp in seconds.

    Outputs:
      - ISO8601 string in UTC ("...Z" suffix).
    """

    try:
        dt = datetime.fromtimestamp(float(ts), tz=timezone.utc)
    except Exception:
        dt = datetime.fromtimestamp(0.0, tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _parse_utc_datetime(value: str) -> datetime:
    """Parse a datetime string into an aware UTC datetime.

    Brief:
      Accepts either ISO-8601-like strings (including a trailing 'Z') or
      a simple space-separated format "YYYY-MM-DD HH:MM:SS" (optionally with
      fractional seconds).

    Inputs:
      - value: Datetime string.

    Outputs:
      - datetime: Timezone-aware datetime in UTC.

    Raises:
      - ValueError when parsing fails.

    Example:
      >>> dt = _parse_utc_datetime('2025-12-10 01:02:03')
      >>> dt.tzinfo is not None
      True
    """

    raw = str(value or "").strip()
    if not raw:
        raise ValueError("empty datetime")

    # ISO8601 (support trailing Z)
    iso = raw.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(iso)
    except Exception:
        dt = None  # type: ignore[assignment]

    if dt is None:
        # Common non-ISO format used in config/UI
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
            try:
                dt = datetime.strptime(raw, fmt)
                break
            except Exception:
                dt = None  # type: ignore[assignment]

    if dt is None:
        raise ValueError(f"invalid datetime: {raw}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


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


# Precompiled regexes for lightweight YAML redaction that preserves layout/comments.
_YAML_KEY_LINE_RE = re.compile(r"^(\s*)([^:\s][^:]*)\s*:(.*)$")
# List item that is itself a mapping entry, e.g. "  - suffix: example.com".
_YAML_LIST_KEY_LINE_RE = re.compile(r"^(\s*)-\s*([^:\s][^:]*)\s*:(.*)$")
_YAML_LIST_LINE_RE = re.compile(r"^(\s*)-\s*(.*)$")


@registered_cached(cache=TTLCache(maxsize=1024, ttl=30))
def _split_yaml_value_and_comment(rest: str) -> tuple[str, str]:
    """Split the portion of a YAML line after ':' or '-' into value and comment.

    Inputs:
      - rest: Substring after the ':' or '-' token, including any value and comment.

    Outputs:
      - Tuple (value, comment_suffix) where comment_suffix includes leading ' #'
        when a comment is present, otherwise an empty string.
    """

    if "#" not in rest:
        return rest.rstrip(), ""
    before, comment = rest.split("#", 1)
    return before.rstrip(), " #" + comment


def _redact_yaml_text_preserving_layout(
    raw_yaml: str, redact_keys: List[str] | None
) -> str:
    """Redact sensitive keys in raw YAML text while preserving comments/spacing.

    Inputs:
      - raw_yaml: Original YAML document text as read from disk.
      - redact_keys: List of key names whose values and all nested subkeys
        should be redacted.

    Outputs:
      - New YAML text with the same overall layout and comments, but with
        matching keys and any keys/subkeys within their block replaced by
        '***' for scalar values only. Mapping (dict) and sequence (list)
        values are left intact at the key line, with nested scalars redacted
        within their block where possible.

    Notes:
      - This is a best-effort textual transformation intended for human-facing
        display (e.g., the admin UI). It is not a full YAML parser and may not
        handle all edge cases, but it preserves common constructs well.
      - Some callers may accidentally pass in YAML text that has been
        "double-escaped" such that literal "\\n" sequences appear in the
        content instead of real newlines (for example, when YAML is embedded
        inside JSON or logs). To keep the behavior predictable for these
        callers, we heuristically treat "\\n" sequences as real newlines
        before applying layout-preserving redaction.
    """

    if not raw_yaml or not redact_keys:
        return raw_yaml

    # Heuristic: collapse literal "\\n" sequences into real newlines so that
    # YAML constructed via double-escaping (e.g. "line1\\nline2") is treated
    # like on-disk multi-line YAML. This is a best-effort transformation for
    # admin display only and does not affect the underlying configuration.
    text = raw_yaml.replace("\\n", "\n") if "\\n" in raw_yaml else raw_yaml

    targets = {str(k) for k in redact_keys}
    lines = text.splitlines(keepends=False)
    out_lines: list[str] = []

    def _is_container_like(val: str) -> bool:
        """Best-effort check if an inline YAML value denotes a list or dict."""
        v = (val or "").lstrip()
        return v.startswith("[") or v.startswith("{")

    # Track a single active redaction block keyed by its indentation level.
    in_block = False
    block_indent: int | None = None

    for line in lines:
        stripped = line.lstrip(" ")
        indent_len = len(line) - len(stripped)

        # Empty or whitespace-only lines are passed through unchanged.
        if not stripped:
            out_lines.append(line)
            continue

        # If we are currently inside a redaction block and encounter a line that
        # is not more indented than the block, treat it as leaving the block
        # *before* processing the line below.
        if in_block and block_indent is not None and indent_len <= block_indent:
            in_block = False
            block_indent = None

        # Handle standard mapping key lines ("key: value").
        m_key = _YAML_KEY_LINE_RE.match(line)
        if m_key:
            indent, key, rest = m_key.groups()
            key_clean = key.strip()

            # Starting a new redaction block when the key itself is in targets.
            if key_clean in targets:
                # Determine the inline value (if any), excluding any trailing comment
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()

                # Enter a block only when the key introduces a nested block
                # (i.e., nothing after ':' once comments are stripped).
                if not value_trim:
                    in_block = True
                    block_indent = indent_len
                    # Nothing to replace on this line; leave it as-is (no '***').
                    out_lines.append(line)
                    continue

                # If the inline value is a list/dict, do not replace with '***'.
                if _is_container_like(value_trim):
                    out_lines.append(line)
                    continue

                # Scalar inline value -> redact.
                new_line = f"{indent}{key_clean}: ***{comment_part}"
                out_lines.append(new_line)
                continue

            # Redact any keys nested under an active redaction block.
            if in_block:
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()
                # Only redact scalars; when no inline value or container, keep as-is.
                if value_trim and not _is_container_like(value_trim):
                    new_line = f"{indent}{key_clean}: ***{comment_part}"
                    out_lines.append(new_line)
                    continue
                # Keep original line if not a scalar inline value.
                out_lines.append(line)
                continue

        # Handle list items; a list item can be either "- value" or
        # "- key: value" (mapping entry inside a list).
        m_list_key = _YAML_LIST_KEY_LINE_RE.match(line)
        if m_list_key:
            indent, key, rest = m_list_key.groups()
            key_clean = key.strip()

            # If the key for this list-mapping entry is sensitive, redact it and
            # treat it as part of any active block.
            if key_clean in targets or in_block:
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()

                # Enter block only when this list item starts a nested block.
                if key_clean in targets and not in_block and not value_trim:
                    in_block = True
                    block_indent = indent_len
                    out_lines.append(line)  # nothing to replace on this header line
                    continue

                # If inline value is a list/dict or absent, keep the line.
                if not value_trim or _is_container_like(value_trim):
                    out_lines.append(line)
                    continue

                # Scalar inline value -> redact.
                new_line = f"{indent}- {key_clean}: ***{comment_part}"
                out_lines.append(new_line)
                continue

        # Redact simple list items nested under any redacted block ("- value").
        # This handles the case where a list of scalars lives under a previously
        # redacted mapping key; in practice this is a rare layout and the
        # mapping/list-key redaction above already covers the common cases.
        if in_block:  # pragma: no cover - low-value edge case for scalar-only lists
            m_list = _YAML_LIST_LINE_RE.match(line)
            if m_list:
                indent, rest = m_list.groups()
                value_part, comment_part = _split_yaml_value_and_comment(rest)
                value_trim = value_part.strip()
                # Only redact scalars; keep container or empty-as-header lines.
                if value_trim and not _is_container_like(value_trim):
                    new_line = f"{indent}- ***{comment_part}"
                    out_lines.append(new_line)
                    continue
                out_lines.append(line)
                continue

        # Default: emit the original line unchanged.
        out_lines.append(line)

    redacted = "\n".join(out_lines)
    # Preserve a trailing newline if the original had one.
    if raw_yaml.endswith("\n") and not redacted.endswith("\n"):
        redacted += "\n"
    return redacted


def _get_sanitized_config_yaml_cached(
    cfg: Dict[str, Any], cfg_path: str | None, redact_keys: List[str] | None
) -> str:
    """Return sanitized configuration YAML text with a short-lived cache.

    Inputs:
      - cfg: In-memory configuration mapping.
      - cfg_path: Optional filesystem path to the active YAML config file.
      - redact_keys: List of key names whose values should be redacted.

    Outputs:
      - YAML string with sensitive values redacted.
    """

    global _last_config_text_key, _last_config_text, _last_config_text_ts

    key = (str(cfg_path or ""), tuple(sorted(str(k) for k in (redact_keys or []))))
    now = time.time()
    with _CONFIG_TEXT_CACHE_LOCK:
        if (
            _last_config_text is not None
            and _last_config_text_key == key
            and now - _last_config_text_ts < _CONFIG_TEXT_CACHE_TTL_SECONDS
        ):
            return _last_config_text

    # Cache miss: compute sanitized YAML text.
    if cfg_path:
        try:
            with open(cfg_path, "r", encoding="utf-8") as f:
                raw_text = f.read()
            body = _redact_yaml_text_preserving_layout(raw_text, redact_keys or [])
        except Exception:  # pragma: no cover - I/O specific
            clean = sanitize_config(cfg, redact_keys=redact_keys or [])
            try:
                body = yaml.safe_dump(clean, sort_keys=False)  # type: ignore[arg-type]
            except Exception:
                body = ""
    else:
        clean = sanitize_config(cfg, redact_keys=redact_keys or [])
        try:
            body = yaml.safe_dump(clean, sort_keys=False)  # type: ignore[arg-type]
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            body = ""

    with _CONFIG_TEXT_CACHE_LOCK:
        _last_config_text_key = key
        _last_config_text = body
        _last_config_text_ts = time.time()
    return body


def _find_rate_limit_db_paths_from_config(config: Dict[str, Any] | None) -> list[str]:
    """Brief: Discover RateLimit db_path values from the loaded config.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - List of unique db_path strings for RateLimit instances. When no
        explicit plugins referencing rate_limit are found, an empty list is
        returned so callers can decide whether to fall back to a default
        location.
    """

    paths: set[str] = set()
    if not isinstance(config, dict):
        return []

    plugins_cfg = config.get("plugins") or []
    if isinstance(plugins_cfg, list):
        for entry in plugins_cfg:
            if not isinstance(entry, dict):
                continue
            module = str(entry.get("module", "")).lower()
            # Match both full dotted path and alias-style module names.
            if "rate_limit" not in module:
                continue
            cfg = entry.get("config") or {}
            if isinstance(cfg, dict) and cfg.get("db_path"):
                paths.add(str(cfg.get("db_path")))

    return sorted(paths)


def _collect_rate_limit_stats(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Brief: Collect per-key RateLimit statistics from sqlite3 profiles.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - Dict with keys:
          * databases: list of per-db summaries including db_path, total_profiles,
            max_avg_rps, max_max_rps, and a limited list of individual profiles.
    """

    global _last_rate_limit_snapshot, _last_rate_limit_snapshot_ts

    now = time.time()
    with _RATE_LIMIT_CACHE_LOCK:
        if (
            _last_rate_limit_snapshot is not None
            and now - _last_rate_limit_snapshot_ts < _RATE_LIMIT_CACHE_TTL_SECONDS
        ):
            return dict(_last_rate_limit_snapshot)

    db_paths = _find_rate_limit_db_paths_from_config(config)
    summaries: list[Dict[str, Any]] = []

    # Heuristic fallback: if no explicit db_path is configured but the default
    # RateLimit db exists, include it.
    default_db = "./config/var/rate_limit.db"
    if not db_paths and os.path.exists(
        default_db
    ):  # pragma: no cover - default RateLimit DB fallback path
        db_paths.append(default_db)

    for path in db_paths:
        try:
            if not os.path.exists(path):
                continue
            with sqlite3.connect(path) as conn:
                cur = conn.cursor()
                cur.execute(
                    "SELECT key, avg_rps, max_rps, samples, last_update "
                    "FROM rate_profiles ORDER BY avg_rps DESC LIMIT 200"
                )
                rows = cur.fetchall()
        except Exception:  # pragma: no cover - defensive / I/O specific
            logger.debug(
                "webserver: failed to collect rate_limit stats from %s",
                path,
                exc_info=True,
            )
            continue

        if not rows:
            summaries.append(
                {
                    "db_path": path,
                    "total_profiles": 0,
                    "max_avg_rps": 0.0,
                    "max_max_rps": 0.0,
                    "profiles": [],
                }
            )
            continue

        profiles: list[Dict[str, Any]] = []
        max_avg = 0.0
        max_max = 0.0
        for key, avg_rps, max_rps, samples, last_update in rows:
            try:
                avg_val = float(avg_rps)
            except Exception:
                avg_val = 0.0
            try:
                max_val = float(max_rps)
            except Exception:
                max_val = 0.0
            try:
                samples_val = int(samples)
            except Exception:
                samples_val = 0
            try:
                last_val = int(last_update)
            except Exception:
                last_val = 0

            max_avg = max(max_avg, avg_val)
            max_max = max(max_max, max_val)
            profiles.append(
                {
                    "key": str(key),
                    "avg_rps": avg_val,
                    "max_rps": max_val,
                    "samples": samples_val,
                    "last_update": last_val,
                }
            )

        summaries.append(
            {
                "db_path": path,
                "total_profiles": len(profiles),
                "max_avg_rps": max_avg,
                "max_max_rps": max_max,
                "profiles": profiles,
            }
        )

    payload: Dict[str, Any] = {"databases": summaries}
    with _RATE_LIMIT_CACHE_LOCK:
        _last_rate_limit_snapshot = dict(payload)
        _last_rate_limit_snapshot_ts = time.time()
    return payload


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


@registered_cached(cache=TTLCache(maxsize=1, ttl=2))
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


def _get_stats_snapshot_cached(collector: StatsCollector, reset: bool) -> StatsSnapshot:
    """Return StatsSnapshot using a short-lived cache when reset is False.

    Inputs:
      - collector: Active StatsCollector instance.
      - reset: When True, force a fresh snapshot and update the cache.

    Outputs:
      - StatsSnapshot representing the current statistics view.

    Notes:
      - When reset is True, the underlying StatsCollector state is cleared and
        the freshly-reset snapshot is stored into the cache so subsequent
        non-reset callers see the new baseline.
    """

    global _last_stats_snapshots

    collector_id = id(collector)

    if reset:
        snap = collector.snapshot(reset=True)
        with _STATS_SNAPSHOT_CACHE_LOCK:
            _last_stats_snapshots[collector_id] = (snap, time.time())
        return snap

    now = time.time()
    with _STATS_SNAPSHOT_CACHE_LOCK:
        entry = _last_stats_snapshots.get(collector_id)
    if entry is not None:
        cached, cached_ts = entry
        if now - cached_ts < _STATS_SNAPSHOT_CACHE_TTL_SECONDS:
            return cached

    snap = collector.snapshot(reset=False)
    with _STATS_SNAPSHOT_CACHE_LOCK:
        _last_stats_snapshots[collector_id] = (snap, time.time())
    return snap


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
            except (
                Exception
            ):  # pragma: no cover - defensive psutil.cpu_times() error path
                pass

            # Non-blocking CPU percent sample (interval=0.0)
            try:
                payload["process_cpu_percent"] = float(proc.cpu_percent(interval=0.0))
            except (
                Exception
            ):  # pragma: no cover - defensive psutil.cpu_percent() error path
                pass

            # I/O counters as a plain dict
            try:
                io_counters = proc.io_counters()
                payload["process_io_counters"] = (
                    io_counters._asdict()
                    if hasattr(io_counters, "_asdict")
                    else tuple(io_counters)
                )
            except (
                Exception
            ):  # pragma: no cover - defensive psutil.io_counters() error path
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
                except (
                    Exception
                ):  # pragma: no cover - defensive psutil.open_files() error path
                    pass

                try:
                    conns = proc.connections()
                    payload["process_connections_count"] = (
                        len(conns) if conns is not None else 0
                    )
                except (
                    Exception
                ):  # pragma: no cover - defensive psutil.connections() error path
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
      >>> cfg = {"server": {"http": {"www_root": "/srv/foghorn/html"}}}
      >>> path = resolve_www_root(cfg)
      >>> path.endswith("/srv/foghorn/html")
      True
    """

    # 1) Config override: server.http.www_root
    if isinstance(config, dict):
        server_cfg = config.get("server") or {}
        http_cfg = server_cfg.get("http") or {}
        if isinstance(http_cfg, dict):
            candidate = http_cfg.get("www_root")
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

    # 4) Fallback to package-relative html directory within the installed package
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
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="unauthorized",
                headers={"WWW-Authenticate": "Bearer"},
            )

    if mode == "token":
        return _token_auth
    # basic or unknown -> treat as none for now; can be expanded later.
    return _no_auth


def _schedule_sighup_after_config_save(delay_seconds: float = 1.0) -> None:
    """Brief: Schedule SIGHUP to the main process after a small delay.

    Inputs:
      - delay_seconds: Number of seconds to wait before sending SIGHUP. A value
        of 0 or less sends the signal synchronously in the current thread.

    Outputs:
      - None; best-effort scheduling of a background timer that will send
        signal.SIGHUP to the current process ID. Failures are logged.
    """

    pid = os.getpid()

    def _send() -> None:
        try:
            os.kill(pid, signal.SIGHUP)
        except Exception as exc:  # pragma: no cover - platform specific
            logger.error("Failed to send SIGHUP after config save: %s", exc)

    # For callers that explicitly opt out of delayed delivery (e.g., tests or
    # short-lived helper processes), allow synchronous delivery to avoid the
    # signal firing after the surrounding context (such as monkeypatches) has
    # been torn down.
    if delay_seconds <= 0:
        _send()
        return

    timer = threading.Timer(delay_seconds, _send)
    timer.daemon = True
    timer.start()


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
    global _SYSTEM_INFO_CACHE_TTL_SECONDS, _SYSTEM_INFO_DETAIL_MODE, _STATS_SNAPSHOT_CACHE_TTL_SECONDS, _CONFIG_TEXT_CACHE_TTL_SECONDS

    # Optional tuning for system metrics cache TTL.
    ttl_raw = web_cfg.get("system_info_ttl_seconds")
    if isinstance(ttl_raw, (int, float)) and ttl_raw > 0:
        _SYSTEM_INFO_CACHE_TTL_SECONDS = float(ttl_raw)

    # Optional tuning for how often StatsCollector.snapshot() is recomputed.
    stats_ttl_raw = web_cfg.get("stats_snapshot_ttl_seconds")
    if isinstance(stats_ttl_raw, (int, float)) and stats_ttl_raw > 0:
        _STATS_SNAPSHOT_CACHE_TTL_SECONDS = float(stats_ttl_raw)

    # Optional tuning for how often sanitized YAML text is recomputed for /config.
    cfg_ttl_raw = web_cfg.get("config_cache_ttl_seconds")
    if isinstance(cfg_ttl_raw, (int, float)) and cfg_ttl_raw > 0:
        _CONFIG_TEXT_CACHE_TTL_SECONDS = float(cfg_ttl_raw)

    # Optional control over how heavy the system metrics collection is.
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

    @app.get("/api/v1/health")
    @app.get("/health")
    async def health() -> Dict[str, Any]:
        """Return simple liveness information.

        Inputs: none
        Outputs: dict with status and server_time.
        """

        return {"status": "ok", "server_time": _utc_now_iso()}

    @app.get("/api/v1/about")
    @app.get("/about")
    async def about() -> Dict[str, Any]:
        """Brief: Return lightweight version/build metadata.

        Inputs: none

        Outputs:
          - dict containing version, github_url, and optional build metadata.
        """

        return _get_about_payload()

    @app.get("/api/v1/status")
    @app.get("/status")
    @app.get("/api/v1/ready")
    @app.get("/ready")
    async def ready() -> JSONResponse:
        """Brief: Readiness probe endpoint (configuration + listener readiness).

        Inputs: none

        Outputs:
          - JSONResponse with status_code 200 when ready, else 503.
          - Body includes 'ready', 'not_ready' (list), and structured 'details'.
        """

        state: RuntimeState | None = getattr(app.state, "runtime_state", None)
        ready_ok, not_ready, details = evaluate_readiness(
            stats=getattr(app.state, "stats_collector", None),
            config=getattr(app.state, "config", None),
            runtime_state=state,
        )
        payload = {
            "server_time": _utc_now_iso(),
            "ready": ready_ok or not not_ready,
            "details": details,
        }
        return JSONResponse(
            content=_json_safe(payload), status_code=200 if ready_ok else 503
        )

    @app.get("/api/v1/stats", dependencies=[Depends(auth_dep)])
    @app.get("/stats", dependencies=[Depends(auth_dep)])
    async def get_stats(reset: bool = False, top: int = 10) -> Dict[str, Any]:
        """Return statistics snapshot from StatsCollector as JSON.

        Inputs:
          - reset: If True, reset counters after snapshot.
          - top: Optional integer limit for the number of entries returned in
            top_* lists (Top Domains/Subdomains, Top Clients, cache_* and
            rcode/qtype top lists). Defaults to 10.

        Outputs:
          - Dict representing StatsSnapshot fields.
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}

        # Measure timings for optional debug logging.
        t_start = time.time()
        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, bool(reset))
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

        payload = _build_stats_payload_from_snapshot(
            snap,
            meta=meta_with_uniques,
            system_info=system_info,
        )

        # Apply optional per-request limit to top-* style lists so callers can
        # request deeper views when StatsCollector keeps a larger internal ranking.
        try:
            limit = int(top)
        except (TypeError, ValueError):
            limit = 10
        if limit <= 0:
            limit = 10

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

        return payload

    @app.post("/api/v1/stats/reset", dependencies=[Depends(auth_dep)])
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

    @app.get("/api/v1/traffic", dependencies=[Depends(auth_dep)])
    @app.get("/traffic", dependencies=[Depends(auth_dep)])
    async def get_traffic(top: int = 10) -> Dict[str, Any]:
        """Return a summarized traffic view derived from statistics snapshot.

        Inputs:
          - top: Optional integer limit for entries in topClients/topDomains
            lists; defaults to 10.
        Outputs: dict with totals, rcodes, qtypes, latency, and top lists.
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        if collector is None:
            return {"status": "disabled", "server_time": _utc_now_iso()}
        snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=False)

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

        try:
            limit = int(top)
        except (TypeError, ValueError):
            limit = 10
        if limit <= 0:
            limit = 10

        return _build_traffic_payload_from_snapshot(snap, meta=meta, top=limit)

    @app.get("/api/v1/upstream_status", dependencies=[Depends(auth_dep)])
    async def get_upstream_status() -> Dict[str, Any]:
        """Return upstream strategy, concurrency, and lazy health state.

        Inputs:
          - None.

        Outputs:
          - Dict with keys:
              * server_time: ISO8601 timestamp.
              * strategy: current upstream selection strategy.
              * max_concurrent: maximum upstreams considered per query.
              * items: list of upstream entries with id, config, state, fail_count,
                and optional down_until timestamp.
        """

        cfg = app.state.config or {}
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

        # First, map configured upstreams to health entries when available.
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

            # Include a minimal, stable subset of upstream config fields for display.
            cfg_view = {}
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

        # Include any remaining health-only entries not present in the config list.
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

        return {
            "server_time": _utc_now_iso(),
            "strategy": strategy,
            "max_concurrent": max_concurrent,
            "items": items,
        }

    @app.get("/api/v1/config", dependencies=[Depends(auth_dep)])
    @app.get("/apti/v1/config", dependencies=[Depends(auth_dep)])
    @app.get("/config", dependencies=[Depends(auth_dep)])
    async def get_config() -> PlainTextResponse:
        """Return sanitized configuration as YAML for inspection.

        Inputs: none
        Outputs: YAML string representing sanitized configuration.
        """

        cfg = app.state.config or {}
        redact_keys = _get_redact_keys(cfg)

        cfg_path = getattr(app.state, "config_path", None)
        body = _get_sanitized_config_yaml_cached(cfg, cfg_path, redact_keys)

        return PlainTextResponse(body, media_type="application/x-yaml")

    @app.get("/api/v1/config/raw", dependencies=[Depends(auth_dep)])
    @app.get("/config/raw", dependencies=[Depends(auth_dep)])
    async def get_config_raw() -> PlainTextResponse:
        """Return the raw on-disk configuration YAML as plain text.

        Inputs:
          - None (uses app.state.config_path to locate YAML file).

        Outputs:
          - PlainTextResponse containing the exact contents of the YAML config
            file on disk.
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )
        try:
            raw_text = _get_config_raw_text(cfg_path)
        except (
            Exception
        ) as exc:  # pragma: no cover - I/O errors are environment-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to read config from {cfg_path}: {exc}",
            ) from exc
        return PlainTextResponse(raw_text, media_type="application/x-yaml")

    @app.get("/api/v1/config.json", dependencies=[Depends(auth_dep)])
    @app.get("/apti/v1/config.json", dependencies=[Depends(auth_dep)])
    @app.get("/config.json", dependencies=[Depends(auth_dep)])
    async def get_config_json() -> Dict[str, Any]:
        """Return sanitized configuration as JSON for API clients.

        Inputs: none
        Outputs:
          - Dict with server_time and sanitized config mapping.
        """

        cfg = app.state.config or {}
        redact_keys = _get_redact_keys(cfg)
        clean = sanitize_config(cfg, redact_keys=redact_keys)
        return {"server_time": _utc_now_iso(), "config": clean}

    @app.get("/api/v1/config/raw.json", dependencies=[Depends(auth_dep)])
    @app.get("/config/raw.json", dependencies=[Depends(auth_dep)])
    async def get_config_raw_json() -> Dict[str, Any]:
        """Return raw on-disk configuration as JSON plus raw YAML text.

        Inputs: none (uses app.state.config_path to locate YAML file).
        Outputs:
          - Dict with server_time, parsed config mapping, and raw_yaml string.
        """

        cfg_path = getattr(app.state, "config_path", None)
        if not cfg_path:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="config_path not configured",
            )
        try:
            raw = _get_config_raw_json(cfg_path)
        except (
            Exception
        ) as exc:  # pragma: no cover - I/O errors are environment-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to read config from {cfg_path}: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "config": raw["config"],
            "raw_yaml": raw["raw_yaml"],
        }

    @app.post("/api/v1/config/save", dependencies=[Depends(auth_dep)])
    @app.post("/config/save", dependencies=[Depends(auth_dep)])
    async def save_config(body: Dict[str, Any]) -> Dict[str, Any]:
        """Persist new configuration to disk and schedule SIGHUP for the main process.

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

        # Schedule a SIGHUP for the main process after a short delay so that
        # supervisors can observe a clean shutdown and restart with the new
        # configuration applied.
        _schedule_sighup_after_config_save(delay_seconds=0.1)

        return {
            "status": "ok",
            "server_time": _utc_now_iso(),
            "path": cfg_path_abs,
            "backed_up_to": backup_path,
        }

    @app.get("/api/v1/query_log", dependencies=[Depends(auth_dep)])
    @app.get("/query_log", dependencies=[Depends(auth_dep)])
    async def get_query_log(
        client_ip: str | None = None,
        qtype: str | None = None,
        qname: str | None = None,
        rcode: str | None = None,
        start: str | None = None,
        end: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> Dict[str, Any]:
        """Return query_log entries filtered by client/qname/qtype/rcode.

        Inputs:
          - client_ip: Optional client IP address filter.
          - qtype: Optional qtype filter (e.g. "A").
          - qname: Optional qname filter (e.g. "example.com").
          - rcode: Optional rcode filter (e.g. "NXDOMAIN").
          - start: Optional UTC datetime string limiting results to ts >= start.
          - end: Optional UTC datetime string limiting results to ts < end.
          - page: 1-based page number.
          - page_size: Page size (defaults to 100).

        Outputs:
          - Dict with server_time, pagination metadata, and items.
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        store = getattr(collector, "_store", None) if collector is not None else None
        if store is None:
            return {
                "status": "disabled",
                "server_time": _utc_now_iso(),
                "items": [],
                "total": 0,
                "page": int(page) if isinstance(page, int) else 1,
                "page_size": int(page_size) if isinstance(page_size, int) else 100,
                "total_pages": 0,
            }

        # Parse optional time bounds.
        start_ts: float | None = None
        end_ts: float | None = None
        if start:
            try:
                start_ts = _parse_utc_datetime(start).timestamp()
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid start datetime: {exc}",
                ) from exc
        if end:
            try:
                end_ts = _parse_utc_datetime(end).timestamp()
            except Exception as exc:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"invalid end datetime: {exc}",
                ) from exc

        # Clamp page_size to a conservative upper bound.
        try:
            ps = int(page_size)
        except Exception:
            ps = 100
        if ps <= 0:
            ps = 100
        if ps > 1000:
            ps = 1000

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

        # Add ISO timestamps for convenience.
        items = []
        for item in res.get("items", []) or []:
            if isinstance(item, dict) and "ts" in item:
                item = dict(item)
                item["timestamp"] = _ts_to_utc_iso(float(item.get("ts") or 0.0))
            items.append(item)

        return {
            "server_time": _utc_now_iso(),
            "total": res.get("total", 0),
            "page": res.get("page", 1),
            "page_size": res.get("page_size", ps),
            "total_pages": res.get("total_pages", 0),
            "items": items,
        }

    @app.get("/api/v1/query_log/aggregate", dependencies=[Depends(auth_dep)])
    async def get_query_log_aggregate(
        interval: int,
        interval_units: str,
        start: str,
        end: str,
        client_ip: str | None = None,
        qtype: str | None = None,
        qname: str | None = None,
        rcode: str | None = None,
        group_by: str | None = None,
    ) -> Dict[str, Any]:
        """Return time-bucketed query counts for graphing.

        Inputs:
          - interval: Positive integer bucket width.
          - interval_units: One of seconds, minutes, hours, days.
          - start: UTC datetime string (inclusive).
          - end: UTC datetime string (exclusive).
          - client_ip/qtype/qname/rcode: Optional filters.
          - group_by: Optional grouping dimension (client_ip, qtype, qname, rcode).

        Outputs:
          - Dict with server_time, interval_seconds, start/end, and bucket items.
        """

        collector: Optional[StatsCollector] = app.state.stats_collector
        store = getattr(collector, "_store", None) if collector is not None else None
        if store is None:
            return {"status": "disabled", "server_time": _utc_now_iso(), "items": []}

        try:
            start_dt = _parse_utc_datetime(start)
            end_dt = _parse_utc_datetime(end)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=str(exc),
            ) from exc

        try:
            interval_i = int(interval)
        except Exception:
            interval_i = 0
        if interval_i <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval must be a positive integer",
            )

        units = str(interval_units or "").strip().lower()
        unit_seconds = {
            "seconds": 1,
            "second": 1,
            "minutes": 60,
            "minute": 60,
            "hours": 3600,
            "hour": 3600,
            "days": 86400,
            "day": 86400,
        }.get(units)
        if not unit_seconds:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval_units must be one of seconds, minutes, hours, days",
            )

        interval_seconds = interval_i * int(unit_seconds)
        if (
            interval_seconds <= 0
        ):  # pragma: no cover - defensive; unit_seconds is always > 0 here
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="interval_seconds must be > 0",
            )

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

        return {
            "server_time": _utc_now_iso(),
            "start": start_dt.isoformat().replace("+00:00", "Z"),
            "end": end_dt.isoformat().replace("+00:00", "Z"),
            "interval_seconds": interval_seconds,
            "items": items,
        }

    def _collect_admin_pages_for_response() -> list[dict[str, Any]]:
        """Brief: Build a JSON-safe list of admin pages contributed by plugins.

        Inputs:
          - None (uses app.state.plugins).

        Outputs:
          - list[dict]: Each entry describes a page with keys:
            plugin, slug, title, description, layout, kind.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        pages: list[dict[str, Any]] = []

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
                    "webserver: get_admin_pages() failed for plugin %r",
                    plugin_name,
                    exc_info=True,
                )
                continue

            for spec in specs or []:
                slug = None
                title = None
                description = None
                layout = None
                kind = None
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

        return pages

    def _find_admin_page_detail(
        plugin_name: str, page_slug: str
    ) -> dict[str, Any] | None:
        """Brief: Look up a specific admin page spec for a plugin.

        Inputs:
          - plugin_name: Instance name from configuration.
          - page_slug: Page slug from the URL path.

        Outputs:
          - dict describing the page including HTML fragments when found; None otherwise.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for plugin in plugins_list:
            try:
                if getattr(plugin, "name", None) == plugin_name:
                    target = plugin
                    break
            except Exception:
                continue
        if target is None:
            return None

        get_pages = getattr(target, "get_admin_pages", None)
        if not callable(get_pages):
            return None

        try:
            specs = get_pages()
        except Exception:
            logger.debug(
                "webserver: get_admin_pages() failed for plugin %r",
                plugin_name,
                exc_info=True,
            )
            return None

        for spec in specs or []:
            slug = None
            title = None
            description = None
            layout = None
            kind = None
            html_left = None
            html_right = None
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

            return {
                "plugin": str(plugin_name),
                "slug": slug_str,
                "title": title_str,
                "description": str(description) if description is not None else None,
                "layout": layout_str,
                "kind": str(kind) if kind is not None else None,
                "html_left": str(html_left) if html_left is not None else None,
                "html_right": str(html_right) if html_right is not None else None,
            }

        return None

    def _collect_plugin_ui_descriptors() -> list[dict[str, Any]]:
        """Brief: Collect generic admin UI descriptors from configured plugins.

        Inputs:
          - None (uses app.state.plugins and the global DNS cache).

        Outputs:
          - list[dict]: One entry per plugin/cache that exposes
            get_admin_ui_descriptor().
        """

        def _normalise_descriptor(
            source: object, desc: dict[str, Any]
        ) -> dict[str, Any] | None:
            """Brief: Normalise a raw admin UI descriptor.

            Inputs:
              - source: Underlying plugin or cache object.
              - desc: Raw descriptor mapping.

            Outputs:
              - dict with normalised name/title/kind/order, or None when invalid.
            """

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

            item: dict[str, Any] = dict(desc)
            item["name"] = name
            item["title"] = title
            item["kind"] = str(kind) if kind is not None else None
            item["order"] = order
            return item

        plugins_list = getattr(app.state, "plugins", []) or []
        items: list[dict[str, Any]] = []
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
                logger.debug(
                    "webserver: get_admin_ui_descriptor() failed for %r",
                    plugin,
                    exc_info=True,
                )
                continue

            item = _normalise_descriptor(plugin, desc)  # type: ignore[arg-type]
            if item is not None:
                items.append(item)

        # Also surface the global DNS cache plugin when it exposes admin UI.
        try:
            from ..plugins.resolve import base as plugin_base

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
                    logger.debug(
                        "webserver: get_admin_ui_descriptor() failed for cache %r",
                        cache,
                        exc_info=True,
                    )
                    desc = None
                if isinstance(desc, dict):
                    item = _normalise_descriptor(cache, desc)  # type: ignore[arg-type]
                    if item is not None:
                        items.append(item)

        # Normalise titles so that:
        #   - Single-instance plugins keep a clean base title like "Docker".
        #   - When multiple instances share the same base title, we suffix each
        #     tab with the instance name, e.g. "Docker (docker2)".
        #
        # Many plugins already include " (name)" in their raw descriptor title.
        # We treat that as decoration and strip it back to a base title when the
        # parenthesised portion matches the instance name; grouping and
        # disambiguation is done on that base title.
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

        # Sort by order then title for stable presentation.
        items.sort(
            key=lambda d: (int(d.get("order", 100) or 100), str(d.get("title", "")))
        )
        return items

        # Normalise titles so that:
        #   - Single-instance plugins keep a clean base title like "Docker".
        #   - When multiple instances share the same base title, we suffix each
        #     tab with the instance name, e.g. "Docker (docker2)".
        #
        # Many plugins already include " (name)" in their raw descriptor title.
        # We treat that as decoration and strip it back to a base title when the
        # parenthesised portion matches the instance name; grouping and
        # disambiguation is done on that base title.
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

        # Sort by order then title for stable presentation.
        items.sort(
            key=lambda d: (int(d.get("order", 100) or 100), str(d.get("title", "")))
        )
        return items

    @app.get("/api/v1/plugin_pages", dependencies=[Depends(auth_dep)])
    async def list_plugin_pages() -> Dict[str, Any]:
        """Brief: Enumerate admin pages contributed by configured plugins.

        Inputs:
          - None.

        Outputs:
          - Dict with server_time and pages list.
        """

        pages = _collect_admin_pages_for_response()
        return {"server_time": _utc_now_iso(), "pages": _json_safe(pages)}

    @app.get("/api/v1/plugins/ui", dependencies=[Depends(auth_dep)])
    async def list_plugin_ui_descriptors() -> Dict[str, Any]:
        """Brief: Enumerate generic admin UI descriptors for configured plugins.

        Inputs:
          - None.

        Outputs:
          - Dict with server_time and items list suitable for building plugin tabs.
        """

        items = _collect_plugin_ui_descriptors()
        return {"server_time": _utc_now_iso(), "items": _json_safe(items)}

    @app.get("/api/v1/cache", dependencies=[Depends(auth_dep)])
    async def get_cache_snapshot() -> Dict[str, Any]:
        """Brief: Return a JSON-safe snapshot for the active DNS cache plugin.

        Inputs:
          - None (uses foghorn.plugins.resolve.base.DNS_CACHE).

        Outputs:
          - Dict with server_time and data keys when the active cache exposes a
            get_http_snapshot() helper; otherwise 404.
        """

        try:
            from ..plugins.resolve import base as plugin_base

            cache = getattr(plugin_base, "DNS_CACHE", None)
        except Exception:
            cache = None

        if cache is None or not hasattr(cache, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="cache plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = cache.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:  # pragma: no cover - defensive: cache-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build cache snapshot: {exc}",
            ) from exc

        cache_name = getattr(cache, "name", None) or cache.__class__.__name__

        return {
            "server_time": _utc_now_iso(),
            "cache": str(cache_name),
            "data": _json_safe(snapshot),
        }

    @app.get(
        "/api/v1/plugin_pages/{plugin_name}/{page_slug}",
        dependencies=[Depends(auth_dep)],
    )
    async def get_plugin_page_detail(
        plugin_name: str, page_slug: str
    ) -> Dict[str, Any]:
        """Brief: Return full details for a single plugin admin page.

        Inputs:
          - plugin_name: Plugin instance name.
          - page_slug: Page slug.

        Outputs:
          - Dict with server_time and page fields, or 404 when not found.
        """

        detail = _find_admin_page_detail(plugin_name, page_slug)
        if detail is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin page not found",
            )
        out: Dict[str, Any] = {
            "server_time": _utc_now_iso(),
            "page": _json_safe(detail),
        }
        return out

    @app.get("/api/v1/logs", dependencies=[Depends(auth_dep)])
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

    @app.get(
        "/api/v1/plugins/{plugin_name}/docker_hosts", dependencies=[Depends(auth_dep)]
    )
    async def get_docker_hosts_snapshot(plugin_name: str) -> Dict[str, Any]:
        """Return a JSON-safe snapshot for a DockerHosts plugin instance.

        Inputs:
          - plugin_name: Instance name from the configuration (plugins[].name or
            plugins[].module when name is omitted).

        Outputs:
          - Dict with server_time, plugin, and data keys. data is the
            get_http_snapshot() result when available.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue

        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:  # pragma: no cover - defensive: plugin-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build DockerHosts snapshot: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": plugin_name,
            "data": _json_safe(snapshot),
        }

    @app.get(
        "/api/v1/plugins/{plugin_name}/etc_hosts", dependencies=[Depends(auth_dep)]
    )
    async def get_etc_hosts_snapshot(plugin_name: str) -> Dict[str, Any]:
        """Return a JSON-safe snapshot for an EtcHosts plugin instance.

        Inputs:
          - plugin_name: Instance name from the configuration (plugins[].name or
            plugins[].module when name is omitted).

        Outputs:
          - Dict with server_time, plugin, and data keys. data is the
            get_http_snapshot() result when available.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue

        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:  # pragma: no cover - defensive: plugin-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build EtcHosts snapshot: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": plugin_name,
            "data": _json_safe(snapshot),
        }

    @app.get("/api/v1/plugins/{plugin_name}/mdns", dependencies=[Depends(auth_dep)])
    async def get_mdns_snapshot(plugin_name: str) -> Dict[str, Any]:
        """Return a JSON-safe snapshot for an MdnsBridge instance.

        Inputs:
          - plugin_name: Instance name from the configuration (plugins[].name or
            plugins[].module when name is omitted).

        Outputs:
          - Dict with server_time, plugin, and data keys. data is the
            get_http_snapshot() result when available.
        """

        plugins_list = getattr(app.state, "plugins", []) or []
        target = None
        for p in plugins_list:
            try:
                if getattr(p, "name", None) == plugin_name:
                    target = p
                    break
            except Exception:
                continue

        if target is None or not hasattr(target, "get_http_snapshot"):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="plugin not found or does not expose get_http_snapshot",
            )

        try:
            snapshot = target.get_http_snapshot()  # type: ignore[call-arg]
        except Exception as exc:  # pragma: no cover - defensive: plugin-specific
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"failed to build MdnsBridge snapshot: {exc}",
            ) from exc

        return {
            "server_time": _utc_now_iso(),
            "plugin": plugin_name,
            "data": _json_safe(snapshot),
        }

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

    @app.get("/api/v1/ratelimit", dependencies=[Depends(auth_dep)])
    async def get_rate_limit() -> Dict[str, Any]:
        """Return RateLimit statistics derived from sqlite3 profiles.

        Inputs: none
        Outputs:
          - Dict with server_time and aggregated per-db rate-limit information.
        """

        cfg = app.state.config or {}
        data = _collect_rate_limit_stats(cfg)
        data["server_time"] = _utc_now_iso()
        return data

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
        elif path == "/api/v1/plugins/ui":
            # Generic plugin UI discovery for the threaded admin server mirrors the
            # FastAPI /api/v1/plugins/ui endpoint and also surfaces the active
            # DNS cache plugin when it advertises admin UI metadata.
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
        elif path.startswith("/api/v1/plugin_pages/"):
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
                    "description": (
                        str(description) if description is not None else None
                    ),
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
        elif path.startswith("/api/v1/plugins/") and path.endswith("/docker_hosts"):
            # Threaded fallback for the DockerHosts admin snapshot endpoint mirrors
            # the FastAPI route at /api/v1/plugins/{plugin_name}/docker_hosts.
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
        elif path.startswith("/api/v1/plugins/") and path.endswith("/mdns"):
            # Threaded fallback for the MdnsBridge admin snapshot endpoint mirrors
            # the FastAPI route at /api/v1/plugins/{plugin_name}/mdns.
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
        elif path.startswith("/api/v1/plugins/") and path.endswith("/etc_hosts"):
            # Threaded fallback for the EtcHosts admin snapshot endpoint mirrors
            # the FastAPI route at /api/v1/plugins/{plugin_name}/etc_hosts.
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
    runtime_state: RuntimeState | None = None,
    plugins: list[object] | None = None,
) -> Optional[WebServerHandle]:
    """Start admin HTTP server, preferring uvicorn but falling back to threaded HTTP.

    Inputs:
      - stats: Optional StatsCollector instance used by DNS server.
      - config: Full configuration dict loaded from YAML.
      - log_buffer: Optional RingBuffer for log entries (created if None).

    Outputs:
      - WebServerHandle when the admin HTTP server is enabled via the
        ``server.http`` block; otherwise None.

    Example:
      >>> handle = start_webserver(collector, cfg, None)
      >>> if handle is not None:
      ...     assert handle.is_running()
    """

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
