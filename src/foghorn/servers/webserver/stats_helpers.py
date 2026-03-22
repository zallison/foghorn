from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict

from cachetools import TTLCache

from foghorn.utils.register_caches import registered_cached

from ...stats import StatsCollector, StatsSnapshot

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


def _utc_now_iso() -> str:
    """Return current UTC time as ISO 8601 string.

    Inputs: None
    Outputs: ISO 8601 UTC timestamp string.
    """

    return datetime.now(timezone.utc).isoformat()


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
      - system_info: System metrics mapping.

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

    ede_totals = getattr(snap, "ede_totals", None)
    if ede_totals:
        payload["ede"] = ede_totals

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
      - Dict suitable for JSON serialization. The payload always includes
        ``totals``, ``rcodes``, ``qtypes``, ``top_clients``, ``top_domains``,
        and ``latency`` when available, and conditionally exposes DNSSEC and
        Extended DNS Error (EDE) aggregates when present on the snapshot.

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

    dnssec_totals = getattr(snap, "dnssec_totals", None)
    if dnssec_totals:
        payload["dnssec"] = dnssec_totals

    ede_totals = getattr(snap, "ede_totals", None)
    if ede_totals:
        payload["ede"] = ede_totals

    if meta is not None:
        payload["meta"] = meta
    return payload


@registered_cached(cache=TTLCache(maxsize=1, ttl=5))
def _read_proc_meminfo(path: str = "/proc/meminfo") -> Dict[str, int]:
    """Brief: Parse a /proc/meminfo-style file into byte counts.

    Inputs:
      - path: Filesystem path to a meminfo-style file (default "/proc/meminfo").

    Outputs:
      - Dict mapping field name (e.g. "MemTotal") to integer byte values.
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
        "memory_available_bytes".
    """

    global _last_system_info, _last_system_info_ts

    # Resolve the webserver core module once so that tests which monkeypatch
    # foghorn.servers.webserver.* can influence behaviour here. When available
    # we also use its cache globals and TTL so tests can control caching via
    # foghorn.servers.webserver._SYSTEM_INFO_CACHE_TTL_SECONDS and
    # _reset_system_info_cache().
    web_core = None
    try:  # pragma: no cover - import failure is environment-specific
        import importlib

        web_core = importlib.import_module("foghorn.servers.webserver.core")
    except Exception:
        web_core = None

    now = time.time()
    cached = _last_system_info
    cached_ts = _last_system_info_ts
    ttl = _SYSTEM_INFO_CACHE_TTL_SECONDS
    if web_core is not None:
        try:
            ttl = float(getattr(web_core, "_SYSTEM_INFO_CACHE_TTL_SECONDS", ttl))
        except Exception:
            ttl = _SYSTEM_INFO_CACHE_TTL_SECONDS
        cached = getattr(web_core, "_last_system_info", cached)
        cached_ts = getattr(web_core, "_last_system_info_ts", cached_ts)

    if cached is not None and now - cached_ts < ttl:
        return dict(cached)

    payload: Dict[str, Any] = {
        "load_1m": None,
        "load_5m": None,
        "load_15m": None,
        "memory_total_bytes": None,
        "memory_used_bytes": None,
        "memory_free_bytes": None,
        "memory_available_bytes": None,
    }

    # Load averages. Prefer the webserver module's os.getloadavg when available
    # so that tests monkeypatching foghorn.servers.webserver.os.getloadavg see
    # their changes reflected here.
    os_mod = os
    if web_core is not None:
        try:
            os_mod = getattr(web_core, "os", os)
        except Exception:  # pragma: no cover - defensive
            os_mod = os

    try:
        if hasattr(os_mod, "getloadavg"):
            load1, load5, load15 = os_mod.getloadavg()  # type: ignore[assignment]
            payload["load_1m"] = float(load1)
            payload["load_5m"] = float(load5)
            payload["load_15m"] = float(load15)
    except Exception:  # pragma: no cover - environment specific
        pass

    # Memory statistics from /proc/meminfo when available.
    #
    # When this module is accessed via foghorn.servers.webserver, tests
    # monkeypatch web_mod._read_proc_meminfo. Prefer that helper when
    # available so monkeypatching remains effective for get_system_info().
    if web_core is not None and hasattr(web_core, "_read_proc_meminfo"):
        try:
            meminfo = web_core._read_proc_meminfo()
        except Exception:  # pragma: no cover - fall back to local helper
            meminfo = _read_proc_meminfo()
    else:
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

    # Process RSS metrics via psutil when available. Psutil is imported and
    # cached in _core; we look it up from there so that tests can monkeypatch
    # foghorn.servers.webserver.psutil to control behaviour.
    rss_bytes: int | None = None
    if web_core is not None:
        try:
            psutil_mod = getattr(web_core, "psutil", None)
        except Exception:  # pragma: no cover - defensive
            psutil_mod = None
    else:
        psutil_mod = None

    process_cpu_times = None
    process_cpu_percent = None
    process_io_counters = None
    process_open_files_count = None
    process_connections_count = None

    if psutil_mod is not None:
        try:
            proc = psutil_mod.Process()  # type: ignore[call-arg]
            # RSS
            try:
                mem_info = proc.memory_info()
                rss_val = getattr(mem_info, "rss", None)
                if isinstance(rss_val, (int, float)):
                    rss_bytes = int(rss_val)
            except Exception:
                rss_bytes = None

            # CPU-related metrics
            try:
                process_cpu_times = proc.cpu_times()
            except Exception:
                process_cpu_times = None
            try:
                process_cpu_percent = proc.cpu_percent(interval=0.0)
            except Exception:
                process_cpu_percent = None

            # I/O counters
            try:
                process_io_counters = proc.io_counters()
            except Exception:
                process_io_counters = None

            # Open files / connections
            try:
                files = proc.open_files()
                process_open_files_count = len(files) if files is not None else 0
            except Exception:
                process_open_files_count = None
            try:
                conns = proc.connections()
                process_connections_count = len(conns) if conns is not None else 0
            except Exception:
                process_connections_count = None
        except Exception:  # pragma: no cover - psutil-specific failures
            rss_bytes = None

    payload["process_rss_bytes"] = rss_bytes
    payload["process_rss_mb"] = (
        float(rss_bytes) / (1024 * 1024) if isinstance(rss_bytes, int) else None
    )
    payload["process_cpu_times"] = process_cpu_times
    payload["process_cpu_percent"] = process_cpu_percent
    payload["process_io_counters"] = process_io_counters
    payload["process_open_files_count"] = process_open_files_count
    payload["process_connections_count"] = process_connections_count

    # Publish into cache for subsequent callers. Keep both this module's cache
    # and the _core module's exported cache in sync so tests that reset or
    # inspect foghorn.servers.webserver._last_system_info* behave as expected.
    now = time.time()
    snapshot = dict(payload)
    with _SYSTEM_INFO_CACHE_LOCK:
        _last_system_info = snapshot
        _last_system_info_ts = now

    if web_core is not None:
        try:
            setattr(web_core, "_last_system_info", snapshot)
            setattr(web_core, "_last_system_info_ts", now)
        except Exception:  # pragma: no cover - defensive
            pass

    return payload


def _is_rate_limit_plugin_entry(entry_obj: Any) -> bool:
    """Brief: Return True when a plugin entry refers to RateLimit.

    Inputs:
      - entry_obj: Plugin entry (typically a dict or string).

    Outputs:
      - bool: True if the entry appears to reference RateLimit.
    """

    candidates: list[str] = []

    if isinstance(entry_obj, str):
        candidates.append(entry_obj)
    elif isinstance(entry_obj, dict):
        for key in ("type", "module"):
            raw_value = entry_obj.get(key)
            if raw_value:
                candidates.append(str(raw_value))

    for raw in candidates:
        text = str(raw or "").strip().lower().replace("-", "_")
        if not text:
            continue
        tail = text.rsplit(".", 1)[-1]
        if text in {"rate_limit", "ratelimit", "rate"}:
            return True
        if tail in {"rate_limit", "ratelimit"}:
            return True
    return False


def _find_rate_limit_db_paths_from_config(config: Dict[str, Any] | None) -> list[str]:
    """Brief: Discover RateLimit db_path values from the loaded config.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - List of unique db_path strings for RateLimit instances.

    Notes:
      - Supports plugin entries using modern ``type`` keys, legacy ``module``
        keys, and common RateLimit aliases (``rate_limit``, ``ratelimit``,
        ``rate``).
    """

    paths: set[str] = set()
    if not isinstance(config, dict):
        return []

    plugins_cfg = config.get("plugins") or []
    if isinstance(plugins_cfg, list):
        for entry in plugins_cfg:
            if not isinstance(entry, dict):
                continue
            if not _is_rate_limit_plugin_entry(entry):
                continue
            cfg = entry.get("config") or {}
            db_path = None
            if isinstance(cfg, dict):
                db_path = cfg.get("db_path")
            if db_path is None:
                db_path = entry.get("db_path")
            if db_path:
                paths.add(str(db_path))

    return sorted(paths)
