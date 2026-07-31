"""Shared transport-agnostic endpoint services for webserver handlers.

This module centralizes payload-building logic that is shared between the
FastAPI route stack and the threaded stdlib fallback handler.
"""

from __future__ import annotations

import json
import os
import socket
from typing import Any, Callable

from ...config.config_schema import get_default_schema_path
from ...stats import StatsCollector, StatsSnapshot, get_process_uptime_seconds
from ...utils.config_diagram import (
    diagram_dark_png_candidate_paths_for_config,
    diagram_png_candidate_paths_for_config,
    diagram_dot_candidate_paths_for_config,
    find_first_existing_path,
    generate_dot_text_from_config_path,
    stale_diagram_warning,
)
from .config_helpers import (
    _get_config_raw_json,
    _get_config_raw_text,
    _get_redact_keys,
    _get_sanitized_config_yaml_cached,
    sanitize_config,
)
from .meta_helpers import FOGHORN_VERSION, _get_about_payload
from .runtime import RuntimeState, evaluate_readiness
from .stats_helpers import (
    _build_stats_payload_from_snapshot,
    _build_traffic_payload_from_snapshot,
    _get_stats_snapshot_cached,
    _trim_top_fields,
    _utc_now_iso,
)


def build_health_payload() -> dict[str, Any]:
    """Brief: Build standard health response payload.

    Inputs:
      - None.

    Outputs:
      - Dict containing health status and server_time.
    """

    return {"status": "ok", "server_time": _utc_now_iso()}


def build_about_payload() -> dict[str, Any]:
    """Brief: Build standard about/version response payload.

    Inputs:
      - None.

    Outputs:
      - Dict with build and version metadata.
    """

    return _get_about_payload()


def build_ready_result(
    *,
    stats: StatsCollector | None,
    config: dict[str, Any] | None,
    runtime_state: RuntimeState | None,
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /ready payload and status code.

    Inputs:
      - stats: Optional statistics collector instance.
      - config: Current loaded configuration mapping.
      - runtime_state: Optional runtime listener state.

    Outputs:
      - Tuple of (status_code, payload).
    """

    ready_ok, not_ready, details = evaluate_readiness(
        stats=stats,
        config=config,
        runtime_state=runtime_state,
    )
    payload = {
        "server_time": _utc_now_iso(),
        "ready": ready_ok,
        "not_ready": not_ready,
        "details": details,
    }
    return (200 if ready_ok else 503, payload)


def _normalize_top_limit(raw_top: Any, default: int = 10) -> int:
    """Brief: Normalize top-list query limits to a safe positive int.

    Inputs:
      - raw_top: Raw user-supplied value.
      - default: Default fallback value when parsing fails.

    Outputs:
      - Positive integer limit.
    """

    try:
        limit = int(raw_top)
    except (TypeError, ValueError):
        return int(default)
    if limit <= 0:
        return int(default)
    return int(limit)


def _resolve_host_identity(
    *,
    hostname: str | None = None,
    host_ip: str | None = None,
) -> tuple[str, str]:
    """Brief: Resolve hostname and host IP with robust fallbacks.

    Inputs:
      - hostname: Optional precomputed hostname.
      - host_ip: Optional precomputed host IP.

    Outputs:
      - Tuple of (hostname, host_ip).
    """

    host_name_out = str(hostname) if isinstance(hostname, str) and hostname else ""
    if not host_name_out:
        try:
            host_name_out = socket.gethostname()
        except Exception:
            host_name_out = "unknown-host"

    host_ip_out = str(host_ip) if isinstance(host_ip, str) and host_ip else ""
    if not host_ip_out:
        try:
            host_ip_out = socket.gethostbyname(host_name_out)
        except Exception:
            host_ip_out = "0.0.0.0"

    return host_name_out, host_ip_out


def build_stats_result(
    *,
    collector: StatsCollector | None,
    reset: bool,
    top: Any,
    get_system_info: Callable[[], dict[str, Any]],
    version: str = FOGHORN_VERSION,
    hostname: str | None = None,
    host_ip: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /stats response payload for either HTTP transport.

    Inputs:
      - collector: Optional StatsCollector instance.
      - reset: Whether counters should reset after snapshot.
      - top: Raw top-list limit parameter.
      - get_system_info: Callable returning system info payload.
      - version: Version string included in metadata.
      - hostname: Optional precomputed hostname for stable snapshots.
      - host_ip: Optional precomputed host IP for stable snapshots.

    Outputs:
      - Tuple of (status_code, payload).
    """

    if collector is None:
        return 200, {"status": "disabled", "server_time": _utc_now_iso()}

    snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=bool(reset))
    resolved_hostname, resolved_host_ip = _resolve_host_identity(
        hostname=hostname,
        host_ip=host_ip,
    )

    meta: dict[str, Any] = {
        "created_at": snap.created_at,
        "server_time": _utc_now_iso(),
        "hostname": resolved_hostname,
        "ip": resolved_host_ip,
        "version": str(version),
        "uptime": int(round(get_process_uptime_seconds())),
    }
    if snap.uniques:
        meta = meta | snap.uniques

    payload = _build_stats_payload_from_snapshot(
        snap,
        meta=meta,
        system_info=get_system_info(),
    )
    payload["created_at"] = snap.created_at

    limit = _normalize_top_limit(top, default=10)
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

    return 200, payload


def build_traffic_result(
    *,
    collector: StatsCollector | None,
    top: Any,
    version: str = FOGHORN_VERSION,
    hostname: str | None = None,
    host_ip: str | None = None,
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /traffic response payload for either HTTP transport.

    Inputs:
      - collector: Optional StatsCollector instance.
      - top: Raw top-list limit parameter.
      - version: Version string included in metadata.
      - hostname: Optional precomputed hostname.
      - host_ip: Optional precomputed host IP.

    Outputs:
      - Tuple of (status_code, payload).
    """

    if collector is None:
        return 200, {"status": "disabled", "server_time": _utc_now_iso()}

    snap: StatsSnapshot = _get_stats_snapshot_cached(collector, reset=False)
    resolved_hostname, resolved_host_ip = _resolve_host_identity(
        hostname=hostname,
        host_ip=host_ip,
    )
    meta: dict[str, Any] = {
        "created_at": snap.created_at,
        "server_time": _utc_now_iso(),
        "hostname": resolved_hostname,
        "ip": resolved_host_ip,
        "version": str(version),
    }
    limit = _normalize_top_limit(top, default=10)
    payload = _build_traffic_payload_from_snapshot(snap, meta=meta, top=limit)
    return 200, payload


def build_logs_result(*, log_buffer: Any, limit: Any) -> tuple[int, dict[str, Any]]:
    """Brief: Build /logs response payload for either HTTP transport.

    Inputs:
      - log_buffer: Ring buffer-like object exposing snapshot(limit=...).
      - limit: Raw limit parameter.

    Outputs:
      - Tuple of (status_code, payload).
    """

    try:
        parsed_limit = max(0, int(limit))
    except (TypeError, ValueError):
        parsed_limit = 100

    entries: list[Any]
    if log_buffer is None:
        entries = []
    else:
        entries = log_buffer.snapshot(limit=parsed_limit)

    return 200, {"server_time": _utc_now_iso(), "entries": entries}


def build_stats_reset_result(
    *,
    collector: StatsCollector | None,
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /stats/reset response payload and apply reset when available.

    Inputs:
      - collector: Optional StatsCollector instance.

    Outputs:
      - Tuple of (status_code, payload).
    """

    if collector is None:
        return 200, {"status": "disabled", "server_time": _utc_now_iso()}
    collector.snapshot(reset=True)
    return 200, {"status": "ok", "server_time": _utc_now_iso()}


def build_upstream_status_result(
    *,
    config: dict[str, Any] | None,
    build_payload: Callable[[dict[str, Any]], dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/upstream_status payload via shared business logic.

    Inputs:
      - config: Current loaded configuration mapping.
      - build_payload: Callable used to build upstream status details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    cfg = config if isinstance(config, dict) else {}
    payload = build_payload(cfg)
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_admin_status_result(
    *,
    config: dict[str, Any] | None,
    config_path: Any,
    stats_collector: StatsCollector | None,
    plugins: list[object] | None,
    admin_runtime_state: object | None,
    build_payload: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/admin/status payload using shared business logic.

    Inputs:
      - config: Current loaded configuration mapping.
      - config_path: Active configuration file path.
      - stats_collector: Optional stats collector instance.
      - plugins: Loaded plugin instances.
      - admin_runtime_state: Runtime object for admin state tracking.
      - build_payload: Callable used to build status details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    payload = build_payload(
        cfg=(config if isinstance(config, dict) else {}),
        config_path=config_path,
        stats_collector=stats_collector,
        plugins=list(plugins or []),
        admin_runtime_state=admin_runtime_state,
    )
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_admin_capabilities_result(
    *,
    stats_collector: StatsCollector | None,
    plugins: list[object] | None,
    build_payload: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/admin/capabilities payload.

    Inputs:
      - stats_collector: Optional stats collector instance.
      - plugins: Loaded plugin instances.
      - build_payload: Callable used to build capabilities details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    payload = build_payload(
        stats_collector=stats_collector,
        plugins=list(plugins or []),
    )
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_admin_restart_status_result(
    *,
    runtime_state: object | None,
    build_payload: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/admin/restart/status payload.

    Inputs:
      - runtime_state: Admin runtime-state object.
      - build_payload: Callable used to build restart-status details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    payload = build_payload(runtime_state=runtime_state)
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_admin_tasks_result(
    *,
    runtime_state: object | None,
    limit: int,
    task_type: str | None,
    status: str | None,
    build_payload: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/admin/tasks payload.

    Inputs:
      - runtime_state: Admin runtime-state object.
      - limit: Maximum number of tasks to return.
      - task_type: Optional task-type filter.
      - status: Optional task-status filter.
      - build_payload: Callable used to build tasks details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    payload = build_payload(
        runtime_state=runtime_state,
        limit=int(limit),
        task_type=task_type,
        status=status,
    )
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_admin_version_compat_result(
    *,
    plugins: list[object] | None,
    stats_collector: StatsCollector | None,
    build_payload: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/admin/version/compat payload.

    Inputs:
      - plugins: Loaded plugin instances.
      - stats_collector: Optional stats collector instance.
      - build_payload: Callable used to build compatibility details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    payload = build_payload(
        plugins=list(plugins or []),
        stats_collector=stats_collector,
    )
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_admin_diag_runtime_snapshot_result(
    *,
    config: dict[str, Any] | None,
    config_path: Any,
    runtime_state: object | None,
    plugins: list[object] | None,
    stats_collector: StatsCollector | None,
    build_payload: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/admin/diag/runtime-snapshot payload.

    Inputs:
      - config: Current loaded configuration mapping.
      - config_path: Active configuration file path.
      - runtime_state: Admin runtime-state object.
      - plugins: Loaded plugin instances.
      - stats_collector: Optional stats collector instance.
      - build_payload: Callable used to build diagnostic snapshot details.

    Outputs:
      - Tuple of (status_code, payload).
    """

    payload = build_payload(
        cfg=(config if isinstance(config, dict) else {}),
        config_path=config_path,
        runtime_state=runtime_state,
        plugins=list(plugins or []),
        stats_collector=stats_collector,
    )
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_rate_limit_result(
    *,
    config: dict[str, Any] | None,
    plugins: list[object] | None,
    collect_stats: Callable[..., dict[str, Any]],
) -> tuple[int, dict[str, Any]]:
    """Brief: Build /api/v1/ratelimit payload from rate-limit profile stats.

    Inputs:
      - config: Current loaded configuration mapping.
      - plugins: Loaded plugin instances.
      - collect_stats: Callable used to collect ratelimit statistics.

    Outputs:
      - Tuple of (status_code, payload).
    """

    cfg = config if isinstance(config, dict) else {}
    payload = collect_stats(cfg, plugins=list(plugins or []))
    payload["server_time"] = _utc_now_iso()
    return 200, payload


def build_config_yaml_result(
    *,
    config: dict[str, Any] | None,
    config_path: Any,
) -> tuple[int, str]:
    """Brief: Build sanitized YAML response body for /config endpoints.

    Inputs:
      - config: In-memory configuration mapping.
      - config_path: Active configuration file path.

    Outputs:
      - Tuple of (status_code, YAML text body).
    """

    cfg = config if isinstance(config, dict) else {}
    redact_keys = _get_redact_keys(cfg)
    body = _get_sanitized_config_yaml_cached(cfg, config_path, redact_keys)
    return 200, body


def build_config_json_result(
    *,
    config: dict[str, Any] | None,
) -> tuple[int, dict[str, Any]]:
    """Brief: Build sanitized JSON payload for /config.json endpoints.

    Inputs:
      - config: In-memory configuration mapping.

    Outputs:
      - Tuple of (status_code, JSON payload).
    """

    cfg = config if isinstance(config, dict) else {}
    redact_keys = _get_redact_keys(cfg)
    clean = sanitize_config(cfg, redact_keys=redact_keys)
    return 200, {"server_time": _utc_now_iso(), "config": clean}


def build_config_raw_yaml_result(
    *,
    config_path: Any,
) -> tuple[int, str, str | None]:
    """Brief: Build raw YAML response for /config/raw endpoints.

    Inputs:
      - config_path: Active configuration file path.

    Outputs:
      - Tuple of (status_code, YAML body, optional error detail).
    """

    if not config_path:
        return 500, "", "config_path not configured"
    try:
        raw_text = _get_config_raw_text(config_path)
    except Exception as exc:
        return 500, "", f"failed to read config from {config_path}: {exc}"
    return 200, raw_text, None


def build_config_raw_json_result(
    *,
    config_path: Any,
) -> tuple[int, dict[str, Any] | None, str | None]:
    """Brief: Build raw JSON payload for /config/raw.json endpoints.

    Inputs:
      - config_path: Active configuration file path.

    Outputs:
      - Tuple of (status_code, payload-or-None, optional error detail).
    """

    if not config_path:
        return 500, None, "config_path not configured"
    try:
        raw = _get_config_raw_json(config_path)
    except Exception as exc:
        return 500, None, f"failed to read config from {config_path}: {exc}"

    payload = {
        "server_time": _utc_now_iso(),
        "config": raw["config"],
        "raw_yaml": raw["raw_yaml"],
    }
    return 200, payload, None


def build_config_schema_result(
    *,
    include_path_in_error: bool = False,
) -> tuple[int, dict[str, Any] | None, str | None]:
    """Brief: Build config schema payload for /config/schema endpoints.

    Inputs:
      - include_path_in_error: Include schema path in error detail text.

    Outputs:
      - Tuple of (status_code, payload-or-None, optional error detail).
    """

    schema_path_str = "<unknown>"
    try:
        schema_path = get_default_schema_path()
        schema_path_str = str(schema_path)
        with schema_path.open("r", encoding="utf-8") as handle:
            schema = json.load(handle)
    except Exception as exc:
        if include_path_in_error:
            return (
                500,
                None,
                f"failed to read config schema from {schema_path_str}: {exc}",
            )
        return 500, None, f"failed to read config schema: {exc}"

    payload = {
        "server_time": _utc_now_iso(),
        "schema_path": schema_path_str,
        "schema": schema,
    }
    return 200, payload, None


def _diagram_config_signature(
    config_path: Any,
    *,
    stat_fn: Callable[[str], Any] | None = None,
) -> str:
    """Brief: Build a stable signature for per-config diagram refresh attempts.

    Inputs:
      - config_path: Config path-like value.
      - stat_fn: Optional stat callable used to fetch mtime/size.

    Outputs:
      - Signature string based on path, mtime, and size when available.
    """
    stat_impl = stat_fn or os.stat

    try:
        stat_result = stat_impl(str(config_path))
        return (
            f"{config_path}:"
            f"{int(stat_result.st_mtime_ns)}:"
            f"{int(stat_result.st_size)}"
        )
    except Exception:
        return str(config_path)


def build_config_diagram_png_result(
    *,
    config_path: Any,
    attempted_signature: str | None,
    candidate_paths_fn: Callable[[Any], Any],
    refresh_stale: bool,
    meta_only: bool,
    stat_fn: Callable[[str], Any] | None = None,
    stale_warning_fn: Callable[..., str | None] | None = None,
) -> tuple[int, dict[str, str], str | None, str | None, str | None]:
    """Brief: Build diagram PNG response metadata for either HTTP transport.

    Inputs:
      - config_path: Active configuration path.
      - attempted_signature: Prior build-attempt signature cache value.
      - candidate_paths_fn: Callable returning candidate PNG paths for config.
      - refresh_stale: Whether stale diagrams should trigger one refresh attempt.
      - meta_only: Whether endpoint is in metadata-only mode.
      - stat_fn: Optional stat callable for signature computation.
      - stale_warning_fn: Optional stale-warning helper.

    Outputs:
      - Tuple of:
          - status_code
          - headers (includes X-Foghorn-Exists and optional warning)
          - diagram_path when available
          - error_detail when status indicates an error
          - next_attempted_signature cache value
    """

    if not config_path:
        return 500, {}, None, "config_path not configured", attempted_signature

    cfg_sig = _diagram_config_signature(config_path, stat_fn=stat_fn)
    next_attempted_signature = attempted_signature
    stale_warning_impl = stale_warning_fn or stale_diagram_warning

    png_file = find_first_existing_path(candidate_paths_fn(config_path))

    if png_file is None and next_attempted_signature != cfg_sig:
        try:
            from ...utils.config_diagram import (
                _find_dot_cmd,
                ensure_config_diagram_png,
            )

            if _find_dot_cmd() is not None:
                next_attempted_signature = cfg_sig
                ensure_config_diagram_png(config_path=str(config_path))
                png_file = find_first_existing_path(candidate_paths_fn(config_path))
        except Exception:
            pass

    warn: str | None = None
    if png_file is not None:
        warn = stale_warning_impl(
            config_path=str(config_path),
            diagram_path=str(png_file),
        )
        if refresh_stale and warn and next_attempted_signature != cfg_sig:
            try:
                from ...utils.config_diagram import (
                    _find_dot_cmd,
                    ensure_config_diagram_png,
                )

                if _find_dot_cmd() is not None:
                    next_attempted_signature = cfg_sig
                    ok, _detail, refreshed = ensure_config_diagram_png(
                        config_path=str(config_path)
                    )
                    if ok and refreshed:
                        from pathlib import Path

                        png_file = Path(str(refreshed))
                        warn = stale_warning_impl(
                            config_path=str(config_path),
                            diagram_path=str(png_file),
                        )
            except Exception:
                pass

    headers: dict[str, str] = {
        "X-Foghorn-Exists": "1" if png_file is not None else "0",
    }
    if warn:
        headers["X-Foghorn-Warning"] = warn

    if meta_only:
        return (
            200,
            headers,
            (str(png_file) if png_file is not None else None),
            None,
            next_attempted_signature,
        )

    if png_file is None:
        return 404, headers, None, "config diagram not found", next_attempted_signature

    return 200, headers, str(png_file), None, next_attempted_signature


def build_config_diagram_dot_result(
    *,
    config_path: Any,
    meta_only: bool,
    stale_warning_fn: Callable[..., str | None] | None = None,
    generate_dot_text_fn: Callable[[str], str] | None = None,
) -> tuple[int, dict[str, str], str | None, str | None]:
    """Brief: Build diagram DOT response body and headers for both transports.

    Inputs:
      - config_path: Active configuration path.
      - meta_only: Whether endpoint is in metadata-only mode.
      - stale_warning_fn: Optional stale-warning helper.
      - generate_dot_text_fn: Optional dot-text generator helper.

    Outputs:
      - Tuple of:
          - status_code
          - headers (optional stale warning)
          - dot text body when available
          - error_detail when status indicates an error
    """

    if not config_path:
        return 500, {}, None, "config_path not configured"

    headers: dict[str, str] = {}
    stale_warning_impl = stale_warning_fn or stale_diagram_warning
    generate_dot_impl = generate_dot_text_fn or generate_dot_text_from_config_path

    png_file = find_first_existing_path(
        diagram_png_candidate_paths_for_config(config_path)
    )
    if png_file is not None:
        warn_png = stale_warning_impl(
            config_path=str(config_path),
            diagram_path=str(png_file),
        )
        if warn_png:
            headers["X-Foghorn-Warning"] = warn_png

    dot_file = find_first_existing_path(
        diagram_dot_candidate_paths_for_config(config_path)
    )
    if dot_file is not None:
        warn_dot = stale_warning_impl(
            config_path=str(config_path),
            diagram_path=str(dot_file),
        )
        if warn_dot and "X-Foghorn-Warning" not in headers:
            headers["X-Foghorn-Warning"] = warn_dot

    if meta_only:
        return 200, headers, "", None

    if dot_file is not None:
        try:
            text = dot_file.read_text(encoding="utf-8")
        except Exception as exc:
            return (
                500,
                headers,
                None,
                f"failed to read config diagram from {dot_file}: {exc}",
            )
        return 200, headers, text, None

    try:
        text = generate_dot_impl(str(config_path))
    except Exception as exc:
        return 500, headers, None, f"failed to generate config diagram: {exc}"
    return 200, headers, text, None
