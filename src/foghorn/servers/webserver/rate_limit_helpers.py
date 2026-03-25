from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict
from foghorn.config.plugin_profiles import resolve_plugin_profile

from .stats_helpers import _find_rate_limit_db_paths_from_config
from .stats_helpers import _is_rate_limit_plugin_entry
from .stats_helpers import logger as _stats_logger

# Reuse the existing webserver logger name for consistency
logger = _stats_logger
_GLOBAL_RPS_DB_KEY = "__global__"
_GLOBAL_RPS_API_KEY = "global"


def _resolve_rate_limit_effective_config(entry: dict[str, Any]) -> Dict[str, Any]:
    """Brief: Return profile-resolved RateLimit config for a plugin entry.

    Inputs:
      - entry: Plugin entry mapping from the loaded configuration.

    Outputs:
      - dict: Effective config after merging profile values with explicit keys.

    Notes:
      - Explicit config values always override profile values.
      - Unknown profiles are handled by resolve_plugin_profile fallback logic.
    """

    cfg_obj = entry.get("config") or {}
    explicit_cfg: Dict[str, Any] = cfg_obj if isinstance(cfg_obj, dict) else {}
    profile_name = str(explicit_cfg.get("profile", "") or "").strip()
    if not profile_name:
        return dict(explicit_cfg)

    try:
        return resolve_plugin_profile(
            plugin_type="rate_limit",
            profile_name=profile_name,
            explicit_cfg=dict(explicit_cfg),
            profiles_files=[],
            abort_on_failure=bool(explicit_cfg.get("abort_on_failure", False)),
        )
    except Exception:
        logger.debug(
            "webserver: failed to resolve rate_limit profile=%r for stats helper",
            profile_name,
            exc_info=True,
        )
        return dict(explicit_cfg)


def _coerce_nonnegative_int(value: Any, default: int = 0) -> int:
    """Brief: Coerce a value into a non-negative integer.

    Inputs:
      - value: Any value expected to represent an integer.
      - default: Fallback value used when coercion fails.

    Outputs:
      - int: Non-negative integer value.
    """

    try:
        parsed = int(value)
    except Exception:
        return int(default)
    return max(0, int(parsed))


def _coerce_nonnegative_float(value: Any, default: float = 0.0) -> float:
    """Brief: Coerce a value into a non-negative float.

    Inputs:
      - value: Any value expected to represent a float.
      - default: Fallback value used when coercion fails.

    Outputs:
      - float: Non-negative float value.
    """

    try:
        parsed = float(value)
    except Exception:
        return float(default)
    return max(0.0, float(parsed))


def _find_rate_limit_db_lookback_seconds_from_config(
    config: Dict[str, Any] | None,
) -> Dict[str, int]:
    """Brief: Map each RateLimit db_path to its configured lookback seconds.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - Dict[str, int]: Mapping of db_path -> lookback seconds, where lookback
        uses stats_window_seconds when set, otherwise stats_log_interval_seconds.
        Profile-derived values are applied before extraction.
    """

    out: Dict[str, int] = {}
    if not isinstance(config, dict):
        return out

    plugins_cfg = config.get("plugins") or []
    if not isinstance(plugins_cfg, list):
        return out

    for entry in plugins_cfg:
        if not isinstance(entry, dict):
            continue
        if not _is_rate_limit_plugin_entry(entry):
            continue
        cfg = _resolve_rate_limit_effective_config(entry)
        db_path = cfg.get("db_path")
        if db_path is None:
            db_path = entry.get("db_path")
        if not db_path:
            continue
        stats_window_seconds = _coerce_nonnegative_int(
            cfg.get("stats_window_seconds"),
            default=0,
        )
        stats_log_interval_seconds = _coerce_nonnegative_int(
            cfg.get("stats_log_interval_seconds"),
            default=0,
        )
        lookback_seconds = (
            stats_window_seconds
            if stats_window_seconds > 0
            else stats_log_interval_seconds
        )
        out[str(db_path)] = int(lookback_seconds)
    return out


def _find_rate_limit_db_limit_settings_from_config(
    config: Dict[str, Any] | None,
) -> Dict[str, Dict[str, float | int]]:
    """Brief: Map each RateLimit db_path to configured limit-related settings.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - Dict[str, Dict[str, float | int]] keyed by db_path with fields:
          * warmup_windows
          * warmup_max_rps
          * burst_factor
          * min_enforce_rps
          * max_enforce_rps
          * global_max_rps
        Profile-derived values are applied before extraction.
    """

    out: Dict[str, Dict[str, float | int]] = {}
    if not isinstance(config, dict):
        return out

    plugins_cfg = config.get("plugins") or []
    if not isinstance(plugins_cfg, list):
        return out

    for entry in plugins_cfg:
        if not isinstance(entry, dict):
            continue
        if not _is_rate_limit_plugin_entry(entry):
            continue
        cfg = _resolve_rate_limit_effective_config(entry)
        db_path = cfg.get("db_path")
        if db_path is None:
            db_path = entry.get("db_path")
        if not db_path:
            continue
        out[str(db_path)] = {
            "warmup_windows": _coerce_nonnegative_int(
                cfg.get("warmup_windows"),
                default=6,
            ),
            "warmup_max_rps": _coerce_nonnegative_float(
                cfg.get("warmup_max_rps"),
                default=0.0,
            ),
            "burst_factor": max(
                1.0,
                _coerce_nonnegative_float(cfg.get("burst_factor"), default=3.0),
            ),
            "min_enforce_rps": _coerce_nonnegative_float(
                cfg.get("min_enforce_rps"),
                default=50.0,
            ),
            "max_enforce_rps": _coerce_nonnegative_float(
                cfg.get("max_enforce_rps"),
                default=5000.0,
            ),
            "global_max_rps": _coerce_nonnegative_float(
                cfg.get("global_max_rps"),
                default=0.0,
            ),
        }
    return out


def _compute_current_limit_rps(
    *,
    avg_rps: float,
    samples: int,
    limit_settings: Dict[str, float | int] | None,
    profile_key: str | None = None,
) -> tuple[float | None, str]:
    """Brief: Compute the current enforcement limit for a single rate bucket.

    Inputs:
      - avg_rps: Learned average RPS for the bucket.
      - samples: Number of completed windows observed for the bucket.
      - limit_settings: Parsed config settings for this db_path.
      - profile_key: Optional profile key name used to detect special buckets.

    Outputs:
      - Tuple[float|None, str]:
          * current_limit_rps: Active numeric limit when enforceable, else None.
          * current_limit_source: Origin label describing how limit was derived.

    Notes:
      - During warmup, warmup_max_rps is used when configured (>0).
      - Without warmup_max_rps during warmup, the bucket is still learning.
      - After warmup, this returns the burst-allowed threshold used by RateLimit.
    """

    settings = limit_settings or {}
    warmup_windows = _coerce_nonnegative_int(settings.get("warmup_windows"), default=6)
    warmup_max_rps = _coerce_nonnegative_float(
        settings.get("warmup_max_rps"),
        default=0.0,
    )
    burst_factor = max(
        1.0,
        _coerce_nonnegative_float(settings.get("burst_factor"), default=3.0),
    )
    min_enforce_rps = _coerce_nonnegative_float(
        settings.get("min_enforce_rps"),
        default=50.0,
    )
    max_enforce_rps = _coerce_nonnegative_float(
        settings.get("max_enforce_rps"),
        default=5000.0,
    )
    global_max_rps = _coerce_nonnegative_float(
        settings.get("global_max_rps"),
        default=0.0,
    )
    key_text = str(profile_key or "")
    if key_text in {_GLOBAL_RPS_DB_KEY, _GLOBAL_RPS_API_KEY}:
        if global_max_rps <= 0.0:
            return None, "global_disabled"
        return float(global_max_rps), "global_max_rps"

    if int(samples) < int(warmup_windows):
        if warmup_max_rps <= 0.0:
            return None, "warmup_learning"
        limit = float(warmup_max_rps)
        source = "warmup_max_rps"
    else:
        if float(avg_rps) < float(min_enforce_rps):
            limit = float(min_enforce_rps)
            source = "below_min_enforce_rps"
        else:
            limit = float(avg_rps) * float(burst_factor)
            source = "burst_threshold"

    if max_enforce_rps > 0.0:
        limit = min(float(limit), float(max_enforce_rps))
    if float(limit) < float(min_enforce_rps):
        limit = float(min_enforce_rps)
    return float(limit), source


def _collect_rate_limit_stats(config: Dict[str, Any] | None) -> Dict[str, Any]:
    """Brief: Collect per-key RateLimit statistics from sqlite3 profiles.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).

    Outputs:
      - Dict with keys:
          * databases: list of per-db summaries including db_path, total_profiles,
            max_avg_rps, max_max_rps, and a limited list of individual profiles.
    """

    import foghorn.servers.webserver as web_core

    now = time.time()
    with web_core._RATE_LIMIT_CACHE_LOCK:
        if (
            web_core._last_rate_limit_snapshot is not None
            and now - web_core._last_rate_limit_snapshot_ts
            < web_core._RATE_LIMIT_CACHE_TTL_SECONDS
        ):
            return dict(web_core._last_rate_limit_snapshot)

    db_paths = _find_rate_limit_db_paths_from_config(config)
    db_lookbacks = _find_rate_limit_db_lookback_seconds_from_config(config)
    db_limit_settings = _find_rate_limit_db_limit_settings_from_config(config)
    db_paths = sorted(
        {
            *(str(path) for path in db_paths if path),
            *(str(path) for path in db_lookbacks.keys() if path),
            *(str(path) for path in db_limit_settings.keys() if path),
        }
    )
    summaries: list[Dict[str, Any]] = []

    # Heuristic fallback: if no explicit db_path is configured but the default
    # RateLimit db exists, include it.
    default_db = "./config/var/dbs/rate_limit.db"
    if not db_paths and os.path.exists(default_db):  # pragma: no cover
        db_paths.append(default_db)

    for path in db_paths:
        lookback_seconds = _coerce_nonnegative_int(db_lookbacks.get(path), default=0)
        limit_settings = db_limit_settings.get(path, {})
        window_by_key: Dict[str, tuple[float, float]] = {}
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
                has_global_row = any(
                    str(row[0]) in {_GLOBAL_RPS_DB_KEY, _GLOBAL_RPS_API_KEY}
                    for row in rows
                )
                if not has_global_row:
                    cur.execute(
                        "SELECT key, avg_rps, max_rps, samples, last_update "
                        "FROM rate_profiles WHERE key IN (?, ?) "
                        "ORDER BY last_update DESC LIMIT 1",
                        (_GLOBAL_RPS_DB_KEY, _GLOBAL_RPS_API_KEY),
                    )
                    global_row = cur.fetchone()
                    if global_row is not None:
                        rows.append(global_row)
                if lookback_seconds > 0:
                    cutoff = int(now) - int(lookback_seconds)
                    try:
                        cur.execute(
                            "SELECT key, AVG(rps), MAX(rps) "
                            "FROM rate_profile_windows "
                            "WHERE last_update >= ? "
                            "GROUP BY key",
                            (int(cutoff),),
                        )
                        for window_key, avg_rps, max_rps in cur.fetchall():
                            key_text = str(window_key)
                            try:
                                avg_val = float(avg_rps or 0.0)
                            except Exception:
                                avg_val = 0.0
                            try:
                                max_val = float(max_rps or 0.0)
                            except Exception:
                                max_val = 0.0
                            window_by_key[key_text] = (avg_val, max_val)
                    except Exception:
                        window_by_key = {}
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
                    "lookback_seconds": int(lookback_seconds),
                    "profiles": [],
                }
            )
            continue

        profiles: list[Dict[str, Any]] = []
        max_avg = 0.0
        max_max = 0.0
        max_window_avg = 0.0
        max_window_max = 0.0
        max_current_limit = 0.0
        global_profile_added = False
        for key, avg_rps, max_rps, samples, last_update in rows:
            key_text = str(key)
            display_key = (
                _GLOBAL_RPS_API_KEY
                if key_text in {_GLOBAL_RPS_DB_KEY, _GLOBAL_RPS_API_KEY}
                else key_text
            )
            if display_key == _GLOBAL_RPS_API_KEY:
                if global_profile_added:
                    continue
                global_profile_added = True
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
            window_vals = window_by_key.get(key_text)
            if window_vals is None:
                if lookback_seconds > 0:
                    window_avg_val = 0.0
                    window_max_val = 0.0
                else:
                    window_avg_val = avg_val
                    window_max_val = max_val
            else:
                window_avg_val = float(window_vals[0] or 0.0)
                window_max_val = float(window_vals[1] or 0.0)
            current_limit_rps, current_limit_source = _compute_current_limit_rps(
                avg_rps=avg_val,
                samples=samples_val,
                limit_settings=limit_settings,
                profile_key=key_text,
            )
            max_window_avg = max(max_window_avg, float(window_avg_val))
            max_window_max = max(max_window_max, float(window_max_val))
            if current_limit_rps is not None:
                max_current_limit = max(max_current_limit, float(current_limit_rps))
            profiles.append(
                {
                    "key": str(display_key),
                    "rps_limit": (
                        float(current_limit_rps)
                        if current_limit_rps is not None
                        else None
                    ),
                    "avg_rps": avg_val,
                    "avg_rps_overall": avg_val,
                    "max_rps": max_val,
                    "max_rps_overall": max_val,
                    "window_avg_rps": float(window_avg_val),
                    "avg_rps_interval": float(window_avg_val),
                    "window_max_rps": float(window_max_val),
                    "max_rps_interval": float(window_max_val),
                    "current_limit_rps": (
                        float(current_limit_rps)
                        if current_limit_rps is not None
                        else None
                    ),
                    "current_limit_source": str(current_limit_source),
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
                "max_window_avg_rps": max_window_avg,
                "max_window_max_rps": max_window_max,
                "max_current_limit_rps": max_current_limit,
                "lookback_seconds": int(lookback_seconds),
                "profiles": profiles,
            }
        )

    payload: Dict[str, Any] = {"databases": summaries}
    import foghorn.servers.webserver as web_core

    with web_core._RATE_LIMIT_CACHE_LOCK:
        web_core._last_rate_limit_snapshot = dict(payload)
        web_core._last_rate_limit_snapshot_ts = time.time()
    return payload
