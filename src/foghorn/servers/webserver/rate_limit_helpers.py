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
_GLOBAL_RPS_DB_KEY = "global"
_GLOBAL_RPS_LEGACY_DB_KEY = "__global__"
_GLOBAL_RPS_API_KEY = "global"
_INVARIANT_WARN_TTL_SECONDS = 60.0
_invariant_warn_cache: Dict[str, float] = {}


def _should_emit_invariant_warning(cache_key: str, now_ts: float) -> bool:
    """Brief: Return True when an invariant warning should be emitted now.

    Inputs:
      - cache_key: Stable warning fingerprint key.
      - now_ts: Current epoch seconds.

    Outputs:
      - bool: True when warning should be logged, False when suppressed by TTL.
    """

    try:
        last_ts = float(_invariant_warn_cache.get(cache_key, 0.0) or 0.0)
    except Exception:
        last_ts = 0.0
    if float(now_ts) - float(last_ts) < float(_INVARIANT_WARN_TTL_SECONDS):
        return False
    _invariant_warn_cache[cache_key] = float(now_ts)
    return True


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
          * burst_windows
          * min_enforce_rps
          * min_burst_threshold
          * max_enforce_rps
          * global_max_rps
          * limit_recalc_windows
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
        min_enforce_rps = _coerce_nonnegative_float(
            cfg.get("min_enforce_rps"),
            default=50.0,
        )
        min_boot_rps = _coerce_nonnegative_float(
            cfg.get("min_boot_rps"),
            default=float(min_enforce_rps),
        )
        min_boost_rps = _coerce_nonnegative_float(
            cfg.get("min_boost_rps"),
            default=float(min_boot_rps),
        )
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
            "burst_windows": _coerce_nonnegative_int(
                cfg.get("burst_windows"),
                default=6,
            ),
            "min_enforce_rps": float(min_enforce_rps),
            "min_burst_threshold": _coerce_nonnegative_float(
                cfg.get("min_burst_threshold"),
                default=float(min_boost_rps),
            ),
            "max_enforce_rps": _coerce_nonnegative_float(
                cfg.get("max_enforce_rps"),
                default=5000.0,
            ),
            "global_max_rps": _coerce_nonnegative_float(
                cfg.get("global_max_rps"),
                default=0.0,
            ),
            "limit_recalc_windows": _coerce_nonnegative_int(
                cfg.get("limit_recalc_windows"),
                default=10,
            ),
        }
    return out


def _compute_current_limit_rps(
    *,
    avg_rps: float,
    samples: int,
    current_rps: float,
    limit_settings: Dict[str, float | int] | None,
    profile_key: str | None = None,
    burst_count: int | None = None,
    recalculated_thresholds: tuple[float, float] | None = None,
) -> tuple[float | None, str, float | None, bool]:
    """Brief: Compute the current enforcement limit for a single rate bucket.

    Inputs:
      - avg_rps: Learned average RPS for the bucket.
      - samples: Number of completed windows observed for the bucket.
      - current_rps: Current in-progress window RPS for this bucket.
      - limit_settings: Parsed config settings for this db_path.
      - profile_key: Optional profile key name used to detect special buckets.
      - burst_count: Optional burst-window counter for this profile key.
      - recalculated_thresholds: Optional tuple of
        (burst_allowed_rps, baseline_allowed_rps) from plugin runtime cadence.

    Outputs:
      - Tuple[float|None, str, float|None, bool]:
          * current_limit_rps: Active numeric limit when enforceable, else None.
          * current_limit_source: Origin label describing how limit was derived.
          * burst_threshold_rps: Burst threshold after applying min_burst_threshold
            floor and max_enforce_rps cap.
          * enforcement_active: True when current_rps exceeds the active limit
            (or the hard max_enforce_rps cap in below-min-enforce mode).

    Notes:
      - During warmup, warmup_max_rps is used when configured (>0).
      - Without warmup_max_rps during warmup, the bucket is still learning.
      - After warmup, this mirrors the plugin pre_resolve() threshold selection.
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
    burst_windows = _coerce_nonnegative_int(settings.get("burst_windows"), default=6)
    min_enforce_rps = _coerce_nonnegative_float(
        settings.get("min_enforce_rps"),
        default=50.0,
    )
    min_boot_rps = _coerce_nonnegative_float(
        settings.get("min_boot_rps"),
        default=float(min_enforce_rps),
    )
    min_boost_rps = _coerce_nonnegative_float(
        settings.get("min_boost_rps"),
        default=float(min_boot_rps),
    )
    min_burst_threshold = _coerce_nonnegative_float(
        settings.get("min_burst_threshold"),
        default=float(min_boost_rps),
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
    if key_text in {
        _GLOBAL_RPS_DB_KEY,
        _GLOBAL_RPS_API_KEY,
        _GLOBAL_RPS_LEGACY_DB_KEY,
    }:
        if global_max_rps <= 0.0:
            return None, "global_disabled", None, False
        limit = float(global_max_rps)
        return limit, "global_max_rps", None, float(current_rps) > float(limit)

    burst_threshold_rps = max(
        float(avg_rps) * float(burst_factor),
        float(min_burst_threshold),
    )
    if max_enforce_rps > 0.0:
        burst_threshold_rps = min(float(burst_threshold_rps), float(max_enforce_rps))

    if int(samples) < int(warmup_windows):
        if warmup_max_rps <= 0.0:
            return None, "warmup_learning", burst_threshold_rps, False
        limit = float(warmup_max_rps)
        if max_enforce_rps > 0.0:
            limit = min(float(limit), float(max_enforce_rps))
        return (
            float(limit),
            "warmup_max_rps",
            burst_threshold_rps,
            float(current_rps) > float(limit),
        )

    if float(avg_rps) < float(min_enforce_rps):
        # Below the minimum enforcement threshold: the plugin allows all
        # traffic through unless it exceeds the absolute hard cap
        # (max_enforce_rps).  Display this as "not actively enforcing" so
        # the UI does not misleadingly show max_enforce_rps as a live limit.
        if max_enforce_rps <= 0.0:
            return None, "below_min_enforce_rps", burst_threshold_rps, False
        return (
            None,
            "below_min_enforce_rps",
            burst_threshold_rps,
            float(current_rps) > float(max_enforce_rps),
        )

    if isinstance(recalculated_thresholds, tuple) and len(recalculated_thresholds) == 2:
        try:
            burst_allowed_rps = float(recalculated_thresholds[0])
            baseline_allowed_rps = float(recalculated_thresholds[1])
        except Exception:
            burst_allowed_rps = float(burst_threshold_rps)
            baseline_allowed_rps = float(avg_rps)
    else:
        burst_allowed_rps = float(burst_threshold_rps)
        baseline_allowed_rps = float(avg_rps)
    if max_enforce_rps > 0.0:
        burst_allowed_rps = min(float(burst_allowed_rps), float(max_enforce_rps))
        baseline_allowed_rps = min(
            float(baseline_allowed_rps),
            float(max_enforce_rps),
        )

    if int(burst_windows) > 0 and burst_count is not None:
        if int(burst_count) >= int(burst_windows):
            allowed_rps = float(baseline_allowed_rps)
            source = "baseline_after_burst_windows"
        else:
            allowed_rps = float(burst_allowed_rps)
            source = "burst_threshold"
    else:
        allowed_rps = float(burst_allowed_rps)
        source = "burst_threshold"
    return (
        float(allowed_rps),
        source,
        burst_threshold_rps,
        float(current_rps) > float(allowed_rps),
    )


def _find_rate_limit_current_rps_readers(
    plugins: list[object] | None,
) -> Dict[str, Any]:
    """Brief: Build db_path -> current-window RPS reader mappings.

    Inputs:
      - plugins: Optional loaded plugin instances from runtime state.

    Outputs:
      - Dict[str, Any]: Mapping of db_path variants to callables compatible with
        _get_current_window_rps(profile_key).

    Notes:
      - Includes both raw and absolute db_path keys for robust matching.
      - Non-RateLimit plugins (or plugins without the helper) are ignored.
    """

    readers: Dict[str, Any] = {}
    if not isinstance(plugins, list):
        return readers

    for plugin in plugins:
        if plugin is None:
            continue
        reader = getattr(plugin, "_get_current_window_rps", None)
        if not callable(reader):
            continue
        db_path = str(getattr(plugin, "db_path", "") or "").strip()
        if not db_path:
            continue
        readers[db_path] = reader
        try:
            readers[os.path.abspath(db_path)] = reader
        except Exception:
            continue
    return readers


def _find_rate_limit_recalculated_allowed_rps_readers(
    plugins: list[object] | None,
) -> Dict[str, Any]:
    """Brief: Build db_path -> recalculated-threshold reader mappings.

    Inputs:
      - plugins: Optional loaded plugin instances from runtime state.

    Outputs:
      - Dict[str, Any]: Mapping of db_path variants to callables compatible with
        _get_recalculated_allowed_rps(profile_key, avg_rps, samples).
    """

    readers: Dict[str, Any] = {}
    if not isinstance(plugins, list):
        return readers

    for plugin in plugins:
        if plugin is None:
            continue
        reader = getattr(plugin, "_get_recalculated_allowed_rps", None)
        if not callable(reader):
            continue
        db_path = str(getattr(plugin, "db_path", "") or "").strip()
        if not db_path:
            continue
        readers[db_path] = reader
        try:
            readers[os.path.abspath(db_path)] = reader
        except Exception:
            continue
    return readers


def _find_rate_limit_current_rps_snapshot_readers(
    plugins: list[object] | None,
) -> Dict[str, Any]:
    """Brief: Build db_path -> current-window key snapshot reader mappings.

    Inputs:
      - plugins: Optional loaded plugin instances from runtime state.

    Outputs:
      - Dict[str, Any]: Mapping of db_path variants to callables compatible with
        _get_current_window_rps_snapshot().
    """

    readers: Dict[str, Any] = {}
    if not isinstance(plugins, list):
        return readers

    for plugin in plugins:
        if plugin is None:
            continue
        reader = getattr(plugin, "_get_current_window_rps_snapshot", None)
        if not callable(reader):
            continue
        db_path = str(getattr(plugin, "db_path", "") or "").strip()
        if not db_path:
            continue
        readers[db_path] = reader
        try:
            readers[os.path.abspath(db_path)] = reader
        except Exception:
            continue
    return readers


def _find_rate_limit_burst_count_readers(
    plugins: list[object] | None,
) -> Dict[str, Any]:
    """Brief: Build db_path -> burst-count reader mappings.

    Inputs:
      - plugins: Optional loaded plugin instances from runtime state.

    Outputs:
      - Dict[str, Any]: Mapping of db_path variants to callables compatible with
        _get_burst_count(profile_key).
    """

    readers: Dict[str, Any] = {}
    if not isinstance(plugins, list):
        return readers

    for plugin in plugins:
        if plugin is None:
            continue
        reader = getattr(plugin, "_get_burst_count", None)
        if not callable(reader):
            continue
        db_path = str(getattr(plugin, "db_path", "") or "").strip()
        if not db_path:
            continue
        readers[db_path] = reader
        try:
            readers[os.path.abspath(db_path)] = reader
        except Exception:
            continue
    return readers


def _collect_rate_limit_stats(
    config: Dict[str, Any] | None,
    plugins: list[object] | None = None,
) -> Dict[str, Any]:
    """Brief: Collect per-key RateLimit statistics from sqlite3 profiles.

    Inputs:
      - config: Full configuration mapping loaded from YAML (or None).
      - plugins: Optional loaded plugin instances used to enrich profiles with
        live current-window RPS values.

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
    db_current_rps_readers = _find_rate_limit_current_rps_readers(plugins)
    db_current_rps_snapshot_readers = _find_rate_limit_current_rps_snapshot_readers(
        plugins
    )
    db_burst_count_readers = _find_rate_limit_burst_count_readers(plugins)
    db_recalculated_allowed_rps_readers = (
        _find_rate_limit_recalculated_allowed_rps_readers(plugins)
    )
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
        current_rps_reader = db_current_rps_readers.get(path)
        if current_rps_reader is None:
            try:
                current_rps_reader = db_current_rps_readers.get(os.path.abspath(path))
            except Exception:
                current_rps_reader = None
        current_rps_snapshot_reader = db_current_rps_snapshot_readers.get(path)
        if current_rps_snapshot_reader is None:
            try:
                current_rps_snapshot_reader = db_current_rps_snapshot_readers.get(
                    os.path.abspath(path)
                )
            except Exception:
                current_rps_snapshot_reader = None
        burst_count_reader = db_burst_count_readers.get(path)
        if burst_count_reader is None:
            try:
                burst_count_reader = db_burst_count_readers.get(os.path.abspath(path))
            except Exception:
                burst_count_reader = None
        recalculated_allowed_rps_reader = db_recalculated_allowed_rps_readers.get(path)
        if recalculated_allowed_rps_reader is None:
            try:
                recalculated_allowed_rps_reader = (
                    db_recalculated_allowed_rps_readers.get(os.path.abspath(path))
                )
            except Exception:
                recalculated_allowed_rps_reader = None
        current_window_rps_by_key: Dict[str, float] = {}
        if callable(current_rps_snapshot_reader):
            try:
                current_window_payload = current_rps_snapshot_reader()
            except Exception:
                current_window_payload = {}
            if isinstance(current_window_payload, dict):
                for raw_key, raw_rps in current_window_payload.items():
                    key_text = str(raw_key)
                    if not key_text:
                        continue
                    key_norm = (
                        _GLOBAL_RPS_DB_KEY
                        if key_text
                        in {
                            _GLOBAL_RPS_DB_KEY,
                            _GLOBAL_RPS_API_KEY,
                            _GLOBAL_RPS_LEGACY_DB_KEY,
                        }
                        else key_text
                    )
                    current_window_rps_by_key[key_norm] = _coerce_nonnegative_float(
                        raw_rps,
                        default=0.0,
                    )
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
                    str(row[0])
                    in {
                        _GLOBAL_RPS_DB_KEY,
                        _GLOBAL_RPS_API_KEY,
                        _GLOBAL_RPS_LEGACY_DB_KEY,
                    }
                    for row in rows
                )
                if not has_global_row:
                    cur.execute(
                        "SELECT key, avg_rps, max_rps, samples, last_update "
                        "FROM rate_profiles WHERE key IN (?, ?, ?) "
                        "ORDER BY last_update DESC LIMIT 1",
                        (
                            _GLOBAL_RPS_DB_KEY,
                            _GLOBAL_RPS_API_KEY,
                            _GLOBAL_RPS_LEGACY_DB_KEY,
                        ),
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

        if not rows and not current_window_rps_by_key:
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

        # Normalize global profile aliases to one deterministic row so API
        # output cannot depend on sqlite ordering by avg_rps.
        canonical_global_row: tuple[Any, Any, Any, Any, Any] | None = None
        normalized_rows: list[tuple[Any, Any, Any, Any, Any]] = []
        for row in rows:
            key_text = str(row[0])
            if key_text in {
                _GLOBAL_RPS_DB_KEY,
                _GLOBAL_RPS_API_KEY,
                _GLOBAL_RPS_LEGACY_DB_KEY,
            }:
                if canonical_global_row is None:
                    canonical_global_row = row
                    continue
                current_key_text = str(canonical_global_row[0])
                try:
                    existing_last_update = int(canonical_global_row[4] or 0)
                except Exception:
                    existing_last_update = 0
                try:
                    new_last_update = int(row[4] or 0)
                except Exception:
                    new_last_update = 0
                if new_last_update > existing_last_update:
                    canonical_global_row = row
                    continue
                if new_last_update < existing_last_update:
                    continue
                # Tie-break identical timestamps by preferring canonical key text.
                if (
                    current_key_text != _GLOBAL_RPS_DB_KEY
                    and key_text == _GLOBAL_RPS_DB_KEY
                ):
                    canonical_global_row = row
                continue
            normalized_rows.append(row)
        if canonical_global_row is not None:
            normalized_rows.append(canonical_global_row)

        profiles: list[Dict[str, Any]] = []
        profile_keys_seen: set[str] = set()
        max_avg = 0.0
        max_max = 0.0
        max_window_avg = 0.0
        max_window_max = 0.0
        max_current_limit = 0.0
        max_current_rps = 0.0
        max_burst_threshold = 0.0
        for key, avg_rps, max_rps, samples, last_update in normalized_rows:
            key_text = str(key)
            display_key = (
                _GLOBAL_RPS_API_KEY
                if key_text
                in {
                    _GLOBAL_RPS_DB_KEY,
                    _GLOBAL_RPS_API_KEY,
                    _GLOBAL_RPS_LEGACY_DB_KEY,
                }
                else key_text
            )
            profile_keys_seen.add(str(display_key))
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
            current_rps_lookup_key = (
                _GLOBAL_RPS_DB_KEY
                if key_text
                in {
                    _GLOBAL_RPS_DB_KEY,
                    _GLOBAL_RPS_API_KEY,
                    _GLOBAL_RPS_LEGACY_DB_KEY,
                }
                else key_text
            )
            if callable(current_rps_reader):
                try:
                    current_rps = _coerce_nonnegative_float(
                        current_rps_reader(current_rps_lookup_key),
                        default=0.0,
                    )
                except Exception:
                    current_rps = 0.0
            else:
                current_rps = 0.0
            if callable(burst_count_reader):
                try:
                    burst_count = _coerce_nonnegative_int(
                        burst_count_reader(current_rps_lookup_key),
                        default=0,
                    )
                except Exception:
                    burst_count = None
            else:
                burst_count = None
            if callable(recalculated_allowed_rps_reader):
                try:
                    recalculated_thresholds = recalculated_allowed_rps_reader(
                        str(current_rps_lookup_key),
                        float(avg_val),
                        int(samples_val),
                    )
                    if not (
                        isinstance(recalculated_thresholds, tuple)
                        and len(recalculated_thresholds) == 2
                    ):
                        recalculated_thresholds = None
                except Exception:
                    recalculated_thresholds = None
            else:
                recalculated_thresholds = None
            (
                current_limit_rps,
                current_limit_source,
                burst_threshold_rps,
                enforcement_active,
            ) = _compute_current_limit_rps(
                avg_rps=avg_val,
                samples=samples_val,
                current_rps=float(current_rps),
                limit_settings=limit_settings,
                profile_key=key_text,
                burst_count=burst_count,
                recalculated_thresholds=recalculated_thresholds,
            )
            max_window_avg = max(max_window_avg, float(window_avg_val))
            max_window_max = max(max_window_max, float(window_max_val))
            if current_limit_rps is not None:
                max_current_limit = max(max_current_limit, float(current_limit_rps))
            max_current_rps = max(max_current_rps, float(current_rps))
            if burst_threshold_rps is not None:
                max_burst_threshold = max(
                    max_burst_threshold,
                    float(burst_threshold_rps),
                )
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
                    "burst_threshold_rps": (
                        float(burst_threshold_rps)
                        if burst_threshold_rps is not None
                        else None
                    ),
                    "enforcement_active": bool(enforcement_active),
                    "current_rps": float(current_rps),
                    "current_limit_source": str(current_limit_source),
                    "samples": samples_val,
                    "last_update": last_val,
                }
            )
        # Include active keys from the current in-progress window even when
        # they do not yet have a persisted rate_profiles row.
        for key_text, current_rps in current_window_rps_by_key.items():
            display_key = (
                _GLOBAL_RPS_API_KEY
                if key_text
                in {
                    _GLOBAL_RPS_DB_KEY,
                    _GLOBAL_RPS_API_KEY,
                    _GLOBAL_RPS_LEGACY_DB_KEY,
                }
                else key_text
            )
            if str(display_key) in profile_keys_seen:
                continue

            burst_count = None
            if callable(burst_count_reader):
                try:
                    burst_count = _coerce_nonnegative_int(
                        burst_count_reader(str(key_text)),
                        default=0,
                    )
                except Exception:
                    burst_count = None
            if callable(recalculated_allowed_rps_reader):
                try:
                    recalculated_thresholds = recalculated_allowed_rps_reader(
                        str(key_text),
                        0.0,
                        0,
                    )
                    if not (
                        isinstance(recalculated_thresholds, tuple)
                        and len(recalculated_thresholds) == 2
                    ):
                        recalculated_thresholds = None
                except Exception:
                    recalculated_thresholds = None
            else:
                recalculated_thresholds = None
            (
                current_limit_rps,
                current_limit_source,
                burst_threshold_rps,
                enforcement_active,
            ) = _compute_current_limit_rps(
                avg_rps=0.0,
                samples=0,
                current_rps=float(current_rps),
                limit_settings=limit_settings,
                profile_key=str(key_text),
                burst_count=burst_count,
                recalculated_thresholds=recalculated_thresholds,
            )

            if current_limit_rps is not None:
                max_current_limit = max(max_current_limit, float(current_limit_rps))
            max_current_rps = max(max_current_rps, float(current_rps))
            if burst_threshold_rps is not None:
                max_burst_threshold = max(
                    max_burst_threshold,
                    float(burst_threshold_rps),
                )

            profiles.append(
                {
                    "key": str(display_key),
                    "rps_limit": (
                        float(current_limit_rps)
                        if current_limit_rps is not None
                        else None
                    ),
                    "avg_rps": 0.0,
                    "avg_rps_overall": 0.0,
                    "max_rps": 0.0,
                    "max_rps_overall": 0.0,
                    "window_avg_rps": 0.0,
                    "avg_rps_interval": 0.0,
                    "window_max_rps": 0.0,
                    "max_rps_interval": 0.0,
                    "current_limit_rps": (
                        float(current_limit_rps)
                        if current_limit_rps is not None
                        else None
                    ),
                    "burst_threshold_rps": (
                        float(burst_threshold_rps)
                        if burst_threshold_rps is not None
                        else None
                    ),
                    "enforcement_active": bool(enforcement_active),
                    "current_rps": float(current_rps),
                    "current_limit_source": str(current_limit_source),
                    "samples": 0,
                    "last_update": None,
                }
            )
        global_profile = None
        non_global_profiles: list[Dict[str, Any]] = []
        for profile in profiles:
            key_name = str(profile.get("key", ""))
            if key_name == _GLOBAL_RPS_API_KEY and global_profile is None:
                global_profile = profile
            elif key_name != _GLOBAL_RPS_API_KEY:
                non_global_profiles.append(profile)

        if global_profile is not None and non_global_profiles:
            now_for_warn = float(time.time())
            max_non_global_samples = -1
            max_non_global_samples_key = ""
            for profile in non_global_profiles:
                profile_samples = int(profile.get("samples", 0) or 0)
                if profile_samples > max_non_global_samples:
                    max_non_global_samples = profile_samples
                    max_non_global_samples_key = str(profile.get("key", ""))
            global_samples = int(global_profile.get("samples", 0) or 0)
            if global_samples < max_non_global_samples:
                # A one-sample skew is expected occasionally because global/key
                # profile rows are updated in separate commits.
                if int(max_non_global_samples - global_samples) > 1:
                    warn_key = (
                        f"{path}|samples|{global_samples}|{max_non_global_samples}|"
                        f"{max_non_global_samples_key}|{global_profile.get('last_update', '')}"
                    )
                    if _should_emit_invariant_warning(warn_key, now_for_warn):
                        logger.warning(
                            "rate_limit invariant violated db_path=%s field=samples global=%s global_key=%s max_key_value=%s max_key_name=%s global_last_update=%s key_last_update=%s; normalizing global samples",
                            path,
                            global_samples,
                            str(global_profile.get("key", "")),
                            max_non_global_samples,
                            max_non_global_samples_key,
                            str(global_profile.get("last_update", "")),
                            str(
                                next(
                                    (
                                        p.get("last_update", "")
                                        for p in non_global_profiles
                                        if str(p.get("key", ""))
                                        == max_non_global_samples_key
                                    ),
                                    "",
                                )
                            ),
                        )
                global_profile["samples"] = int(max_non_global_samples)

            invariant_metrics = (
                ("current_rps", "current_rps"),
                ("max_rps", "max_rps_overall"),
                ("window_max_rps", "max_rps_interval"),
            )
            for canonical_metric, alias_metric in invariant_metrics:
                fresh_non_global_profiles = non_global_profiles
                if int(lookback_seconds) > 0:
                    try:
                        global_last_update = int(
                            global_profile.get("last_update", 0) or 0
                        )
                    except Exception:
                        global_last_update = 0
                    if global_last_update > 0:
                        cutoff_last_update = int(global_last_update) - int(
                            lookback_seconds
                        )
                        fresh_non_global_profiles = [
                            p
                            for p in non_global_profiles
                            if int(p.get("last_update", 0) or 0)
                            >= int(cutoff_last_update)
                        ]
                if not fresh_non_global_profiles:
                    continue
                max_non_global_value = 0.0
                max_non_global_key = ""
                for profile in fresh_non_global_profiles:
                    candidate = _coerce_nonnegative_float(
                        profile.get(canonical_metric), default=0.0
                    )
                    if candidate > max_non_global_value:
                        max_non_global_value = float(candidate)
                        max_non_global_key = str(profile.get("key", ""))
                global_value = _coerce_nonnegative_float(
                    global_profile.get(canonical_metric),
                    default=0.0,
                )
                if global_value >= max_non_global_value:
                    continue
                warn_key = (
                    f"{path}|{canonical_metric}|{global_value:.4f}|{max_non_global_value:.4f}|"
                    f"{max_non_global_key}|{global_profile.get('last_update', '')}"
                )
                if _should_emit_invariant_warning(warn_key, now_for_warn):
                    logger.warning(
                        "rate_limit invariant violated db_path=%s field=%s global=%.4f global_key=%s max_key_value=%.4f max_key_name=%s global_last_update=%s key_last_update=%s; normalizing global value",
                        path,
                        canonical_metric,
                        global_value,
                        str(global_profile.get("key", "")),
                        max_non_global_value,
                        max_non_global_key,
                        str(global_profile.get("last_update", "")),
                        str(
                            next(
                                (
                                    p.get("last_update", "")
                                    for p in fresh_non_global_profiles
                                    if str(p.get("key", "")) == max_non_global_key
                                ),
                                "",
                            )
                        ),
                    )
                global_profile[canonical_metric] = float(max_non_global_value)
                if alias_metric != canonical_metric:
                    global_profile[alias_metric] = float(max_non_global_value)
        elif global_profile is None and non_global_profiles:
            logger.warning(
                "rate_limit invariant violated db_path=%s field=global_profile missing while %d key profiles exist",
                path,
                len(non_global_profiles),
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
                "max_current_rps": max_current_rps,
                "max_burst_threshold_rps": max_burst_threshold,
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
