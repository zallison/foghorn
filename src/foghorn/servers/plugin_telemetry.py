"""Per-plugin execution telemetry for resolve plugin chains.

Brief:
  Provides a small dataclass and helpers used by the resolver pipeline to
  time each resolve-plugin hook invocation (pre_resolve / post_resolve) and
  log a per-plugin millisecond breakdown for a single DNS query at DEBUG
  level, plus a WARNING when a plugin exceeds a configurable slow threshold.

Inputs:
  - None directly; the helpers are called from the plugin loops in
    foghorn.servers.server (_resolve_core) and foghorn.servers.udp_server
    (DNSUDPHandler._apply_pre_plugins / _apply_post_plugins).

Outputs:
  - PluginExecution records appended to caller-provided lists, one DEBUG
    breakdown line per completed plugin chain, and WARNING lines for slow
    plugins.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass

# Default slow-plugin threshold in milliseconds; override with the
# FOGHORN_SLOW_PLUGIN_MS environment variable (0 or negative disables the
# warning entirely).
DEFAULT_SLOW_PLUGIN_THRESHOLD_MS = 50.0
SLOW_PLUGIN_ENV_VAR = "FOGHORN_SLOW_PLUGIN_MS"

# Cached env threshold so hot-path logging does not re-parse environ per query.
_cached_env_threshold_ms: float | None = None
_cached_env_raw: str | None = None


@dataclass
class PluginExecution:
    """Telemetry record for a single resolve-plugin hook invocation.

    Attributes:
      - plugin_name: Class name of the plugin that was invoked.
      - duration_ms: Wall-clock duration of the hook call in milliseconds.
      - success: True when the hook returned without raising.
      - error_message: "Type: message" summary when the hook raised, else None.
    """

    plugin_name: str
    duration_ms: float
    success: bool
    error_message: str | None = None


def time_plugin_call(
    records: list[PluginExecution],
    plugin_name: str,
    call: Callable[[], object],
    *,
    record: bool = True,
) -> object:
    """Run one resolve-plugin hook while recording execution telemetry.

    Inputs:
      - records: List of PluginExecution to append the new record to.
      - plugin_name: Class name of the plugin being invoked.
      - call: Zero-argument callable performing the actual plugin hook call.
      - record: When False, skip timing/allocation and just invoke call().

    Outputs:
      - object: The plugin hook return value, unchanged.

    Notes:
      - Exceptions raised by the hook are re-raised unchanged so existing
        per-transport error handling keeps its current behaviour; a record
        with success=False is appended either way when record=True.
    """

    if not record:
        return call()

    started = time.perf_counter()
    success = True
    error_message: str | None = None
    try:
        return call()
    except Exception as exc:
        success = False
        error_message = f"{type(exc).__name__}: {exc}"
        raise
    finally:
        records.append(
            PluginExecution(
                plugin_name=plugin_name,
                duration_ms=(time.perf_counter() - started) * 1000.0,
                success=success,
                error_message=error_message,
            )
        )


def get_slow_plugin_threshold_ms(explicit: float | None = None) -> float:
    """Resolve the slow-plugin threshold in milliseconds.

    Inputs:
      - explicit: Caller-provided threshold; wins when not None.

    Outputs:
      - float: Threshold in milliseconds. Values <= 0 disable the warning.
        Defaults to DEFAULT_SLOW_PLUGIN_THRESHOLD_MS unless the
        FOGHORN_SLOW_PLUGIN_MS environment variable overrides it.
    """

    global _cached_env_threshold_ms, _cached_env_raw

    if explicit is not None:
        try:
            return max(0.0, float(explicit))
        except (TypeError, ValueError):
            return 0.0

    raw = os.environ.get(SLOW_PLUGIN_ENV_VAR)
    raw_key = None if raw is None else str(raw)
    if _cached_env_threshold_ms is not None and raw_key == _cached_env_raw:
        return _cached_env_threshold_ms

    if raw is None or str(raw).strip() == "":
        value = DEFAULT_SLOW_PLUGIN_THRESHOLD_MS
    else:
        try:
            value = max(0.0, float(str(raw).strip()))
        except (TypeError, ValueError):
            value = DEFAULT_SLOW_PLUGIN_THRESHOLD_MS

    _cached_env_raw = raw_key
    _cached_env_threshold_ms = value
    return value


def plugin_telemetry_enabled(logger: logging.Logger) -> bool:
    """Brief: Return True when plugin timing records are worth collecting.

    Inputs:
      - logger: Logger that will receive telemetry output.

    Outputs:
      - bool: True when DEBUG breakdowns are enabled, or when
        FOGHORN_SLOW_PLUGIN_MS is explicitly set to a positive value (so
        slow-plugin WARNINGs can still run without DEBUG).

    Notes:
      - Default INFO deployments skip per-plugin timing entirely to avoid
        hot-path allocation. Operators opt into slow warnings via the env var.
    """

    if logger.isEnabledFor(logging.DEBUG):
        return True
    raw = os.environ.get(SLOW_PLUGIN_ENV_VAR)
    if raw is None or str(raw).strip() == "":
        return False
    return get_slow_plugin_threshold_ms() > 0.0 and logger.isEnabledFor(logging.WARNING)


def log_plugin_telemetry(
    logger: logging.Logger,
    stage: str,
    qname: str,
    records: list[PluginExecution],
    slow_threshold_ms: float | None = None,
) -> None:
    """Log the per-plugin millisecond breakdown for one completed plugin chain.

    Inputs:
      - logger: Logger instance (typically the foghorn.server logger).
      - stage: Chain label, e.g. "pre" or "post".
      - qname: Query name the chain ran for.
      - records: PluginExecution records collected while the chain ran.
      - slow_threshold_ms: Optional explicit slow threshold in milliseconds;
        when omitted, get_slow_plugin_threshold_ms() decides (environment
        variable FOGHORN_SLOW_PLUGIN_MS, default 50ms).

    Outputs:
      - None; emits one DEBUG line describing every recorded execution and a
        WARNING for each plugin that exceeded the slow threshold.
    """

    if not records:
        return

    want_debug = logger.isEnabledFor(logging.DEBUG)
    # Only emit slow warnings when DEBUG is on or the env threshold was set
    # explicitly (see plugin_telemetry_enabled).
    raw = os.environ.get(SLOW_PLUGIN_ENV_VAR)
    env_set = raw is not None and str(raw).strip() != ""
    threshold = get_slow_plugin_threshold_ms(slow_threshold_ms)
    want_warn = (
        threshold > 0.0
        and logger.isEnabledFor(logging.WARNING)
        and (want_debug or env_set or slow_threshold_ms is not None)
    )
    if not want_debug and not want_warn:
        return

    parts: list[str] | None = [] if want_debug else None
    for rec in records:
        if parts is not None:
            part = f"{rec.plugin_name}={rec.duration_ms:.2f}ms"
            if not rec.success:
                part += f"(error:{rec.error_message})"
            parts.append(part)
        if want_warn and rec.duration_ms > threshold:
            logger.warning(
                "Slow resolve plugin %s in %s chain for %s: %.2fms exceeds %.1fms threshold",
                rec.plugin_name,
                stage,
                qname,
                rec.duration_ms,
                threshold,
            )
    if parts is not None:
        logger.debug(
            "resolve plugin telemetry [%s] %s: %s",
            stage,
            qname,
            " | ".join(parts),
        )
