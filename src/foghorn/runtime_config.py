"""In-process runtime configuration snapshot and reload helpers.

Brief:
  This module implements a small, portable, in-process config reload mechanism.
  The active runtime is represented as an immutable snapshot that request
  handlers can read once per request.

  The reload mechanism supports a "reload-only" mode that applies only changes
  that are safe without rebinding sockets or reloading TLS materials. When the
  desired config includes changes that require a full restart (e.g., listener
  binds or TLS cert/key paths), reload-only will preserve the currently-effective
  listener/http configuration while still applying reloadable settings such as:
    - upstream endpoints and resolver knobs
    - plugins (reloaded + setup())
    - cache backend selection
    - dnssec and EDNS knobs used by the resolver

Inputs:
  - YAML config file paths (for reload_from_disk)
  - Parsed config dicts (for reload_from_config)

Outputs:
  - RuntimeSnapshot objects and ReloadResult describing applied vs restart-needed
    configuration.

Notes:
  - The snapshot is swapped atomically by assigning a single module-level
    reference under a lock. Readers do not take a lock.
  - Callers must still ensure listener socket rebinds/TLS reload are handled via
    a full restart; this module only reports those conditions.
"""

from __future__ import annotations

import copy
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Tuple

from .config.config_parser import (
    load_plugins,
    normalize_upstream_backup_config,
    normalize_upstream_config,
    parse_config_file,
)
from .plugins.setup import run_setup_plugins

logger = logging.getLogger("foghorn.runtime_config")


@dataclass(frozen=True)
class UpstreamHealthConfig:
    """Brief: Configuration knobs for upstream health tracking.

    Inputs:
      - Parsed from cfg['upstreams']['health'] by runtime_config._build_snapshot.

    Outputs:
      - UpstreamHealthConfig instance used by the shared resolver.

    Notes:
      - Percent values are expressed as 0.0–100.0.
      - unknown_after_seconds controls when a previously healthy upstream becomes
        status='unknown' due to lack of successful responses. Unknown is treated
        as eligible for selection (like healthy) but can be used for reporting.
    """

    max_serv_fail: int
    unknown_after_seconds: float

    probe_percent: float
    probe_min_percent: float
    probe_max_percent: float
    probe_increase: float
    probe_decrease: float


def parse_upstream_health_config(upstream_cfg: Dict[str, Any]) -> UpstreamHealthConfig:
    """Brief: Parse upstream health configuration with defensive defaults.

    Inputs:
      - upstream_cfg: cfg['upstreams'] mapping.

    Outputs:
      - UpstreamHealthConfig.

    Notes:
      - Supports optional presets via upstreams.health.profile.
      - When profile is set, values from upstreams_health_profiles.yaml are
        merged first, then explicit keys under upstreams.health override them.
      - Missing/invalid values are clamped to conservative defaults.
      - This helper is used by both startup (foghorn.main) and reload snapshots.
    """

    health_cfg = upstream_cfg.get("health") if isinstance(upstream_cfg, dict) else None
    if not isinstance(health_cfg, dict):
        health_cfg = {}
    else:
        # Backward-compatible alias used by earlier configs/docs.
        if "probe_percent" not in health_cfg and "probe_pct" in health_cfg:
            health_cfg["probe_percent"] = health_cfg.get("probe_pct")

    profile_name = str(health_cfg.get("profile") or "").strip()
    if profile_name:
        try:
            from foghorn.config.plugin_profiles import load_builtin_profiles

            profiles = load_builtin_profiles("upstreams_health")
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: profile file load errors are fatal
            raise ValueError(
                "Failed to load upstream health profiles (upstreams_health_profiles.yaml)"
            ) from exc

        if not isinstance(profiles, dict):  # pragma: no cover
            raise ValueError(
                "upstreams_health_profiles.yaml did not parse to a mapping"
            )

        base = profiles.get(profile_name)
        if base is None:
            raise ValueError(
                f"Unknown upstreams.health.profile {profile_name!r}; see upstreams_health_profiles.yaml"
            )
        if not isinstance(
            base, dict
        ):  # pragma: no cover - defensive, config should be valid
            raise ValueError(
                f"upstreams_health profile {profile_name!r} must be a mapping of knobs"
            )

        merged: Dict[str, Any] = dict(base)
        for k, v in health_cfg.items():
            if k == "profile":
                continue
            merged[k] = v
        health_cfg = merged

    def _clamp_float(key: str, default: float, *, lo: float, hi: float) -> float:
        raw = health_cfg.get(key, default)
        try:
            val = float(raw)
        except Exception:
            val = float(default)
        return max(lo, min(hi, val))

    def _clamp_int(key: str, default: int, *, lo: int, hi: int | None = None) -> int:
        raw = health_cfg.get(key, default)
        try:
            val = int(raw)
        except Exception:
            val = int(default)
        if hi is not None:
            return max(lo, min(int(hi), val))
        return max(lo, val)  # pragma: no cover - defensive

    max_serv_fail = _clamp_int("max_serv_fail", 3, lo=0)
    unknown_after_seconds = _clamp_float(
        "unknown_after_seconds", 300.0, lo=0.0, hi=86400.0
    )

    # probe_min_percent must never be 0.0; if probe_percent ever hits 0 we may
    # stop probing unhealthy upstreams entirely and never observe them recover.
    probe_floor = 0.5

    probe_min = _clamp_float("probe_min_percent", probe_floor, lo=0.0, hi=100.0)
    probe_max = _clamp_float("probe_max_percent", 50.0, lo=0.0, hi=100.0)

    # Ensure min <= max and enforce the floor.
    probe_min, probe_max = (
        (probe_min, probe_max) if probe_min <= probe_max else (probe_max, probe_min)
    )
    probe_min = max(float(probe_floor), float(probe_min))
    probe_max = max(float(probe_min), float(probe_max))

    probe_percent = _clamp_float("probe_percent", 1.0, lo=probe_min, hi=probe_max)
    probe_increase = _clamp_float("probe_increase", 1.0, lo=0.0, hi=100.0)
    probe_decrease = _clamp_float("probe_decrease", 1.0, lo=0.0, hi=100.0)

    return UpstreamHealthConfig(
        max_serv_fail=int(max_serv_fail),
        unknown_after_seconds=float(unknown_after_seconds),
        probe_percent=float(probe_percent),
        probe_min_percent=float(probe_min),
        probe_max_percent=float(probe_max),
        probe_increase=float(probe_increase),
        probe_decrease=float(probe_decrease),
    )


@dataclass(frozen=True)
class RuntimeSnapshot:
    """Brief: Immutable snapshot of resolver-relevant runtime configuration.

    Inputs:
      - Constructed by initialize_runtime() and reload helpers.

    Outputs:
      - RuntimeSnapshot that can be safely shared across threads.

    Notes:
      - Only include values needed on the hot path (_resolve_core) and by request
        handlers.
      - Listener bind settings are generally excluded because they cannot be
        changed without a restart, but a small number of listener-adjacent knobs
        (e.g. UDP max response bytes) are included because they are consulted by
        the listener adapter after resolution.
    """

    cfg: Dict[str, Any]
    plugins: List[object]
    upstream_addrs: List[Dict[str, Any]]
    upstream_backup_addrs: List[Dict[str, Any]]
    upstream_health: UpstreamHealthConfig
    timeout_ms: int
    upstream_strategy: str
    upstream_max_concurrent: int
    resolver_mode: str
    recursive_max_depth: int
    recursive_timeout_ms: int
    recursive_per_try_timeout_ms: int
    dnssec_mode: str
    dnssec_validation: str
    edns_udp_payload: int
    enable_ede: bool
    forward_local: bool
    min_cache_ttl: int
    cache_prefetch_enabled: bool
    cache_prefetch_min_ttl: int
    cache_prefetch_max_ttl: int
    cache_prefetch_refresh_before_expiry: float
    cache_prefetch_allow_stale_after_expiry: float
    stats_collector: object | None
    cache_plugin: object | None
    # Optional explicit UDP response size ceiling (bytes). When None, the
    # effective ceiling is derived from client EDNS(0) and edns_udp_payload.
    udp_max_response_bytes: int | None
    # AXFR/IXFR policy for TCP/DoT listeners.
    axfr_enabled: bool
    axfr_allow_clients: List[str]
    axfr_max_zone_rrs: int | None
    axfr_max_concurrent_transfers: int
    axfr_rate_limit_per_client_per_second: float
    axfr_rate_limit_burst: float
    axfr_max_transfer_rate_bytes_per_second: int | None
    axfr_message_max_bytes: int
    axfr_require_tsig: bool
    axfr_tsig_keys: List[Dict[str, str]]
    generation: int
    applied_at_epoch: float


@dataclass(frozen=True)
class ReloadResult:
    """Brief: Result of a reload attempt.

    Inputs:
      - Constructed by reload_from_disk/reload_from_config.

    Outputs:
      - ReloadResult with applied/restart-needed details.
    """

    ok: bool
    generation: int
    restart_required: bool
    restart_reasons: List[str]
    error: str | None = None


_LOCK = threading.Lock()
_ACTIVE: RuntimeSnapshot | None = None
_CONFIG_PATH: str | None = None
_CLI_VARS: List[str] = []
_UNKNOWN_KEYS_POLICY: str = "warn"

# Background teardown tracking for old plugin instances.
_OLD_PLUGINS_LOCK = threading.Lock()
_OLD_PLUGINS: List[Tuple[float, List[object]]] = []
_PLUGIN_SHUTDOWN_GRACE_SECONDS = 30.0


def initialize_runtime(
    *,
    snapshot: RuntimeSnapshot,
    config_path: str,
    cli_vars: Sequence[str] | None = None,
    unknown_keys_policy: str = "warn",
) -> None:
    """Brief: Initialize the active runtime snapshot used by the resolver.

    Inputs:
      - snapshot: RuntimeSnapshot representing the current effective runtime.
      - config_path: Path to the on-disk YAML config.
      - cli_vars: Optional list of CLI KEY=YAML overrides that must continue to
        apply for future reloads.
      - unknown_keys_policy: Schema policy for unknown keys ('ignore'|'warn'|'error').

    Outputs:
      - None. Updates the module-global snapshot.

    Notes:
      - This should be called by foghorn.main after startup has finished building
        plugins/caches/etc.
    """

    global _ACTIVE, _CONFIG_PATH, _CLI_VARS, _UNKNOWN_KEYS_POLICY
    with _LOCK:
        _ACTIVE = snapshot
        _CONFIG_PATH = str(config_path)
        _CLI_VARS = list(cli_vars or [])
        _UNKNOWN_KEYS_POLICY = str(unknown_keys_policy or "warn")

    _apply_snapshot_to_runtime_globals(snapshot)


def clear_runtime() -> None:
    """Brief: Clear the active runtime snapshot and associated reload state.

    Inputs:
      - None.

    Outputs:
      - None.

    Notes:
      - This is primarily used to avoid cross-test contamination when unit tests
        call foghorn.main.main() multiple times in a single Python process.
      - In normal production operation, the process exits shortly after main()
        returns, so clearing has no observable effect.
    """

    global _ACTIVE, _CONFIG_PATH, _CLI_VARS, _UNKNOWN_KEYS_POLICY

    with _LOCK:
        _ACTIVE = None
        _CONFIG_PATH = None
        _CLI_VARS = []
        _UNKNOWN_KEYS_POLICY = "warn"

    with _OLD_PLUGINS_LOCK:
        _OLD_PLUGINS[:] = []


def get_runtime_snapshot() -> RuntimeSnapshot:
    """Brief: Return the current active runtime snapshot.

    Inputs:
      - None.

    Outputs:
      - RuntimeSnapshot.

    Notes:
      - Readers do not take a lock. The active reference is swapped atomically
        under the GIL.
      - When runtime is not initialized (common in unit tests), this returns a
        conservative default snapshot that does not depend on any listener
        implementation details.
    """

    snap = _ACTIVE
    if snap is not None:
        return snap

    return _default_snapshot()


def load_config_from_disk(*, config_path: str | None = None) -> Dict[str, Any]:
    """Brief: Parse and validate configuration from disk without applying it.

    Inputs:
      - config_path: Optional path override; defaults to the initialized config_path.

    Outputs:
      - Parsed, schema-validated configuration mapping.

    Notes:
      - Uses the same CLI vars and unknown-keys policy captured by initialize_runtime().
      - This is intended for admin UIs that want to persist config changes and
        decide whether to reload or restart later.
    """

    cfg_path = str(config_path or _CONFIG_PATH or "")
    if not cfg_path:
        raise ValueError("config_path not configured")

    return parse_config_file(
        cfg_path,
        cli_vars=list(_CLI_VARS or []),
        unknown_keys=str(_UNKNOWN_KEYS_POLICY or "warn"),
    )


def analyze_config_change(
    desired_cfg: Dict[str, Any],
    *,
    current_cfg: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    """Brief: Analyze whether a desired config implies reload or restart.

    Inputs:
      - desired_cfg: Parsed configuration mapping (schema-validated).
      - current_cfg: Optional current effective configuration mapping. When not
        provided, uses the active runtime snapshot's cfg (or {} when uninitialized).

    Outputs:
      - Dict containing:
          - changed: bool
          - restart_required: bool
          - restart_reasons: list[str]
          - reload_required: bool

    Notes:
      - "restart_required" is conservative and currently only looks at server.listen
        and server.http changes.
      - "reload_required" means the config differs and can be applied with
        zero-downtime reload (no listener/http changes).
    """

    if current_cfg is None:
        try:
            current_cfg = get_runtime_snapshot().cfg or {}
        except Exception:
            current_cfg = {}

    changed = bool(current_cfg != desired_cfg)
    restart_reasons = _restart_required_reasons(current_cfg or {}, desired_cfg or {})
    restart_required = bool(restart_reasons)
    reload_required = bool(changed and not restart_required)

    return {
        "changed": bool(changed),
        "restart_required": bool(restart_required),
        "restart_reasons": list(restart_reasons or []),
        "reload_required": bool(reload_required),
    }


def reload_from_disk(
    *,
    config_path: str | None = None,
    mode: str = "reload_only",
) -> ReloadResult:
    """Brief: Reload configuration from disk and atomically apply a new snapshot.

    Inputs:
      - config_path: Optional path override; defaults to the initialized config_path.
      - mode: 'reload_only' (default) preserves listener/http settings when the
        desired config requires restart.

    Outputs:
      - ReloadResult.

    Example:
      >>> # In-process: triggered by admin endpoint
      >>> res = reload_from_disk(config_path='config.yaml')
      >>> res.ok
      True
    """

    cfg_path = str(config_path or _CONFIG_PATH or "")
    if not cfg_path:
        return ReloadResult(
            ok=False,
            generation=get_runtime_snapshot().generation,
            restart_required=False,
            restart_reasons=[],
            error="config_path not configured",
        )

    try:
        desired = parse_config_file(
            cfg_path,
            cli_vars=list(_CLI_VARS or []),
            unknown_keys=str(_UNKNOWN_KEYS_POLICY or "warn"),
        )
    except Exception as exc:
        return ReloadResult(
            ok=False,
            generation=get_runtime_snapshot().generation,
            restart_required=False,
            restart_reasons=[],
            error=f"failed to parse/validate config: {exc}",
        )

    return reload_from_config(desired, mode=mode)


def reload_from_config(
    cfg: Dict[str, Any], *, mode: str = "reload_only"
) -> ReloadResult:
    """Brief: Apply a new runtime snapshot from an already-parsed config mapping.

    Inputs:
      - cfg: Parsed configuration mapping (schema-validated).
      - mode: 'reload_only' (default) applies only zero-downtime-safe changes.

    Outputs:
      - ReloadResult.

    Notes:
      - When restart-required changes are detected, reload_only preserves the
        currently-effective server.listen and server.http blocks.
    """

    current = get_runtime_snapshot()
    restart_reasons = _restart_required_reasons(current.cfg, cfg)
    restart_required = bool(restart_reasons)

    effective_cfg = cfg
    if restart_required and str(mode).lower() == "reload_only":
        effective_cfg = _effective_cfg_for_reload_only(current.cfg, cfg)

    try:
        new_snapshot = _build_snapshot(
            effective_cfg,
            stats_collector=current.stats_collector,
            generation=current.generation + 1,
        )
    except Exception as exc:
        logger.error("Reload failed while building new runtime: %s", exc, exc_info=True)
        return ReloadResult(
            ok=False,
            generation=current.generation,
            restart_required=restart_required,
            restart_reasons=restart_reasons,
            error=str(exc),
        )

    _swap_snapshot(new_snapshot)
    return ReloadResult(
        ok=True,
        generation=new_snapshot.generation,
        restart_required=restart_required,
        restart_reasons=restart_reasons,
        error=None,
    )


def _swap_snapshot(snapshot: RuntimeSnapshot) -> None:
    """Brief: Atomically swap the active snapshot and schedule old plugin shutdown.

    Inputs:
      - snapshot: New snapshot to activate.

    Outputs:
      - None.

    Notes:
      - Old plugins are shut down asynchronously after a grace period.
    """

    global _ACTIVE

    old_plugins: List[object] | None = None
    with _LOCK:
        if _ACTIVE is not None:
            old_plugins = list(_ACTIVE.plugins or [])
        _ACTIVE = snapshot

    _apply_snapshot_to_runtime_globals(snapshot)

    if old_plugins:
        with _OLD_PLUGINS_LOCK:
            _OLD_PLUGINS.append((time.time(), old_plugins))
        _ensure_old_plugin_reaper_thread()


def _ensure_old_plugin_reaper_thread() -> None:
    """Brief: Ensure a background thread is running to shutdown old plugins.

    Inputs: none
    Outputs: none

    Notes:
      - This is intentionally best-effort and should never raise.
    """

    try:
        t = threading.Thread(
            target=_reap_old_plugins_loop, name="FoghornPluginReaper", daemon=True
        )
        # Starting multiple reapers is harmless; they contend on the lock.
        t.start()
    except Exception:  # pragma: no cover - defensive: thread start failure is unlikely
        return


def _reap_old_plugins_loop() -> None:
    """Brief: Background loop that shuts down old plugin instances after grace.

    Inputs: none
    Outputs: none
    """

    while True:
        now = time.time()
        batch: List[List[object]] = []
        with _OLD_PLUGINS_LOCK:
            remaining: List[Tuple[float, List[object]]] = []
            for ts, plugins in _OLD_PLUGINS:
                if now - ts >= _PLUGIN_SHUTDOWN_GRACE_SECONDS:
                    batch.append(list(plugins or []))
                else:
                    remaining.append((ts, plugins))
            _OLD_PLUGINS[:] = remaining

        if not batch:
            return

        for plugins in batch:
            for p in plugins:
                try:
                    shutdown = getattr(p, "shutdown", None)
                    if callable(shutdown):
                        shutdown()
                except Exception:
                    logger.debug(
                        "Plugin shutdown failed for %r", p, exc_info=True
                    )  # pragma: no cover - defensive


def _build_snapshot(
    cfg: Dict[str, Any],
    *,
    stats_collector: object | None,
    generation: int,
) -> RuntimeSnapshot:
    """Brief: Build a new RuntimeSnapshot from a validated config mapping.

    Inputs:
      - cfg: Parsed configuration mapping.
      - stats_collector: Current StatsCollector (kept stable for now).
      - generation: Next generation counter.

    Outputs:
      - RuntimeSnapshot.

    Notes:
      - This rebuilds plugins and cache. Listener binds/TLS are not applied here,
        but a small number of listener-adjacent knobs used by request handlers
        (e.g. UDP max response bytes) are included.
    """

    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        raise ValueError("config.server must be a mapping when present")

    resolver_cfg = server_cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        raise ValueError("config.server.resolver must be a mapping when present")

    resolver_mode = str(resolver_cfg.get("mode", "forward")).lower()
    # "none" and "master" behave the same way
    if resolver_mode == "none":  # pragma: no cover - legacy alias
        resolver_mode = "master"

    try:
        recursive_max_depth = int(resolver_cfg.get("max_depth", 16))
    except Exception:
        recursive_max_depth = 16  # pragma: no cover - defensive
    try:
        recursive_timeout_ms = int(resolver_cfg.get("timeout_ms", 2000))
    except Exception:
        recursive_timeout_ms = 2000
    try:
        recursive_per_try_timeout_ms = int(
            resolver_cfg.get("per_try_timeout_ms", recursive_timeout_ms)
        )
    except Exception:  # pragma: no cover - defensive
        recursive_per_try_timeout_ms = recursive_timeout_ms

    if resolver_mode == "forward":
        upstream_addrs, timeout_ms = normalize_upstream_config(cfg)
        try:
            upstream_backup_addrs = normalize_upstream_backup_config(cfg)
        except Exception:
            upstream_backup_addrs = []  # pragma: no cover - defensive
    else:
        upstream_addrs = []
        upstream_backup_addrs = []
        timeout_ms = recursive_timeout_ms

    upstream_cfg = cfg.get("upstreams") or {}
    if not isinstance(upstream_cfg, dict):
        upstream_cfg = {}
    upstream_strategy = str(upstream_cfg.get("strategy", "failover")).lower()
    upstream_health = parse_upstream_health_config(upstream_cfg)
    try:
        upstream_max_concurrent = int(upstream_cfg.get("max_concurrent", 1) or 1)
    except Exception:
        upstream_max_concurrent = 1
    if upstream_max_concurrent < 1:  # pragma: no cover - defensive
        upstream_max_concurrent = 1

    # Cache plugin selection (same precedence as startup).
    cache_plugin = None
    try:
        from foghorn.plugins.cache.registry import load_cache_plugin

        cache_cfg = server_cfg.get("cache") if isinstance(server_cfg, dict) else None
        cache_plugin = load_cache_plugin(cache_cfg)
    except Exception:  # pragma: no cover - defensive
        cache_plugin = None

    min_cache_ttl = 0
    if cache_plugin is not None:
        try:
            min_cache_ttl = int(getattr(cache_plugin, "min_cache_ttl", 0) or 0)
        except Exception:  # pragma: no cover - defensive
            min_cache_ttl = 0
    min_cache_ttl = max(0, int(min_cache_ttl))

    # Plugins
    plugins = load_plugins(cfg.get("plugins", []))
    # Warn if exposed listeners lack rate limiting
    try:  # pragma: no cover - rate limit check is optional
        from .config.rate_limit_check import check_rate_limit_plugin_config

        check_rate_limit_plugin_config(plugins=plugins, cfg=cfg)
    except Exception:
        pass
    run_setup_plugins(
        plugins,
        upstreams=upstream_addrs,
        upstream_backups=upstream_backup_addrs,
        timeout_ms=timeout_ms,
        resolver_mode=resolver_mode,
        upstream_max_concurrent=upstream_max_concurrent,
    )

    # DNSSEC / EDNS
    dnssec_cfg = server_cfg.get("dnssec") or {}
    if not isinstance(dnssec_cfg, dict):
        dnssec_cfg = {}
    dnssec_mode = str(dnssec_cfg.get("mode", "ignore")).lower()
    dnssec_validation = str(dnssec_cfg.get("validation", "upstream_ad")).lower()
    try:
        edns_udp_payload = int(dnssec_cfg.get("udp_payload_size", 1232))
    except Exception:  # pragma: no cover - defensive
        edns_udp_payload = 1232

    enable_ede = bool(server_cfg.get("enable_ede", False))
    forward_local = bool(server_cfg.get("forward_local", False))

    # UDP listener-adjacent knobs.
    udp_max_response_bytes = None
    try:
        listen_cfg = server_cfg.get("listen") or {}
        udp_cfg = listen_cfg.get("udp") or {}
        if isinstance(udp_cfg, dict):
            raw_max = udp_cfg.get("max_response_bytes")
            if raw_max is not None:
                udp_max_response_bytes = int(raw_max)
    except Exception:  # pragma: no cover - defensive
        udp_max_response_bytes = None

    # AXFR/IXFR transfer policy (applies to TCP/DoT listeners).
    axfr_cfg = server_cfg.get("axfr") or {}
    if not isinstance(axfr_cfg, dict):
        axfr_cfg = {}
    axfr_enabled = bool(axfr_cfg.get("enabled", False))
    axfr_allow_clients = axfr_cfg.get("allow_clients") or []
    if not isinstance(axfr_allow_clients, list):
        axfr_allow_clients = []
    axfr_allow_clients = [str(x) for x in axfr_allow_clients if x]
    try:
        raw_max_zone_rrs = axfr_cfg.get("max_zone_rrs")
        axfr_max_zone_rrs = (
            int(raw_max_zone_rrs)
            if raw_max_zone_rrs is not None and str(raw_max_zone_rrs).strip() != ""
            else None
        )
    except Exception:
        axfr_max_zone_rrs = None
    if axfr_max_zone_rrs is not None and axfr_max_zone_rrs <= 0:
        axfr_max_zone_rrs = None
    try:
        axfr_max_concurrent_transfers = int(axfr_cfg.get("max_concurrent_transfers", 4))
    except Exception:
        axfr_max_concurrent_transfers = 4
    axfr_max_concurrent_transfers = max(1, int(axfr_max_concurrent_transfers))
    try:
        axfr_rate_limit_per_client_per_second = float(
            axfr_cfg.get("rate_limit_per_client_per_second", 0.0)
        )
    except Exception:
        axfr_rate_limit_per_client_per_second = 0.0
    axfr_rate_limit_per_client_per_second = max(
        0.0, float(axfr_rate_limit_per_client_per_second)
    )
    try:
        axfr_rate_limit_burst = float(axfr_cfg.get("rate_limit_burst", 2.0))
    except Exception:
        axfr_rate_limit_burst = 2.0
    axfr_rate_limit_burst = max(1.0, float(axfr_rate_limit_burst))
    try:
        raw_max_rate = axfr_cfg.get("max_transfer_rate_bytes_per_second")
        axfr_max_transfer_rate_bytes_per_second = (
            int(raw_max_rate)
            if raw_max_rate is not None and str(raw_max_rate).strip() != ""
            else None
        )
    except Exception:
        axfr_max_transfer_rate_bytes_per_second = None
    if (
        axfr_max_transfer_rate_bytes_per_second is not None
        and axfr_max_transfer_rate_bytes_per_second <= 0
    ):
        axfr_max_transfer_rate_bytes_per_second = None
    try:
        axfr_message_max_bytes = int(axfr_cfg.get("message_max_bytes", 64000))
    except Exception:
        axfr_message_max_bytes = 64000
    axfr_message_max_bytes = max(512, min(65535, int(axfr_message_max_bytes)))
    axfr_require_tsig = bool(axfr_cfg.get("require_tsig", False))
    axfr_tsig_keys_raw = axfr_cfg.get("tsig_keys") or []
    axfr_tsig_keys: List[Dict[str, str]] = []
    if isinstance(axfr_tsig_keys_raw, list):
        for entry in axfr_tsig_keys_raw:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            secret = str(entry.get("secret") or "").strip()
            algorithm = str(entry.get("algorithm") or "hmac-sha256").strip().lower()
            if not name or not secret:
                continue
            axfr_tsig_keys.append(
                {"name": name, "secret": secret, "algorithm": algorithm}
            )

    # Cache prefetch knobs are not yet config-plumbed; preserve current values
    # from the active snapshot when available.
    current = (
        get_runtime_snapshot()
    )  # pragma: no cover - prefetch preserved from current

    return RuntimeSnapshot(
        cfg=cfg,
        plugins=list(plugins or []),
        upstream_addrs=list(upstream_addrs or []),
        upstream_backup_addrs=list(upstream_backup_addrs or []),
        upstream_health=upstream_health,
        timeout_ms=int(timeout_ms),
        upstream_strategy=str(upstream_strategy),
        upstream_max_concurrent=int(upstream_max_concurrent),
        resolver_mode=str(resolver_mode),
        recursive_max_depth=int(recursive_max_depth),
        recursive_timeout_ms=int(recursive_timeout_ms),
        recursive_per_try_timeout_ms=int(recursive_per_try_timeout_ms),
        dnssec_mode=str(dnssec_mode),
        dnssec_validation=str(dnssec_validation),
        edns_udp_payload=max(512, int(edns_udp_payload)),
        enable_ede=bool(enable_ede),
        forward_local=bool(forward_local),
        min_cache_ttl=int(min_cache_ttl),
        cache_prefetch_enabled=bool(current.cache_prefetch_enabled),
        cache_prefetch_min_ttl=int(current.cache_prefetch_min_ttl),
        cache_prefetch_max_ttl=int(current.cache_prefetch_max_ttl),
        cache_prefetch_refresh_before_expiry=float(
            current.cache_prefetch_refresh_before_expiry
        ),
        cache_prefetch_allow_stale_after_expiry=float(
            current.cache_prefetch_allow_stale_after_expiry
        ),
        stats_collector=stats_collector,
        cache_plugin=cache_plugin,
        udp_max_response_bytes=(
            max(0, int(udp_max_response_bytes))
            if udp_max_response_bytes is not None
            else None
        ),
        axfr_enabled=bool(axfr_enabled),
        axfr_allow_clients=list(axfr_allow_clients or []),
        axfr_max_zone_rrs=(
            int(axfr_max_zone_rrs) if axfr_max_zone_rrs is not None else None
        ),
        axfr_max_concurrent_transfers=int(axfr_max_concurrent_transfers),
        axfr_rate_limit_per_client_per_second=float(
            axfr_rate_limit_per_client_per_second
        ),
        axfr_rate_limit_burst=float(axfr_rate_limit_burst),
        axfr_max_transfer_rate_bytes_per_second=(
            int(axfr_max_transfer_rate_bytes_per_second)
            if axfr_max_transfer_rate_bytes_per_second is not None
            else None
        ),
        axfr_message_max_bytes=int(axfr_message_max_bytes),
        axfr_require_tsig=bool(axfr_require_tsig),
        axfr_tsig_keys=list(axfr_tsig_keys or []),
        generation=int(generation),
        applied_at_epoch=time.time(),
    )


def _restart_required_reasons(
    old_cfg: Dict[str, Any], new_cfg: Dict[str, Any]
) -> List[str]:
    """Brief: Determine which config changes require a full restart.

    Inputs:
      - old_cfg: Currently-effective config mapping.
      - new_cfg: Desired config mapping.

    Outputs:
      - list[str]: Human-readable reasons.

    Current restart-required triggers:
      - Any change under server.listen (binds, enable flags, TLS material paths).
      - Any change under server.http (admin server binds/auth).

    This is intentionally conservative.
    """

    reasons: List[str] = []

    old_server = old_cfg.get("server") if isinstance(old_cfg, dict) else None
    new_server = new_cfg.get("server") if isinstance(new_cfg, dict) else None
    old_server = old_server if isinstance(old_server, dict) else {}
    new_server = new_server if isinstance(new_server, dict) else {}

    old_listen = old_server.get("listen") if isinstance(old_server, dict) else None
    new_listen = new_server.get("listen") if isinstance(new_server, dict) else None
    old_listen = old_listen if isinstance(old_listen, dict) else {}
    new_listen = new_listen if isinstance(new_listen, dict) else {}

    if old_listen != new_listen:
        reasons.append(
            "server.listen changed (binds/TLS/enabled flags require restart)"
        )

    old_http = old_server.get("http") if isinstance(old_server, dict) else None
    new_http = new_server.get("http") if isinstance(new_server, dict) else None
    old_http = old_http if isinstance(old_http, dict) else {}
    new_http = new_http if isinstance(new_http, dict) else {}

    if old_http != new_http:
        reasons.append(
            "server.http changed (admin webserver bind/auth requires restart)"
        )

    return reasons


def _effective_cfg_for_reload_only(
    old_cfg: Dict[str, Any], new_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """Brief: Compute an effective config that can be applied without restart.

    Inputs:
      - old_cfg: Current effective config.
      - new_cfg: Desired config.

    Outputs:
      - dict: Effective config mapping suitable for building a runtime snapshot.

    Behaviour:
      - Preserves old server.listen and old server.http while adopting all other
        values from new_cfg.

    Example:
      >>> eff = _effective_cfg_for_reload_only({'server': {'listen': {'udp': {}}}}, {'server': {'listen': {'udp': {'port': 53}}}})
      >>> isinstance(eff, dict)
      True
    """

    eff = copy.deepcopy(new_cfg)
    if not isinstance(eff, dict):  # pragma: no cover - defensive
        return dict(old_cfg or {})

    old_server = old_cfg.get("server") if isinstance(old_cfg, dict) else None
    old_server = old_server if isinstance(old_server, dict) else {}

    server = eff.get("server")
    if not isinstance(server, dict):  # pragma: no cover - defensive
        server = {}
        eff["server"] = server

    if "listen" in old_server:
        server["listen"] = copy.deepcopy(old_server.get("listen"))
    if "http" in old_server:
        server["http"] = copy.deepcopy(old_server.get("http"))

    return eff


def _apply_snapshot_to_runtime_globals(snapshot: RuntimeSnapshot) -> None:
    """Brief: Update shared runtime globals for the active snapshot.

    Inputs:
      - snapshot: Active runtime snapshot.

    Outputs:
      - None.

    Notes:
      - The shared resolver pipeline consults RuntimeSnapshot directly.
      - plugin_base.DNS_CACHE remains a global reference used by multiple
        plugins and resolver helpers.
    """

    try:
        from foghorn.plugins.resolve import base as plugin_base

        plugin_base.DNS_CACHE = snapshot.cache_plugin  # type: ignore[assignment]
    except Exception:
        return  # pragma: no cover - defensive: import/assign failures are unlikely


def _default_snapshot() -> RuntimeSnapshot:
    """Brief: Construct a conservative default runtime snapshot.

    Inputs: none

    Outputs:
      - RuntimeSnapshot with safe defaults suitable for unit tests.

    Notes:
      - This does not consult any listener implementation details.
      - cache_plugin defaults to the current plugin_base.DNS_CACHE when available.
    """

    try:
        from foghorn.plugins.resolve import base as plugin_base

        cache_plugin = getattr(plugin_base, "DNS_CACHE", None)
    except Exception:
        cache_plugin = None  # pragma: no cover - defensive: import failures unlikely

    return RuntimeSnapshot(
        cfg={},
        plugins=[],
        upstream_addrs=[],
        upstream_backup_addrs=[],
        upstream_health=parse_upstream_health_config({}),
        timeout_ms=2000,
        upstream_strategy="failover",
        upstream_max_concurrent=1,
        resolver_mode="forward",
        recursive_max_depth=16,
        recursive_timeout_ms=2000,
        recursive_per_try_timeout_ms=2000,
        dnssec_mode="ignore",
        dnssec_validation="upstream_ad",
        edns_udp_payload=1232,
        enable_ede=False,
        forward_local=False,
        min_cache_ttl=0,
        cache_prefetch_enabled=False,
        cache_prefetch_min_ttl=0,
        cache_prefetch_max_ttl=0,
        cache_prefetch_refresh_before_expiry=0.0,
        cache_prefetch_allow_stale_after_expiry=0.0,
        stats_collector=None,
        cache_plugin=cache_plugin,
        udp_max_response_bytes=None,
        axfr_enabled=False,
        axfr_allow_clients=[],
        axfr_max_zone_rrs=None,
        axfr_max_concurrent_transfers=4,
        axfr_rate_limit_per_client_per_second=0.0,
        axfr_rate_limit_burst=2.0,
        axfr_max_transfer_rate_bytes_per_second=None,
        axfr_message_max_bytes=64000,
        axfr_require_tsig=False,
        axfr_tsig_keys=[],
        generation=0,
        applied_at_epoch=time.time(),
    )
