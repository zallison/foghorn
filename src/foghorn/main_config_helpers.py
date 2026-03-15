from __future__ import annotations

import argparse
import ipaddress
import logging
import re

from foghorn.utils.register_caches import apply_decorated_cache_overrides

from .config.config_parser import (
    normalize_upstream_backup_config,
    normalize_upstream_config,
)
from .servers.runtime_state import RuntimeState


def _build_main_arg_parser() -> argparse.ArgumentParser:
    """Brief: Build the CLI parser used by main().

    Inputs:
      - None.

    Outputs:
      - argparse.ArgumentParser: Parser configured with all supported flags.
    """

    parser = argparse.ArgumentParser(description="Caching DNS server with plugins")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    parser.add_argument(
        "-v",
        "--var",
        action="append",
        default=[],
        help=(
            "Set a configuration variable (KEY=YAML). May be provided multiple times; "
            "CLI overrides environment overrides config file variables."
        ),
    )
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help=(
            "Rebuild statistics counts from the persistent query_log on startup "
            "(overrides existing counts when present)."
        ),
    )
    parser.add_argument(
        "--config-extras",
        dest="config_extras",
        choices=["ignore", "warn", "error"],
        default="warn",
        help=(
            "Policy for unknown config keys not described by the JSON Schema: "
            "ignore (keep current behaviour), warn (default), or error."
        ),
    )
    parser.add_argument(
        "--skip-schema-validation",
        dest="skip_schema_validation",
        action="store_true",
        help=(
            "Skip JSON Schema validation of the configuration. This is unsafe and "
            "should only be used for debugging or in environments where the schema "
            "file cannot be shipped."
        ),
    )
    return parser


def _extract_server_and_logging_cfg(
    cfg: dict,
) -> tuple[dict, dict, dict]:
    """Brief: Extract validated server/logging config blocks.

    Inputs:
      - cfg: Parsed root configuration mapping.

    Outputs:
      - tuple[dict, dict, dict]: (server_cfg, logging_cfg, python_logging_cfg).
    """

    server_cfg = cfg.get("server") or {}
    if not isinstance(server_cfg, dict):
        raise ValueError("config.server must be a mapping when present")

    logging_cfg = cfg.get("logging") or {}
    if not isinstance(logging_cfg, dict):
        raise ValueError("config.logging must be a mapping when present")

    # New layout: Python logging configuration lives under logging.python.
    # Only this shape is supported; legacy root-level logging keys are no
    # longer interpreted.
    python_logging_cfg = logging_cfg.get("python") or {}
    if not isinstance(python_logging_cfg, dict):
        python_logging_cfg = {}

    return server_cfg, logging_cfg, python_logging_cfg


def _apply_cache_overrides_from_config(
    *,
    logger: logging.Logger,
    server_cfg: dict,
) -> None:
    """Brief: Apply decorated cache overrides from config, best effort.

    Inputs:
      - logger: Logger for debug output on failure.
      - server_cfg: Parsed server config mapping.

    Outputs:
      - None.
    """

    try:
        cache_block = server_cfg.get("cache") if isinstance(server_cfg, dict) else None
        raw_overrides = []
        if isinstance(cache_block, dict):
            # Preferred key: server.cache.func_caches (list of DecoratedCacheOverride).
            candidate = cache_block.get("func_caches")
            used_key = "func_caches"

            # Backwards-compatible fallbacks for older configs/tests.
            if not isinstance(candidate, list):
                candidate = cache_block.get("modify")
                used_key = "modify"
            if not isinstance(candidate, list):
                candidate = cache_block.get("decorated_overrides")
                used_key = "decorated_overrides"

            if used_key != "func_caches" and isinstance(candidate, list):
                logger.warning(
                    "server.cache.%s is deprecated; use server.cache.func_caches",
                    used_key,
                )

            if isinstance(candidate, list):
                raw_overrides = [o for o in candidate if isinstance(o, dict)]
        apply_decorated_cache_overrides(raw_overrides)
    except (
        Exception
    ):  # pragma: no cover - defensive: cache override failures must not block startup
        logger.debug(
            "Failed to apply decorated cache overrides from config", exc_info=True
        )


def _merge_listen_subsection(
    *,
    listen_cfg: dict,
    key: str,
    defaults: dict,
) -> dict:
    """Brief: Merge a listen subsection over defaults when present.

    Inputs:
      - listen_cfg: Parsed server.listen mapping.
      - key: Subsection key (e.g., udp/tcp/dot/doh).
      - defaults: Default values for this listener section.

    Outputs:
      - dict: Merged subsection.
    """

    section = listen_cfg.get(key, {}) or {}
    out = {**defaults, **section} if isinstance(section, dict) else defaults
    return out


def _build_listener_configs(
    *,
    server_cfg: dict,
) -> tuple[dict, dict, dict, dict, dict, str, int]:
    """Brief: Normalize listener config with defaults.

    Inputs:
      - server_cfg: Parsed server config mapping.

    Outputs:
      - tuple: (listen_cfg, udp_cfg, tcp_cfg, dot_cfg, doh_cfg, default_host, default_port).
    """

    # Normalize listen configuration.
    listen_cfg = server_cfg.get("listen") or {}
    if not isinstance(listen_cfg, dict):
        listen_cfg = {}

    dns_cfg = listen_cfg.get("dns")
    if not isinstance(dns_cfg, dict):
        dns_cfg = {}

    # Listener defaults are sourced from listen.dns when present; otherwise
    # they fall back to hard-coded defaults.
    raw_host = dns_cfg.get("host", "127.0.0.1")
    raw_port = dns_cfg.get("port", 5335)

    default_host = str(raw_host).strip()
    if not default_host:
        raise ValueError("config.server.listen.dns.host must be a non-empty string")

    # Best-effort validation: accept IP literals or plausible hostnames.
    try:
        ipaddress.ip_address(default_host)
    except Exception:
        hostname_re = re.compile(
            r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$"
        )
        if hostname_re.match(default_host) is None:
            raise ValueError(
                f"config.server.listen.dns.host must be a valid IP or hostname, got: {default_host!r}"
            )

    try:
        default_port = int(raw_port)
    except (TypeError, ValueError):
        default_port = 5335

    udp_section = listen_cfg.get("udp")
    if isinstance(udp_section, dict):
        udp_default_enabled = bool(udp_section.get("enabled", True))
    else:
        udp_default_enabled = True

    udp_cfg = _merge_listen_subsection(
        listen_cfg=listen_cfg,
        key="udp",
        defaults={
            "enabled": udp_default_enabled,
            "host": default_host,
            "port": default_port or 5335,
        },
    )

    tcp_section = listen_cfg.get("tcp")
    if isinstance(tcp_section, dict):
        tcp_default_enabled = bool(tcp_section.get("enabled", True))
    else:
        tcp_default_enabled = False

    tcp_cfg = _merge_listen_subsection(
        listen_cfg=listen_cfg,
        key="tcp",
        defaults={
            "enabled": tcp_default_enabled,
            "host": default_host,
            "port": default_port or 5335,
        },
    )

    dot_section = listen_cfg.get("dot")
    if isinstance(dot_section, dict):
        dot_default_enabled = bool(dot_section.get("enabled", True))
    else:
        dot_default_enabled = False
    dot_cfg = _merge_listen_subsection(
        listen_cfg=listen_cfg,
        key="dot",
        defaults={"enabled": dot_default_enabled, "host": default_host, "port": 853},
    )

    doh_section = listen_cfg.get("doh")
    if isinstance(doh_section, dict):
        doh_default_enabled = bool(doh_section.get("enabled", True))
    else:
        doh_default_enabled = False
    doh_cfg = _merge_listen_subsection(
        listen_cfg=listen_cfg,
        key="doh",
        defaults={"enabled": doh_default_enabled, "host": default_host, "port": 1443},
    )

    return listen_cfg, udp_cfg, tcp_cfg, dot_cfg, doh_cfg, default_host, default_port


def _seed_listener_runtime_state(
    *,
    runtime_state: RuntimeState,
    udp_cfg: dict,
    tcp_cfg: dict,
    dot_cfg: dict,
    doh_cfg: dict,
) -> None:
    """Brief: Seed runtime readiness state for DNS listeners.

    Inputs:
      - runtime_state: Shared runtime readiness state.
      - udp_cfg: UDP listener config.
      - tcp_cfg: TCP listener config.
      - dot_cfg: DoT listener config.
      - doh_cfg: DoH listener config.

    Outputs:
      - None.
    """

    runtime_state.set_listener(
        "udp", enabled=bool(udp_cfg.get("enabled", True)), thread=None
    )
    runtime_state.set_listener(
        "tcp", enabled=bool(tcp_cfg.get("enabled", False)), thread=None
    )
    runtime_state.set_listener(
        "dot", enabled=bool(dot_cfg.get("enabled", False)), thread=None
    )
    runtime_state.set_listener(
        "doh", enabled=bool(doh_cfg.get("enabled", False)), thread=None
    )


def _parse_resolver_cfg(
    *,
    cfg: dict,
    server_cfg: dict,
    logger: logging.Logger,
) -> tuple[dict, str, int, int, int]:
    """Brief: Normalize resolver mode and timeout/depth settings.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - server_cfg: Parsed server config mapping.
      - logger: Logger for warnings on deprecated/unsafe values.

    Outputs:
      - tuple: (resolver_cfg, resolver_mode, recursive_max_depth, recursive_timeout_ms, recursive_per_try_timeout_ms).

    Notes:
      - resolver.mode: "none" is treated as the legacy alias for "master" and will log a warning.
      - resolver.max_depth is capped to a safe maximum.
    """

    # Resolver configuration (forward vs recursive) with conservative defaults.
    resolver_cfg = server_cfg.get("resolver") or cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        raise ValueError("config.server.resolver must be a mapping when present")

    resolver_mode = str(resolver_cfg.get("mode", "forward")).lower().strip()
    if resolver_mode == "none":
        logger.warning('resolver.mode "none" is deprecated; use "master"')
        resolver_mode = "master"

    allowed_modes = {"forward", "recursive", "master"}
    if resolver_mode not in allowed_modes:
        raise ValueError(
            f"config.server.resolver.mode must be one of {sorted(allowed_modes)}, got: {resolver_mode!r}"
        )

    try:
        recursive_max_depth = int(resolver_cfg.get("max_depth", 12))
    except (TypeError, ValueError):
        recursive_max_depth = 12

    if recursive_max_depth < 1:
        logger.warning(
            "resolver.max_depth must be >= 1; clamping %s -> 1",
            recursive_max_depth,
        )
        recursive_max_depth = 1

    max_safe_depth = 32
    if recursive_max_depth > max_safe_depth:
        logger.warning(
            "resolver.max_depth too high; clamping %s -> %s",
            recursive_max_depth,
            max_safe_depth,
        )
        recursive_max_depth = max_safe_depth
    try:
        recursive_timeout_ms = int(resolver_cfg.get("timeout_ms", 2000))
    except (TypeError, ValueError):
        recursive_timeout_ms = 2000
    try:
        recursive_per_try_timeout_ms = int(
            resolver_cfg.get("per_try_timeout_ms", recursive_timeout_ms)
        )
    except (TypeError, ValueError):
        recursive_per_try_timeout_ms = recursive_timeout_ms

    return (
        resolver_cfg,
        resolver_mode,
        recursive_max_depth,
        recursive_timeout_ms,
        recursive_per_try_timeout_ms,
    )


def _normalize_upstreams_for_mode(
    *,
    cfg: dict,
    resolver_mode: str,
    recursive_timeout_ms: int,
    logger: logging.Logger,
) -> tuple[list, list, int]:
    """Brief: Normalize upstream and timeout settings by resolver mode.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - resolver_mode: Effective resolver mode.
      - recursive_timeout_ms: Recursive timeout fallback.
      - logger: Logger for warnings on malformed backup upstream config.

    Outputs:
      - tuple[list, list, int]: (upstreams, upstream_backups, timeout_ms).
    """

    # Normalize upstream configuration only in forwarder mode.
    if resolver_mode == "forward":
        upstreams, timeout_ms = normalize_upstream_config(cfg)
        try:
            upstream_backups = normalize_upstream_backup_config(cfg)
        except Exception as exc:
            logger.warning(
                "Failed to parse upstream backup config, backups disabled: %s",
                exc,
            )
            upstream_backups = []
    else:
        upstreams = []
        upstream_backups = []
        timeout_ms = recursive_timeout_ms

    return upstreams, upstream_backups, timeout_ms


def _configure_resolver_executor(
    *,
    limits_cfg: dict,
    logger: logging.Logger,
) -> None:
    """Brief: Configure shared resolver ThreadPoolExecutor from limits config.

    Inputs:
      - limits_cfg: server.limits mapping.
      - logger: Logger for best-effort failure diagnostics.

    Outputs:
      - None.
    """

    try:
        from .servers.executors import configure_resolver_executor

        raw_workers = limits_cfg.get("resolver_executor_workers")
        try:
            resolver_workers = int(raw_workers) if raw_workers is not None else None
        except Exception:
            resolver_workers = None

        configure_resolver_executor(max_workers=resolver_workers)
    except Exception:
        logger.warning("Failed to configure resolver executor", exc_info=True)


def _load_cache_plugin_from_cfg(
    *,
    cfg: dict,
    server_cfg: dict,
    logger: logging.Logger,
) -> object | None:
    """Brief: Load configured cache plugin using v2 and legacy config fallbacks.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - server_cfg: Parsed server config mapping.
      - logger: Logger for warning output on failure.

    Outputs:
      - object | None: Cache plugin instance or None on failure.
    """
    # Cache plugin selection.
    #
    # Brief:
    #   Cache is configured at the top-level `cache:` block so operators can
    #   swap implementations without changing the resolver pipeline.
    #
    # Inputs:
    #   - server.cache: null | mapping (preferred, v2 layout)
    #   - cfg['cache']: null | str | mapping (legacy root-level fallback)
    #
    # Outputs:
    #   - cache_plugin: CachePlugin instance
    try:
        from foghorn.plugins.cache.registry import load_cache_plugin

        cache_cfg = None
        if isinstance(server_cfg, dict):
            cache_cfg = server_cfg.get("cache")
        if cache_cfg is None:
            cache_cfg = cfg.get("cache")
        cache_plugin = load_cache_plugin(cache_cfg)
    except Exception as exc:
        logger.warning("Failed to load cache plugin, running without cache: %s", exc)
        cache_plugin = None
    return cache_plugin


def _install_cache_plugin_global(
    *,
    cache_plugin: object | None,
    logger: logging.Logger,
) -> None:
    """Brief: Install cache plugin into global resolver cache slot, best effort.

    Inputs:
      - cache_plugin: Cache plugin instance or None.
      - logger: Logger for warning output on failure.

    Outputs:
      - None.
    """

    # Install the configured cache plugin globally so all transports (UDP/TCP/DoT/DoH)
    # share it, even when the UDP DNSServer is not started.
    if cache_plugin is not None:
        try:
            from foghorn.plugins.resolve import base as plugin_base

            plugin_base.DNS_CACHE = cache_plugin  # type: ignore[assignment]
        except Exception as exc:
            logger.warning("Failed to install cache plugin globally: %s", exc)


def _get_min_cache_ttl(cache_plugin: object | None) -> int:
    """Brief: Read non-negative cache TTL floor from plugin.

    Inputs:
      - cache_plugin: Cache plugin instance or None.

    Outputs:
      - int: Non-negative min_cache_ttl value.
    """

    # Cache TTL floor (applied to cache expiry, not the on-wire DNS TTL) is now
    # configured via the cache plugin.
    min_cache_ttl = 0
    if cache_plugin is not None:
        try:
            min_cache_ttl = int(getattr(cache_plugin, "min_cache_ttl", 0) or 0)
        except Exception:
            min_cache_ttl = 0
    min_cache_ttl = max(0, min_cache_ttl)
    return min_cache_ttl


def _resolve_web_config(
    *,
    cfg: dict,
    server_cfg: dict,
) -> tuple[dict, bool]:
    """Brief: Resolve admin webserver config and enabled flag.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - server_cfg: Parsed server config mapping.

    Outputs:
      - tuple[dict, bool]: (web_cfg, web_enabled).
    """

    # Preferred v2 location:
    #   server:
    #     http: {...}
    #
    # Legacy fallbacks (still accepted for existing configs/tests):
    #   - root-level http: {...}
    #   - root-level webserver: {...}
    server_http = None
    try:
        if isinstance(server_cfg, dict):
            server_http = server_cfg.get("http")
    except Exception:
        server_http = None

    if server_http is not None:
        web_cfg = server_http
    else:
        web_cfg = cfg.get("http") or cfg.get("webserver", {}) or {}
    if not isinstance(web_cfg, dict):
        web_cfg = {}
    # If a http block exists, default enabled to True unless explicitly disabled
    # with enabled: false. This mirrors the listener expectations and
    # start_webserver() behaviour.
    has_web_cfg = bool(web_cfg)
    raw_web_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    web_enabled = bool(raw_web_enabled) if raw_web_enabled is not None else has_web_cfg
    return web_cfg, web_enabled
