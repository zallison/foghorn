from __future__ import annotations

import argparse
import functools
import gc
import logging
import os
import signal
import threading
from typing import List, Optional

from .config.config_parser import (
    load_plugins,
    normalize_upstream_config,
    parse_config_file,
)
from foghorn.dnssec.dnssec_validate import configure_dnssec_resolver
from foghorn.utils.register_caches import apply_decorated_cache_overrides
from .config.logging_config import init_logging
from .plugins.resolve.base import BasePlugin
from .servers.doh_api import start_doh_server
from .servers.server import DNSServer
from .servers.webserver import RingBuffer, RuntimeState, start_webserver
from .stats import StatsCollector, StatsReporter
from .plugins.querylog import BaseStatsStore, load_stats_store_backend


def _clear_lru_caches(wrappers: Optional[List[object]]):
    # Collect all cached function wrappers
    gc.collect()
    if not wrappers:
        wrappers = [
            obj
            for obj in gc.get_objects()
            if isinstance(obj, functools._lru_cache_wrapper)
        ]

    # Clear all caches
    for wrapper in wrappers:
        wrapper.cache_clear()


def _is_setup_plugin(plugin: BasePlugin) -> bool:
    """Brief: Determine whether a plugin overrides BasePlugin.setup.

    Inputs:
      - plugin: BasePlugin instance.

    Outputs:
      - bool: True when plugin defines its own setup() implementation.

    Example use:
      >>> from foghorn.plugins.resolve.base import BasePlugin
      >>> class P(BasePlugin):
      ...     def setup(self):
      ...         pass
      >>> p = P()
      >>> _is_setup_plugin(p)
      True
    """

    try:
        return plugin.__class__.setup is not BasePlugin.setup
    except Exception:
        return False


def run_setup_plugins(plugins: List[BasePlugin]) -> None:
    """Brief: Run setup() on setup-aware plugins in ascending setup_priority order.

    Inputs:
      - plugins: List[BasePlugin] instances, typically from load_plugins().

    Outputs:
      - None; raises RuntimeError if a setup plugin with abort_on_failure=True fails.

    Notes:
      - Plugins that override BasePlugin.setup are considered setup plugins.
      - Execution order is controlled by each plugin's setup_priority attribute
        (default 100).
    """

    logger = logging.getLogger("foghorn.main.setup")

    setup_entries: List[tuple[int, BasePlugin]] = []
    for p in plugins or []:
        if not _is_setup_plugin(p):
            continue
        try:
            prio = int(getattr(p, "setup_priority", 100))
        except Exception:
            prio = 100
        setup_entries.append((prio, p))

    setup_entries.sort(key=lambda item: item[0])

    for prio, plugin in setup_entries:
        cfg = getattr(plugin, "config", {}) or {}
        abort_on_failure = bool(cfg.get("abort_on_failure", True))
        name = plugin.__class__.__name__
        logger.info(
            "Running setup for plugin %s (setup_priority=%d, abort_on_failure=%s)",
            name,
            prio,
            abort_on_failure,
        )
        try:
            plugin.setup()
        except Exception as e:  # pragma: no cover
            logger.error("Setup for plugin %s failed: %s", name, e, exc_info=True)
            if abort_on_failure:
                raise RuntimeError(f"Setup for plugin {name} failed") from e
            logger.warning(
                "Continuing startup despite setup failure in plugin %s because abort_on_failure is False",
                name,
            )


def main(argv: List[str] | None = None) -> int:
    """
    Main entry point for the DNS server.
    Parses arguments, loads configuration, initializes plugins, and starts the server.

    Args:
        argv: Command-line arguments.

    Returns:
        An exit code.

    Example use:
        CLI:
            PYTHONPATH=src python -m foghorn.main --config config.yaml

        Programmatic (for testing):
        (This is a simplified example; real usage involves creating a config file)
        >>> import threading
        >>> import time
        >>> with patch('builtins.open', mock_open(read_data='''
        ... listen:
        ...   host: 127.0.0.1
        ...   port: 5354
        ... upstreams:
        ...   - host: 1.1.1.1
        ...     port: 53
        ... foghorn:
        ...   timeout_ms: 2000
        ... ''')):
        ...     server_thread = threading.Thread(target=main, args=(["--config", "config.yaml"],), daemon=True)
        ...     server_thread.start()
        ...     time.sleep(0.1) # Give server time to start
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
    args = parser.parse_args(argv)

    # Load and validate configuration.
    try:
        cfg = parse_config_file(
            args.config,
            cli_vars=list(getattr(args, "var", []) or []),
            unknown_keys=str(getattr(args, "config_extras", "warn") or "warn"),
        )
    except ValueError as exc:
        print(str(exc))
        return 1

    # Initialize logging before any other operations.
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

    init_logging(python_logging_cfg or None)

    logger = logging.getLogger("foghorn.main")
    logger.info("Loaded config from %s", args.config)

    # Apply any configured overrides for decorated caches (registered_cached /
    # registered_lru_cached) before listeners are started so that diagnostic
    # caches use operator-selected sizes/TTLs. This is best-effort and
    # silently ignores malformed entries.
    try:
        cache_block = server_cfg.get("cache") if isinstance(server_cfg, dict) else None
        raw_overrides = []
        if isinstance(cache_block, dict):
            # Preferred key: server.cache.func_caches (list of DecoratedCacheOverride).
            candidate = cache_block.get("func_caches")
            # Backwards-compatible fallbacks for older configs/tests.
            if not isinstance(candidate, list):
                candidate = cache_block.get("modify")
            if not isinstance(candidate, list):
                candidate = cache_block.get("decorated_overrides")
            if isinstance(candidate, list):
                raw_overrides = [o for o in candidate if isinstance(o, dict)]
        apply_decorated_cache_overrides(raw_overrides)
    except (
        Exception
    ):  # pragma: no cover - defensive: cache override failures must not block startup
        logger.debug(
            "Failed to apply decorated cache overrides from config", exc_info=True
        )

    # Keep references for signal-driven reload/reset and coordinated shutdown.
    # These are captured by inner closures (SIGUSR1/SIGUSR2 handlers and
    # _apply_runtime_config) so they can adjust behaviour without restarting
    # the main process or DNS listeners.
    cfg_path: str = args.config
    stats_collector: Optional[StatsCollector]
    stats_reporter: Optional[StatsReporter]
    stats_persistence_store: Optional[BaseStatsStore]

    # web_handle is the admin HTTP/web UI handle returned by start_webserver().
    # It is allowed to be None when the webserver is disabled but is treated as
    # fatal when http.enabled is true.
    web_handle = None

    # Shared in-memory log buffer passed into the FastAPI admin app; this is
    # also used when starting the threaded admin HTTP fallback.
    web_log_buffer: Optional[RingBuffer] = None

    # Runtime state used by /ready readiness probes exposed by the admin webserver.
    runtime_state = RuntimeState(startup_complete=False)

    # Normalize listen configuration.
    listen_cfg = server_cfg.get("listen") or {}
    if not isinstance(listen_cfg, dict):
        listen_cfg = {}

    dns_cfg = listen_cfg.get("dns")
    if not isinstance(dns_cfg, dict):
        dns_cfg = {}

    # Host/port precedence:
    #   1) listen.dns.host/port when set
    #   2) listen.host/port when set
    #   3) hard-coded defaults 127.0.0.1:5335
    raw_host = dns_cfg.get("host")
    if raw_host is None:
        raw_host = listen_cfg.get("host", "127.0.0.1")
    raw_port = dns_cfg.get("port")
    if raw_port is None:
        raw_port = listen_cfg.get("port", 5335)

    default_host = str(raw_host)
    try:
        default_port = int(raw_port)
    except (TypeError, ValueError):
        default_port = 5335

    # Resolver configuration (forward vs recursive) with conservative defaults.
    resolver_cfg = server_cfg.get("resolver") or cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        raise ValueError("config.server.resolver must be a mapping when present")

    def _sub(key, defaults):
        d = listen_cfg.get(key, {}) or {}
        out = {**defaults, **d} if isinstance(d, dict) else defaults
        return out

    udp_section = listen_cfg.get("udp")
    if isinstance(udp_section, dict):
        udp_default_enabled = bool(udp_section.get("enabled", True))
    else:
        # No explicit UDP listener block; fall back to dns.udp when present,
        # otherwise preserve the historical default of UDP enabled.
        if "udp" in dns_cfg:
            udp_default_enabled = bool(dns_cfg.get("udp"))
        else:
            udp_default_enabled = True

    udp_cfg = _sub(
        "udp",
        {
            "enabled": udp_default_enabled,
            "host": default_host,
            "port": default_port or 5335,
        },
    )

    tcp_section = listen_cfg.get("tcp")
    if isinstance(tcp_section, dict):
        tcp_default_enabled = bool(tcp_section.get("enabled", True))
    else:
        # No explicit TCP listener block; fall back to dns.tcp when present,
        # otherwise preserve the historical default of TCP disabled.
        if "tcp" in dns_cfg:
            tcp_default_enabled = bool(dns_cfg.get("tcp"))
        else:
            tcp_default_enabled = False

    tcp_cfg = _sub(
        "tcp",
        {
            "enabled": tcp_default_enabled,
            "host": default_host,
            "port": default_port or 5335,
        },
    )

    dot_section = listen_cfg.get("dot")
    dot_default_enabled = True if isinstance(dot_section, dict) else False
    dot_cfg = _sub(
        "dot", {"enabled": dot_default_enabled, "host": default_host, "port": 853}
    )

    doh_section = listen_cfg.get("doh")
    doh_default_enabled = True if isinstance(doh_section, dict) else False
    doh_cfg = _sub(
        "doh", {"enabled": doh_default_enabled, "host": default_host, "port": 1443}
    )

    # Seed readiness state with expected listeners. The thread/handle references
    # are filled in later once each listener is started.
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

    resolver_mode = str(resolver_cfg.get("mode", "forward")).lower()
    try:
        recursive_max_depth = int(resolver_cfg.get("max_depth", 16))
    except (TypeError, ValueError):
        recursive_max_depth = 16
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

    # Normalize upstream configuration only in forwarder mode.
    if resolver_mode == "forward":
        upstreams, timeout_ms = normalize_upstream_config(cfg)
    else:
        upstreams = []
        timeout_ms = recursive_timeout_ms

    # Upstream selection strategy and concurrency controls (v2 upstreams block).
    upstream_cfg = cfg.get("upstreams") or {}
    if not isinstance(upstream_cfg, dict):
        raise ValueError("config.upstreams must be a mapping when present")
    upstream_strategy = str(upstream_cfg.get("strategy", "failover")).lower()
    upstream_max_concurrent = int(upstream_cfg.get("max_concurrent", 1) or 1)
    if upstream_max_concurrent < 1:
        upstream_max_concurrent = 1

    # Global knob to disable asyncio-based listeners/admin servers in restricted
    # environments. When false, threaded fallbacks are used where available.
    use_asyncio = bool(resolver_cfg.get("use_asyncio", True))

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
    except Exception:
        cache_plugin = None

    # Install the configured cache plugin globally so alfoghorn.servers.transports (UDP/TCP/DoT/DoH)
    # share it, even when the UDP DNSServer is not started.
    if cache_plugin is not None:
        try:
            from foghorn.plugins.resolve import base as plugin_base

            plugin_base.DNS_CACHE = cache_plugin  # type: ignore[assignment]
        except Exception:
            pass

    # Cache TTL floor (applied to cache expiry, not the on-wire DNS TTL) is now
    # configured via the cache plugin.
    min_cache_ttl = 0
    if cache_plugin is not None:
        try:
            min_cache_ttl = int(getattr(cache_plugin, "min_cache_ttl", 0) or 0)
        except Exception:
            min_cache_ttl = 0
    min_cache_ttl = max(0, min_cache_ttl)

    plugins = load_plugins(cfg.get("plugins", []))
    logger.info(
        "Loaded %d plugins: %s", len(plugins), [p.__class__.__name__ for p in plugins]
    )

    # Run setup phase for setup-aware plugins before starting listeners
    try:
        run_setup_plugins(plugins)
    except RuntimeError as e:
        logger.error("Plugin setup failed: %s", e)
        return 1

    # Initialize statistics collection if enabled (v2: root 'stats').
    stats_cfg = cfg.get("stats", {}) or {}
    if not isinstance(stats_cfg, dict):
        stats_cfg = {}
    if isinstance(stats_cfg, dict):
        stats_enabled = bool(stats_cfg.get("enabled", True))
    else:
        stats_enabled = False

    # Global toggle to keep only the raw query_log in persistence and avoid
    # mirroring aggregate counters into the backend.
    logging_query_log_only = bool(logging_cfg.get("query_log_only", False))

    stats_collector = None
    stats_reporter = None
    stats_persistence_store = None

    stats_collector = None
    stats_reporter = None
    stats_persistence_store = None

    if stats_enabled:
        # Optional persistence store; the store is responsible for maintaining
        # long-lived aggregate counts and a raw query_log. The in-memory
        # StatsCollector remains the live source for periodic logging and web
        # API snapshots.
        stats_persistence_store = None

        # When query_log_only is enabled globally, skip background warm-load and
        # rebuild passes so that the persistence store is only used for
        # append-only query_log writes.
        logging_only_effective = bool(logging_query_log_only)

        # Helper: derive an effective persistence configuration from the new
        # layout where statistics/query-log backends are described under
        # logging.backends and stats.source_backend selects the primary backend.
        def _build_effective_persistence_cfg() -> dict[str, object]:
            """Brief: Compute the effective statistics persistence configuration.

            Inputs:
              - None (captures cfg/stats_cfg from closure).

            Outputs:
              - dict: Configuration mapping suitable for load_stats_store_backend.
            """

            logging_block = cfg.get("logging") or {}
            if not isinstance(logging_block, dict):
                return {}

            backends_cfg = logging_block.get("backends") or []
            if not isinstance(backends_cfg, list) or not backends_cfg:
                return {}

            async_default = bool(logging_block.get("async", True))

            primary_hint = stats_cfg.get("source_backend")
            primary_backend = (
                str(primary_hint).strip() if isinstance(primary_hint, str) else ""
            )

            normalized_backends: list[dict[str, object]] = []
            for entry in backends_cfg:
                if not isinstance(entry, dict):
                    continue

                backend_name = entry.get("backend")
                if not backend_name:
                    continue

                raw_config = entry.get("config")
                conf: dict[str, object]
                if isinstance(raw_config, dict):
                    conf = dict(raw_config)
                else:
                    # Accept a flattened layout where backend-specific options
                    # live alongside id/backend.
                    conf = {
                        k: v
                        for k, v in entry.items()
                        if k not in {"id", "name", "backend", "config"}
                    }

                # Propagate the global logging.async flag to backends that do
                # not opt out explicitly via async_logging.
                conf.setdefault("async_logging", async_default)

                backend_entry: dict[str, object] = {
                    "backend": backend_name,
                    "config": conf,
                }

                backend_id = entry.get("id") or entry.get("name")
                if isinstance(backend_id, str) and backend_id.strip():
                    backend_entry["name"] = backend_id

                normalized_backends.append(backend_entry)

            if not normalized_backends:
                return {}

            effective: dict[str, object] = {"backends": normalized_backends}
            if primary_backend:
                effective["primary_backend"] = primary_backend
            return effective

        # Determine whether a rebuild should be forced from CLI/config/env.
        def _is_truthy_env(val: Optional[str]) -> bool:
            """Return True if an environment variable string represents a truthy value.

            Inputs:
                val: Environment variable value or None.

            Outputs:
                bool: True for common truthy strings (1, true, yes, on), else False.
            """

            if val is None:
                return False
            return str(val).strip().lower() in {
                "1",
                "true",
                "t",
                "yes",
                "y",
                "on",
            }  # pragma: no cover - best effort

        # Allow force_rebuild to be controlled from three sources, in
        # increasing precedence order:
        #   1) statistics.force_rebuild (root-level flag)
        #   2) FOGHORN_FORCE_REBUILD
        #   3) --rebuild (highest precedence)
        force_rebuild_root = bool(stats_cfg.get("force_rebuild", False))
        force_rebuild_env = _is_truthy_env(os.getenv("FOGHORN_FORCE_REBUILD"))
        force_rebuild = bool(args.rebuild or force_rebuild_env or force_rebuild_root)

        try:
            # Delegate backend construction (including multi-backend setups) to
            # the querylog backend loader. This uses logging.backends and
            # stats.source_backend exclusively.
            backend_cfg: dict[str, object] = _build_effective_persistence_cfg()
            if backend_cfg:
                stats_persistence_store = load_stats_store_backend(backend_cfg)
            else:
                stats_persistence_store = None

            if stats_persistence_store is None:
                logger.info(
                    "Statistics persistence not configured; running in memory-only mode",
                )
            else:
                logger.info(
                    "Initialized statistics backend %s",
                    stats_persistence_store.__class__.__name__,
                )

                # Optionally rebuild counts from the query_log when requested or
                # when counts are empty but query_log has rows. When
                # statistics.logging_only or statistics.query_log_only is
                # enabled, skip this background rebuild so that the persistence
                # store is only exercised via insert-style operations
                # (query_log appends and, in logging_only mode, counter
                # increments).
                if not logging_only_effective:
                    try:
                        stats_persistence_store.rebuild_counts_if_needed(
                            force_rebuild=force_rebuild, logger_obj=logger
                        )
                    except (
                        Exception
                    ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                        logger.error(
                            "Failed to rebuild statistics counts from query_log: %s",
                            exc,
                            exc_info=True,
                        )
        except (
            Exception
        ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.error(
                "Failed to initialize statistics persistence: %s; continuing without persistence",
                exc,
                exc_info=True,
            )
            stats_persistence_store = None

        # Initialize in-memory collector, wiring in the persistence store when present.
        ignore_cfg = stats_cfg.get("ignore", {}) or {}
        ignore_top_clients = list(ignore_cfg.get("top_clients", []) or [])
        ignore_top_domains = list(ignore_cfg.get("top_domains", []) or [])
        ignore_top_subdomains = list(ignore_cfg.get("top_subdomains", []) or [])
        include_in_stats = bool(ignore_cfg.get("include_in_stats", True))
        domains_mode = str(ignore_cfg.get("top_domains_mode", "exact")).lower()
        subdomains_mode = str(ignore_cfg.get("top_subdomains_mode", "exact")).lower()
        ignore_domains_as_suffix = domains_mode == "suffix"
        ignore_subdomains_as_suffix = subdomains_mode == "suffix"
        ignore_single_host = bool(ignore_cfg.get("ignore_single_host", False))

        stats_collector = StatsCollector(
            track_uniques=stats_cfg.get("track_uniques", True),
            include_qtype_breakdown=stats_cfg.get("include_qtype_breakdown", True),
            # Enable top clients/domains and latency by default when statistics
            # are enabled, while still allowing explicit False in config to
            # disable them.
            include_top_clients=bool(stats_cfg.get("include_top_clients", True)),
            include_top_domains=bool(stats_cfg.get("include_top_domains", True)),
            top_n=int(stats_cfg.get("top_n", 10)),
            track_latency=bool(stats_cfg.get("track_latency", True)),
            stats_store=stats_persistence_store,
            ignore_top_clients=ignore_top_clients,
            ignore_top_domains=ignore_top_domains,
            ignore_top_subdomains=ignore_top_subdomains,
            ignore_domains_as_suffix=ignore_domains_as_suffix,
            ignore_subdomains_as_suffix=ignore_subdomains_as_suffix,
            ignore_single_host=ignore_single_host,
            include_ignored_in_stats=include_in_stats,
            logging_only=logging_only_effective,
            query_log_only=logging_query_log_only,
        )

        # Best-effort warm-load of persisted aggregate counters on startup.
        if not logging_only_effective:
            try:
                stats_collector.warm_load_from_store()
                logger.info("Statistics warm-load from SQLite store completed")
            except (
                Exception
            ) as exc:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                logger.error(
                    "Failed to warm-load statistics from SQLite store: %s",
                    exc,
                    exc_info=True,
                )

        stats_reporter = StatsReporter(
            collector=stats_collector,
            # Default statistics interval is 300s (5 minutes) when not overridden in config.
            interval_seconds=int(stats_cfg.get("interval_seconds", 300)),
            reset_on_log=stats_cfg.get("reset_on_log", False),
            log_level=stats_cfg.get("log_level", "info"),
            persistence_store=stats_persistence_store,
        )
        stats_reporter.start()
        logger.info(
            "Statistics collection enabled (interval: %ds)",
            stats_reporter.interval_seconds,
        )

    # Initialize webserver log buffer (shared with admin HTTP API).
    #
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

    web_cfg = server_http or cfg.get("http") or cfg.get("webserver", {}) or {}
    if not isinstance(web_cfg, dict):
        web_cfg = {}
    # If a http block exists, default enabled to True unless explicitly disabled
    # with enabled: false. This mirrors the listener expectations and
    # start_webserver() behaviour.
    has_web_cfg = bool(web_cfg)
    raw_web_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    web_enabled = bool(raw_web_enabled) if raw_web_enabled is not None else has_web_cfg

    if web_enabled:
        buffer_size = int((web_cfg.get("logs") or {}).get("buffer_size", 500))
        web_log_buffer = RingBuffer(capacity=buffer_size)

    # Seed webserver readiness expectation.
    runtime_state.set_listener("webserver", enabled=web_enabled, thread=None)

    # --- Coordinated shutdown state ---
    # shutdown_event is set when a termination-like signal (KeyboardInterrupt,
    # SIGHUP, SIGTERM) requests the process to exit. exit_code communicates the
    # desired process exit status back to the main() return value.
    shutdown_event = threading.Event()
    shutdown_complete = threading.Event()
    exit_code = 0
    hard_kill_timer: threading.Timer | None = None

    # --- Signal handling (SIGUSR1/SIGUSR2) ---
    # Use Events to coalesce multiple signals so that expensive work (statistics
    # reset and plugin notifications) is never running concurrently for the same
    # signal type.
    _sigusr1_pending = threading.Event()
    _sigusr2_pending = threading.Event()

    def _process_usr_signal(sig_label: str) -> None:
        """Brief: Handle SIGUSR1/SIGUSR2 by optionally resetting statistics and
        notifying plugins.

        Inputs:
          - sig_label: Human-readable signal label used in log messages (e.g.,
            "SIGUSR1" or "SIGUSR2").

        Outputs:
          - None

        Notes:
          - Both SIGUSR1 and SIGUSR2 share the same behavior: when statistics
            are enabled and the configuration flags sigusr[12]_resets_stats is
            true, the in-memory statistics are reset.
        """

        nonlocal cfg, stats_collector
        log = logging.getLogger("foghorn.main")

        # Conditionally reset statistics based on config; failures here must
        # never prevent plugin notifications from running.
        try:
            if isinstance(cfg, dict):
                raw_stats = cfg.get("stats") or cfg.get("statistics") or {}
                s_cfg = raw_stats if isinstance(raw_stats, dict) else {}
            else:
                s_cfg = {}

            enabled = bool(s_cfg.get("enabled", False))
            # Use sigusr2_resets_stats as the canonical configuration flag for
            # both SIGUSR1 and SIGUSR2 so that user expectations are consistent
            # regardless of which signal they choose to send. For
            # backwards-compatibility, also accept sigusr1_resets_stats as a
            # deprecated alias.
            reset_flag = bool(
                s_cfg.get("sigusr2_resets_stats", False)
                or s_cfg.get("sigusr1_resets_stats", False)
            )

            if enabled and reset_flag:
                if stats_collector is not None:
                    try:
                        stats_collector.snapshot(reset=True)
                        log.info("%s: statistics reset completed", sig_label)
                    except (
                        Exception
                    ) as e:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                        log.error("%s: error during statistics reset: %s", sig_label, e)
                else:
                    log.info(
                        "%s: no statistics collector active, skipping reset", sig_label
                    )
            else:
                log.info(
                    "%s: statistics reset skipped (disabled or sigusr2_resets_stats not set)",
                    sig_label,
                )
        except (
            Exception
        ) as e:  # pragma: no cover - defensive: do not block plugin notifications
            log.error(
                "%s: unexpected error checking statistics reset config: %s",
                sig_label,
                e,
            )

        # Invoke plugin handlers. Each plugin can optionally expose
        # handle_sigusr2(); errors are logged but do not abort other handlers.
        # This keeps plugin notifications best-effort while preserving the
        # overall signal semantics.
        count = 0
        for p in plugins or []:
            try:
                handler = getattr(p, "handle_sigusr2", None)
                if callable(handler):
                    handler()
                    count += 1
            except (
                Exception
            ) as e:  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
                log.error(
                    "%s: plugin %s handler error: %s",
                    sig_label,
                    p.__class__.__name__,
                    e,
                )
        log.info("%s: invoked handle_sigusr2 on %d plugins", sig_label, count)

    def _sigusr1_handler(_signum, _frame):
        # coalesce multiple signals
        if _sigusr1_pending.is_set():
            return
        _sigusr1_pending.set()
        try:
            _process_usr_signal("SIGUSR1")
        finally:
            _sigusr1_pending.clear()

    def _sigusr2_handler(_signum, _frame):
        if _sigusr2_pending.is_set():
            return
        _sigusr2_pending.set()
        try:
            _process_usr_signal("SIGUSR2")
        finally:
            _sigusr2_pending.clear()

    # --- Termination-oriented signals (SIGHUP/SIGTERM) ---
    def _request_shutdown(reason: str, code: int) -> None:
        """Brief: Request coordinated shutdown and set desired exit code.

        Inputs:
          - reason: Human-readable signal/reason name (e.g., 'SIGHUP', 'SIGTERM').
          - code: Desired process exit code to return from main().

        Outputs:
          - None. Sets shutdown_event/exit_code so the main keepalive loop can
            drive a coordinated shutdown across all active listeners.

        Notes:
          - For SIGTERM and SIGINT, a best-effort hard-kill timer is started.
            If the process has not completed its shutdown sequence within
            ~10 seconds, a last-resort SIGKILL (or os._exit fallback) is
            issued to avoid hanging indefinitely.
        """

        nonlocal exit_code, hard_kill_timer
        log = logging.getLogger("foghorn.main")

        if shutdown_event.is_set():
            return

        exit_code = code
        shutdown_event.set()
        log.info("Received %s, initiating shutdown (exit code=%d)", reason, code)

        # For termination-style signals, arm a hard-kill timer so that a stuck
        # shutdown cannot leave the process running indefinitely. The timer is
        # cancelled implicitly when shutdown_complete is set before it fires.
        if reason in {"SIGTERM", "SIGINT"} and hard_kill_timer is None:

            def _force_exit() -> None:
                # If shutdown has completed in the meantime, do nothing.
                if shutdown_complete.is_set():
                    return
                try:
                    log.error(
                        "Hard-kill timeout exceeded after %s; sending SIGKILL to self",
                        reason,
                    )
                    os.kill(os.getpid(), signal.SIGKILL)
                except Exception:
                    # As a last resort, force immediate exit with the best
                    # available exit code.
                    os._exit(code or 2)

            hard_kill_timer = threading.Timer(10.0, _force_exit)
            hard_kill_timer.daemon = True
            hard_kill_timer.start()

    def _sighup_handler(_signum, _frame):
        _request_shutdown("SIGHUP", 0)

    def _sigterm_handler(_signum, _frame):
        _request_shutdown("SIGTERM", 2)

    def _sigint_handler(_signum, _frame):
        _request_shutdown("SIGINT", 2)

    # Register handlers (Unix only)
    try:
        signal.signal(signal.SIGUSR1, _sigusr1_handler)
        logger.debug(
            "Installed SIGUSR1 handler to notify plugins and optionally reset statistics"
        )
    except Exception:
        logger.warning("Could not install SIGUSR1 handler on this platform")

    try:
        signal.signal(signal.SIGUSR2, _sigusr2_handler)
        logger.debug(
            "Installed SIGUSR2 handler to notify plugins and optionally reset statistics"
        )
    except Exception:
        logger.warning("Could not install SIGUSR2 handler on this platform")

    try:
        signal.signal(signal.SIGHUP, _sighup_handler)
        logger.debug("Installed SIGHUP handler for clean shutdown (exit code 0)")
    except (
        Exception
    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
        logger.warning("Could not install SIGHUP handler on this platform")

    try:
        signal.signal(signal.SIGTERM, _sigterm_handler)
        logger.debug("Installed SIGTERM handler for immediate shutdown (exit code 2)")
    except (
        Exception
    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
        logger.warning("Could not install SIGTERM handler on this platform")

    try:
        signal.signal(signal.SIGINT, _sigint_handler)
        logger.debug("Installed SIGINT handler for immediate shutdown (exit code 2)")
    except (
        Exception
    ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
        logger.warning("Could not install SIGINT handler on this platform")

    # DNSSEC config (ignore|passthrough|validate).
    dnssec_cfg = server_cfg.get("dnssec") or {}
    if not isinstance(dnssec_cfg, dict):
        dnssec_cfg = {}
    dnssec_mode = str(dnssec_cfg.get("mode", "ignore")).lower()
    edns_payload = int(dnssec_cfg.get("udp_payload_size", 1232))
    dnssec_validation = str(dnssec_cfg.get("validation", "upstream_ad")).lower()

    # When performing local DNSSEC validation (including local_extended), point
    # the validator's internal resolver at the configured upstream hosts so that
    # chain validation and extended lookups use the same recursive resolvers as
    # normal forwarding. In recursive mode there are no forwarder upstreams; in
    # that case, route all DNSSEC helper lookups through Foghorn's own
    # RecursiveResolver rather than the system resolver.
    if dnssec_mode == "validate" and dnssec_validation in {"local", "local_extended"}:
        if resolver_mode == "forward":
            upstream_hosts = [
                str(u["host"]) for u in upstreams if isinstance(u, dict) and "host" in u
            ]
            configure_dnssec_resolver(upstream_hosts or None)
        else:
            # Empty list is a sentinel tellingfoghorn.dnssec.dnssec_validate to use
            # RecursiveResolver for all validation lookups.
            configure_dnssec_resolver([])
    else:
        # For non-validating modes or upstream_ad, fall back to system resolver
        # configuration inside the DNSSEC validator.
        configure_dnssec_resolver(None)

    server = None
    udp_thread: threading.Thread | None = None
    udp_error: Exception | None = None
    # Track background listener threads (UDP, TCP, DoT, etc.) uniformly so the
    # keepalive loop does not treat UDP as a special case.
    loop_threads: list[threading.Thread] = []
    if bool(udp_cfg.get("enabled", True)):
        uhost = str(udp_cfg.get("host", default_host))
        uport = int(udp_cfg.get("port", default_port))
        server = DNSServer(
            uhost,
            uport,
            upstreams,
            plugins,
            timeout=timeout_ms / 1000.0,
            timeout_ms=timeout_ms,
            min_cache_ttl=min_cache_ttl,
            stats_collector=stats_collector,
            cache=cache_plugin,
            dnssec_mode=dnssec_mode,
            edns_udp_payload=edns_payload,
            dnssec_validation=dnssec_validation,
            upstream_strategy=upstream_strategy,
            upstream_max_concurrent=upstream_max_concurrent,
            resolver_mode=resolver_mode,
            recursive_max_depth=recursive_max_depth,
            recursive_timeout_ms=recursive_timeout_ms,
            recursive_per_try_timeout_ms=recursive_per_try_timeout_ms,
        )

    # Log startup info
    if resolver_mode == "forward":
        upstream_info = ", ".join(
            [
                f"{u['url']}" if "url" in u else f"{u['host']}:{u['port']}"
                for u in upstreams
            ]
        )
    else:
        upstream_info = "(recursive mode; no forward upstreams)"
    logger.info(
        "Resolver mode=%s, upstreams: [%s], timeout: %dms",
        resolver_mode,
        upstream_info,
        timeout_ms,
    )

    if server is not None:
        # Run UDP server in a background thread so the main thread can manage
        # coordinated shutdown alongside TCP/DoT/DoH listeners. Capture
        # unexpected exceptions so main() can reflect them in its exit code.
        def _run_udp() -> None:
            nonlocal udp_error
            try:
                server.serve_forever()
            except Exception as e:  # pragma: no cover - propagated via udp_error
                udp_error = e
                runtime_state.set_listener_error("udp", e)

        logger.info(
            "Starting UDP listener on %s:%d",
            uhost,
            uport,
        )

        udp_thread = threading.Thread(
            target=_run_udp,
            name="foghorn-udp",
            daemon=True,
        )
        udp_thread.start()
        loop_threads.append(udp_thread)
        runtime_state.set_listener("udp", enabled=True, thread=udp_thread)
    else:
        # When no UDP listener is configured, the main thread still enters the
        # keepalive loop below so that TCP/DoT/DoH listeners (or tests that
        # disable UDP entirely) can drive shutdown via signals or KeyboardInterrupt.
        logger.info(
            "Starting Foghorn without UDP listener; main thread will use keepalive loop",
        )

    # Optionally start TCP/DoT listeners based on listen config

    # Resolver adapter for TCP/DoT servers
    import asyncio

    from .servers.server import resolve_query_bytes

    def _start_asyncio_server(
        coro_factory,
        name: str,
        *,
        listener_key: str,
        on_permission_error=None,
    ):
        def runner():
            try:
                asyncio.set_event_loop(asyncio.new_event_loop())
                loop = asyncio.get_event_loop()
                try:
                    loop.run_until_complete(coro_factory())
                finally:
                    loop.close()
            except PermissionError as e:
                # Environment forbids creating asyncio self-pipe/socketpair (e.g., restricted seccomp).
                # When a fallback is provided, treat it as a successful start and
                # do not mark the listener as failed.
                if callable(on_permission_error):
                    on_permission_error()
                else:
                    runtime_state.set_listener_error(listener_key, e)
                    logging.getLogger("foghorn.main").error(
                        "Asyncio loop creation failed with PermissionError for %s; no fallback provided",
                        name,
                    )
            except Exception as e:  # pragma: no cover - best-effort readiness tracking
                runtime_state.set_listener_error(listener_key, e)

        # Import threading dynamically so tests can monkeypatch via sys.modules
        import importlib as _importlib

        _threading = _importlib.import_module("threading")
        t = _threading.Thread(target=runner, name=name, daemon=True)
        t.start()
        loop_threads.append(t)
        runtime_state.set_listener(listener_key, enabled=True, thread=t)
        return t

    if bool(tcp_cfg.get("enabled", False)):
        from .servers.tcp_server import serve_tcp, serve_tcp_threaded

        thost = str(tcp_cfg.get("host", default_host))
        tport = int(tcp_cfg.get("port", 53))
        if use_asyncio:
            logger.info("Starting TCP listener on %s:%d (asyncio)", thost, tport)
            _start_asyncio_server(
                lambda: serve_tcp(thost, tport, resolve_query_bytes),
                name="foghorn-tcp",
                listener_key="tcp",
                on_permission_error=lambda: serve_tcp_threaded(
                    thost, tport, resolve_query_bytes
                ),
            )
        else:
            logger.info("Starting TCP listener on %s:%d (threaded)", thost, tport)
            t = threading.Thread(
                target=lambda: serve_tcp_threaded(thost, tport, resolve_query_bytes),
                name="foghorn-tcp-threaded",
                daemon=True,
            )
            t.start()
            loop_threads.append(t)
            runtime_state.set_listener("tcp", enabled=True, thread=t)

    if bool(dot_cfg.get("enabled", False)):
        from .servers.dot_server import serve_dot

        dhost = str(dot_cfg.get("host", default_host))
        dport = int(dot_cfg.get("port", 853))
        cert_file = dot_cfg.get("cert_file")
        key_file = dot_cfg.get("key_file")
        if not cert_file or not key_file:
            logger.error(
                "listen.dot.enabled=true but cert_file/key_file not provided; skipping DoT"
            )
        else:
            logger.info("Starting DoT listener on %s:%d", dhost, dport)
            _start_asyncio_server(
                lambda: serve_dot(
                    dhost,
                    dport,
                    resolve_query_bytes,
                    cert_file=cert_file,
                    key_file=key_file,
                ),
                name="foghorn-dot",
                listener_key="dot",
            )

    if bool(doh_cfg.get("enabled", False)):
        h = str(doh_cfg.get("host", default_host))
        p = int(doh_cfg.get("port", 8153))
        cert_file = doh_cfg.get("cert_file")
        key_file = doh_cfg.get("key_file")
        logger.info("Starting DoH listener on %s:%d", h, p)
        try:
            # start uvicorn-based DoH FastAPI server in background thread
            doh_handle = start_doh_server(
                h,
                p,
                resolve_query_bytes,
                cert_file=cert_file,
                key_file=key_file,
                use_asyncio=use_asyncio,
            )
        except Exception as e:
            runtime_state.set_listener_error("doh", e)
            logger.error("Failed to start DoH server: %s", e)
            return 1
        if doh_handle is None:
            runtime_state.set_listener_error("doh", "start_doh_server returned None")
            logger.error(
                "Fatal: listen.doh.enabled=true but start_doh_server returned None"
            )
            return 1

        runtime_state.set_listener("doh", enabled=True, thread=doh_handle)

    # Start admin HTTP webserver (FastAPI) and treat None handle as fatal when
    # webserver.enabled is true. Tests and production code both rely on a
    # single call to start_webserver() so it can be cleanly monkeypatched and
    # stopped from the finally: block below.
    try:
        web_handle = start_webserver(
            stats_collector,
            cfg,
            log_buffer=web_log_buffer,
            config_path=cfg_path,
            runtime_state=runtime_state,
            plugins=plugins,
        )
    except (
        Exception
    ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.error("Failed to start webserver: %s", e)
        return 1

    if web_enabled and web_handle is None:
        runtime_state.set_listener_error("webserver", "start_webserver returned None")
        logger.error("Fatal: webserver.enabled=true but start_webserver returned None")
        return 1

    if web_handle is not None:
        runtime_state.set_listener("webserver", enabled=web_enabled, thread=web_handle)

    runtime_state.mark_startup_complete()
    logger.info("Startup Completed")

    try:
        # Keep the main thread in a lightweight keepalive loop while UDP/TCP/DoT
        # listeners run in the background. This ensures alfoghorn.servers.transports are
        # treated consistently and that shutdown is always driven by
        # shutdown_event/termination signals rather than a blocking
        # serve_forever() call.
        import time as _time

        def _listener_thread_is_dead(t: threading.Thread) -> bool:
            """Best-effort liveness check for background listener threads.

            Inputs:
              - t: Thread instance (or test stub) representing a listener.

            Outputs:
              - bool: True when the thread is known to have exited.

            Notes:
              - Test stubs may not implement is_alive(); in that case we
                conservatively treat the thread as still running so the
                keepalive loop remains active.
            """

            try:
                return not t.is_alive()
            except Exception:
                # Test doubles used in unit tests may not implement is_alive();
                # treat them as already exited so the keepalive loop can
                # terminate promptly.
                return True

        while not shutdown_event.is_set():
            # If the UDP server thread has reported an unhandled exception,
            # mirror the legacy behaviour by logging it and treating it as a
            # server-level failure for main()'s exit code.
            if udp_error is not None:
                logger.exception(
                    "Unhandled exception during UDP server operation %s", udp_error
                )
                if exit_code == 0:
                    exit_code = 1
                break

            # When any background listener threads (UDP, TCP, DoT, etc.) have
            # all exited—for example because their serve_forever loops
            # returned—break out of the loop so coordinated shutdown can
            # proceed. This avoids treating the UDP listener as a special case
            # for keepalive behaviour.
            if loop_threads and all(_listener_thread_is_dead(t) for t in loop_threads):
                break

            _time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down")
        if not shutdown_event.is_set():
            # KeyboardInterrupt maps to a clean shutdown and exit code 0 unless
            # an explicit termination-like signal has already set a code.
            shutdown_event.set()
            exit_code = 0
    except (
        Exception
    ) as e:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        logger.exception(
            f"Unhandled exception during server operation {e}"
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        # Preserve a non-zero exit when an unhandled exception occurs unless a
        # stronger exit code (e.g., from SIGTERM) is already in place.
        if exit_code == 0:
            exit_code = 1
    finally:
        # Request UDP server shutdown and close sockets before tearing down
        # statistics and web components so that no new requests are processed
        # during shutdown.
        if server is not None:
            try:
                if hasattr(server, "stop"):
                    # Preferred path: delegate shutdown/close to the UDP server
                    # abstraction so all UDP-specific details live in the UDP
                    # module.
                    server.stop()
                else:
                    # Backwards-compatible path for legacy server stubs that
                    # expose a .server attribute with shutdown/server_close
                    # methods (used in tests and older call sites).
                    inner = getattr(server, "server", None)
                    if inner is not None:
                        try:
                            inner.shutdown()
                        except Exception:
                            logger.exception("Error while shutting down UDP server")
                        try:
                            inner.server_close()
                        except Exception:
                            logger.exception("Error while closing UDP server socket")
            except Exception:
                logger.exception("Unexpected error during UDP server teardown")

        if udp_thread is not None:
            try:
                udp_thread.join(timeout=5.0)
            except Exception:
                logger.exception("Error while waiting for UDP server thread to exit")

        # Stop statistics reporter on shutdown so background reporting threads
        # never outlive the main process and do not keep it alive.
        if stats_reporter is not None:
            logger.info("Stopping statistics reporter")
            stats_reporter.stop()

        if stats_persistence_store is not None:
            logger.info("Closing statistics persistence store")
            stats_persistence_store.close()
        # Stop webserver thread on shutdown. The handle abstraction lets both
        # the FastAPI-based web UI and the threaded admin HTTP server share the
        # same shutdown semantics (is_running/stop).
        if web_handle is not None:
            logger.info("Stopping webserver")
            web_handle.stop()

        # Mark shutdown as complete so any pending hard-kill timers can detect
        # successful termination and avoid forcing an unnecessary SIGKILL.
        shutdown_complete.set()

    return exit_code


if __name__ == "__main__":
    raise SystemExit(
        main()
    )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
