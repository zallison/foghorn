from __future__ import annotations

import argparse
import functools
import gc
import logging
import os
import signal
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

import yaml

from .doh_api import start_doh_server
from .logging_config import init_logging
from .plugins.base import BasePlugin
from .plugins.registry import discover_plugins, get_plugin_class
from .server import DNSServer
from .stats import StatsCollector, StatsReporter, StatsSQLiteStore, format_snapshot_json
from .webserver import RingBuffer, start_webserver


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


def _get_min_cache_ttl(cfg: dict) -> int:
    """
    Extracts and sanitizes min_cache_ttl from config.

    Inputs:
      - cfg: dict loaded from YAML
    Outputs:
      - int: non-negative min_cache_ttl in seconds (default 60)

    Returns a sanitized min_cache_ttl value. Negative values are clamped to 0.
    """
    val = cfg.get("min_cache_ttl", 60)
    try:
        ival = int(val)
    except (TypeError, ValueError):
        ival = 60
    return max(0, ival)


def normalize_upstream_config(
    cfg: Dict[str, Any],
) -> Tuple[List[Dict[str, Union[str, int, dict]]], int]:
    """
    Brief: Normalize modern upstream configuration to a list-of-endpoints plus a timeout.

    Inputs:
      - cfg: dict containing parsed YAML. Supports only the modern form:
          - cfg['upstream'] as a list of upstream entries, each either:
              * DoH entry: {'transport': 'doh', 'url': str, ...}
              * host/port entry: {'host': str, 'port': int, ...}
          - cfg['timeout_ms'] at top level.

    Outputs:
      - (upstreams, timeout_ms):
          - upstreams: list[dict] with keys like {'host': str, 'port': int} or DoH metadata.
          - timeout_ms: int timeout in milliseconds applied per upstream attempt (default 2000).

    Legacy single-dict forms for cfg['upstream'] and upstream.timeout_ms are no longer supported.
    """
    upstream_raw = cfg.get("upstream")
    if not isinstance(upstream_raw, list):
        raise ValueError("config.upstream must be a list of upstream definitions")

    upstreams: List[Dict[str, Union[str, int, dict]]] = []
    for u in upstream_raw:
        if not isinstance(u, dict):
            raise ValueError("each upstream entry must be a mapping")

        # DoH entries using URL
        if str(u.get("transport", "")).lower() == "doh":
            logger = logging.getLogger("foghorn.main.setup")
            logger.warning("doh: {u}")
            rec: Dict[str, Union[str, int, dict]] = {
                "transport": "doh",
                "url": str(u["url"]),
            }
            if "method" in u:
                rec["method"] = str(u.get("method"))
            if "headers" in u and isinstance(u["headers"], dict):
                rec["headers"] = u["headers"]
            if "tls" in u and isinstance(u["tls"], dict):
                rec["tls"] = u["tls"]
            upstreams.append(rec)
            continue

        # Host/port-based upstream (udp/tcp/dot)
        if "host" not in u:
            raise ValueError("each upstream entry must include 'host'")
        rec2: Dict[str, Union[str, int, dict]] = {
            "host": str(u["host"]),
            "port": int(u.get("port", 53)),
        }
        if "transport" in u:
            rec2["transport"] = str(u.get("transport"))
        if "tls" in u and isinstance(u["tls"], dict):
            rec2["tls"] = u["tls"]
        if "pool" in u and isinstance(u["pool"], dict):
            rec2["pool"] = u["pool"]
        upstreams.append(rec2)

    timeout_ms = int(cfg.get("timeout_ms", 2000))
    return upstreams, timeout_ms


def load_plugins(plugin_specs: List[dict]) -> List[BasePlugin]:
    """
    Loads and initializes plugins from a list of plugin specifications.

    Supports either full dotted class paths or short aliases:
    - access_control | acl -> foghorn.plugins.access_control.AccessControlPlugin
    - new_domain_filter | new_domain -> foghorn.plugins.new_domain_filter.NewDomainFilterPlugin
    - upstream_router | router -> foghorn.plugins.upstream_router.UpstreamRouterPlugin

    Args:
        plugin_specs: A list where each item is either a dict with keys
                      {"module": <path-or-alias>, "config": {...}} or a string
                      alias/dotted path.

    Returns:
        A list of initialized plugin instances.

    Example use:
        >>> from foghorn.plugins.base import BasePlugin
        >>> class MyTestPlugin(BasePlugin):
        ...     pass
        >>> specs = [{"module": "__main__.MyTestPlugin"}]
        >>> plugins = load_plugins(specs)
        >>> isinstance(plugins[0], MyTestPlugin)
        True
        >>> # Using aliases
        >>> plugins = load_plugins(["acl", {"module": "router", "config": {}}])
    """
    alias_registry = discover_plugins()
    plugins: List[BasePlugin] = []
    for spec in plugin_specs or []:
        if isinstance(spec, str):
            module_path = spec
            config = {}
        else:
            module_path = spec.get("module")
            config = spec.get("config", {})
        if not module_path:
            continue

        plugin_cls = get_plugin_class(module_path, alias_registry)
        plugin = plugin_cls(**config)
        plugins.append(plugin)
    return plugins


def _is_setup_plugin(plugin: BasePlugin) -> bool:
    """
    Determine whether a plugin overrides BasePlugin.setup and should
    participate in the setup phase.

    Inputs:
      - plugin: BasePlugin instance.
    Outputs:
      - bool: True if the plugin defines its own setup() implementation.

    Example use:
      >>> from foghorn.plugins.base import BasePlugin
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
    """
    Run setup() on all setup-aware plugins in ascending setup_priority order.

    Inputs:
      - plugins: List[BasePlugin] instances, typically from load_plugins().
    Outputs:
      - None; raises RuntimeError if a setup plugin with abort_on_failure=True
        fails.

    Brief: This helper is invoked by main() after plugin instantiation but
    before listeners start. Plugins that override BasePlugin.setup are
    considered setup plugins. Their setup_priority attribute (or corresponding
    config value) controls execution order.

    Example use:
      >>> plugins = load_plugins([])
      >>> run_setup_plugins(plugins)  # no-op when there are no setup plugins
    """
    logger = logging.getLogger("foghorn.main.setup")
    # Collect (priority, plugin) pairs for setup-capable plugins
    setup_entries: List[tuple[int, BasePlugin]] = []
    for p in plugins or []:
        if not _is_setup_plugin(p):
            continue
        try:
            prio = int(getattr(p, "setup_priority", 50))
        except Exception:
            prio = 50
        setup_entries.append((prio, p))

    # Stable sort by priority; list order is preserved for equal priorities
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
                "Continuing startup despite setup failure in plugin %s "
                "because abort_on_failure is False",
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
        ... upstream:
        ...   host: 1.1.1.1
        ...   port: 53
        ... ''')):
        ...     server_thread = threading.Thread(target=main, args=(["--config", "config.yaml"],), daemon=True)
        ...     server_thread.start()
        ...     time.sleep(0.1) # Give server time to start
    """
    parser = argparse.ArgumentParser(description="Caching DNS server with plugins")
    parser.add_argument("--config", default="config.yaml", help="Path to YAML config")
    parser.add_argument(
        "--rebuild",
        action="store_true",
        help=(
            "Rebuild statistics counts from the persistent query_log on startup "
            "(overrides existing counts when present)."
        ),
    )
    args = parser.parse_args(argv)

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f) or {}

    # Initialize logging before any other operations
    init_logging(cfg.get("logging"))
    logger = logging.getLogger("foghorn.main")
    logger.info("Loaded config from %s", args.config)

    # Keep references for signal-driven reload/reset and coordinated shutdown.
    # These are captured by inner closures (SIGUSR1/SIGUSR2 handlers and
    # _apply_runtime_config) so they can adjust behaviour without restarting
    # the main process or DNS listeners.
    cfg_path: str = args.config
    stats_collector: Optional[StatsCollector]
    stats_reporter: Optional[StatsReporter]
    stats_persistence_store: Optional[StatsSQLiteStore]
    # web_handle is the admin HTTP/web UI handle returned by start_webserver().
    # It is allowed to be None when the webserver is disabled but is treated as
    # fatal when webserver.enabled is true.
    web_handle = None
    # Shared in-memory log buffer passed into the FastAPI admin app; this is
    # also used when starting the threaded admin HTTP fallback.
    web_log_buffer: Optional[RingBuffer] = None

    # Normalize listen configuration with backward compatibility.
    # If listen.udp is present, prefer it; otherwise fall back to legacy listen.host/port.
    listen_cfg = cfg.get("listen", {}) or {}
    legacy_host = str(listen_cfg.get("host", "127.0.0.1"))
    # Default legacy port is 5333 to match the recommended example config.
    legacy_port = int(listen_cfg.get("port", 5333))

    def _sub(key, defaults):
        d = listen_cfg.get(key, {}) or {}
        out = {**defaults, **d} if isinstance(d, dict) else defaults
        return out

    udp_cfg = _sub("udp", {"enabled": True, "host": legacy_host, "port": legacy_port})
    # Default TCP port now matches the UDP listener (5333) when not explicitly set.
    tcp_cfg = _sub("tcp", {"enabled": False, "host": legacy_host, "port": legacy_port})
    dot_cfg = _sub("dot", {"enabled": False, "host": legacy_host, "port": 853})
    # Default DoH listener port is 1443 (non-privileged HTTPS-like port) when not explicitly set.
    doh_cfg = _sub("doh", {"enabled": False, "host": legacy_host, "port": 1443})

    # Normalize upstream configuration
    upstreams, timeout_ms = normalize_upstream_config(cfg)
    min_cache_ttl = _get_min_cache_ttl(cfg)

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

    # Initialize statistics collection if enabled
    stats_cfg = cfg.get("statistics", {})
    stats_enabled = stats_cfg.get("enabled", False)
    stats_collector = None
    stats_reporter = None
    stats_persistence_store = None

    if stats_enabled:
        # Optional SQLite-backed persistence; the store is responsible for
        # maintaining long-lived aggregate counts and a raw query_log. The
        # in-memory StatsCollector remains the live source for periodic
        # logging and web API snapshots.
        persistence_cfg = stats_cfg.get("persistence", {}) or {}
        persistence_enabled = bool(persistence_cfg.get("enabled", True))
        stats_persistence_store = None

        if persistence_enabled:
            db_path = str(persistence_cfg.get("db_path", "./config/var/stats.db"))
            batch_writes = bool(persistence_cfg.get("batch_writes", True))
            batch_time_sec = float(persistence_cfg.get("batch_time_sec", 15.0))
            batch_max_size = int(persistence_cfg.get("batch_max_size", 1000))

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
                return str(val).strip().lower() in {"1", "true", "t", "yes", "y", "on"}

            force_rebuild_cfg = bool(persistence_cfg.get("force_rebuild", False))
            force_rebuild_env = _is_truthy_env(os.getenv("FOGHORN_FORCE_REBUILD"))
            force_rebuild = bool(args.rebuild or force_rebuild_cfg or force_rebuild_env)

            try:
                stats_persistence_store = StatsSQLiteStore(
                    db_path=db_path,
                    batch_writes=batch_writes,
                    batch_time_sec=batch_time_sec,
                    batch_max_size=batch_max_size,
                )
                logger.info("Initialized statistics SQLite store at %s", db_path)

                # Optionally rebuild counts from the query_log when requested or
                # when counts are empty but query_log has rows.
                try:
                    stats_persistence_store.rebuild_counts_if_needed(
                        force_rebuild=force_rebuild, logger_obj=logger
                    )
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error(
                        "Failed to rebuild statistics counts from query_log: %s",
                        exc,
                        exc_info=True,
                    )
            except Exception as exc:  # pragma: no cover - defensive
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
        )

        # Best-effort warm-load of persisted aggregate counters on startup.
        try:
            stats_collector.warm_load_from_store()
            logger.info("Statistics warm-load from SQLite store completed")
        except Exception as exc:  # pragma: no cover - defensive
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

    # Initialize webserver log buffer (shared with admin HTTP API)
    web_cfg = cfg.get("webserver", {}) or {}
    if web_cfg.get("enabled", False):
        buffer_size = int((web_cfg.get("logs") or {}).get("buffer_size", 500))
        web_log_buffer = RingBuffer(capacity=buffer_size)

    # --- Signal handling (SIGUSR1/SIGUSR2) ---
    # Use Events to coalesce multiple signals so that expensive work (config
    # reload, stats reset, plugin notifications) is never running concurrently
    # for the same signal type.
    _sigusr1_pending = threading.Event()
    _sigusr2_pending = threading.Event()

    def _apply_runtime_config(new_cfg: dict) -> None:
        """Apply runtime-safe settings from a freshly-loaded config mapping.

        Inputs:
          - new_cfg: dict configuration just loaded
        Outputs:
          - None

        Notes:
          - Reinitializes logging and DNSSEC knobs
          - Manages StatsReporter per configuration changes without touching listeners
        """
        nonlocal stats_collector, stats_reporter, stats_persistence_store
        # Re-init logging
        init_logging(new_cfg.get("logging"))
        # Apply DNSSEC/EDNS knobs to UDP handler
        dnssec_cfg = new_cfg.get("dnssec", {}) or {}
        try:
            from . import server as _server_mod

            _server_mod.DNSUDPHandler.dnssec_mode = str(
                dnssec_cfg.get("mode", "ignore")
            ).lower()
            _server_mod.DNSUDPHandler.edns_udp_payload = max(
                512, int(dnssec_cfg.get("udp_payload_size", 1232))
            )
            _server_mod.DNSUDPHandler.dnssec_validation = str(
                dnssec_cfg.get("validation", "upstream_ad")
            ).lower()
        except Exception:
            pass

        # Stats management: we intentionally avoid touching the DNS listeners
        # here. Only logging and StatsCollector/StatsReporter wiring are
        # updated so that long-lived sockets are unaffected by reloads.
        s_cfg = new_cfg.get("statistics", {}) or {}
        s_enabled = bool(s_cfg.get("enabled", False))

        # Refresh display-only ignore filters for top lists on reload.
        ignore_cfg = s_cfg.get("ignore", {}) or {}
        ignore_top_clients = list(ignore_cfg.get("top_clients", []) or [])
        ignore_top_domains = list(ignore_cfg.get("top_domains", []) or [])
        ignore_top_subdomains = list(ignore_cfg.get("top_subdomains", []) or [])
        domains_mode = str(ignore_cfg.get("top_domains_mode", "exact")).lower()
        subdomains_mode = str(ignore_cfg.get("top_subdomains_mode", "exact")).lower()
        ignore_domains_as_suffix = domains_mode == "suffix"
        ignore_subdomains_as_suffix = subdomains_mode == "suffix"
        ignore_single_host = bool(ignore_cfg.get("ignore_single_host", False))
        if stats_collector is not None:
            try:
                stats_collector.set_ignore_filters(
                    ignore_top_clients,
                    ignore_top_domains,
                    ignore_top_subdomains,
                    domains_as_suffix=ignore_domains_as_suffix,
                    subdomains_as_suffix=ignore_subdomains_as_suffix,
                )
                # Apply ignore_single_host as a simple attribute toggle on reload.
                stats_collector.ignore_single_host = bool(ignore_single_host)
            except Exception:  # pragma: no cover - defensive
                logging.getLogger("foghorn.main").error(
                    "Failed to apply statistics ignore filters on reload", exc_info=True
                )

        # Start/stop reporter based on enabled flag
        if not s_enabled:
            if stats_reporter is not None:
                logging.getLogger("foghorn.main").info(
                    "Disabling statistics reporter per reload"
                )
                try:
                    stats_reporter.stop()
                finally:
                    stats_reporter = None
            # keep collector instance to allow later re-enable, but it will be unused
        else:
            # Ensure we have a collector
            if stats_collector is None:
                stats_collector = StatsCollector(
                    track_uniques=s_cfg.get("track_uniques", True),
                    include_qtype_breakdown=s_cfg.get("include_qtype_breakdown", True),
                    include_top_clients=bool(s_cfg.get("include_top_clients", True)),
                    include_top_domains=bool(s_cfg.get("include_top_domains", True)),
                    top_n=int(s_cfg.get("top_n", 10)),
                    track_latency=bool(s_cfg.get("track_latency", True)),
                )
            # Recreate reporter if settings changed or reporter missing
            need_restart = False
            if stats_reporter is None:
                need_restart = True
            else:
                # If interval/reset_on_log/log_level differ, restart
                try:
                    # Default to 300s (5 minutes) when interval_seconds is not provided.
                    interval_seconds = int(s_cfg.get("interval_seconds", 300))
                    reset_on_log = bool(s_cfg.get("reset_on_log", False))
                    # log_level = str(s_cfg.get("log_level", "info"))
                    if (
                        stats_reporter.interval_seconds != max(1, interval_seconds)
                        or stats_reporter.log_level
                        != logging.getLogger().getEffectiveLevel()  # rough check
                        or reset_on_log != stats_reporter.reset_on_log
                    ):
                        need_restart = True
                except Exception:
                    need_restart = True
            if need_restart:
                if stats_reporter is not None:
                    try:
                        stats_reporter.stop()
                    except Exception:
                        pass
                stats_reporter = StatsReporter(
                    collector=stats_collector,
                    interval_seconds=int(s_cfg.get("interval_seconds", 300)),
                    reset_on_log=bool(s_cfg.get("reset_on_log", False)),
                    log_level=str(s_cfg.get("log_level", "info")),
                    persistence_store=stats_persistence_store,
                )
                stats_reporter.start()

    def _process_sigusr1() -> None:
        """
        Brief: Handle SIGUSR1 by reloading config, re-applying runtime settings, and optionally logging and resetting statistics.

        Inputs: none
        Outputs: none

        Example:
            >>> # Internal use; invoked by signal handler thread
        """
        nonlocal cfg, stats_collector, stats_reporter
        logger = logging.getLogger("foghorn.main")
        try:
            with open(cfg_path, "r") as f:
                new_cfg = yaml.safe_load(f) or {}
        except Exception as e:
            logger.error("SIGUSR1: failed to read config %s: %s", cfg_path, e)
            return
        # Apply runtime config (logging, DNSSEC, reporter)
        _apply_runtime_config(new_cfg)
        # Handle statistics reset if enabled and configured. This is only
        # invoked on successful reload and only when explicitly requested via
        # statistics.reset_on_sigusr1.
        s_cfg = new_cfg.get("statistics", {}) or {}
        if bool(s_cfg.get("enabled", False)) and bool(
            s_cfg.get("reset_on_sigusr1", False)
        ):
            if stats_collector is not None:
                try:
                    # Log snapshot then reset
                    snap = stats_collector.snapshot(reset=False)
                    json_line = format_snapshot_json(snap)
                    logging.getLogger("foghorn.stats").info(json_line)
                    # Now reset
                    stats_collector.snapshot(reset=True)
                    logger.info("SIGUSR1: statistics reset completed")
                except Exception as e:
                    logger.error(
                        "SIGUSR1: error during statistics snapshot/reset: %s", e
                    )
        else:
            logger.info(
                "SIGUSR1: statistics reset skipped (disabled or reset_on_sigusr1 not set)"
            )
        # Replace current cfg
        cfg = new_cfg

    def _sigusr1_handler(_signum, _frame):
        # coalesce multiple signals
        if _sigusr1_pending.is_set():
            return
        _sigusr1_pending.set()
        try:
            _process_sigusr1()
        finally:
            _sigusr1_pending.clear()

    # Register handlers (Unix only)
    try:
        signal.signal(signal.SIGUSR1, _sigusr1_handler)
        logger.info(
            "Installed SIGUSR1 handler for config reload and optional stats reset"
        )
    except Exception:
        logger.warning("Could not install SIGUSR1 handler on this platform")

    def _process_sigusr2() -> None:
        """
        Brief: Handle SIGUSR2 by optionally resetting statistics and invoking handle_sigusr2() on all active plugins.

        Inputs: none
        Outputs: none

        Example:
            >>> # Internal use; invoked by signal handler thread
        """
        nonlocal cfg, stats_collector
        log = logging.getLogger("foghorn.main")

        # Conditionally reset statistics based on config; failures here must
        # never prevent plugin notifications from running.
        try:
            s_cfg = (cfg.get("statistics") or {}) if isinstance(cfg, dict) else {}
            if bool(s_cfg.get("enabled", False)) and bool(
                s_cfg.get("sigusr2_resets_stats", False)
            ):
                if stats_collector is not None:
                    try:
                        stats_collector.snapshot(reset=True)
                        log.info("SIGUSR2: statistics reset completed")
                    except Exception as e:
                        log.error("SIGUSR2: error during statistics reset: %s", e)
                else:
                    log.info("SIGUSR2: no statistics collector active, skipping reset")
            else:
                log.info(
                    "SIGUSR2: statistics reset skipped (disabled or sigusr2_resets_stats not set)"
                )
        except Exception as e:  # defensive: do not block plugin notifications
            log.error(
                "SIGUSR2: unexpected error checking statistics reset config: %s", e
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
            except Exception as e:
                log.error(
                    "SIGUSR2: plugin %s handler error: %s", p.__class__.__name__, e
                )
        log.info("SIGUSR2: invoked handle_sigusr2 on %d plugins", count)

    def _sigusr2_handler(_signum, _frame):
        if _sigusr2_pending.is_set():
            return
        _sigusr2_pending.set()
        try:
            _process_sigusr2()
        finally:
            _sigusr2_pending.clear()

    try:
        signal.signal(signal.SIGUSR2, _sigusr2_handler)
        logger.info("Installed SIGUSR2 handler to notify plugins")
    except Exception:
        logger.warning("Could not install SIGUSR2 handler on this platform")

    # DNSSEC config (ignore|passthrough|validate)
    dnssec_cfg = cfg.get("dnssec", {}) or {}
    dnssec_mode = str(dnssec_cfg.get("mode", "ignore")).lower()
    edns_payload = int(dnssec_cfg.get("udp_payload_size", 1232))

    server = None
    if bool(udp_cfg.get("enabled", True)):
        uhost = str(udp_cfg.get("host", legacy_host))
        uport = int(udp_cfg.get("port", legacy_port))
        server = DNSServer(
            uhost,
            uport,
            upstreams,
            plugins,
            timeout=timeout_ms / 1000.0,
            timeout_ms=timeout_ms,
            min_cache_ttl=min_cache_ttl,
            stats_collector=stats_collector,
        )
        # Set DNSSEC/EDNS knobs on handler class (keeps DNSServer signature stable)
        try:
            from . import server as _server_mod

            _server_mod.DNSUDPHandler.dnssec_mode = dnssec_mode
            _server_mod.DNSUDPHandler.edns_udp_payload = max(512, int(edns_payload))
            _server_mod.DNSUDPHandler.dnssec_validation = str(
                dnssec_cfg.get("validation", "upstream_ad")
            ).lower()
        except Exception:  # pragma: no cover
            pass

    # Log startup info
    upstream_info = ", ".join(
        [f"{u['url']}" if "url" in u else f"{u['host']}:{u['port']}" for u in upstreams]
    )
    if server is not None:
        logger.info(
            "Starting Foghorn on %s:%d, upstreams: [%s], timeout: %dms\n",
            uhost,
            uport,
            upstream_info,
            timeout_ms,
        )
    else:
        logger.info(
            "Starting Foghorn without UDP listener; upstreams: [%s], timeout: %dms\n",
            upstream_info,
            timeout_ms,
        )

    # Optionally start TCP/DoT listeners based on listen config

    # Resolver adapter for TCP/DoT servers
    import asyncio

    from .server import resolve_query_bytes

    loop_threads = []

    def _start_asyncio_server(coro_factory, name: str, *, on_permission_error=None):
        def runner():
            try:
                asyncio.set_event_loop(asyncio.new_event_loop())
                loop = asyncio.get_event_loop()
                try:
                    loop.run_until_complete(coro_factory())
                finally:
                    loop.close()
            except PermissionError:
                # Environment forbids creating asyncio self-pipe/socketpair (e.g., restricted seccomp).
                if callable(on_permission_error):
                    on_permission_error()
                else:
                    logging.getLogger("foghorn.main").error(
                        "Asyncio loop creation failed with PermissionError for %s; no fallback provided",
                        name,
                    )

        # Import threading dynamically so tests can monkeypatch via sys.modules
        import importlib as _importlib

        _threading = _importlib.import_module("threading")
        t = _threading.Thread(target=runner, name=name, daemon=True)
        t.start()
        loop_threads.append(t)

    if bool(tcp_cfg.get("enabled", False)):
        from .tcp_server import serve_tcp, serve_tcp_threaded

        thost = str(tcp_cfg.get("host", legacy_host))
        tport = int(tcp_cfg.get("port", 53))
        logger.info("Starting TCP listener on %s:%d", thost, tport)
        _start_asyncio_server(
            lambda: serve_tcp(thost, tport, resolve_query_bytes),
            name="foghorn-tcp",
            on_permission_error=lambda: serve_tcp_threaded(
                thost, tport, resolve_query_bytes
            ),
        )

    if bool(dot_cfg.get("enabled", False)):
        from .dot_server import serve_dot

        dhost = str(dot_cfg.get("host", legacy_host))
        dport = int(dot_cfg.get("port", 853))
        cert_file = dot_cfg.get("cert_file")
        key_file = dot_cfg.get("key_file")
        if not cert_file or not key_file:
            logger.error(
                "listen.dot.enabled=true but cert_file/key_file not provided; skipping DoT listener"
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
            )

    if bool(doh_cfg.get("enabled", False)):
        h = str(doh_cfg.get("host", legacy_host))
        p = int(doh_cfg.get("port", 8053))
        cert_file = doh_cfg.get("cert_file")
        key_file = doh_cfg.get("key_file")
        logger.info("Starting DoH listener on %s:%d", h, p)
        try:
            # start uvicorn-based DoH FastAPI server in background thread
            doh_handle = start_doh_server(
                h, p, resolve_query_bytes, cert_file=cert_file, key_file=key_file
            )
        except Exception as e:
            logger.error("Failed to start DoH server: %s", e)
            return 1
        if doh_handle is None:
            logger.error(
                "Fatal: listen.doh.enabled=true but start_doh_server returned None"
            )
            return 1

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
        )
    except Exception as e:  # pragma: no cover
        logger.error("Failed to start webserver: %s", e)
        return 1

    if bool(web_cfg.get("enabled", False)) and web_handle is None:
        logger.error("Fatal: webserver.enabled=true but start_webserver returned None")
        return 1

    try:
        if server is not None:
            server.serve_forever()
        else:
            #  keep main thread alive while async listeners run
            import time as _time

            while True:
                _time.sleep(3600)
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down")
    except Exception as e:  # pragma: no cover
        logger.exception(
            f"Unhandled exception during server operation {e}"
        )  # pragma: no cover
        return 1  # pragma: no cover
    finally:
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

    return 0


if __name__ == "__main__":
    raise SystemExit(main())  # pragma: no cover
