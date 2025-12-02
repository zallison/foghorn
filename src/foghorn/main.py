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

from .config_schema import validate_config
from .doh_api import start_doh_server
from .logging_config import init_logging
from .plugins.base import BasePlugin
from .plugins.registry import discover_plugins, get_plugin_class
from .server import DNSServer
from .stats import StatsCollector, StatsReporter, StatsSQLiteStore
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
      - int: non-negative min_cache_ttl in seconds (default 0 when omitted)

    Returns a sanitized min_cache_ttl value. Negative values are clamped to 0.
    """
    # Treat missing or None as 0 to avoid unintentionally extending cache TTLs
    val = cfg.get("min_cache_ttl", 0)
    try:
        ival = int(val)
    except (TypeError, ValueError):
        ival = 0
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
            logger.debug(f"doh: {u}")
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


def _validate_plugin_config(plugin_cls: type[BasePlugin], config: dict | None) -> dict:
    """Brief: Validate and normalize plugin configuration via optional schema hooks.

    Inputs:
      - plugin_cls: Plugin class (subclass of BasePlugin).
      - config: Raw config mapping for this plugin (may be None).

    Outputs:
      - dict: Validated/normalized config mapping to be passed into plugin_cls.

    Behavior:
      - If plugin_cls exposes get_config_model() and it returns a model class,
        the config is validated by instantiating the model; the resulting
        mapping (model.dict() when available) is returned.
      - If get_config_model() returns None, the config is accepted as-is.
      - Otherwise, if plugin_cls exposes get_config_schema() and it returns a
        JSON Schema dict, the config is validated using jsonschema; on success
        the original config mapping is returned.
      - If get_config_schema() returns None or no hooks are present, the config
        is returned unchanged.
    """

    cfg = config or {}

    # Prefer typed config models (e.g., Pydantic) when provided.
    get_model = getattr(plugin_cls, "get_config_model", None)
    if callable(get_model):  # pragma: no cover - exercised via plugin tests
        model_cls = get_model()
        if model_cls is None:
            return cfg
        try:
            model_instance = model_cls(**cfg)
        except Exception as exc:  # pragma: no cover - defensive, surfaced in tests
            raise ValueError(
                f"Invalid configuration for plugin {plugin_cls.__name__}: {exc}"
            ) from exc

        # Best-effort conversion back to a plain mapping so existing plugins
        # that expect dict-like config continue to work.
        for attr in ("dict", "model_dump"):
            method = getattr(model_instance, attr, None)
            if callable(method):
                try:
                    return dict(method())
                except Exception:  # pragma: no cover - defensive
                    break
        try:
            return dict(model_instance)
        except Exception:  # pragma: no cover - defensive
            return cfg

    # Fallback: JSON Schema-based per-plugin validation.
    get_schema = getattr(plugin_cls, "get_config_schema", None)
    if callable(get_schema):  # pragma: no cover - exercised via plugin tests
        schema = get_schema()
        if schema is None:
            return cfg
        try:
            from jsonschema import validate as _js_validate  # type: ignore

            _js_validate(instance=cfg, schema=schema)
        except Exception as exc:  # pragma: no cover - defensive, surfaced in tests
            raise ValueError(
                f"Invalid configuration for plugin {plugin_cls.__name__}: {exc}"
            ) from exc

    return cfg


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
        validated_config = _validate_plugin_config(plugin_cls, config)
        plugin = plugin_cls(**validated_config)
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

    # Validate configuration against JSON Schema before proceeding.
    try:
        validate_config(cfg, config_path=args.config)
    except ValueError as exc:
        print(str(exc))
        return 1

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
    default_host = str(listen_cfg.get("host", "127.0.0.1"))
    default_port = int(listen_cfg.get("port", 5333))

    def _sub(key, defaults):
        d = listen_cfg.get(key, {}) or {}
        out = {**defaults, **d} if isinstance(d, dict) else defaults
        return out

    # Get listeners configs
    udp_cfg = _sub(
        "udp", {"enabled": True, "host": default_host, "port": default_port or 5333}
    )
    tcp_cfg = _sub(
        "tcp", {"enabled": False, "host": default_host, "port": default_port or 5333}
    )
    dot_cfg = _sub("dot", {"enabled": False, "host": default_host, "port": 853})
    doh_cfg = _sub("doh", {"enabled": False, "host": default_host, "port": 1443})

    # Normalize upstream configuration
    upstreams, timeout_ms = normalize_upstream_config(cfg)

    # Hold responses this long, even if the actual ttl is lower.
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
                return str(val).strip().lower() in {
                    "1",
                    "true",
                    "t",
                    "yes",
                    "y",
                    "on",
                }  # pragma: nocover - best effort

            # Allow force_rebuild to be controlled from three sources, in
            # increasing precedence order:
            #   1) statistics.force_rebuild (root-level flag)
            #   2) statistics.persistence.force_rebuild (legacy location)
            #   3) FOGHORN_FORCE_REBUILD / --rebuild (highest precedence)
            force_rebuild_root = bool(stats_cfg.get("force_rebuild", False))
            force_rebuild_cfg = bool(persistence_cfg.get("force_rebuild", False))
            force_rebuild_env = _is_truthy_env(os.getenv("FOGHORN_FORCE_REBUILD"))
            force_rebuild = bool(
                args.rebuild
                or force_rebuild_env
                or force_rebuild_cfg
                or force_rebuild_root
            )

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
            are enabled and the configuration flag sigusr2_resets_stats is
            true, the in-memory statistics are reset. In all cases, active
            plugins that implement handle_sigusr2() are notified.
        """

        nonlocal cfg, stats_collector
        log = logging.getLogger("foghorn.main")

        # Conditionally reset statistics based on config; failures here must
        # never prevent plugin notifications from running.
        try:
            s_cfg = (cfg.get("statistics") or {}) if isinstance(cfg, dict) else {}
            enabled = bool(s_cfg.get("enabled", False))
            # reset_on_sigusr1 is treated as a backwards-compatible alias for
            # sigusr2_resets_stats so existing configs continue to work.
            reset_flag = bool(
                s_cfg.get(
                    "sigusr2_resets_stats",
                    s_cfg.get("reset_on_sigusr1", False),
                )
            )
            if enabled and reset_flag:
                if stats_collector is not None:
                    try:
                        stats_collector.snapshot(reset=True)
                        log.info("%s: statistics reset completed", sig_label)
                    except Exception as e:  # pragma: no cover - defensive
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
        ) as e:  # pragma: nocover - defensive: do not block plugin notifications
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
            except Exception as e:  # pragma: no cover - defensive
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
          - None. Sets shutdown_event/exit_code and triggers server shutdown
            when running with a UDP listener.

        Notes:
          - For SIGTERM and SIGINT, a best-effort hard-kill timer is started.
            If the process has not completed its shutdown sequence within
            ~10 seconds, a last-resort SIGKILL (or os._exit fallback) is
            issued to avoid hanging indefinitely.
        """

        nonlocal exit_code, server, hard_kill_timer
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

        # When a UDP server is active, ask socketserver to stop its loop so the
        # main thread can proceed to the coordinated shutdown logic.
        try:
            if server is not None and getattr(server, "server", None) is not None:
                server.server.shutdown()
        except Exception:  # pragma: no cover - defensive
            log.exception("Error while requesting UDP server shutdown for %s", reason)

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
    except Exception:  # pragma: no cover - defensive
        logger.warning("Could not install SIGHUP handler on this platform")

    try:
        signal.signal(signal.SIGTERM, _sigterm_handler)
        logger.debug("Installed SIGTERM handler for immediate shutdown (exit code 2)")
    except Exception:  # pragma: no cover - defensive
        logger.warning("Could not install SIGTERM handler on this platform")

    try:
        signal.signal(signal.SIGINT, _sigint_handler)
        logger.debug("Installed SIGINT handler for immediate shutdown (exit code 2)")
    except Exception:  # pragma: no cover - defensive
        logger.warning("Could not install SIGINT handler on this platform")

    # DNSSEC config (ignore|passthrough|validate)
    dnssec_cfg = cfg.get("dnssec", {}) or {}
    dnssec_mode = str(dnssec_cfg.get("mode", "ignore")).lower()
    edns_payload = int(dnssec_cfg.get("udp_payload_size", 1232))

    server = None
    udp_thread: threading.Thread | None = None
    udp_error: Exception | None = None
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
    logger.info(
        "Upstreams: [%s], timeout: %dms",
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

        thost = str(tcp_cfg.get("host", default_host))
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

        dhost = str(dot_cfg.get("host", default_host))
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
        h = str(doh_cfg.get("host", default_host))
        p = int(doh_cfg.get("port", 8153))
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

    logger.info("Startup Completed")

    try:
        # Keep the main thread in a lightweight keepalive loop while UDP/TCP/DoT
        # listeners run in the background. This ensures all transports are
        # treated consistently and that shutdown is always driven by
        # shutdown_event/termination signals rather than a blocking
        # serve_forever() call.
        import time as _time

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

            # If a UDP server thread was started and it has exited (for example
            # because a test's DummyServer.serve_forever() raised
            # KeyboardInterrupt or another exception), break out of the loop so
            # coordinated shutdown can proceed.
            if udp_thread is not None and not udp_thread.is_alive():
                break
            _time.sleep(1.0)
    except KeyboardInterrupt:
        logger.info("Received interrupt, shutting down")
        if not shutdown_event.is_set():
            # KeyboardInterrupt maps to a clean shutdown and exit code 0 unless
            # an explicit termination-like signal has already set a code.
            shutdown_event.set()
            exit_code = 0
    except Exception as e:  # pragma: no cover
        logger.exception(
            f"Unhandled exception during server operation {e}"
        )  # pragma: no cover
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
                if getattr(server, "server", None) is not None:
                    try:
                        server.server.shutdown()
                    except Exception:
                        logger.exception("Error while shutting down UDP server")
                    try:
                        server.server.server_close()
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
    raise SystemExit(main())  # pragma: no cover
