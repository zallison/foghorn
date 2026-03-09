from __future__ import annotations

import argparse
import functools
import gc
import logging
import os
import platform
import re
import signal
import socket
import sys
import threading
from typing import List, Optional

# Backward-compatible export: some tests and third-party code monkeypatch
# foghorn.main.DNSServer to avoid starting a real server.
try:  # pragma: no cover - simple import surface for tests
    from dnslib.server import DNSServer  # type: ignore
except Exception:  # pragma: no cover - defensive
    DNSServer = object  # type: ignore[assignment]

from foghorn.stats.meta import FOGHORN_VERSION
from foghorn.utils.register_caches import apply_decorated_cache_overrides

from .config.config_parser import (
    load_plugins,
    normalize_upstream_backup_config,
    normalize_upstream_config,
    parse_config_file,
)
from .config.logging_config import init_logging
from .plugins.querylog import BaseStatsStore, load_stats_store_backend
from .plugins.resolve.base import BasePlugin
from .plugins.setup import run_setup_plugins
from .runtime_config import (
    RuntimeSnapshot,
    initialize_runtime,
    parse_upstream_health_config,
)
from .servers.runtime_state import RingBuffer, RuntimeState
from .stats import StatsCollector, StatsReporter


def main(argv: List[str] | None = None) -> int:
    """
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
    parser = _build_main_arg_parser()
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
    server_cfg, logging_cfg, python_logging_cfg = _extract_server_and_logging_cfg(cfg)

    init_logging(python_logging_cfg or None)

    logger = logging.getLogger("foghorn.main")
    _log_startup_banner(logger, config_path=str(args.config))

    # Apply any configured overrides for decorated caches (registered_cached /
    # registered_lru_cached) before listeners are started so that diagnostic
    # caches use operator-selected sizes/TTLs. This is best-effort and
    # silently ignores malformed entries.
    _apply_cache_overrides_from_config(logger=logger, server_cfg=server_cfg)

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
    (
        listen_cfg,
        udp_cfg,
        tcp_cfg,
        dot_cfg,
        doh_cfg,
        default_host,
        default_port,
    ) = _build_listener_configs(server_cfg=server_cfg)

    # Seed readiness state with expected listeners. The thread/handle references
    # are filled in later once each listener is started.
    _seed_listener_runtime_state(
        runtime_state=runtime_state,
        udp_cfg=udp_cfg,
        tcp_cfg=tcp_cfg,
        dot_cfg=dot_cfg,
        doh_cfg=doh_cfg,
    )

    (
        resolver_cfg,
        resolver_mode,
        recursive_max_depth,
        recursive_timeout_ms,
        recursive_per_try_timeout_ms,
    ) = _parse_resolver_cfg(cfg=cfg, server_cfg=server_cfg)

    # Normalize upstream configuration only in forwarder mode.
    upstreams, upstream_backups, timeout_ms = _normalize_upstreams_for_mode(
        cfg=cfg,
        resolver_mode=resolver_mode,
        recursive_timeout_ms=recursive_timeout_ms,
    )

    # Upstream selection strategy and concurrency controls (v2 upstreams block).
    upstream_cfg = cfg.get("upstreams") or {}
    if not isinstance(upstream_cfg, dict):
        raise ValueError("config.upstreams must be a mapping when present")
    upstream_strategy = str(upstream_cfg.get("strategy", "failover")).lower()
    upstream_health = parse_upstream_health_config(upstream_cfg)
    upstream_max_concurrent = int(upstream_cfg.get("max_concurrent", 1) or 1)
    if upstream_max_concurrent < 1:
        upstream_max_concurrent = 1

    # Global knob to disable asyncio-based listeners/admin servers in restricted
    # environments. When false, threaded fallbacks are used where available.
    use_asyncio = bool(resolver_cfg.get("use_asyncio", True))

    # Configure a shared, bounded ThreadPoolExecutor for asyncio-based listeners
    # (TCP/DoT and any other paths that call run_in_executor).
    limits_cfg = server_cfg.get("limits") if isinstance(server_cfg, dict) else None
    if not isinstance(limits_cfg, dict):
        limits_cfg = {}

    _configure_resolver_executor(limits_cfg=limits_cfg, logger=logger)

    cache_plugin = _load_cache_plugin_from_cfg(cfg=cfg, server_cfg=server_cfg)
    _install_cache_plugin_global(cache_plugin)
    min_cache_ttl = _get_min_cache_ttl(cache_plugin)

    plugins = load_plugins(cfg.get("plugins", []))
    logger.info(
        "Loaded %d plugins: %s", len(plugins), [p.__class__.__name__ for p in plugins]
    )

    # Warn if exposed listeners lack rate limiting
    try:
        from .config.rate_limit_check import check_rate_limit_plugin_config

        check_rate_limit_plugin_config(plugins=plugins, cfg=cfg)
    except Exception:
        pass

    # Run setup phase for setup-aware plugins before starting listeners
    try:
        run_setup_plugins(plugins)
    except RuntimeError as e:
        logger.error("Plugin setup failed: %s", e)
        return 1

    stats_collector, stats_reporter, stats_persistence_store = (
        _initialize_statistics_subsystem(
            cfg=cfg,
            logging_cfg=logging_cfg,
            args=args,
            logger=logger,
        )
    )

    # Initialize webserver log buffer (shared with admin HTTP API).
    web_cfg, web_enabled = _resolve_web_config(cfg=cfg, server_cfg=server_cfg)

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
    _install_signal_handler(
        sig=signal.SIGUSR1,
        handler=_sigusr1_handler,
        logger=logger,
        success_log="Installed SIGUSR1 handler to notify plugins and optionally reset statistics",
        failure_log="Could not install SIGUSR1 handler on this platform",
    )
    _install_signal_handler(
        sig=signal.SIGUSR2,
        handler=_sigusr2_handler,
        logger=logger,
        success_log="Installed SIGUSR2 handler to notify plugins and optionally reset statistics",
        failure_log="Could not install SIGUSR2 handler on this platform",
    )
    _install_signal_handler(
        sig=signal.SIGHUP,
        handler=_sighup_handler,
        logger=logger,
        success_log="Installed SIGHUP handler for clean shutdown (exit code 0)",
        failure_log="Could not install SIGHUP handler on this platform",
    )
    _install_signal_handler(
        sig=signal.SIGTERM,
        handler=_sigterm_handler,
        logger=logger,
        success_log="Installed SIGTERM handler for immediate shutdown (exit code 2)",
        failure_log="Could not install SIGTERM handler on this platform",
    )
    _install_signal_handler(
        sig=signal.SIGINT,
        handler=_sigint_handler,
        logger=logger,
        success_log="Installed SIGINT handler for immediate shutdown (exit code 2)",
        failure_log="Could not install SIGINT handler on this platform",
    )

    # DNSSEC config (ignore|passthrough|validate).
    dnssec_cfg = server_cfg.get("dnssec") or {}
    if not isinstance(dnssec_cfg, dict):
        dnssec_cfg = {}
    dnssec_mode = str(dnssec_cfg.get("mode", "ignore")).lower()
    edns_payload = int(dnssec_cfg.get("udp_payload_size", 1232))
    dnssec_validation = str(dnssec_cfg.get("validation", "upstream_ad")).lower()

    # Extended DNS Errors (RFC 8914) feature gate. When false, the resolver
    # will not add any EDE options of its own and will continue to treat
    # upstream EDNS options opaquely.
    enable_ede = bool(server_cfg.get("enable_ede", True))

    # .local forward blocking (RFC 6762). When false (default), queries for
    # .local names that are not answered by plugins are blocked from being
    # forwarded to upstream resolvers and return NXDOMAIN instead.
    forward_local = bool(server_cfg.get("forward_local", False))

    # AXFR/IXFR transfer policy (applies to TCP/DoT listeners).
    axfr_cfg = server_cfg.get("axfr") or {}
    if not isinstance(axfr_cfg, dict):
        axfr_cfg = {}
    axfr_enabled = bool(axfr_cfg.get("enabled", False))
    axfr_allow_clients = axfr_cfg.get("allow_clients") or []
    if not isinstance(axfr_allow_clients, list):
        axfr_allow_clients = []
    axfr_allow_clients = [str(x) for x in axfr_allow_clients if x]

    # When performing local DNSSEC validation (including local_extended), point
    # the validator's internal resolver at the configured upstream hosts so that
    # chain validation and extended lookups use the same recursive resolvers as
    # normal forwarding. In recursive mode there are no forwarder upstreams; in
    # that case, route all DNSSEC helper lookups through Foghorn's own
    # RecursiveResolver rather than the system resolver.
    _initialize_runtime_snapshot(
        logger=logger,
        cfg=cfg,
        plugins=plugins,
        upstreams=upstreams,
        upstream_backups=upstream_backups,
        upstream_health=upstream_health,
        timeout_ms=timeout_ms,
        upstream_strategy=upstream_strategy,
        upstream_max_concurrent=upstream_max_concurrent,
        resolver_mode=resolver_mode,
        recursive_max_depth=recursive_max_depth,
        recursive_timeout_ms=recursive_timeout_ms,
        recursive_per_try_timeout_ms=recursive_per_try_timeout_ms,
        dnssec_mode=dnssec_mode,
        dnssec_validation=dnssec_validation,
        edns_payload=edns_payload,
        enable_ede=enable_ede,
        forward_local=forward_local,
        min_cache_ttl=min_cache_ttl,
        stats_collector=stats_collector,
        cache_plugin=cache_plugin,
        udp_cfg=udp_cfg,
        axfr_enabled=axfr_enabled,
        axfr_allow_clients=axfr_allow_clients,
        cfg_path=cfg_path,
        args=args,
    )
    if not _configure_dnssec_validation_resolver(
        logger=logger,
        dnssec_mode=dnssec_mode,
        dnssec_validation=dnssec_validation,
        resolver_mode=resolver_mode,
        upstreams=upstreams,
    ):
        return 1

    server = None
    udp_handle = None
    udp_thread: threading.Thread | None = None
    udp_error: Exception | None = None
    # Track background listener threads (UDP, TCP, DoT, etc.) uniformly so the
    # keepalive loop does not treat UDP as a special case.
    loop_threads: list[threading.Thread] = []

    # Shared resolver adapter for UDP listener.
    from .servers.server import resolve_query_bytes as _resolve_query_bytes

    def _resolve_udp(query_bytes: bytes, client_ip: str) -> bytes:
        """Brief: Resolve a DNS query received via UDP listener.

        Inputs:
          - query_bytes: Wire-format DNS query bytes.
          - client_ip: Client IP address string.

        Outputs:
          - bytes: Wire-format DNS response produced by the shared resolver.

        Notes:
          - Enforces the UDP response size ceiling (TC=1) after resolution so
            both asyncio and threaded UDP paths share consistent truncation
            behavior.
        """

        wire = _resolve_query_bytes(
            query_bytes,
            client_ip,
            listener="udp",
            secure=False,
        )

        try:
            from foghorn.runtime_config import get_runtime_snapshot
            from .servers.udp_server import enforce_udp_response_size_ceiling

            server_max = get_runtime_snapshot().udp_max_response_bytes
            wire = enforce_udp_response_size_ceiling(
                query_wire=query_bytes,
                response_wire=wire,
                server_max_bytes=server_max,
            )
        except Exception:
            pass

        return wire

    if bool(udp_cfg.get("enabled", True)):
        uhost = str(udp_cfg.get("host", default_host))
        uport = int(udp_cfg.get("port", default_port))

        # UDP listener defaults to asyncio. Threaded fallback is only allowed
        # on localhost or when allow_unsafe_threaded_listeners is true.
        allow_unsafe = bool(limits_cfg.get("allow_unsafe_threaded_listeners", False))
        from foghorn.security_limits import is_loopback_host

        is_loopback = is_loopback_host(uhost)
        # Default to asyncio everywhere. Config can override with explicit
        # use_asyncio setting.
        udp_use_asyncio = bool(udp_cfg.get("use_asyncio", True))

        # Allow threaded fallback only on localhost or when allow_unsafe is true.
        # If neither is true and threaded is needed due to PermissionError,
        # the server will refuse to start.
        allow_threaded_default = is_loopback or allow_unsafe
        allow_threaded_fallback = bool(
            udp_cfg.get("allow_threaded_fallback", allow_threaded_default)
        )
        exit_on_asyncio_failure = bool(
            udp_cfg.get("exit_on_asyncio_failure", False)
            or udp_cfg.get("refuse_threaded_fallback", False)
        )

        try:
            max_inflight = int(udp_cfg.get("max_inflight", 1024) or 1024)
        except Exception:
            max_inflight = 1024
        try:
            max_inflight_per_ip = int(udp_cfg.get("max_inflight_per_ip", 64) or 64)
        except Exception:
            max_inflight_per_ip = 64

        max_inflight_by_cidr = udp_cfg.get("max_inflight_by_cidr")
        if max_inflight_by_cidr is not None and not isinstance(
            max_inflight_by_cidr, list
        ):
            max_inflight_by_cidr = None

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

        if use_asyncio and udp_use_asyncio:
            try:
                from .servers.executors import get_resolver_executor
                from .servers.udp_asyncio_server import start_udp_asyncio_threaded

                logger.info(
                    "Starting UDP listener on %s:%d (asyncio)",
                    uhost,
                    uport,
                )

                udp_handle = start_udp_asyncio_threaded(
                    uhost,
                    uport,
                    _resolve_udp,
                    max_inflight=max_inflight,
                    max_inflight_per_ip=max_inflight_per_ip,
                    max_inflight_by_cidr=max_inflight_by_cidr,
                    executor=get_resolver_executor(),
                    thread_name="foghorn-udp",
                )
                udp_thread = udp_handle.thread
                loop_threads.append(udp_thread)
                runtime_state.set_listener("udp", enabled=True, thread=udp_thread)
            except PermissionError as exc:
                runtime_state.set_listener_error("udp", exc)
                if not allow_threaded_fallback or exit_on_asyncio_failure:
                    logger.error(
                        "Asyncio UDP listener failed with PermissionError and threaded fallback is disabled; exiting. Error: %s",
                        exc,
                    )
                    return 1

                logger.warning(
                    "Asyncio UDP listener failed with PermissionError; falling back to ThreadingUDPServer (less robust under DDoS). "
                    "Consider enabling asyncio UDP. Error: %s",
                    exc,
                )
            except Exception as exc:
                runtime_state.set_listener_error("udp", exc)
                logger.error("Failed to start asyncio UDP listener: %s", exc)
                return 1

        if udp_thread is None:
            # Threaded UDP (legacy fallback).
            from foghorn.security_limits import is_loopback_host

            allow_unsafe = bool(
                limits_cfg.get("allow_unsafe_threaded_listeners", False)
            )
            if not is_loopback_host(uhost) and not allow_unsafe:
                logger.error(
                    "Refusing to start threaded UDP listener on non-loopback host %s. "
                    "Enable UDP asyncio listener or set server.limits.allow_unsafe_threaded_listeners=true.",
                    uhost,
                )
                return 1

            from foghorn.servers.udp_server import DNSUDPHandler
            import socketserver as _socketserver

            server = _socketserver.ThreadingUDPServer((uhost, uport), DNSUDPHandler)
            server.daemon_threads = True

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
                "Starting UDP listener on %s:%d (threaded)",
                uhost,
                uport,
            )

            udp_thread = threading.Thread(
                target=_run_udp,
                name="foghorn-udp-threaded",
                daemon=True,
            )
            udp_thread.start()
            loop_threads.append(udp_thread)
            runtime_state.set_listener("udp", enabled=True, thread=udp_thread)

    if not bool(udp_cfg.get("enabled", True)):
        # When no UDP listener is configured, the main thread still enters the
        # keepalive loop below so that TCP/DoT/DoH listeners (or tests that
        # disable UDP entirely) can drive shutdown via signals or KeyboardInterrupt.
        logger.info(
            "Starting Foghorn without UDP listener; main thread will use keepalive loop",
        )

    # Optionally start TCP/DoT listeners based on listen config

    # Resolver adapter for TCP/DoT servers
    import asyncio

    def _resolve_tcp(query_bytes: bytes, client_ip: str) -> bytes:
        """Brief: Resolve a DNS query received via TCP listener.

        Inputs:
          - query_bytes: Wire-format DNS query bytes.
          - client_ip: Client IP address string.

        Outputs:
          - bytes: Wire-format DNS response produced by the shared resolver.
        """

        return _resolve_query_bytes(
            query_bytes,
            client_ip,
            listener="tcp",
            secure=False,
        )

    def _resolve_dot(query_bytes: bytes, client_ip: str) -> bytes:
        """Brief: Resolve a DNS query received via DoT (TLS) listener.

        Inputs:
          - query_bytes: Wire-format DNS query bytes.
          - client_ip: Client IP address string.

        Outputs:
          - bytes: Wire-format DNS response produced by the shared resolver.
        """

        return _resolve_query_bytes(
            query_bytes,
            client_ip,
            listener="dot",
            secure=True,
        )

    def _resolve_doh(query_bytes: bytes, client_ip: str) -> bytes:
        """Brief: Resolve a DNS query received via DoH (HTTPS) listener.

        Inputs:
          - query_bytes: Wire-format DNS query bytes.
          - client_ip: Client IP address string.

        Outputs:
          - bytes: Wire-format DNS response produced by the shared resolver.
        """

        return _resolve_query_bytes(
            query_bytes,
            client_ip,
            listener="doh",
            secure=True,
        )

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
        from foghorn.security_limits import is_loopback_host

        from .servers.tcp_server import serve_tcp, serve_tcp_threaded

        thost = str(tcp_cfg.get("host", default_host))
        tport = int(tcp_cfg.get("port", 53))

        def _start_tcp_threaded() -> None:
            allow_unsafe = bool(
                limits_cfg.get("allow_unsafe_threaded_listeners", False)
            )
            if not is_loopback_host(thost) and not allow_unsafe:
                raise RuntimeError(
                    "Refusing to start threaded TCP listener on non-loopback host. "
                    "Enable asyncio TCP listener or set server.limits.allow_unsafe_threaded_listeners=true."
                )
            serve_tcp_threaded(thost, tport, _resolve_tcp)

        if use_asyncio:
            logger.info("Starting TCP listener on %s:%d (asyncio)", thost, tport)
            _start_asyncio_server(
                lambda: serve_tcp(
                    thost,
                    tport,
                    _resolve_tcp,
                    max_connections=int(tcp_cfg.get("max_connections", 1024) or 1024),
                    max_connections_per_ip=int(
                        tcp_cfg.get("max_connections_per_ip", 64) or 64
                    ),
                    max_queries_per_connection=int(
                        tcp_cfg.get("max_queries_per_connection", 100) or 100
                    ),
                    idle_timeout_seconds=float(
                        tcp_cfg.get("idle_timeout_seconds", 15.0) or 15.0
                    ),
                ),
                name="foghorn-tcp",
                listener_key="tcp",
                on_permission_error=_start_tcp_threaded,
            )
        else:
            logger.info("Starting TCP listener on %s:%d (threaded)", thost, tport)
            allow_unsafe = bool(
                limits_cfg.get("allow_unsafe_threaded_listeners", False)
            )
            if not is_loopback_host(thost) and not allow_unsafe:
                logger.error(
                    "Refusing to start threaded TCP listener on non-loopback host %s. "
                    "Enable asyncio TCP listener or set server.limits.allow_unsafe_threaded_listeners=true.",
                    thost,
                )
                return 1
            t = threading.Thread(
                target=_start_tcp_threaded,
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
                    _resolve_dot,
                    cert_file=cert_file,
                    key_file=key_file,
                    max_connections=int(dot_cfg.get("max_connections", 1024) or 1024),
                    max_connections_per_ip=int(
                        dot_cfg.get("max_connections_per_ip", 64) or 64
                    ),
                    max_queries_per_connection=int(
                        dot_cfg.get("max_queries_per_connection", 100) or 100
                    ),
                    idle_timeout_seconds=float(
                        dot_cfg.get("idle_timeout_seconds", 15.0) or 15.0
                    ),
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

        allow_threaded_fallback = bool(doh_cfg.get("allow_threaded_fallback", True))
        try:
            # Start uvicorn-based DoH FastAPI server in background thread.
            doh_handle = start_doh_server(
                h,
                p,
                _resolve_doh,
                cert_file=cert_file,
                key_file=key_file,
                use_asyncio=use_asyncio,
                allow_threaded_fallback=allow_threaded_fallback,
            )
        except Exception as exc:
            runtime_state.set_listener_error("doh", exc)
            if isinstance(exc, (ImportError, ModuleNotFoundError)):
                logger.error(
                    "listen.doh.enabled=true but DoH dependencies are missing (%s). "
                    "Install fastapi+uvicorn or disable listen.doh.",
                    exc,
                )
            else:
                logger.error("Failed to start DoH server: %s", exc)
            return 1
        if doh_handle is None:
            runtime_state.set_listener_error("doh", "start_doh_server returned None")
            logger.error(
                "Fatal: listen.doh.enabled=true but start_doh_server returned None"
            )
            return 1

        runtime_state.set_listener("doh", enabled=True, thread=doh_handle)

    # Start admin HTTP webserver (FastAPI). When disabled, avoid importing the
    # FastAPI implementation so minimal/headless builds can omit it.
    if web_enabled:
        try:
            web_handle = start_webserver(
                stats_collector,
                cfg,
                log_buffer=web_log_buffer,
                config_path=cfg_path,
                runtime_state=runtime_state,
                plugins=plugins,
            )
        except Exception as exc:  # pragma: no cover - defensive
            runtime_state.set_listener_error("webserver", exc)
            if isinstance(exc, (ImportError, ModuleNotFoundError)):
                logger.error(
                    "server.http.enabled=true (or legacy http/webserver config present) but "
                    "admin webserver dependencies are missing (%s). Install fastapi+uvicorn or disable server.http.",
                    exc,
                )
            else:
                logger.error("Failed to start webserver: %s", exc)
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
        if udp_handle is not None:
            try:
                udp_handle.stop()
            except Exception:
                logger.exception("Unexpected error while stopping asyncio UDP listener")

        if server is not None:
            try:
                if hasattr(server, "stop"):
                    # Preferred path: delegate shutdown/close to the UDP server
                    # abstraction so all UDP-specific details live in the UDP
                    # module.
                    server.stop()
                elif hasattr(server, "shutdown") and hasattr(server, "server_close"):
                    # socketserver.ThreadingUDPServer and compatible servers.
                    try:
                        server.shutdown()
                    except Exception:
                        logger.exception("Error while shutting down UDP server")
                    try:
                        server.server_close()
                    except Exception:
                        logger.exception("Error while closing UDP server socket")
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

        # Clear in-process runtime snapshot state. This is mostly relevant for
        # unit tests that call main() multiple times in one Python process.
        try:
            from foghorn import runtime_config as _runtime_config

            _runtime_config.clear_runtime()
        except Exception:
            pass

        # Mark shutdown as complete so any pending hard-kill timers can detect
        # successful termination and avoid forcing an unnecessary SIGKILL.
        shutdown_complete.set()

    return exit_code


def start_doh_server(
    host: str,
    port: int,
    resolve_bytes,
    *,
    cert_file: str | None = None,
    key_file: str | None = None,
    use_asyncio: bool = True,
    allow_threaded_fallback: bool = True,
) -> object | None:
    """Brief: Start the optional DoH (DNS-over-HTTPS) server.

    This wrapper exists so tests can monkeypatch foghorn.main.start_doh_server
    without importing FastAPI/uvicorn at foghorn.main import time.

    Inputs:
      - host: Bind host.
      - port: Bind port.
      - resolve_bytes: Callable that takes (query_bytes, client_ip) and returns response bytes.
      - cert_file: Optional TLS certificate path.
      - key_file: Optional TLS private key path.
      - use_asyncio: When true, prefer asyncio; otherwise use threaded fallback when supported.
      - allow_threaded_fallback: When false, refuse to start the threaded fallback.

    Outputs:
      - object | None: A server handle/thread-like object, or None on failure.

    Example use:
      In tests, monkeypatch the wrapper symbol without importing FastAPI at import time:
        monkeypatch.setattr(foghorn.main, 'start_doh_server', fake_start)
    """

    from .servers.doh_api import start_doh_server as _start_doh_server

    return _start_doh_server(
        host,
        port,
        resolve_bytes,
        cert_file=cert_file,
        key_file=key_file,
        use_asyncio=use_asyncio,
        allow_threaded_fallback=allow_threaded_fallback,
    )


def start_webserver(
    stats_collector,
    cfg,
    *,
    log_buffer=None,
    config_path: str | None = None,
    runtime_state: RuntimeState | None = None,
    plugins: list[BasePlugin] | None = None,
) -> object | None:
    """Brief: Start the optional admin HTTP webserver.

    This wrapper exists so tests can monkeypatch foghorn.main.start_webserver
    without importing FastAPI/uvicorn at foghorn.main import time.

    Inputs:
      - stats_collector: StatsCollector instance or None.
      - cfg: Parsed config mapping.
      - log_buffer: Optional RingBuffer for recent logs.
      - config_path: Path to the loaded config file.
      - runtime_state: Optional RuntimeState for readiness endpoints.
      - plugins: Optional list of active plugins.

    Outputs:
      - object | None: A webserver handle/thread-like object, or None on failure.

    Example use:
      In tests, monkeypatch the wrapper symbol without importing FastAPI at import time:
        monkeypatch.setattr(foghorn.main, 'start_webserver', fake_start)
    """

    from .servers.webserver import start_webserver as _start_webserver

    return _start_webserver(
        stats_collector,
        cfg,
        log_buffer=log_buffer,
        config_path=config_path,
        runtime_state=runtime_state,
        plugins=plugins,
    )


def _env_first(*keys: str) -> str | None:
    """Brief: Return the first non-empty environment variable value.

    Inputs:
      - keys: Environment variable names to check in order.

    Outputs:
      - str | None: The first non-empty value, or None if none are set.
    """

    for key in keys:
        val = os.environ.get(key)
        if val:
            return str(val)
    return None


def _format_bytes(num_bytes: int) -> str:
    """Brief: Human-friendly bytes formatter.

    Inputs:
      - num_bytes: Size in bytes.

    Outputs:
      - str: Formatted size (e.g., '123B', '4.5KiB', '12.0MiB').

    Example:
      >>> _format_bytes(1024)
      '1.0KiB'
    """

    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    size = float(max(0, num_bytes))
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)}{unit}"
            return f"{size:.1f}{unit}"
        size /= 1024.0
    return f"{int(num_bytes)}B"


def _get_file_size_bytes(path: str) -> int | None:
    """Brief: Best-effort file size lookup.

    Inputs:
      - path: File path.

    Outputs:
      - int | None: Size in bytes, or None if not found/unreadable.
    """

    try:
        return int(os.stat(path).st_size)
    except Exception:
        return None


def _detect_docker_container_id() -> str | None:
    """Brief: Best-effort Docker container id detection.

    Inputs:
      - None.

    Outputs:
      - str | None: Container id (typically 12-64 hex chars), or None if not detected.

    Notes:
      - In Docker, HOSTNAME commonly equals the container id.
      - On modern Docker, cgroup entries may not include the container id;
        mountinfo parsing is used as a fallback.
    """

    candidate = os.environ.get("HOSTNAME")
    if candidate and re.fullmatch(r"[0-9a-f]{12,64}", candidate):
        return candidate

    if not os.path.exists("/.dockerenv"):
        return None
    try:
        with open("/proc/self/mountinfo", "r", encoding="utf-8") as f:
            for line in f:
                m = re.search(r"/docker/containers/([0-9a-f]{12,64})/", line)
                if m:
                    return m.group(1)
    except Exception:
        pass

    try:
        with open("/proc/self/cgroup", "r", encoding="utf-8") as f:
            for line in f:
                m = re.search(r"([0-9a-f]{12,64})", line)
                if m:
                    return m.group(1)
    except Exception:
        pass

    return None


def _log_startup_banner(logger: logging.Logger, *, config_path: str) -> None:
    """Brief: Log startup metadata immediately after logging is configured.

    Inputs:
      - logger: Logger to write startup messages to.
      - config_path: Path to the config file used for this run.

    Outputs:
      - None.
    """

    abs_cfg = os.path.abspath(config_path)
    cfg_size = _get_file_size_bytes(abs_cfg)
    cfg_size_str = (
        f"{cfg_size} bytes ({_format_bytes(cfg_size)})"
        if cfg_size is not None
        else "unknown"
    )

    hostname = socket.gethostname()
    arch = platform.machine() or "unknown"
    os_id = f"{platform.system()} {platform.release()}".strip()
    py_ver = sys.version.split()[0] if sys.version else "unknown"
    pid = os.getpid()

    container_id = _detect_docker_container_id()
    git_sha = _env_first("FOGHORN_GIT_SHA", "GIT_SHA")
    build_id = _env_first(
        "FOGHORN_BUILD_ID",
        "BUILD_ID",
        "FOGHORN_IMAGE_ID",
        "IMAGE_ID",
        "IMAGE_SHA",
        "DOCKER_IMAGE_SHA",
        "OCI_IMAGE_DIGEST",
        "IMAGE_DIGEST",
        "CONTAINER_IMAGE",
    )

    logger.info("Starting Foghorn")
    logger.info("  version=%s", FOGHORN_VERSION)
    logger.info("  config=%s (size=%s)", abs_cfg, cfg_size_str)
    logger.info("  hostname=%s", hostname)
    logger.info("  arch=%s", arch)
    logger.info("  os=%s", os_id)
    logger.info("  python=%s", py_ver)
    logger.info("  pid=%d", pid)
    if container_id:
        logger.info(
            "  container_id=%s",
            f"{container_id[:12]}[{container_id[12:]}]",
        )
    if build_id:
        logger.info("  image_or_build_id=%s", build_id)
    if git_sha:
        logger.info("  git_sha=%s", git_sha)


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

    default_host = str(raw_host)
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
    dot_default_enabled = True if isinstance(dot_section, dict) else False
    dot_cfg = _merge_listen_subsection(
        listen_cfg=listen_cfg,
        key="dot",
        defaults={"enabled": dot_default_enabled, "host": default_host, "port": 853},
    )

    doh_section = listen_cfg.get("doh")
    doh_default_enabled = True if isinstance(doh_section, dict) else False
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
) -> tuple[dict, str, int, int, int]:
    """Brief: Normalize resolver mode and timeout/depth settings.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - server_cfg: Parsed server config mapping.

    Outputs:
      - tuple: (resolver_cfg, resolver_mode, recursive_max_depth, recursive_timeout_ms, recursive_per_try_timeout_ms).
    """

    # Resolver configuration (forward vs recursive) with conservative defaults.
    resolver_cfg = server_cfg.get("resolver") or cfg.get("resolver") or {}
    if not isinstance(resolver_cfg, dict):
        raise ValueError("config.server.resolver must be a mapping when present")

    resolver_mode = str(resolver_cfg.get("mode", "forward")).lower()
    if resolver_mode == "none":
        resolver_mode = "master"
    try:
        recursive_max_depth = int(resolver_cfg.get("max_depth", 12))
    except (TypeError, ValueError):
        recursive_max_depth = 12
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
) -> tuple[list, list, int]:
    """Brief: Normalize upstream and timeout settings by resolver mode.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - resolver_mode: Effective resolver mode.
      - recursive_timeout_ms: Recursive timeout fallback.

    Outputs:
      - tuple[list, list, int]: (upstreams, upstream_backups, timeout_ms).
    """

    # Normalize upstream configuration only in forwarder mode.
    if resolver_mode == "forward":
        upstreams, timeout_ms = normalize_upstream_config(cfg)
        try:
            upstream_backups = normalize_upstream_backup_config(cfg)
        except Exception:
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
        logger.debug("Failed to configure resolver executor", exc_info=True)


def _load_cache_plugin_from_cfg(
    *,
    cfg: dict,
    server_cfg: dict,
) -> object | None:
    """Brief: Load configured cache plugin using v2 and legacy config fallbacks.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - server_cfg: Parsed server config mapping.

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
    except Exception:
        cache_plugin = None
    return cache_plugin


def _install_cache_plugin_global(cache_plugin: object | None) -> None:
    """Brief: Install cache plugin into global resolver cache slot, best effort.

    Inputs:
      - cache_plugin: Cache plugin instance or None.

    Outputs:
      - None.
    """

    # Install the configured cache plugin globally so alfoghorn.servers.transports (UDP/TCP/DoT/DoH)
    # share it, even when the UDP DNSServer is not started.
    if cache_plugin is not None:
        try:
            from foghorn.plugins.resolve import base as plugin_base

            plugin_base.DNS_CACHE = cache_plugin  # type: ignore[assignment]
        except Exception:
            pass


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


def _build_effective_persistence_cfg(
    *,
    cfg: dict,
    stats_cfg: dict,
) -> dict[str, object]:
    """Brief: Compute effective stats persistence config from logging.backends.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - stats_cfg: Parsed stats configuration mapping.

    Outputs:
      - dict[str, object]: Mapping suitable for load_stats_store_backend().
    """

    logging_block = cfg.get("logging") or {}
    if not isinstance(logging_block, dict):
        return {}

    backends_cfg = logging_block.get("backends") or []
    if not isinstance(backends_cfg, list) or not backends_cfg:
        return {}

    async_default = bool(logging_block.get("async", True))

    primary_hint = stats_cfg.get("source_backend")
    primary_backend = str(primary_hint).strip() if isinstance(primary_hint, str) else ""

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


def _initialize_statistics_subsystem(
    *,
    cfg: dict,
    logging_cfg: dict,
    args: argparse.Namespace,
    logger: logging.Logger,
) -> tuple[Optional[StatsCollector], Optional[StatsReporter], Optional[BaseStatsStore]]:
    """Brief: Initialize stats collector/reporter/store from configuration.

    Inputs:
      - cfg: Parsed root configuration mapping.
      - logging_cfg: Parsed logging configuration mapping.
      - args: Parsed CLI args.
      - logger: Logger for startup diagnostics.

    Outputs:
      - tuple[Optional[StatsCollector], Optional[StatsReporter], Optional[BaseStatsStore]]:
        Initialized stats components (None when stats are disabled/unavailable).
    """

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
            backend_cfg: dict[str, object] = _build_effective_persistence_cfg(
                cfg=cfg,
                stats_cfg=stats_cfg,
            )
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

    return stats_collector, stats_reporter, stats_persistence_store


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

    web_cfg = server_http or cfg.get("http") or cfg.get("webserver", {}) or {}
    if not isinstance(web_cfg, dict):
        web_cfg = {}
    # If a http block exists, default enabled to True unless explicitly disabled
    # with enabled: false. This mirrors the listener expectations and
    # start_webserver() behaviour.
    has_web_cfg = bool(web_cfg)
    raw_web_enabled = web_cfg.get("enabled") if isinstance(web_cfg, dict) else None
    web_enabled = bool(raw_web_enabled) if raw_web_enabled is not None else has_web_cfg
    return web_cfg, web_enabled


def _initialize_runtime_snapshot(
    *,
    logger: logging.Logger,
    cfg: dict,
    plugins: list[BasePlugin],
    upstreams: list,
    upstream_backups: list,
    upstream_health,
    timeout_ms: int,
    upstream_strategy: str,
    upstream_max_concurrent: int,
    resolver_mode: str,
    recursive_max_depth: int,
    recursive_timeout_ms: int,
    recursive_per_try_timeout_ms: int,
    dnssec_mode: str,
    dnssec_validation: str,
    edns_payload: int,
    enable_ede: bool,
    forward_local: bool,
    min_cache_ttl: int,
    stats_collector: Optional[StatsCollector],
    cache_plugin: object | None,
    udp_cfg: dict,
    axfr_enabled: bool,
    axfr_allow_clients: list[str],
    cfg_path: str,
    args: argparse.Namespace,
) -> None:
    """Brief: Initialize process-wide runtime snapshot, best effort.

    Inputs:
      - logger: Logger for debug output on failure.
      - cfg: Parsed root configuration mapping.
      - plugins: Active plugin instances.
      - upstreams: Normalized primary upstream list.
      - upstream_backups: Normalized backup upstream list.
      - upstream_health: Parsed upstream health config.
      - timeout_ms: Effective upstream timeout.
      - upstream_strategy: Effective upstream strategy.
      - upstream_max_concurrent: Effective max concurrent upstream requests.
      - resolver_mode: Effective resolver mode.
      - recursive_max_depth: Recursive resolver max depth.
      - recursive_timeout_ms: Recursive resolver timeout.
      - recursive_per_try_timeout_ms: Per-try recursive timeout.
      - dnssec_mode: DNSSEC mode.
      - dnssec_validation: DNSSEC validation mode.
      - edns_payload: Effective EDNS UDP payload size.
      - enable_ede: EDE feature toggle.
      - forward_local: .local forwarding toggle.
      - min_cache_ttl: Cache TTL floor.
      - stats_collector: Stats collector instance or None.
      - cache_plugin: Cache plugin instance or None.
      - udp_cfg: UDP listener config.
      - axfr_enabled: AXFR enable flag.
      - axfr_allow_clients: AXFR allowlist client entries.
      - cfg_path: Active config file path.
      - args: Parsed CLI args.

    Outputs:
      - None.
    """

    # Initialize the in-process runtime snapshot before starting any listeners
    # so that shared resolver paths (UDP/TCP/DoT/DoH) can consult a consistent,
    # per-request configuration snapshot.
    try:
        import time as _time

        udp_max_response_bytes = None
        try:
            raw_udp_max = (
                udp_cfg.get("max_response_bytes") if isinstance(udp_cfg, dict) else None
            )
            if raw_udp_max is not None:
                udp_max_response_bytes = int(raw_udp_max)
        except Exception:
            udp_max_response_bytes = None

        snapshot = RuntimeSnapshot(
            cfg=cfg,
            plugins=list(plugins or []),
            upstream_addrs=list(upstreams or []),
            upstream_backup_addrs=list(upstream_backups or []),
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
            edns_udp_payload=max(512, int(edns_payload)),
            enable_ede=bool(enable_ede),
            forward_local=bool(forward_local),
            min_cache_ttl=int(min_cache_ttl),
            # Cache prefetch is not config-plumbed yet; keep defaults.
            cache_prefetch_enabled=False,
            cache_prefetch_min_ttl=0,
            cache_prefetch_max_ttl=0,
            cache_prefetch_refresh_before_expiry=0.0,
            cache_prefetch_allow_stale_after_expiry=0.0,
            stats_collector=stats_collector,
            cache_plugin=cache_plugin,
            udp_max_response_bytes=udp_max_response_bytes,
            axfr_enabled=bool(axfr_enabled),
            axfr_allow_clients=list(axfr_allow_clients or []),
            generation=1,
            applied_at_epoch=_time.time(),
        )
        initialize_runtime(
            snapshot=snapshot,
            config_path=cfg_path,
            cli_vars=list(getattr(args, "var", []) or []),
            unknown_keys_policy=str(getattr(args, "config_extras", "warn") or "warn"),
        )
    except Exception:
        logger.debug("Failed to initialize runtime snapshot", exc_info=True)


def _configure_dnssec_validation_resolver(
    *,
    logger: logging.Logger,
    dnssec_mode: str,
    dnssec_validation: str,
    resolver_mode: str,
    upstreams: list,
) -> bool:
    """Brief: Configure DNSSEC validator resolver routing.

    Inputs:
      - logger: Logger for dependency/mode diagnostics.
      - dnssec_mode: Effective DNSSEC mode.
      - dnssec_validation: DNSSEC validation strategy.
      - resolver_mode: Effective resolver mode.
      - upstreams: Normalized forward upstreams.

    Outputs:
      - bool: True when startup should continue; False on fatal dependency errors.
    """

    if dnssec_mode == "validate" and dnssec_validation in {"local", "local_extended"}:
        try:
            from foghorn.dnssec.dnssec_validate import (
                configure_dnssec_resolver as _configure_dnssec_resolver,
            )
        except Exception as exc:
            logger.error(
                "DNSSEC validation is enabled (dnssec.mode=validate, dnssec.validation=%s) "
                "but required dependencies are missing (%s). Install dnspython+cryptography or disable DNSSEC validation.",
                dnssec_validation,
                exc,
            )
            return False

        if resolver_mode == "forward":
            upstream_hosts = [
                str(u["host"]) for u in upstreams if isinstance(u, dict) and "host" in u
            ]
            _configure_dnssec_resolver(upstream_hosts or None)
        else:
            # Empty list is a sentinel telling foghorn.dnssec.dnssec_validate to use
            # RecursiveResolver for all validation lookups.
            _configure_dnssec_resolver([])
    else:
        # DNSSEC validation is not using local lookups. Avoid importing dnspython
        # at startup so minimal/headless builds can omit it.
        try:
            from foghorn.dnssec.dnssec_validate import (
                configure_dnssec_resolver as _configure_dnssec_resolver,
            )

            _configure_dnssec_resolver(None)
        except Exception:
            pass

    return True


def _install_signal_handler(
    *,
    sig,
    handler,
    logger: logging.Logger,
    success_log: str,
    failure_log: str,
) -> None:
    """Brief: Install a signal handler with consistent logging.

    Inputs:
      - sig: Signal constant from signal module.
      - handler: Callable signal handler.
      - logger: Logger for success/failure messages.
      - success_log: Debug message when handler installation succeeds.
      - failure_log: Warning message when installation fails.

    Outputs:
      - None.
    """

    try:
        signal.signal(sig, handler)
        logger.debug(success_log)
    except Exception:
        logger.warning(failure_log)


if __name__ == "__main__":
    raise SystemExit(
        main()
    )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
