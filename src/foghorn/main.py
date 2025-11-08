from __future__ import annotations
import importlib
import sys
import argparse
import logging
from typing import List, Tuple, Dict, Union, Any
import yaml
from unittest.mock import patch, mock_open

from .server import DNSServer
from .plugins.base import BasePlugin
from .logging_config import init_logging
from .plugins.registry import discover_plugins, get_plugin_class
from .stats import StatsCollector, StatsReporter


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
    Normalize upstream configuration to a list-of-endpoints plus a timeout.

    Inputs:
      - cfg: dict containing parsed YAML. Supports:
          - cfg['upstream'] as either:
              * dict with keys host, port, optional timeout_ms (legacy), or
              * list of {host, port} entries (new format)
          - cfg['timeout_ms'] at top level (new preferred location)

    Outputs:
      - (upstreams, timeout_ms): tuple where
          - upstreams: list[dict] with keys {'host': str, 'port': int}
          - timeout_ms: int timeout in milliseconds applied per upstream attempt

    Notes:
      - If both top-level timeout_ms and legacy upstream.timeout_ms are present, top-level wins.
      - If none provided, default to 2000 ms.

    Example:
      upstreams, timeout = normalize_upstream_config({
          'upstream': [{'host': '1.1.1.1', 'port': 53}, {'host': '1.0.0.1', 'port': 53}],
          'timeout_ms': 1500
      })
      # upstreams -> [{'host': '1.1.1.1', 'port': 53}, {'host': '1.0.0.1', 'port': 53}]
      # timeout -> 1500
    """
    upstream_raw = cfg.get("upstream", {})
    top_level_timeout = cfg.get("timeout_ms")
    legacy_warned = False

    # Handle upstream format (dict vs list)
    if isinstance(upstream_raw, list):
        # New format: list of upstream objects
        upstreams = []
        for u in upstream_raw:
            if not isinstance(u, dict):
                continue
            # Support DoH entries that specify a URL instead of host/port
            if str(u.get("transport", "")).lower() == "doh" and "url" in u:
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
            # Default host/port-based upstream (udp/tcp/dot)
            if "host" in u:
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
    elif isinstance(upstream_raw, dict):
        # Legacy format: single upstream object
        if "host" in upstream_raw:
            rec: Dict[str, Union[str, int, dict]] = {
                "host": str(upstream_raw["host"]),
                "port": int(upstream_raw.get("port", 53)),
            }
            if "transport" in upstream_raw:
                rec["transport"] = str(upstream_raw.get("transport"))
            if "tls" in upstream_raw and isinstance(upstream_raw["tls"], dict):
                rec["tls"] = upstream_raw["tls"]
            upstreams = [rec]
        else:
            # Default fallback
            upstreams = [{"host": "1.1.1.1", "port": 53}]  # pragma: no cover
    else:
        # Default fallback
        upstreams = [{"host": "1.1.1.1", "port": 53}]

    # Handle timeout precedence
    if top_level_timeout is not None:
        timeout_ms = int(top_level_timeout)
        # Check for legacy timeout and warn if both present
        if (
            isinstance(upstream_raw, dict)
            and "timeout_ms" in upstream_raw
            and not legacy_warned
        ):
            logging.getLogger("foghorn.main").warning(
                "Both top-level timeout_ms and legacy upstream.timeout_ms provided; using top-level timeout_ms"
            )
            legacy_warned = True
    elif isinstance(upstream_raw, dict) and "timeout_ms" in upstream_raw:
        timeout_ms = int(upstream_raw["timeout_ms"])
    else:
        timeout_ms = 2000  # Default

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
    args = parser.parse_args(argv)

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f) or {}

    # Initialize logging before any other operations
    init_logging(cfg.get("logging"))
    logger = logging.getLogger("foghorn.main")
    logger.info("Loaded config from %s", args.config)

    # Normalize listen configuration with backward compatibility.
    # If listen.udp is present, prefer it; otherwise fall back to legacy listen.host/port.
    listen_cfg = cfg.get("listen", {}) or {}
    legacy_host = str(listen_cfg.get("host", "127.0.0.1"))
    legacy_port = int(listen_cfg.get("port", 5353))

    def _sub(key, defaults):
        d = listen_cfg.get(key, {}) or {}
        out = {**defaults, **d} if isinstance(d, dict) else defaults
        return out

    udp_cfg = _sub("udp", {"enabled": True, "host": legacy_host, "port": legacy_port})
    tcp_cfg = _sub("tcp", {"enabled": False, "host": legacy_host, "port": 53})
    dot_cfg = _sub("dot", {"enabled": False, "host": legacy_host, "port": 853})
    doh_cfg = _sub("doh", {"enabled": False, "host": legacy_host, "port": 8053})

    # Normalize upstream configuration
    upstreams, timeout_ms = normalize_upstream_config(cfg)
    min_cache_ttl = _get_min_cache_ttl(cfg)

    plugins = load_plugins(cfg.get("plugins", []))
    logger.info(
        "Loaded %d plugins: %s", len(plugins), [p.__class__.__name__ for p in plugins]
    )

    # Initialize statistics collection if enabled
    stats_cfg = cfg.get("statistics", {})
    stats_enabled = stats_cfg.get("enabled", False)
    stats_collector = None
    stats_reporter = None

    if stats_enabled:
        stats_collector = StatsCollector(
            track_uniques=stats_cfg.get("track_uniques", True),
            include_qtype_breakdown=stats_cfg.get("include_qtype_breakdown", True),
            include_top_clients=stats_cfg.get("include_top_clients", False),
            include_top_domains=stats_cfg.get("include_top_domains", False),
            top_n=int(stats_cfg.get("top_n", 10)),
            track_latency=stats_cfg.get("track_latency", False),
        )

        stats_reporter = StatsReporter(
            collector=stats_collector,
            interval_seconds=int(stats_cfg.get("interval_seconds", 10)),
            reset_on_log=stats_cfg.get("reset_on_log", False),
            log_level=stats_cfg.get("log_level", "info"),
        )
        stats_reporter.start()
        logger.info(
            "Statistics collection enabled (interval: %ds)",
            stats_reporter.interval_seconds,
        )

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
        except Exception:
            pass  # pragma: no cover

    # Log startup info
    upstream_info = ", ".join([f"{u['host']}:{u['port']}" for u in upstreams])
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
    from .server import resolve_query_bytes
    import threading
    import asyncio

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

        t = threading.Thread(target=runner, name=name, daemon=True)
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
        from .doh_server import serve_doh

        h = str(doh_cfg.get("host", legacy_host))
        p = int(doh_cfg.get("port", 8053))
        cert_file = doh_cfg.get("cert_file")
        key_file = doh_cfg.get("key_file")
        logger.info("Starting DoH listener on %s:%d", h, p)
        _start_asyncio_server(
            lambda: serve_doh(
                h,
                p,
                resolve_query_bytes,
                cert_file=cert_file,
                key_file=key_file,
            ),
            name="foghorn-doh",
        )

    try:
        if server is not None:
            server.serve_forever()
        else:
            # No UDP server; keep main thread alive while async listeners run
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
        # Stop statistics reporter on shutdown
        if stats_reporter is not None:
            logger.info("Stopping statistics reporter")
            stats_reporter.stop()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())  # pragma: no cover
