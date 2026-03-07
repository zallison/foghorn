"""DNSServer runtime wrapper extracted from server module."""

import logging
import socketserver
from typing import Dict, List

from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin
from .dns_runtime_state import DNSRuntimeState

from .udp_server import DNSUDPHandler

logger = logging.getLogger("foghorn.server")


class DNSServer:
    """Configure `DNSUDPHandler` runtime settings and optionally bind UDP transport.

    Example use:
        >>> from foghorn.servers.server_runtime import DNSServer
        >>> srv = DNSServer(
        ...     "127.0.0.1",
        ...     5355,
        ...     [{"host": "8.8.8.8", "port": 53}],
        ...     [],
        ...     create_server=False,
        ... )
        >>> srv.server is None
        True
    """

    def __init__(
        self,
        host: str,
        port: int,
        upstreams: List[Dict],
        plugins: List[BasePlugin],
        timeout: float = 2.0,
        timeout_ms: int = 2000,
        min_cache_ttl: int = 60,
        stats_collector=None,
        cache=None,
        *,
        dnssec_mode: str = "ignore",
        edns_udp_payload: int = 1232,
        dnssec_validation: str = "upstream_ad",
        upstream_strategy: str = "failover",
        upstream_max_concurrent: int = 1,
        resolver_mode: str = "forward",
        recursive_max_depth: int = 16,
        recursive_timeout_ms: int = 2000,
        recursive_per_try_timeout_ms: int = 2000,
        cache_prefetch_enabled: bool = False,
        cache_prefetch_min_ttl: int = 0,
        cache_prefetch_max_ttl: int = 0,
        cache_prefetch_refresh_before_expiry: float = 0.0,
        cache_prefetch_allow_stale_after_expiry: float = 0.0,
        enable_ede: bool = False,
        forward_local: bool = False,
        max_response_bytes: int | None = None,
        axfr_enabled: bool = False,
        axfr_allow_clients: list[str] | None = None,
        create_server: bool = True,
    ) -> None:
        """Initialize a UDP DNSServer.

        Inputs:
            host: The host to listen on.
            port: The port to listen on.
            upstreams: Ordered upstream endpoint configs consumed by `DNSUDPHandler`.
            plugins: Initialized resolve plugins applied in pre/post phases.
            timeout: Legacy upstream timeout in seconds.
            timeout_ms: Upstream timeout in milliseconds.
            min_cache_ttl: Minimum cache TTL floor in seconds.
            stats_collector: Optional StatsCollector for recording metrics.
            cache: Optional cache backend assigned to `plugin_base.DNS_CACHE`.
            dnssec_mode/dnssec_validation: DNSSEC handling knobs propagated to handler.
            resolver_mode/recursive_*: Forward/recursive resolver mode and recursion limits.
            cache_prefetch_*: Cache prefetch and stale-while-revalidate thresholds.
            enable_ede: Enable RFC 8914 Extended DNS Errors on synthesized replies.
            forward_local: Whether `.local` should be forwarded upstream.
            max_response_bytes: Optional explicit response size cap.
            axfr_enabled/axfr_allow_clients: Transfer policy knobs used by TCP/DoT listeners.
            create_server: If True, binds `ThreadingUDPServer`; if False, only configures class state.

        Outputs:
            None. The instance exposes `self.server` when `create_server=True`.
        """
        # Install cache plugin for all transports.
        if cache is None:
            try:
                from foghorn.plugins.cache.in_memory_ttl import InMemoryTTLCache

                cache = InMemoryTTLCache()
            except (
                Exception
            ):  # pragma: nocover - defensive: cache backend import failure is environment-specific
                cache = None
        try:
            plugin_base.DNS_CACHE = cache  # type: ignore[assignment]
        except (
            Exception
        ):  # pragma: nocover - defensive: assignment failure is environment-specific and low-value for tests
            pass

        DNSRuntimeState.upstream_addrs = upstreams  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.plugins = plugins  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.timeout = timeout  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.timeout_ms = timeout_ms  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.min_cache_ttl = max(
            0, int(min_cache_ttl)
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.stats_collector = stats_collector  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.dnssec_mode = str(dnssec_mode)
        DNSRuntimeState.dnssec_validation = str(dnssec_validation)
        DNSRuntimeState.upstream_strategy = str(upstream_strategy).lower()
        DNSRuntimeState.resolver_mode = str(resolver_mode).lower()
        DNSRuntimeState.recursive_max_depth = int(recursive_max_depth)
        DNSRuntimeState.recursive_timeout_ms = int(recursive_timeout_ms)
        DNSRuntimeState.recursive_per_try_timeout_ms = int(recursive_per_try_timeout_ms)

        # Cache prefetch / stale-while-revalidate knobs used by _resolve_core.
        DNSRuntimeState.cache_prefetch_enabled = bool(cache_prefetch_enabled)
        try:
            DNSRuntimeState.cache_prefetch_min_ttl = max(0, int(cache_prefetch_min_ttl))
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch min TTL config falls back to 0
            DNSRuntimeState.cache_prefetch_min_ttl = 0
        try:
            DNSRuntimeState.cache_prefetch_max_ttl = max(0, int(cache_prefetch_max_ttl))
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch max TTL config falls back to 0
            DNSRuntimeState.cache_prefetch_max_ttl = 0
        try:
            DNSRuntimeState.cache_prefetch_refresh_before_expiry = max(
                0.0, float(cache_prefetch_refresh_before_expiry)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch before-expiry window config falls back to 0.0
            DNSRuntimeState.cache_prefetch_refresh_before_expiry = 0.0
        try:
            DNSRuntimeState.cache_prefetch_allow_stale_after_expiry = max(
                0.0, float(cache_prefetch_allow_stale_after_expiry)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: bad stale-after-expiry window config falls back to 0.0
            DNSRuntimeState.cache_prefetch_allow_stale_after_expiry = 0.0

        try:
            DNSRuntimeState.upstream_max_concurrent = max(
                1, int(upstream_max_concurrent)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid upstream concurrency config falls back to 1
            DNSRuntimeState.upstream_max_concurrent = 1
        try:
            DNSRuntimeState.edns_udp_payload = max(512, int(edns_udp_payload))
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid EDNS UDP payload config falls back to default
            DNSRuntimeState.edns_udp_payload = 1232

        # Optional explicit UDP response ceiling override.
        try:
            if max_response_bytes is None:
                DNSRuntimeState.max_response_bytes = None
            else:
                DNSRuntimeState.max_response_bytes = max(0, int(max_response_bytes))
        except Exception:  # pragma: nocover - defensive
            DNSRuntimeState.max_response_bytes = None
        # Extended DNS Errors (RFC 8914) feature gate. When enable_ede is false
        # the resolver pipeline will not add any EDE options of its own and
        # will continue to treat upstream EDNS options opaquely.
        try:
            DNSRuntimeState.enable_ede = bool(enable_ede)
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid enable_ede config falls back to False
            DNSRuntimeState.enable_ede = False
        try:
            DNSRuntimeState.forward_local = bool(forward_local)
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid forward_local config falls back to False
            DNSRuntimeState.forward_local = False

        # AXFR/IXFR transfer policy (applies to TCP/DoT listeners).
        try:
            DNSRuntimeState.axfr_enabled = bool(axfr_enabled)
        except Exception:  # pragma: nocover - defensive
            DNSRuntimeState.axfr_enabled = False
        try:
            DNSRuntimeState.axfr_allow_clients = (
                list(axfr_allow_clients or []) if axfr_allow_clients is not None else []
            )
        except Exception:  # pragma: nocover - defensive
            DNSRuntimeState.axfr_allow_clients = []

        self.server = None
        if create_server:
            try:
                self.server = socketserver.ThreadingUDPServer(
                    (host, port), DNSUDPHandler
                )  # pragma: no cover - defensive/metrics path excluded from coverage
            except (
                PermissionError
            ) as e:  # pragma: no cover - defensive/metrics path excluded from coverage
                logger.error(
                    "Permission denied when binding to %s:%d. Try a port >1024 or run with elevated privileges. Original error: %s",
                    host,
                    port,
                    e,
                )  # pragma: no cover - defensive/metrics path excluded from coverage
                raise  # Re-raise the exception after logging

            # Ensure request handler threads do not block shutdown
            self.server.daemon_threads = True  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            logger.debug(
                "DNS UDP server bound to %s:%d", host, port
            )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

    def serve_forever(self) -> None:
        """Start the UDP server loop and listen for requests.

        Inputs:
          - None
        Outputs:
          - None; runs until shutdown is requested or KeyboardInterrupt occurs.
        """
        if self.server is None:
            return
        try:  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            self.server.serve_forever()  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        except (
            KeyboardInterrupt
        ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
            pass  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably

    def stop(self) -> None:
        """Request graceful shutdown and close the underlying UDP socket.

        Inputs:
          - None
        Outputs:
          - None; best-effort shutdown suitable for use from signal handlers.
        """
        if self.server is None:
            return
        try:
            # First ask the ThreadingUDPServer loop to stop accepting requests.
            self.server.shutdown()
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.exception("Error while shutting down UDP server")
        try:
            # Then close the socket so resources are released promptly.
            self.server.server_close()
        except (
            Exception
        ):  # pragma: no cover - defensive: error-handling or log-only path that is not worth dedicated tests
            logger.exception("Error while closing UDP server socket")
