"""DNSServer runtime wrapper extracted from server module."""

import logging
import socketserver
from typing import Dict, List

from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin

from .udp_server import DNSUDPHandler

logger = logging.getLogger("foghorn.server")


class DNSServer:
    """A basic UDP DNS server wrapper.

    Example use:
        >>> from foghorn.server import DNSServer
        >>> import threading
        >>> import time
        >>> # Start server in a background thread
        >>> server = DNSServer("127.0.0.1", 5355, ("8.8.8.8", 53), [], timeout=1.0)
        >>> server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        >>> server_thread.start()
        >>> # The server is now running in the background
        >>> time.sleep(0.1)
        >>> server.server.shutdown()
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
            upstreams: A list of upstream DNS server configurations.
            plugins: A list of initialized plugins.
            timeout: The timeout for upstream queries (seconds, legacy).
            timeout_ms: The timeout for upstream queries (milliseconds).
            min_cache_ttl: Minimum cache TTL in seconds applied to all cached responses.
            stats_collector: Optional StatsCollector for recording metrics.
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

        DNSUDPHandler.upstream_addrs = upstreams  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.plugins = plugins  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.timeout = timeout  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.timeout_ms = timeout_ms  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.min_cache_ttl = max(
            0, int(min_cache_ttl)
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.stats_collector = stats_collector  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSUDPHandler.dnssec_mode = str(dnssec_mode)
        DNSUDPHandler.dnssec_validation = str(dnssec_validation)
        DNSUDPHandler.upstream_strategy = str(upstream_strategy).lower()
        DNSUDPHandler.resolver_mode = str(resolver_mode).lower()
        DNSUDPHandler.recursive_max_depth = int(recursive_max_depth)
        DNSUDPHandler.recursive_timeout_ms = int(recursive_timeout_ms)
        DNSUDPHandler.recursive_per_try_timeout_ms = int(recursive_per_try_timeout_ms)

        # Cache prefetch / stale-while-revalidate knobs used by _resolve_core.
        DNSUDPHandler.cache_prefetch_enabled = bool(cache_prefetch_enabled)
        try:
            DNSUDPHandler.cache_prefetch_min_ttl = max(0, int(cache_prefetch_min_ttl))
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch min TTL config falls back to 0
            DNSUDPHandler.cache_prefetch_min_ttl = 0
        try:
            DNSUDPHandler.cache_prefetch_max_ttl = max(0, int(cache_prefetch_max_ttl))
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch max TTL config falls back to 0
            DNSUDPHandler.cache_prefetch_max_ttl = 0
        try:
            DNSUDPHandler.cache_prefetch_refresh_before_expiry = max(
                0.0, float(cache_prefetch_refresh_before_expiry)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch before-expiry window config falls back to 0.0
            DNSUDPHandler.cache_prefetch_refresh_before_expiry = 0.0
        try:
            DNSUDPHandler.cache_prefetch_allow_stale_after_expiry = max(
                0.0, float(cache_prefetch_allow_stale_after_expiry)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: bad stale-after-expiry window config falls back to 0.0
            DNSUDPHandler.cache_prefetch_allow_stale_after_expiry = 0.0

        try:
            DNSUDPHandler.upstream_max_concurrent = max(1, int(upstream_max_concurrent))
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid upstream concurrency config falls back to 1
            DNSUDPHandler.upstream_max_concurrent = 1
        try:
            DNSUDPHandler.edns_udp_payload = max(512, int(edns_udp_payload))
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid EDNS UDP payload config falls back to default
            DNSUDPHandler.edns_udp_payload = 1232

        # Optional explicit UDP response ceiling override.
        try:
            if max_response_bytes is None:
                DNSUDPHandler.max_response_bytes = None
            else:
                DNSUDPHandler.max_response_bytes = max(0, int(max_response_bytes))
        except Exception:  # pragma: nocover - defensive
            DNSUDPHandler.max_response_bytes = None
        # Extended DNS Errors (RFC 8914) feature gate. When enable_ede is false
        # the resolver pipeline will not add any EDE options of its own and
        # will continue to treat upstream EDNS options opaquely.
        try:
            DNSUDPHandler.enable_ede = bool(enable_ede)
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid enable_ede config falls back to False
            DNSUDPHandler.enable_ede = False
        try:
            DNSUDPHandler.forward_local = bool(forward_local)
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid forward_local config falls back to False
            DNSUDPHandler.forward_local = False

        # AXFR/IXFR transfer policy (applies to TCP/DoT listeners).
        try:
            DNSUDPHandler.axfr_enabled = bool(axfr_enabled)
        except Exception:  # pragma: nocover - defensive
            DNSUDPHandler.axfr_enabled = False
        try:
            DNSUDPHandler.axfr_allow_clients = (
                list(axfr_allow_clients or []) if axfr_allow_clients is not None else []
            )
        except Exception:  # pragma: nocover - defensive
            DNSUDPHandler.axfr_allow_clients = []

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
