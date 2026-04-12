"""DNSServer runtime wrapper extracted from server module."""

import ipaddress

import logging
import socketserver
from urllib.parse import urlparse
from typing import Dict, List

from foghorn.plugins.resolve import base as plugin_base
from foghorn.plugins.resolve.base import BasePlugin
from .dns_runtime_state import DNSRuntimeState

from .udp_server import DNSUDPHandler

logger = logging.getLogger("foghorn.server")
_VALID_DNSSEC_MODES = {"ignore", "passthrough", "validate"}
_VALID_DNSSEC_VALIDATION = {"upstream_ad", "local", "local_extended"}
_VALID_UPSTREAM_TRANSPORTS = {"udp", "tcp", "dot", "doh"}
_MAX_RECURSIVE_DEPTH = 32


def _normalize_dnssec_mode(value: object) -> str:
    """Brief: Normalize dnssec mode to a known value.

    Inputs:
      - value: Candidate mode value from runtime config.
    Outputs:
      - str: One of ignore/passthrough/validate, defaulting to ignore.
    """
    mode = str(value or "ignore").strip().lower()
    if mode not in _VALID_DNSSEC_MODES:
        logger.warning(
            "Invalid dnssec_mode=%r; using default %r",
            value,
            "ignore",
        )
        return "ignore"
    return mode


def _normalize_dnssec_validation(value: object) -> str:
    """Brief: Normalize dnssec validation mode to a known value.

    Inputs:
      - value: Candidate validation value from runtime config.
    Outputs:
      - str: One of upstream_ad/local/local_extended, defaulting to upstream_ad.
    """
    validation = str(value or "upstream_ad").strip().lower()
    if validation not in _VALID_DNSSEC_VALIDATION:
        logger.warning(
            "Invalid dnssec_validation=%r; using default %r",
            value,
            "upstream_ad",
        )
        return "upstream_ad"
    return validation


def _validate_axfr_allow_clients(entries: object) -> list[str]:
    """Brief: Validate and normalize AXFR client CIDR allowlist entries.

    Inputs:
      - entries: Candidate iterable of CIDR/IP strings.
    Outputs:
      - list[str]: Canonical CIDR strings parsed successfully.
    """
    if entries is None:
        return []
    validated: list[str] = []
    try:
        iterable = list(entries)  # type: ignore[arg-type]
    except Exception as exc:
        logger.warning("Invalid axfr_allow_clients; using empty allowlist: %s", exc)
        return []
    for idx, entry in enumerate(iterable):
        text = str(entry or "").strip()
        if not text:
            continue
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            logger.warning("Ignoring invalid axfr_allow_clients entry at index %d", idx)
            continue
        validated.append(str(network))
    return validated


def _validate_upstreams(upstreams: object) -> list[dict]:
    """Brief: Validate upstream endpoint entries before runtime use.

    Inputs:
      - upstreams: Candidate list of upstream endpoint mappings.
    Outputs:
      - list[dict]: Validated upstream mappings safe for runtime failover logic.
    """
    if upstreams is None:
        return []
    if not isinstance(upstreams, list):
        logger.warning(
            "Invalid upstreams value type %s; using empty list", type(upstreams)
        )
        return []
    validated: list[dict] = []
    for idx, item in enumerate(upstreams):
        if not isinstance(item, dict):
            entry_type = type(item).__name__
            logger.warning(
                "Ignoring upstream[%d]: expected mapping, got %s", idx, entry_type
            )
            continue
        record = dict(item)
        transport = str(record.get("transport", "udp") or "udp").strip().lower()
        if transport not in _VALID_UPSTREAM_TRANSPORTS:
            logger.warning(
                "Ignoring upstream[%d]: invalid transport %r",
                idx,
                record.get("transport"),
            )
            continue
        record["transport"] = transport
        if transport == "doh":
            doh_url = str(record.get("url") or record.get("endpoint") or "").strip()
            if not doh_url:
                logger.warning(
                    "Ignoring upstream[%d]: DoH upstream missing url/endpoint", idx
                )
                continue
            parsed = urlparse(doh_url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                logger.warning(
                    "Ignoring upstream[%d]: invalid DoH url/endpoint %r",
                    idx,
                    doh_url,
                )
                continue
            if "url" not in record:
                record["url"] = doh_url
            validated.append(record)
            continue

        host = str(record.get("host") or "").strip()
        if not host:
            logger.warning(
                "Ignoring upstream[%d]: %s upstream missing host",
                idx,
                transport,
            )
            continue
        default_port = 853 if transport == "dot" else 53
        port_candidate = record.get("port", default_port)
        try:
            port = int(port_candidate)
        except Exception:
            port_type = type(port_candidate).__name__
            logger.warning(
                "Ignoring upstream[%d]: invalid port value type=%s",
                idx,
                port_type,
            )
            continue
        if port < 1 or port > 65535:
            logger.warning("Ignoring upstream[%d]: port out of range %r", idx, port)
            continue
        record["host"] = host
        record["port"] = port
        validated.append(record)
    return validated


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

        DNSRuntimeState.upstream_addrs = _validate_upstreams(upstreams)
        DNSRuntimeState.plugins = plugins  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.timeout = timeout  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.timeout_ms = timeout_ms  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.min_cache_ttl = max(
            0, int(min_cache_ttl)
        )  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.stats_collector = stats_collector  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
        DNSRuntimeState.dnssec_mode = _normalize_dnssec_mode(dnssec_mode)
        DNSRuntimeState.dnssec_validation = _normalize_dnssec_validation(
            dnssec_validation
        )
        DNSRuntimeState.upstream_strategy = str(upstream_strategy).lower()
        rm = str(resolver_mode).lower()
        # "none" and "master" behave the same way
        if rm == "none":  # pragma: no cover - legacy alias
            rm = "master"
        DNSRuntimeState.resolver_mode = rm
        try:
            DNSRuntimeState.recursive_max_depth = max(
                1, min(int(recursive_max_depth), _MAX_RECURSIVE_DEPTH)
            )
            if int(recursive_max_depth) != DNSRuntimeState.recursive_max_depth:
                logger.warning(
                    "Clamped recursive_max_depth=%r to %d",
                    recursive_max_depth,
                    DNSRuntimeState.recursive_max_depth,
                )
        except Exception:
            logger.warning(
                "Invalid recursive_max_depth=%r; using default 16",
                recursive_max_depth,
            )
            DNSRuntimeState.recursive_max_depth = 16
        DNSRuntimeState.recursive_timeout_ms = int(recursive_timeout_ms)
        DNSRuntimeState.recursive_per_try_timeout_ms = int(recursive_per_try_timeout_ms)

        # Cache prefetch / stale-while-revalidate knobs used by _resolve_core.
        DNSRuntimeState.cache_prefetch_enabled = bool(cache_prefetch_enabled)
        try:
            DNSRuntimeState.cache_prefetch_min_ttl = max(0, int(cache_prefetch_min_ttl))
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch min TTL config falls back to 0
            logger.warning(
                "Invalid cache_prefetch_min_ttl=%r; using default 0",
                cache_prefetch_min_ttl,
            )
            DNSRuntimeState.cache_prefetch_min_ttl = 0
        try:
            DNSRuntimeState.cache_prefetch_max_ttl = max(0, int(cache_prefetch_max_ttl))
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch max TTL config falls back to 0
            logger.warning(
                "Invalid cache_prefetch_max_ttl=%r; using default 0",
                cache_prefetch_max_ttl,
            )
            DNSRuntimeState.cache_prefetch_max_ttl = 0
        try:
            DNSRuntimeState.cache_prefetch_refresh_before_expiry = max(
                0.0, float(cache_prefetch_refresh_before_expiry)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: bad prefetch before-expiry window config falls back to 0.0
            logger.warning(
                "Invalid cache_prefetch_refresh_before_expiry=%r; using default 0.0",
                cache_prefetch_refresh_before_expiry,
            )
            DNSRuntimeState.cache_prefetch_refresh_before_expiry = 0.0
        try:
            DNSRuntimeState.cache_prefetch_allow_stale_after_expiry = max(
                0.0, float(cache_prefetch_allow_stale_after_expiry)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: bad stale-after-expiry window config falls back to 0.0
            logger.warning(
                "Invalid cache_prefetch_allow_stale_after_expiry=%r; using default 0.0",
                cache_prefetch_allow_stale_after_expiry,
            )
            DNSRuntimeState.cache_prefetch_allow_stale_after_expiry = 0.0

        try:
            DNSRuntimeState.upstream_max_concurrent = max(
                1, int(upstream_max_concurrent)
            )
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid upstream concurrency config falls back to 1
            logger.warning(
                "Invalid upstream_max_concurrent=%r; using default 1",
                upstream_max_concurrent,
            )
            DNSRuntimeState.upstream_max_concurrent = 1
        try:
            DNSRuntimeState.edns_udp_payload = max(512, int(edns_udp_payload))
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid EDNS UDP payload config falls back to default
            logger.warning(
                "Invalid edns_udp_payload=%r; using default 1232",
                edns_udp_payload,
            )
            DNSRuntimeState.edns_udp_payload = 1232

        # Optional explicit UDP response ceiling override.
        try:
            if max_response_bytes is None:
                DNSRuntimeState.max_response_bytes = None
            else:
                DNSRuntimeState.max_response_bytes = max(0, int(max_response_bytes))
        except Exception:  # pragma: nocover - defensive
            logger.warning(
                "Invalid max_response_bytes=%r; using default None",
                max_response_bytes,
            )
            DNSRuntimeState.max_response_bytes = None
        # Extended DNS Errors (RFC 8914) feature gate. When enable_ede is false
        # the resolver pipeline will not add any EDE options of its own and
        # will continue to treat upstream EDNS options opaquely.
        try:
            DNSRuntimeState.enable_ede = bool(enable_ede)
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid enable_ede config falls back to False
            logger.warning("Invalid enable_ede=%r; using default False", enable_ede)
            DNSRuntimeState.enable_ede = False
        try:
            DNSRuntimeState.forward_local = bool(forward_local)
        except (
            Exception
        ):  # pragma: nocover - defensive: invalid forward_local config falls back to False
            logger.warning(
                "Invalid forward_local=%r; using default False",
                forward_local,
            )
            DNSRuntimeState.forward_local = False

        # AXFR/IXFR transfer policy (applies to TCP/DoT listeners).
        try:
            DNSRuntimeState.axfr_enabled = bool(axfr_enabled)
        except Exception:  # pragma: nocover - defensive
            DNSRuntimeState.axfr_enabled = False
        try:
            DNSRuntimeState.axfr_allow_clients = _validate_axfr_allow_clients(
                axfr_allow_clients
            )
        except Exception:  # pragma: nocover - defensive
            logger.warning(
                "Invalid axfr_allow_clients=%r; using empty allowlist",
                axfr_allow_clients,
            )
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
