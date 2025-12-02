from __future__ import annotations

import socket
from typing import Optional

from .recursive_resolver import AuthorityEndpoint, TransportFacade


class DefaultTransportFacade(TransportFacade):
    """TransportFacade that reuses Foghorn's existing upstream transports.

    Inputs:
      - source_ip: Optional source address to bind for UDP queries.

    Outputs:
      - Instance suitable for use by resolve_iterative to contact authorities.

    Brief:
      This implementation focuses on DNS-over-UDP for authority servers, with
      basic support for DNS-over-TCP and DoT via connection pools. DoH and
      unknown transports currently yield an "unsupported_transport" error.
    """

    def __init__(self, source_ip: Optional[str] = None) -> None:
        """Initialize the facade with optional UDP source address.

        Inputs:
          - source_ip: Optional IPv4/IPv6 address to bind client UDP socket.

        Outputs:
          - None
        """

        self._source_ip = source_ip

    def query(  # type: ignore[override]
        self,
        authority: AuthorityEndpoint,
        wire_query: bytes,
        *,
        timeout_ms: int,
    ) -> tuple[bytes | None, str | None]:
        """Send a DNS query to one authority and return (response_wire, error).

        Inputs:
          - authority: AuthorityEndpoint describing the upstream server.
          - wire_query: Wire-format DNS query.
          - timeout_ms: Per-attempt timeout in milliseconds.

        Outputs:
          - (response_wire, error):
            * response_wire: bytes on success or None on timeout/transport failure.
            * error: None on success or a short string such as 'timeout',
              'network_error', or 'unsupported_transport'.
        """

        host = authority.host
        port = int(authority.port)
        transport = (authority.transport or "udp").lower()

        if timeout_ms <= 0:
            return None, "timeout"

        try:
            if transport == "udp":
                from .transports.udp import udp_query

                resp = udp_query(
                    host,
                    port,
                    wire_query,
                    timeout_ms=int(timeout_ms),
                    source_ip=self._source_ip,
                )
                return resp, None

            if transport == "tcp":
                from .transports.tcp import get_tcp_pool

                pool = get_tcp_pool(host, port)
                resp = pool.send(
                    wire_query,
                    connect_timeout_ms=int(timeout_ms),
                    read_timeout_ms=int(timeout_ms),
                )
                return resp, None

            if transport == "dot":
                from .transports.dot import get_dot_pool

                # For authority servers discovered via NS/glue we typically only
                # have host/port. DoT-specific settings (server_name, verify,
                # ca_file) follow conservative defaults here.
                pool = get_dot_pool(
                    host, port, server_name=None, verify=True, ca_file=None
                )
                resp = pool.send(
                    wire_query,
                    connect_timeout_ms=int(timeout_ms),
                    read_timeout_ms=int(timeout_ms),
                )
                return resp, None

            # DoH and any other transport are not currently modeled for
            # authority endpoints in the recursive resolver.
            return None, "unsupported_transport"

        except socket.timeout:
            return None, "timeout"
        except Exception as exc:  # pragma: no cover - mapped to stable error string
            # Normalize known transport-layer exceptions to a generic
            # 'network_error' classification so resolve_iterative can treat all
            # of them uniformly.
            _ignored = exc  # avoid unused variable in optimized builds
            return None, "network_error"
