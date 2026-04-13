import socket
from typing import Optional


def _resolve_ipv4_host(host: str) -> str:
    """Brief: Resolve a hostname to an IPv4 address for UDP transport.

    Inputs:
      - host: Hostname or IPv4 address string.

    Outputs:
      - str: Resolved IPv4 address (dotted quad).

    Notes:
      - This transport currently uses an AF_INET socket, so we resolve to IPv4.
      - We do best-effort resolution; failures propagate as UDPError from udp_query.
    """

    # Fast-path for already-normalized IPv4 literals
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass

    infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_DGRAM)
    if not infos:
        raise OSError(f"Failed to resolve host {host!r} to IPv4")
    # getaddrinfo returns tuples; sockaddr is (ip, port)
    return str(infos[0][4][0])


class UDPError(Exception):
    """
    Brief: DNS-over-UDP transport error.

    Inputs:
    - message: description

    Outputs:
    - Exception instance
    """

    pass


def udp_query(
    host: str,
    port: int,
    query: bytes,
    *,
    timeout_ms: int = 2000,
    source_ip: Optional[str] = None,
) -> bytes:
    """
    Brief: Perform a single UDP DNS query.

    Inputs:
    - host: upstream resolver host/IP
    - port: upstream UDP port
    - query: wire-format DNS query bytes
    - timeout_ms: socket timeout in milliseconds
    - source_ip: optional source address to bind

    Outputs:
    - bytes: wire-format DNS response

    Example:
        >>> try:
        ...     udp_query('127.0.0.1', 53, b'\x00\x01')
        ... except UDPError:
        ...     pass
    """
    try:
        target_ip = _resolve_ipv4_host(str(host))
        target_port = int(port)
        expected_peer = (target_ip, target_port)

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if source_ip:
                s.bind((source_ip, 0))
            s.settimeout(timeout_ms / 1000.0)
            s.sendto(query, expected_peer)

            # Validate that the response comes from the intended upstream. This
            # helps defend against off-path UDP response injection.
            while True:
                data, peer = s.recvfrom(4096)
                if peer == expected_peer:
                    return data
                # Ignore unexpected datagrams until timeout.
        finally:
            try:
                s.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
    except OSError as e:
        raise UDPError(f"UDP error: {e}")
