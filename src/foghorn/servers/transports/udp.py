import socket
from typing import Optional


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
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            if source_ip:
                s.bind((source_ip, 0))
            s.settimeout(timeout_ms / 1000.0)
            s.sendto(query, (host, int(port)))
            data, _ = s.recvfrom(4096)
            return data
        finally:
            try:
                s.close()
            except (
                Exception
            ):  # pragma: no cover - defensive: low-value edge case or environment-specific behaviour that is hard to test reliably
                pass
    except OSError as e:
        raise UDPError(f"UDP error: {e}")
