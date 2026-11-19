"""Best-effort DNS-over-TCP framed write helpers (RFC 7766 length prefix).

Used by inbound TCP and DoT listeners when writing replies. Outbound upstream
clients should continue to raise on write failure so failover can react.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("foghorn.tcp_framed_write")


def frame_dns_message(data: bytes) -> bytes:
    """Brief: Prefix DNS wire bytes with a 2-byte big-endian length.

    Inputs:
      - data: DNS message wire bytes (must be non-empty for a useful frame).

    Outputs:
      - bytes: ``len(data).to_bytes(2, \"big\") + data``.

    Example:
      >>> frame_dns_message(b\"ab\")[:2]
      b'\\x00\\x02'
    """
    return len(data).to_bytes(2, "big") + data


def sendall_framed(
    sock: Any,
    data: bytes,
    *,
    client_ip: str | None = None,
    log: logging.Logger | None = None,
) -> bool:
    """Brief: Best-effort blocking framed TCP/TLS write that never raises.

    Inputs:
      - sock: Socket-like object with ``sendall(bytes)`` (plain TCP or TLS).
      - data: DNS message wire bytes to send (empty is a no-op).
      - client_ip: Optional peer IP for debug logging.
      - log: Optional logger; defaults to module logger.

    Outputs:
      - bool: True when a framed sendall completed; False when sock/data is
        missing or sendall raises.

    Notes:
      - Frames with a 2-byte big-endian length prefix (RFC 7766 / RFC 7858).
    """
    if sock is None or not data:
        return False
    try:
        sock.sendall(frame_dns_message(data))
        return True
    except Exception:
        (log or logger).debug(
            "Failed to send framed TCP response to %s",
            client_ip or "?",
            exc_info=True,
        )
        return False


async def write_framed(
    writer: Any,
    data: bytes,
    *,
    client_ip: str | None = None,
    log: logging.Logger | None = None,
) -> bool:
    """Brief: Best-effort asyncio framed stream write that never raises.

    Inputs:
      - writer: asyncio StreamWriter-like object with ``write`` and ``drain``.
      - data: DNS message wire bytes to send (empty is a no-op).
      - client_ip: Optional peer IP for debug logging.
      - log: Optional logger; defaults to module logger.

    Outputs:
      - bool: True when write+drain completed; False when writer/data is missing
        or write/drain raises.

    Notes:
      - Frames with a 2-byte big-endian length prefix (RFC 7766 / RFC 7858).
      - Callers that need fail-closed connection teardown on write failure can
        treat a False return as a signal to break/close.
    """
    if writer is None or not data:
        return False
    try:
        writer.write(frame_dns_message(data))
        await writer.drain()
        return True
    except Exception:
        (log or logger).debug(
            "Failed to send framed stream response to %s",
            client_ip or "?",
            exc_info=True,
        )
        return False
