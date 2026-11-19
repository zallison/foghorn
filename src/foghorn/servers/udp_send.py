"""Best-effort UDP send helpers shared by inbound UDP listeners."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("foghorn.udp_send")


def sendto_safe(
    transport: Any,
    data: bytes,
    addr: Any,
    *,
    log: logging.Logger | None = None,
) -> bool:
    """Brief: Best-effort UDP send that never raises into the caller.

    Inputs:
      - transport: Object with ``sendto(data, addr)`` (socket or DatagramTransport).
      - data: Wire bytes to send.
      - addr: Destination address (typically ``(ip, port)``).
      - log: Optional logger; defaults to module logger.

    Outputs:
      - bool: True when send completed without error; False when transport is
        missing, payload is empty, or ``sendto`` raises.

    Notes:
      - Isolates OSError/ConnectionResetError and other send failures so they
        are not confused with resolver exceptions on inbound reply paths.
      - Outbound upstream UDP clients should keep raising (see transports/udp.py).

    Example:
      >>> class T:
      ...     def sendto(self, data, addr):
      ...         return None
      >>> sendto_safe(T(), b\"x\", (\"127.0.0.1\", 53))
      True
    """
    if transport is None or not data:
        return False
    try:
        transport.sendto(data, addr)
        return True
    except Exception:
        client = addr[0] if isinstance(addr, tuple) and addr else "?"
        (log or logger).debug(
            "Failed to send UDP response to %s",
            client,
            exc_info=True,
        )
        return False
