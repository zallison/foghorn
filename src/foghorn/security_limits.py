"""Security-related limits and helpers.

Brief:
  Centralizes conservative bounds used to reduce DoS/DDoS impact from oversized
  DNS and DoH requests, as well as helper functions used to detect potentially
  risky listener exposure.

Inputs/Outputs:
  - Provides integer size limits (bytes) and small helper functions.

Notes:
  - These are intentionally internal. Configuration plumbing can override them
    in higher-level modules when needed.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

# DNS-over-TCP maximum message size.
#
# RFC 7766 uses a 16-bit length prefix, so the protocol max is 65535 bytes.
# Keeping this at the protocol max preserves compatibility, while callers may
# choose to enforce a lower operational ceiling.
MAX_DNS_TCP_MESSAGE_BYTES: int = 65535

# DNS message size accepted via DoH (GET/POST).
MAX_DOH_DNS_MESSAGE_BYTES: int = 65535

# Maximum decoded size for the DoH GET "dns=" query parameter.
# This should match MAX_DOH_DNS_MESSAGE_BYTES, but is kept separate to allow
# tuning if desired.
MAX_DOH_QUERY_PARAM_BYTES: int = 65535

# AXFR is length-prefixed DNS over TCP. Keep protocol max by default.
MAX_AXFR_FRAME_BYTES: int = 65535


def is_loopback_host(host: str) -> bool:
    """Brief: Return True when *host* is loopback-only.

    Inputs:
      - host: Listener bind host string.

    Outputs:
      - bool: True for 127.0.0.0/8 and ::1 and common loopback aliases.

    Notes:
      - Treats empty host as non-loopback (conservative).
      - Treats 'localhost' as loopback.
    """

    if not host:
        return False

    text = str(host).strip().lower()
    if text in {"localhost"}:
        return True

    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False

    return bool(addr.is_loopback)


def clamp_positive_int(value: object, *, default: int, minimum: int = 1) -> int:
    """Brief: Parse an integer config value and clamp to >= minimum.

    Inputs:
      - value: Raw object from config.
      - default: Default integer when parsing fails.
      - minimum: Inclusive minimum value.

    Outputs:
      - int: Parsed integer clamped to >= minimum.
    """

    try:
        out = int(value)  # type: ignore[arg-type]
    except Exception:
        out = int(default)
    if out < int(minimum):
        return int(minimum)
    return int(out)


def maybe_parse_content_length(value: Optional[str]) -> int:
    """Brief: Parse Content-Length header safely.

    Inputs:
      - value: Raw header string or None.

    Outputs:
      - int: Parsed non-negative integer length; returns 0 for missing/invalid.
    """

    if value is None:
        return 0
    try:
        ln = int(str(value).strip())
    except Exception:
        return 0
    return ln if ln > 0 else 0
