from __future__ import annotations

"""Helpers for transport overload response policy handling.

Brief:
  Provides shared normalization and DNS wire-building helpers used by listener
  overload/limit paths (UDP/TCP/DoT) so behavior is consistent across
  transports.

Inputs:
  - Raw policy values from config (e.g. "servfail", "refused", "drop").
  - Original DNS query wire bytes (for TXID preservation).

Outputs:
  - Normalized overload policy strings.
  - Minimal DNS response wire bytes for SERVFAIL/REFUSED, or None for drop.
"""

from typing import Final


OVERLOAD_RESPONSE_SERVFAIL: Final[str] = "servfail"
OVERLOAD_RESPONSE_REFUSED: Final[str] = "refused"
OVERLOAD_RESPONSE_DROP: Final[str] = "drop"

ALLOWED_OVERLOAD_RESPONSES: Final[frozenset[str]] = frozenset(
    {
        OVERLOAD_RESPONSE_SERVFAIL,
        OVERLOAD_RESPONSE_REFUSED,
        OVERLOAD_RESPONSE_DROP,
    }
)


def normalize_overload_response(
    value: object, *, default: str = OVERLOAD_RESPONSE_SERVFAIL
) -> str:
    """Brief: Normalize overload policy to one of servfail/refused/drop.

    Inputs:
      - value: Candidate policy value from config.
      - default: Fallback policy when value is missing/invalid.

    Outputs:
      - str: One of 'servfail', 'refused', or 'drop'.
    """

    default_norm = str(default or OVERLOAD_RESPONSE_SERVFAIL).strip().lower()
    if default_norm not in ALLOWED_OVERLOAD_RESPONSES:
        default_norm = OVERLOAD_RESPONSE_SERVFAIL

    candidate = str(value or "").strip().lower()
    if candidate in ALLOWED_OVERLOAD_RESPONSES:
        return candidate
    return default_norm


def _build_minimal_dns_overload_header(
    query_wire: bytes, *, rcode: int
) -> bytes | None:
    """Brief: Build a minimal 12-byte DNS response header for overload handling.

    Inputs:
      - query_wire: Original DNS query wire bytes.
      - rcode: DNS RCODE integer (e.g. 2=SERVFAIL, 5=REFUSED).

    Outputs:
      - bytes | None: Minimal DNS response header with matching TXID, or None
        when query_wire is too short to carry a transaction ID.
    """

    if len(query_wire) < 2:
        return None

    txid = query_wire[0:2]
    flags_hi = 0x80
    flags_lo = int(rcode) & 0x0F
    return (
        txid
        + bytes((flags_hi, flags_lo))
        + b"\x00\x01"
        + b"\x00\x00"
        + b"\x00\x00"
        + b"\x00\x00"
    )


def build_overload_dns_response(
    query_wire: bytes, overload_response: str
) -> bytes | None:
    """Brief: Build policy-selected DNS overload response wire bytes.

    Inputs:
      - query_wire: Original DNS query wire bytes.
      - overload_response: Policy string ('servfail'|'refused'|'drop').

    Outputs:
      - bytes | None:
        - SERVFAIL minimal response when policy is servfail.
        - REFUSED minimal response when policy is refused.
        - None when policy is drop.
    """

    policy = normalize_overload_response(overload_response)
    if policy == OVERLOAD_RESPONSE_DROP:
        return None
    if policy == OVERLOAD_RESPONSE_REFUSED:
        return _build_minimal_dns_overload_header(query_wire, rcode=5)
    return _build_minimal_dns_overload_header(query_wire, rcode=2)
