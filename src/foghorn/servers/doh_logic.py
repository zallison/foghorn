"""Shared business logic for DNS-over-HTTPS (DoH).

This module contains framework-neutral helpers used by both:
- the FastAPI/uvicorn DoH implementation, and
- the threaded stdlib http.server DoH fallback implementation.

The functions here avoid importing FastAPI or http.server types.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class DohLogicError(Exception):
    """Brief: Error type for mapping DoH logic failures to HTTP responses.

    Inputs:
      - status_code: HTTP status code that should be returned.
      - detail: Human-readable error message.

    Outputs:
      - Exception instance suitable for conversion to an HTTP error response.

    Example:
      >>> raise DohLogicError(status_code=400, detail='invalid request')
    """

    status_code: int
    detail: str


def b64url_decode_nopad(value: str) -> bytes:
    """Brief: Decode base64url value that may omit '=' padding.

    Inputs:
      - value: base64url-encoded string.

    Outputs:
      - Decoded bytes.

    Raises:
      - ValueError when value is not a str or cannot be decoded.

    Example:
      >>> b64url_decode_nopad('AQI')
      b'\x01\x02'
    """

    if not isinstance(value, str):
        raise ValueError("value must be str")
    pad = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(value + pad)
    except Exception as exc:
        raise ValueError("invalid base64url value") from exc


def parse_doh_get_dns_param(
    dns_param: str | None,
    *,
    decoder: Callable[[str], bytes] | None = None,
    max_decoded_bytes: int | None = None,
) -> bytes:
    """Brief: Parse and validate the GET /dns-query?dns=... parameter.

    Inputs:
      - dns_param: Value of the "dns" query parameter.
      - decoder: Optional callable used to decode base64url without padding.
        This allows callers (and tests) to inject custom decoding behavior.

    Outputs:
      - Decoded DNS message bytes.

    Raises:
      - DohLogicError(400) when missing or invalid.

    Example:
      >>> parse_doh_get_dns_param('AQI')
      b'\x01\x02'
    """

    if not dns_param:
        raise DohLogicError(status_code=400, detail="missing dns query parameter")

    decode = decoder or b64url_decode_nopad
    try:
        out = decode(dns_param)
    except Exception as exc:
        raise DohLogicError(
            status_code=400, detail="invalid dns query parameter"
        ) from exc

    if max_decoded_bytes is not None:
        try:
            limit = int(max_decoded_bytes)
        except Exception:
            limit = 0
        if limit > 0 and len(out) > limit:
            raise DohLogicError(status_code=413, detail="dns query parameter too large")

    return out


def validate_doh_post_content_type(content_type: str | None, *, dns_ct: str) -> None:
    """Brief: Validate the DoH POST Content-Type.

    Inputs:
      - content_type: Content-Type header value.
      - dns_ct: Required DNS message MIME type (typically 'application/dns-message').

    Outputs:
      - None.

    Raises:
      - DohLogicError(415) when the content type is not acceptable.
    """

    ctype = str(content_type or "")
    if dns_ct not in ctype:
        raise DohLogicError(status_code=415, detail="unsupported media type")


def call_resolver(
    resolver: Callable[[bytes, str], bytes],
    *,
    query: bytes,
    client_ip: str,
) -> bytes:
    """Brief: Invoke the configured resolver callable.

    Inputs:
      - resolver: Callable (query_bytes, client_ip) -> response_bytes.
      - query: DNS request bytes.
      - client_ip: Best-effort client IP string.

    Outputs:
      - Response bytes from resolver.

    Raises:
      - Exception propagated from the resolver.
    """

    return resolver(query, client_ip)
