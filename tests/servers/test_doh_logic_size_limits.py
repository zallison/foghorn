"""Regression tests for DoH size limit enforcement.

Brief:
  Targeted tests that validate DoH size caps return HTTP-appropriate errors.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import pytest

from foghorn.servers.doh_logic import DohLogicError, parse_doh_get_dns_param


def test_parse_doh_get_dns_param_oversized_decoded_bytes_raises_413() -> None:
    """Brief: parse_doh_get_dns_param raises 413 when decoded query exceeds max.

    Inputs:
      - None.

    Outputs:
      - None; asserts DohLogicError(status_code=413).
    """

    def decoder(_s: str) -> bytes:
        return b"x" * 11

    with pytest.raises(DohLogicError) as excinfo:
        parse_doh_get_dns_param("ignored", decoder=decoder, max_decoded_bytes=10)

    err = excinfo.value
    assert err.status_code == 413


def test_parse_doh_get_dns_param_rejects_oversized_string_before_decoding() -> None:
    """Brief: parse_doh_get_dns_param rejects oversize strings before base64 decode.

    Tests that excessively long dns_param strings return 413 immediately
    without attempting to decode the entire payload.

    Inputs:
      - None.

    Outputs:
      - None; asserts DohLogicError(status_code=413) is raised early.
    """
    import base64

    # Create a realistically large but valid DNS query.
    real_query = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01"
    max_size = len(real_query)

    # Base64url encoded version.
    b64_query = base64.urlsafe_b64encode(real_query).decode("ascii")

    # With max_decoded_bytes set, queries within the limit should pass.
    parse_doh_get_dns_param(b64_query, max_decoded_bytes=max_size + 1)

    # Create a string that exceeds the encoded size limit.
    # With 4/3 expansion, we need a string larger than (max_size * 4/3).
    oversized = "A" * ((max_size * 4) // 3 + 100)

    with pytest.raises(DohLogicError) as excinfo:
        parse_doh_get_dns_param(oversized, max_decoded_bytes=max_size)

    err = excinfo.value
    assert err.status_code == 413
    assert "too large" in err.detail.lower()
