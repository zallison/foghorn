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
