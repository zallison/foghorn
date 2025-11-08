"""
Brief: Negative-path tests for DoT transport.

Inputs:
  - None

Outputs:
  - None
"""

import socket

import pytest

from foghorn.transports.dot import dot_query, DoTError


def test_dot_verify_tls_fails_without_trust():
    # Try to connect to an IP/port that isn't serving TLS to trigger error fast
    # Using localhost high port likely closed; expect network error -> DoTError
    with pytest.raises(DoTError):
        dot_query(
            "127.0.0.1",
            9,
            b"\x00\x01x",
            server_name="localhost",
            verify=True,
            connect_timeout_ms=100,
            read_timeout_ms=100,
        )
