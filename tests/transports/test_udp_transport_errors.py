"""
Brief: Negative-path tests for UDP transport.

Inputs:
  - None

Outputs:
  - None
"""

import pytest

from foghorn.servers.transports.udp import UDPError, udp_query


def test_udp_timeout_raises(monkeypatch):
    # Use unroutable address 203.0.113.1 (TEST-NET-3) to trigger timeout quickly
    with pytest.raises(UDPError):
        udp_query("203.0.113.1", 9, b"\x12\x34", timeout_ms=10)
