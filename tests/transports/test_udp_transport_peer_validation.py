"""Brief: Tests for UDP upstream peer validation to reduce response injection risk.

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations

import socket

from foghorn.servers.transports.udp import udp_query


class _FakeSock:
    """Brief: Socket stub that returns a datagram from the wrong peer first.

    Inputs:
      - None.

    Outputs:
      - Fake socket object supporting the subset used by udp_query.
    """

    def __init__(self) -> None:
        self._sent: list[tuple[bytes, tuple[str, int]]] = []
        self._recv_calls = 0
        self._timeout = None
        self._bound = None

    def bind(self, addr):  # noqa: D401
        """Record bind address."""

        self._bound = addr

    def settimeout(self, t):  # noqa: D401
        """Record timeout value."""

        self._timeout = t

    def sendto(self, data: bytes, peer):  # noqa: D401
        """Record sent datagrams."""

        self._sent.append((data, peer))

    def recvfrom(self, _n: int):
        self._recv_calls += 1
        if self._recv_calls == 1:
            return b"wrong", ("127.0.0.1", 9999)
        return b"right", ("127.0.0.1", 5353)

    def close(self):  # noqa: D401
        """No-op close."""

        return None


def test_udp_query_ignores_unexpected_peer(monkeypatch):
    """Brief: udp_query should ignore datagrams from the wrong peer.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None.
    """

    def fake_socket(*_args, **_kwargs):
        return _FakeSock()

    monkeypatch.setattr(socket, "socket", fake_socket)

    resp = udp_query("127.0.0.1", 5353, b"q", timeout_ms=50)
    assert resp == b"right"
