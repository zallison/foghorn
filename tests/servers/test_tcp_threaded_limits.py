"""Brief: Tests for threaded TCP connection and query limits.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import foghorn.servers.tcp_server as tcp_server_mod


def _restore_tcp_handler_defaults() -> None:
    """Brief: Restore _TCPHandler class attributes to defaults after tests.

    Inputs:
      - None.

    Outputs:
      - None.
    """

    tcp_server_mod._TCPHandler.resolver = staticmethod(lambda b, ip: b)  # type: ignore[assignment]
    tcp_server_mod._TCPHandler.idle_timeout_seconds = 15.0
    tcp_server_mod._TCPHandler.max_queries_per_connection = 100
    tcp_server_mod._TCPHandler.overload_response = tcp_server_mod.OVERLOAD_RESPONSE_DROP
    tcp_server_mod._TCPHandler.conn_limiter = None


def test_threaded_conn_limiter_enforces_global_and_per_ip_caps() -> None:
    """Brief: _ThreadedConnLimiter rejects excess global and per-IP connections.

    Inputs:
      - None.

    Outputs:
      - None; asserts acquire/release bookkeeping.
    """

    limiter = tcp_server_mod._ThreadedConnLimiter(max_connections=2, max_per_ip=1)
    assert limiter.acquire("1.1.1.1") is True
    assert limiter.acquire("1.1.1.1") is False  # per-ip
    assert limiter.acquire("2.2.2.2") is True
    assert limiter.acquire("3.3.3.3") is False  # global
    limiter.release("1.1.1.1")
    assert limiter.acquire("3.3.3.3") is True
    limiter.release("2.2.2.2")
    limiter.release("3.3.3.3")


def test_tcphandler_rejects_when_limiter_full(monkeypatch) -> None:
    """Brief: _TCPHandler returns without resolving when connection limit is hit.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts resolver is not called.
    """

    class _Sock:
        def settimeout(self, t: float) -> None:
            self.timeout = t

        def sendall(self, data: bytes) -> None:  # pragma: no cover - unused
            raise AssertionError("should not send when limited")

    seen = {"calls": 0}

    def resolver(q: bytes, ip: str) -> bytes:
        seen["calls"] += 1
        return q

    tcp_server_mod._TCPHandler.resolver = staticmethod(resolver)  # type: ignore[assignment]
    limiter = tcp_server_mod._ThreadedConnLimiter(max_connections=1, max_per_ip=1)
    assert limiter.acquire("9.9.9.9") is True
    tcp_server_mod._TCPHandler.conn_limiter = limiter
    tcp_server_mod._TCPHandler.max_queries_per_connection = 100
    tcp_server_mod._TCPHandler.idle_timeout_seconds = 15.0

    try:
        tcp_server_mod._TCPHandler(_Sock(), ("9.9.9.9", 5353), None)
        assert seen["calls"] == 0
        limiter.release("9.9.9.9")
    finally:
        _restore_tcp_handler_defaults()


def test_tcphandler_enforces_max_queries_per_connection(monkeypatch) -> None:
    """Brief: _TCPHandler stops after max_queries_per_connection non-transfer queries.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None; asserts resolver called exactly once when max_queries=1.
    """

    class _Sock:
        def __init__(self) -> None:
            self.timeout = None
            self.sent: list[bytes] = []

        def settimeout(self, t: float) -> None:
            self.timeout = t

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    calls = {"n": 0, "resolve": 0}

    def fake_recv_exact(sock, length):  # noqa: ARG001
        calls["n"] += 1
        # Two full queries advertised, but max_queries=1 should stop after one.
        if calls["n"] in (1, 3):
            return (4).to_bytes(2, "big")
        if calls["n"] in (2, 4):
            return b"data"
        return b""

    monkeypatch.setattr(tcp_server_mod, "_recv_exact", fake_recv_exact)

    def resolver(q: bytes, ip: str) -> bytes:
        calls["resolve"] += 1
        return q.upper()

    tcp_server_mod._TCPHandler.resolver = staticmethod(resolver)  # type: ignore[assignment]
    tcp_server_mod._TCPHandler.conn_limiter = None
    tcp_server_mod._TCPHandler.max_queries_per_connection = 1
    tcp_server_mod._TCPHandler.idle_timeout_seconds = 5.0

    sock = _Sock()
    try:
        tcp_server_mod._TCPHandler(sock, ("1.2.3.4", 5353), None)
        assert calls["resolve"] == 1
        assert sock.sent == [len(b"DATA").to_bytes(2, "big") + b"DATA"]
        assert sock.timeout == 5.0
    finally:
        _restore_tcp_handler_defaults()
