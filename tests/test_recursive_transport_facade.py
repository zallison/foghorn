"""Tests for the DefaultTransportFacade used by the recursive resolver.

Inputs:
  - None (pytest discovers and runs tests).

Outputs:
  - None (pytest assertions).
"""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

import foghorn.recursive_transport as rt
from foghorn.recursive_resolver import AuthorityEndpoint


class _Recorder:
    """Brief: Simple helper to capture calls in tests.

    Inputs:
      - None

    Outputs:
      - Instance with .calls list storing (args, kwargs).
    """

    def __init__(self) -> None:
        self.calls: List[Tuple[Tuple[Any, ...], Dict[str, Any]]] = []

    def record(self, *args: Any, **kwargs: Any) -> bytes:
        self.calls.append((args, kwargs))
        # Return a synthetic DNS wire payload.
        return b"reply"


def test_udp_success_path(monkeypatch) -> None:
    """Brief: UDP transport success yields response bytes and no error.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures DefaultTransportFacade calls udp_query with expected args.
    """

    rec = _Recorder()

    def _fake_udp_query(host: str, port: int, query: bytes, *, timeout_ms: int, source_ip=None):  # type: ignore[override]
        return rec.record(host, port, query, timeout_ms=timeout_ms, source_ip=source_ip)

    monkeypatch.setattr("foghorn.transports.udp.udp_query", _fake_udp_query)

    facade = rt.DefaultTransportFacade(source_ip="127.0.0.1")
    authority = AuthorityEndpoint(name=".", host="192.0.2.1", port=53, transport="udp")

    resp, err = facade.query(authority, b"query", timeout_ms=500)

    assert err is None
    assert resp == b"reply"
    assert rec.calls
    args, kwargs = rec.calls[0]
    assert args[0] == "192.0.2.1"
    assert args[1] == 53
    assert args[2] == b"query"
    assert kwargs["timeout_ms"] == 500
    assert kwargs["source_ip"] == "127.0.0.1"


def test_udp_timeout_maps_to_error(monkeypatch) -> None:
    """Brief: socket.timeout from udp_query is reported as 'timeout'.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures UDP timeouts become (None, 'timeout').
    """

    import socket

    def _timeout_udp(*_args: Any, **_kwargs: Any) -> bytes:  # type: ignore[override]
        raise socket.timeout()

    monkeypatch.setattr("foghorn.transports.udp.udp_query", _timeout_udp)

    facade = rt.DefaultTransportFacade()
    authority = AuthorityEndpoint(name=".", host="192.0.2.2", port=53, transport="udp")

    resp, err = facade.query(authority, b"q", timeout_ms=250)

    assert resp is None
    assert err == "timeout"


def test_tcp_success_uses_pool(monkeypatch) -> None:
    """Brief: TCP transport uses get_tcp_pool().send().

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures pool.send is called with expected timeouts.
    """

    class _FakePool:
        def __init__(self) -> None:
            self.calls: List[Tuple[bytes, int, int]] = []

        def send(self, query: bytes, connect_timeout_ms: int, read_timeout_ms: int) -> bytes:  # type: ignore[override]
            self.calls.append((query, connect_timeout_ms, read_timeout_ms))
            return b"tcp-reply"

    pool = _FakePool()

    def _get_pool(host: str, port: int):  # type: ignore[override]
        assert host == "192.0.2.3"
        assert port == 53
        return pool

    monkeypatch.setattr("foghorn.transports.tcp.get_tcp_pool", _get_pool)

    facade = rt.DefaultTransportFacade()
    authority = AuthorityEndpoint(name=".", host="192.0.2.3", port=53, transport="tcp")

    resp, err = facade.query(authority, b"tcp-q", timeout_ms=750)

    assert err is None
    assert resp == b"tcp-reply"
    assert pool.calls == [(b"tcp-q", 750, 750)]


def test_unsupported_transport_reports_error() -> None:
    """Brief: unknown transport types are reported as 'unsupported_transport'.

    Inputs:
      - None

    Outputs:
      - Ensures query() fails fast for non-UDP/TCP/DoT transports.
    """

    facade = rt.DefaultTransportFacade()
    authority = AuthorityEndpoint(
        name=".", host="example.com", port=443, transport="doh"
    )

    resp, err = facade.query(authority, b"q", timeout_ms=500)

    assert resp is None
    assert err == "unsupported_transport"
