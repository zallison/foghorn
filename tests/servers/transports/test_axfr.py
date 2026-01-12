"""
Brief: Unit tests for the DNS AXFR transport helper.

Inputs:
  - None (tests use fake sockets and monkeypatching; no real network I/O).

Outputs:
  - None (assertions on axfr_transfer behaviour and error handling).
"""

from __future__ import annotations

from typing import List

import pytest
from dnslib import QTYPE, DNSRecord, RR, SOA

import foghorn.servers.transports.axfr as axfr_mod


class _FakeSocket:
    """Brief: Minimal fake socket implementing recv/settimeout/close.

    Inputs:
      - chunks: Sequence of bytes chunks returned by recv() in order.

    Outputs:
      - recv() returns data until exhausted, then b"".
    """

    def __init__(self, chunks: List[bytes]) -> None:
        self._chunks = list(chunks)
        self.timeout = None
        self.closed = False

    def settimeout(self, t: float) -> None:  # noqa: D401
        """Inputs: timeout seconds. Outputs: stores timeout for inspection."""

        self.timeout = t

    def recv(self, n: int) -> bytes:
        if not self._chunks:
            return b""
        # Pop from the front; if chunk is larger than n, split it.
        chunk = self._chunks[0]
        if len(chunk) <= n:
            self._chunks.pop(0)
            return chunk
        self._chunks[0] = chunk[n:]
        return chunk[:n]

    def sendall(self, data: bytes) -> None:  # noqa: D401
        """Inputs: data bytes. Outputs: records last payload and does nothing."""

        self.last_sent = data

    def close(self) -> None:
        self.closed = True


def _mk_axfr_frames(zone: str) -> list[bytes]:
    """Brief: Build two AXFR reply frames with matching SOA start/end.

    Inputs:
      - zone: Zone apex name (without trailing dot or with; both accepted).
    Outputs:
      - list[bytes]: Two length-prefixed DNS reply frames.
    """

    apex = (zone.rstrip(".") or ".") + "."

    # First message with initial SOA
    q1 = DNSRecord.question(apex, "AXFR")
    r1 = q1.reply()
    r1.add_answer(
        RR(
            rname=apex,
            rtype=QTYPE.SOA,
            rdata=SOA(
                mname="ns1." + apex,
                rname="hostmaster." + apex,
                times=(1, 3600, 600, 86400, 300),
            ),
            ttl=300,
        )
    )
    body1 = r1.pack()

    # Second message with final identical SOA
    q2 = DNSRecord.question(apex, "AXFR")
    r2 = q2.reply()
    r2.add_answer(r1.rr[0])
    body2 = r2.pack()

    def _frame(b: bytes) -> bytes:
        ln = len(b).to_bytes(2, "big")
        return ln + b

    return [_frame(body1), _frame(body2), b""]


def test_axfr_transfer_success_two_messages(monkeypatch) -> None:
    """Brief: axfr_transfer returns all RRs when transfer terminates with matching SOA.

    Inputs:
      - monkeypatch: pytest fixture to replace socket.create_connection.

    Outputs:
      - Asserts that returned RR list contains both SOA records.
    """

    frames = _mk_axfr_frames("example.com")
    fake_sock = _FakeSocket(frames)

    def _fake_create_connection(addr, timeout=None):  # noqa: ARG001
        return fake_sock

    monkeypatch.setattr(axfr_mod.socket, "create_connection", _fake_create_connection)

    rrs = axfr_mod.axfr_transfer("192.0.2.1", 53, "example.com")
    assert len(rrs) == 2
    assert all(rr.rtype == QTYPE.SOA for rr in rrs)
    assert fake_sock.closed is True


def test_axfr_transfer_dot_uses_tls_and_context(monkeypatch) -> None:
    """Brief: axfr_transfer with transport="dot" wraps the socket in TLS.

    Inputs:
      - monkeypatch: pytest fixture for patching socket.create_connection and _build_ssl_context.

    Outputs:
      - Asserts that TLS context is constructed and wrap_socket is used with
        the expected server_name/verify parameters, and that AXFR completes.
    """

    frames = _mk_axfr_frames("example.com")
    tls_sock = _FakeSocket(frames)
    base_sock = _FakeSocket([])

    def _fake_create_connection(addr, timeout=None):  # noqa: ARG001
        return base_sock

    class _FakeContext:
        def __init__(self) -> None:
            self.wrap_calls = []

        def wrap_socket(self, sock, server_hostname=None):  # noqa: D401
            """Inputs: underlying sock/server_hostname. Outputs: tls_sock."""

            self.wrap_calls.append((sock, server_hostname))
            return tls_sock

    fake_ctx = _FakeContext()

    def _fake_build_ssl_context(
        server_name, verify=True, ca_file=None, min_version=None
    ):  # noqa: D401,ARG001
        """Inputs: TLS params. Outputs: fake SSL context for assertions."""

        # Verify that axfr_transfer passes through TLS-related options.
        assert server_name == "axfr.example.com"
        assert verify is False
        assert ca_file == "/tmp/ca.pem"
        return fake_ctx

    monkeypatch.setattr(axfr_mod.socket, "create_connection", _fake_create_connection)
    monkeypatch.setattr(axfr_mod, "_build_ssl_context", _fake_build_ssl_context)

    rrs = axfr_mod.axfr_transfer(
        "192.0.2.1",
        853,
        "example.com",
        transport="dot",
        server_name="axfr.example.com",
        verify=False,
        ca_file="/tmp/ca.pem",
    )

    assert len(rrs) == 2
    assert all(rr.rtype == QTYPE.SOA for rr in rrs)
    # TLS context was used to wrap the underlying socket with no SNI when verify=False.
    assert fake_ctx.wrap_calls == [(base_sock, None)]
    assert tls_sock.closed is True


def test_axfr_transfer_no_messages_raises() -> None:
    """Brief: axfr_transfer raises AXFRError when no messages are received.

    Inputs:
      - None (uses a fake socket with immediate EOF).

    Outputs:
      - Asserts that AXFRError is raised with an informative message.
    """

    fake_sock = _FakeSocket([b""])

    def _fake_create_connection(addr, timeout=None):  # noqa: ARG001
        return fake_sock

    old = axfr_mod.socket.create_connection
    axfr_mod.socket.create_connection = _fake_create_connection  # type: ignore[assignment]
    try:
        with pytest.raises(axfr_mod.AXFRError) as excinfo:
            axfr_mod.axfr_transfer("192.0.2.1", 53, "nodata.example")
        assert "returned no data" in str(excinfo.value)
    finally:
        axfr_mod.socket.create_connection = old  # type: ignore[assignment]


def test_axfr_transfer_incomplete_frame_raises(monkeypatch) -> None:
    """Brief: Short body read compared to length header raises AXFRError.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that a short body triggers a "short read" AXFRError.
    """

    # Header says length 10 but only 4 bytes follow.
    hdr = (10).to_bytes(2, "big")
    fake_sock = _FakeSocket([hdr + b"abcd", b""])

    def _fake_create_connection(addr, timeout=None):  # noqa: ARG001
        return fake_sock

    monkeypatch.setattr(axfr_mod.socket, "create_connection", _fake_create_connection)

    with pytest.raises(axfr_mod.AXFRError) as excinfo:
        axfr_mod.axfr_transfer("192.0.2.1", 53, "short.example")
    assert "short read" in str(excinfo.value)


def test_axfr_transfer_parse_error_raises(monkeypatch) -> None:
    """Brief: Invalid DNS message bytes cause AXFRError from parse failure.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that a parse error is wrapped in AXFRError.
    """

    body = b"not-a-dns-message"
    hdr = len(body).to_bytes(2, "big")
    fake_sock = _FakeSocket([hdr + body, b""])

    def _fake_create_connection(addr, timeout=None):  # noqa: ARG001
        return fake_sock

    monkeypatch.setattr(axfr_mod.socket, "create_connection", _fake_create_connection)

    with pytest.raises(axfr_mod.AXFRError) as excinfo:
        axfr_mod.axfr_transfer("192.0.2.1", 53, "badparse.example")
    assert "failed to parse AXFR response" in str(excinfo.value)


def test_axfr_transfer_missing_terminal_soa_raises(monkeypatch) -> None:
    """Brief: AXFR without matching terminal SOA raises AXFRError.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - Asserts that AXFRError indicates missing terminal SOA.
    """

    # Single message with one SOA only; helper should treat this as missing
    # terminal SOA and raise.
    apex = "example.net."
    q = DNSRecord.question(apex, "AXFR")
    r = q.reply()
    r.add_answer(
        RR(
            rname=apex,
            rtype=QTYPE.SOA,
            rdata=SOA(
                mname="ns1." + apex,
                rname="hostmaster." + apex,
                times=(1, 3600, 600, 86400, 300),
            ),
            ttl=300,
        )
    )
    body = r.pack()
    frame = len(body).to_bytes(2, "big") + body
    fake_sock = _FakeSocket([frame, b""])

    def _fake_create_connection(addr, timeout=None):  # noqa: ARG001
        return fake_sock

    monkeypatch.setattr(axfr_mod.socket, "create_connection", _fake_create_connection)

    with pytest.raises(axfr_mod.AXFRError) as excinfo:
        axfr_mod.axfr_transfer("192.0.2.1", 53, "example.net")
    assert "did not terminate with a matching SOA" in str(excinfo.value)
