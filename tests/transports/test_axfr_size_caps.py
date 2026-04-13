"""Regression tests for AXFR transport size limit enforcement.

Brief:
  Ensure that AXFR transfer code rejects oversized response frames before
  attempting to read/parse large bodies.

Inputs:
  - None

Outputs:
  - None
"""

from __future__ import annotations

import pytest
from dnslib import A, DNSRecord, QTYPE, RR

from foghorn.servers.transports.axfr import AXFRError, axfr_transfer


class _DummySock:
    def __init__(self):
        self.sent: list[bytes] = []
        self.timeout = None
        self.closed = False

    def settimeout(self, t: float) -> None:
        self.timeout = t

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, _n: int) -> bytes:
        return b""  # not used (we patch _recv_exact)

    def close(self) -> None:
        self.closed = True


def _make_response_bytes(qname: str, rrs: list[RR]) -> bytes:
    """Brief: Build a minimal DNS response payload with provided answers.

    Inputs:
      - qname: Owner name used for the DNS question.
      - rrs: Answer RR list to include in the response.

    Outputs:
      - bytes: Packed DNS response payload.
    """
    q = DNSRecord.question(qname, "AXFR")
    resp = q.reply()
    for rr in rrs:
        resp.add_answer(rr)
    return resp.pack()


def test_axfr_transfer_rejects_oversized_frame(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: axfr_transfer raises AXFRError when a frame length exceeds cap.

    Inputs:
      - monkeypatch: patches socket.create_connection and _recv_exact.

    Outputs:
      - None; asserts AXFRError is raised.
    """

    import foghorn.servers.transports.axfr as axfr_mod

    dummy = _DummySock()

    monkeypatch.setattr(
        axfr_mod.socket,
        "create_connection",
        lambda *a, **k: dummy,
    )

    # Length prefix is 2 bytes (max 65535). The project-wide cap is 65535, so
    # monkeypatch the cap lower to exercise the oversize branch.
    monkeypatch.setattr(axfr_mod, "MAX_AXFR_FRAME_BYTES", 10)

    oversize = 11

    calls = {"n": 0}

    def fake_recv_exact(sock, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        # First read is the 2-byte length prefix.
        if calls["n"] == 1 and n == 2:
            return int(oversize).to_bytes(2, "big")
        return b""

    monkeypatch.setattr(axfr_mod, "_recv_exact", fake_recv_exact)

    with pytest.raises(AXFRError):
        axfr_transfer("127.0.0.1", 53, "example.com")


def test_axfr_transfer_rejects_max_total_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: axfr_transfer raises AXFRError when total bytes exceed cap.

    Inputs:
      - monkeypatch: patches socket.create_connection and _recv_exact.

    Outputs:
      - None; asserts AXFRError is raised.
    """
    import foghorn.servers.transports.axfr as axfr_mod

    dummy = _DummySock()

    monkeypatch.setattr(
        axfr_mod.socket,
        "create_connection",
        lambda *a, **k: dummy,
    )

    body = _make_response_bytes(
        "example.com.",
        [RR("example.com.", QTYPE.A, rdata=A("192.0.2.10"), ttl=300)],
    )
    body_len = len(body)
    calls = {"n": 0}

    def fake_recv_exact(sock, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return int(body_len).to_bytes(2, "big")
        if calls["n"] == 2 and n == body_len:
            return body
        if calls["n"] == 3 and n == 2:
            return int(body_len).to_bytes(2, "big")
        if calls["n"] == 4 and n == body_len:
            return body
        return b""

    monkeypatch.setattr(axfr_mod, "_recv_exact", fake_recv_exact)

    with pytest.raises(AXFRError):
        axfr_transfer(
            "127.0.0.1",
            53,
            "example.com",
            max_total_bytes=body_len + (body_len // 2),
        )


def test_axfr_transfer_rejects_max_rrs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Brief: axfr_transfer raises AXFRError when RR count exceeds cap.

    Inputs:
      - monkeypatch: patches socket.create_connection and _recv_exact.

    Outputs:
      - None; asserts AXFRError is raised.
    """
    import foghorn.servers.transports.axfr as axfr_mod

    dummy = _DummySock()

    monkeypatch.setattr(
        axfr_mod.socket,
        "create_connection",
        lambda *a, **k: dummy,
    )

    body = _make_response_bytes(
        "example.com.",
        [
            RR("example.com.", QTYPE.A, rdata=A("192.0.2.10"), ttl=300),
            RR("example.com.", QTYPE.A, rdata=A("192.0.2.11"), ttl=300),
        ],
    )
    body_len = len(body)
    calls = {"n": 0}

    def fake_recv_exact(sock, n: int) -> bytes:  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 1 and n == 2:
            return int(body_len).to_bytes(2, "big")
        if calls["n"] == 2 and n == body_len:
            return body
        return b""

    monkeypatch.setattr(axfr_mod, "_recv_exact", fake_recv_exact)

    with pytest.raises(AXFRError):
        axfr_transfer("127.0.0.1", 53, "example.com", max_rrs=1)
