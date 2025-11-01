"""
Brief: Focused unit tests for foghorn.server helpers to ensure coverage.

Inputs:
  - None

Outputs:
  - None
"""

import pytest
from foghorn.server import (
    _set_response_id,
    compute_effective_ttl,
    send_query_with_failover,
)
from dnslib import DNSRecord, DNSHeader, QTYPE, RR, A, RCODE


def test_set_response_id_rewrites_first_two_bytes():
    """
    Brief: _set_response_id replaces the first two bytes with the request ID.

    Inputs:
      - wire: bytes of DNS response
      - req_id: integer ID to set

    Outputs:
      - None: Asserts bytes[0:2] equal to req_id
    """
    wire = b"\x12\x34restofpacket"
    out = _set_response_id(wire, 0xBEEF)
    assert out[:2] == bytes([0xBE, 0xEF])
    assert out[2:] == b"restofpacket"


def test_set_response_id_short_wire_returns_unchanged():
    """
    Brief: _set_response_id returns original when wire shorter than 2 bytes.

    Inputs:
      - wire: one-byte bytes object

    Outputs:
      - None: Asserts same object content
    """
    wire = b"\x00"
    out = _set_response_id(wire, 0x1234)
    assert out == wire


def test_compute_effective_ttl_noerror_with_answers_uses_min_floor():
    """
    Brief: compute_effective_ttl applies min floor across answers.

    Inputs:
      - resp: DNSRecord with two answers of TTL 30 and 120
      - min_cache_ttl: 60

    Outputs:
      - None: Asserts effective ttl = max(min(answer.ttl), floor)
    """
    q = DNSRecord.question("example.com", "A")
    resp = q.reply()
    resp.add_answer(RR("example.com", QTYPE.A, rdata=A("1.2.3.4"), ttl=30))
    resp.add_answer(RR("example.com", QTYPE.A, rdata=A("2.3.4.5"), ttl=120))
    ttl = compute_effective_ttl(resp, 60)
    assert ttl == 60


def test_compute_effective_ttl_non_noerror_or_no_answers_returns_floor():
    """
    Brief: compute_effective_ttl returns floor for NXDOMAIN or no answers.

    Inputs:
      - resp: DNSRecord with NXDOMAIN

    Outputs:
      - None: Asserts floor returned
    """
    q = DNSRecord.question("example.com", "A")
    resp = q.reply()
    resp.header.rcode = RCODE.NXDOMAIN
    assert compute_effective_ttl(resp, 50) == 50


def test_send_query_with_failover_parsing_and_servfail_failover(monkeypatch):
    """
    Brief: send_query_with_failover skips SERVFAIL and parsing errors, succeeds on next.

    Inputs:
      - upstreams: two servers, first returns SERVFAIL, second OK

    Outputs:
      - None: Asserts second upstream chosen and 'ok' reason
    """

    class DummyQuery:
        def send(self, host, port, timeout=None):
            if host == "bad":
                return b"bad-bytes"
            return b"good-bytes"

    class DummyParsed:
        class header:
            rcode = RCODE.SERVFAIL

    class DummyParsedOK:
        class header:
            rcode = RCODE.NOERROR

    parse_calls = {"count": 0}

    def fake_parse(wire):
        parse_calls["count"] += 1
        if wire == b"bad-bytes":
            return DummyParsed
        return DummyParsedOK

    monkeypatch.setattr("foghorn.server.DNSRecord.parse", fake_parse)

    resp, used, reason = send_query_with_failover(
        DummyQuery(),
        upstreams=[{"host": "bad", "port": 53}, {"host": "good", "port": 53}],
        timeout_ms=1000,
        qname="example.com",
        qtype=QTYPE.A,
    )

    assert resp == b"good-bytes"
    assert used == {"host": "good", "port": 53}
    assert reason == "ok"


def test_send_query_with_failover_all_failed(monkeypatch):
    """
    Brief: send_query_with_failover returns all_failed when all attempts fail.

    Inputs:
      - upstreams: two servers raising exceptions

    Outputs:
      - None: Asserts all_failed with None response
    """

    class DummyQuery:
        def send(self, host, port, timeout=None):
            raise RuntimeError("boom")

    # Make parse raise to simulate malformed bytes (not reached here but keep consistent)
    def fake_parse(wire):
        raise ValueError("bad packet")

    monkeypatch.setattr("foghorn.server.DNSRecord.parse", fake_parse)

    resp, used, reason = send_query_with_failover(
        DummyQuery(),
        upstreams=[{"host": "u1", "port": 53}, {"host": "u2", "port": 53}],
        timeout_ms=500,
        qname="ex",
        qtype=QTYPE.A,
    )

    assert resp is None and used is None and reason == "all_failed"


def test_send_query_with_failover_no_upstreams():
    """
    Brief: send_query_with_failover returns no_upstreams when list is empty.

    Inputs:
      - upstreams: empty list

    Outputs:
      - None: Asserts (None, None, 'no_upstreams')
    """
    q = DNSRecord.question("example.com", "A")
    resp, used, reason = send_query_with_failover(
        q, upstreams=[], timeout_ms=100, qname="x", qtype=1
    )
    assert resp is None and used is None and reason == "no_upstreams"
