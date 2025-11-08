"""
Brief: Test TC=1 on UDP triggers TCP fallback in send_query_with_failover.

Inputs:
  - None

Outputs:
  - None
"""

import types

from dnslib import DNSRecord, DNSHeader, QTYPE, RCODE

import foghorn.server as srv


def test_tc_bit_udp_fallbacks_to_tcp(monkeypatch):
    # Build a normal query
    q = DNSRecord.question("example.com", "A")

    # Build a truncated UDP reply (TC=1) by taking a normal reply and flipping TC
    r_norm = q.reply()
    r_norm.header.tc = 1
    truncated = r_norm.pack()

    # Monkeypatch udp_query to return truncated
    def fake_udp_query(host, port, query_bytes, timeout_ms=0):
        return truncated

    # Monkeypatch tcp_query to return a full non-truncated reply
    r2 = q.reply()
    r2.header.tc = 0
    good = r2.pack()

    def fake_tcp_query(
        host, port, query_bytes, connect_timeout_ms=0, read_timeout_ms=0
    ):
        return good

    # udp_query is imported locally inside send_query_with_failover, so patch the transport function
    import foghorn.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", fake_udp_query)
    # tcp_query is imported at module level; patch on srv
    monkeypatch.setattr(srv, "tcp_query", fake_tcp_query)

    upstreams = [{"host": "1.1.1.1", "port": 53, "transport": "udp"}]

    resp, used, reason = srv.send_query_with_failover(
        q, upstreams, 500, "example.com", QTYPE.A
    )

    # We expect TCP fallback to be used and a successful response
    assert used["transport"] == "tcp"
    assert reason == "ok"
    # And response should parse without TC flag
    parsed = DNSRecord.parse(resp)
    assert getattr(parsed.header, "tc", 0) == 0
