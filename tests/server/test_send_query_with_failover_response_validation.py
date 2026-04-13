"""Brief: Tests for failover response validation (TXID/question matching).

Inputs:
  - None.

Outputs:
  - None.
"""

from __future__ import annotations

from dnslib import QTYPE, DNSRecord

import foghorn.servers.server as srv


def test_failover_rejects_mismatched_response(monkeypatch):
    """Brief: Mismatched upstream responses should be treated as failures.

    Inputs:
      - monkeypatch: pytest fixture.

    Outputs:
      - None.

    Scenario:
      - First upstream returns a valid DNS packet but with a different TXID.
      - Second upstream returns a correct response.
      - send_query_with_failover should ignore the first and accept the second.
    """

    q = DNSRecord.question("example.com", "A")

    bad = q.reply()
    bad.header.id = (q.header.id + 1) & 0xFFFF
    bad_wire = bad.pack()

    good = q.reply()
    good.header.id = q.header.id
    good_wire = good.pack()

    calls = {"n": 0}

    def fake_udp_query(host, port, query_bytes, timeout_ms=0):
        calls["n"] += 1
        if calls["n"] == 1:
            return bad_wire
        return good_wire

    import foghorn.servers.transports.udp as udp_mod

    monkeypatch.setattr(udp_mod, "udp_query", fake_udp_query)

    upstreams = [
        {"host": "1.1.1.1", "port": 53, "transport": "udp"},
        {"host": "8.8.8.8", "port": 53, "transport": "udp"},
    ]

    resp, used, reason = srv.send_query_with_failover(
        q, upstreams, 500, "example.com", QTYPE.A
    )

    assert reason == "ok"
    assert resp == good_wire
    assert used is not None
    assert used.get("host") == "8.8.8.8"
