"""End-to-end tests for recursive resolver mode via resolve_query_bytes.

Inputs:
  - None (pytest discovers and runs tests).

Outputs:
  - None (pytest assertions verifying recursive mode behavior).

Brief:
  These tests exercise resolver.mode == 'recursive' through the public
  resolve_query_bytes helper, using a fake TransportFacade and patched
  root hints so no real network I/O occurs.
"""

from __future__ import annotations

from typing import List, Tuple

from dnslib import A, NS, QTYPE, RCODE, RR, DNSRecord

from foghorn.server import resolve_query_bytes
from foghorn.udp_server import DNSUDPHandler
from foghorn import recursive_resolver as rr
from foghorn.recursive_cache import InMemoryRecursiveCache


class _FakeRecursiveTransport:
    """Brief: In-memory TransportFacade used to simulate authority answers.

    Inputs:
      - None

    Outputs:
      - Instance with .calls list capturing (authority, wire_query, timeout_ms).
    """

    def __init__(self) -> None:
        self.calls: List[Tuple[rr.AuthorityEndpoint, bytes, int]] = []

    def query(  # type: ignore[override]
        self,
        authority: rr.AuthorityEndpoint,
        wire_query: bytes,
        *,
        timeout_ms: int,
    ) -> tuple[bytes | None, str | None]:
        """Brief: Simulate a root referral followed by a child answer.

        Inputs:
          - authority: AuthorityEndpoint selected by resolve_iterative.
          - wire_query: Wire-format DNS query bytes.
          - timeout_ms: Per-attempt timeout (ignored here but recorded).

        Outputs:
          - (wire, None) on success, or (None, 'network_error') otherwise.
        """

        self.calls.append((authority, wire_query, timeout_ms))

        # Parse query to inspect qname/qtype.
        msg = DNSRecord.parse(wire_query)
        q = msg.questions[0]
        qname = str(q.qname).rstrip(".")

        # Root authority: return a referral to example.test with NS+glue.
        if authority.host == "192.0.2.1":
            root_reply = msg.reply()
            root_reply.header.rcode = RCODE.NOERROR
            root_reply.add_auth(
                RR("example.test", QTYPE.NS, rdata=NS("ns.example.test."), ttl=300)
            )
            root_reply.add_ar(
                RR("ns.example.test", QTYPE.A, rdata=A("198.51.100.1"), ttl=300)
            )
            return root_reply.pack(), None

        # Child authority reached via glue IP: return final NOERROR answer.
        if authority.host == "198.51.100.1" and qname == "www.example.test":
            child_reply = msg.reply()
            child_reply.header.rcode = RCODE.NOERROR
            child_reply.add_answer(
                RR("www.example.test", QTYPE.A, rdata=A("203.0.113.5"), ttl=300)
            )
            return child_reply.pack(), None

        # Any unexpected authority/qname combination is treated as a failure.
        return None, "network_error"


def test_resolver_mode_recursive_uses_iterative_core(monkeypatch) -> None:
    """Brief: resolver.mode=recursive drives resolution via resolve_iterative.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures resolve_query_bytes returns a final NOERROR answer produced by
        the iterative core and that our fake transport sees root and child
        authority traffic.
    """

    # Configure DNSUDPHandler to run in recursive mode for this test only and
    # disable any installed plugins so they do not alter the recursive answer.
    monkeypatch.setattr(DNSUDPHandler, "recursive_mode", "recursive", raising=False)
    monkeypatch.setattr(DNSUDPHandler, "plugins", [], raising=False)

    # Attach a fresh recursive cache and our fake transport facade.
    cache = InMemoryRecursiveCache()
    transports = _FakeRecursiveTransport()
    monkeypatch.setattr(DNSUDPHandler, "recursive_cache", cache, raising=False)
    monkeypatch.setattr(
        DNSUDPHandler, "recursive_transports", transports, raising=False
    )

    # Ensure forwarding path is effectively disabled so we can detect any
    # accidental fallback out of recursive mode.
    monkeypatch.setattr(DNSUDPHandler, "upstream_addrs", [], raising=False)
    monkeypatch.setattr(DNSUDPHandler, "dnssec_mode", "ignore", raising=False)

    # Patch get_root_servers to return a single synthetic root authority.
    root = rr.AuthorityEndpoint(name=".", host="192.0.2.1", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    # Build a client query and run it through the public helper.
    q = DNSRecord.question("www.example.test", "A")
    wire = resolve_query_bytes(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(wire)

    assert resp.header.rcode == RCODE.NOERROR
    answers = [rr_ for rr_ in (resp.rr or []) if rr_.rtype == QTYPE.A]
    assert answers, "expected at least one A answer"
    assert str(answers[0].rdata) == "203.0.113.5"

    # Ensure our fake transport saw both the root and child authorities.
    hosts = [call[0].host for call in transports.calls]
    assert "192.0.2.1" in hosts
    assert "198.51.100.1" in hosts
