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
from foghorn.stats import StatsCollector


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
            # Pretend the upstream validated this response so AD is set.
            child_reply.header.ad = 1
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


def test_recursive_acl_denies_client_and_uses_forwarding(monkeypatch) -> None:
    """Brief: allow_recursive_from prevents recursion for disallowed clients.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures resolve_query_bytes falls back to forwarding when the client IP
        is not in resolver.allow_recursive_from and that resolve_iterative is
        never invoked.
    """

    # Configure handler for recursive mode but restrict recursion to 192.0.2.0/24.
    monkeypatch.setattr(DNSUDPHandler, "recursive_mode", "recursive", raising=False)
    monkeypatch.setattr(
        DNSUDPHandler,
        "recursive_allow_nets",
        [
            __import__("ipaddress").ip_network("192.0.2.0/24", strict=False),
        ],
        raising=False,
    )

    # Provide upstreams so the forwarding path can succeed.
    monkeypatch.setattr(
        DNSUDPHandler,
        "upstream_addrs",
        [{"host": "192.0.2.200", "port": 53, "transport": "udp"}],
        raising=False,
    )

    # Ensure recursive path is never entered by making it raise if called.
    def _boom(*args, **kwargs):  # type: ignore[override]
        raise AssertionError(
            "resolve_iterative should not be called for disallowed client"
        )

    monkeypatch.setattr(rr, "resolve_iterative", _boom, raising=False)

    # Forwarding path: return a trivial NOERROR answer.
    def _fake_forward(query, upstreams, timeout_ms, qname, qtype):  # type: ignore[override]
        resp = query.reply()
        resp.header.rcode = RCODE.NOERROR
        return resp.pack(), upstreams[0], "ok"

    monkeypatch.setattr(
        "foghorn.server.send_query_with_failover", _fake_forward, raising=False
    )

    # Disallowed client IP (not in 192.0.2.0/24) should be served via forwarding.
    q = DNSRecord.question("acl-forward.example", "A")
    wire = resolve_query_bytes(q.pack(), "203.0.113.1")
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR


def test_recursive_max_inflight_falls_back_to_forward(monkeypatch) -> None:
    """Brief: when recursive_max_inflight is reached, query uses forward path.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures that once recursive_inflight reaches recursive_max_inflight,
        additional queries skip resolve_iterative and go through forwarding.
    """

    # Enable recursive mode and set a small inflight cap that is already
    # saturated before the call.
    monkeypatch.setattr(DNSUDPHandler, "recursive_mode", "recursive", raising=False)
    monkeypatch.setattr(DNSUDPHandler, "recursive_max_inflight", 1, raising=False)
    monkeypatch.setattr(DNSUDPHandler, "recursive_inflight", 1, raising=False)

    # No ACL restrictions for this test.
    monkeypatch.setattr(DNSUDPHandler, "recursive_allow_nets", None, raising=False)

    # Any attempt to use resolve_iterative should fail the test.
    def _boom(*args, **kwargs):  # type: ignore[override]
        raise AssertionError(
            "resolve_iterative should not be called when at inflight cap"
        )

    monkeypatch.setattr(rr, "resolve_iterative", _boom, raising=False)

    # Forwarding path returns a simple NOERROR answer.
    def _fake_forward(query, upstreams, timeout_ms, qname, qtype):  # type: ignore[override]
        resp = query.reply()
        resp.header.rcode = RCODE.NOERROR
        return resp.pack(), upstreams[0], "ok"

    monkeypatch.setattr(
        "foghorn.server.send_query_with_failover", _fake_forward, raising=False
    )
    monkeypatch.setattr(
        DNSUDPHandler,
        "upstream_addrs",
        [{"host": "192.0.2.201", "port": 53, "transport": "udp"}],
        raising=False,
    )

    q = DNSRecord.question("limit-forward.example", "A")
    wire = resolve_query_bytes(q.pack(), "192.0.2.55")
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR


def test_recursive_stats_counters_for_recursive_query(monkeypatch) -> None:
    """Brief: recursive mode updates recursion-specific statistics.

    Inputs:
      - monkeypatch: pytest monkeypatch fixture.

    Outputs:
      - Ensures resolve_query_bytes in recursive mode increments recursive
        counters in the attached StatsCollector.
    """

    # Fresh stats collector attached to the handler.
    stats = StatsCollector(
        track_uniques=False,
        include_qtype_breakdown=False,
        include_top_clients=False,
        include_top_domains=False,
        track_latency=False,
    )
    monkeypatch.setattr(DNSUDPHandler, "stats_collector", stats, raising=False)

    # Configure recursive mode with fake cache/transport as in the core test.
    monkeypatch.setattr(DNSUDPHandler, "recursive_mode", "recursive", raising=False)
    monkeypatch.setattr(DNSUDPHandler, "plugins", [], raising=False)
    # Enable DNSSEC passthrough so that dnssec_queries and AD stats are updated.
    monkeypatch.setattr(DNSUDPHandler, "dnssec_mode", "passthrough", raising=False)

    cache = InMemoryRecursiveCache()
    transports = _FakeRecursiveTransport()
    monkeypatch.setattr(DNSUDPHandler, "recursive_cache", cache, raising=False)
    monkeypatch.setattr(
        DNSUDPHandler, "recursive_transports", transports, raising=False
    )

    # Disable forwarding path so any accidental fallback would fail the test.
    monkeypatch.setattr(DNSUDPHandler, "upstream_addrs", [], raising=False)
    root = rr.AuthorityEndpoint(name=".", host="192.0.2.1", port=53, transport="udp")
    monkeypatch.setattr(rr, "get_root_servers", lambda: [root])

    q = DNSRecord.question("www.example.test", "A")
    wire = resolve_query_bytes(q.pack(), "127.0.0.1")
    resp = DNSRecord.parse(wire)
    assert resp.header.rcode == RCODE.NOERROR

    snap = stats.snapshot(reset=False)
    assert snap.totals["recursive_queries"] == 1
    assert snap.totals["recursive_rcode_NOERROR"] == 1
    # Successful recursion should not record fallback counters.
    assert snap.totals.get("recursive_fallback_acl", 0) == 0
    # DNSSEC stats should reflect the recursive query and AD=1 on the upstream
    # reply from the fake transport.
    assert snap.totals["dnssec_queries"] == 1
    assert snap.totals["dnssec_ad_upstream"] == 1
